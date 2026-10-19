# Allowlist review, 2026-10-19

Input: the "missing entry" table of `run_eval.py` over the **tune half** of the 943-file Hugging Face
corpus (435 files from 347 repos, `evaluation/splits/hf-tune.txt`). The held-out half was not looked
at for this review; its false-positive rate is the headline number.

Rules applied to every candidate:

- exact `(module, name)` pairs only, never a module or a prefix;
- a pair is added only when nothing it does while loading can run code an attacker chooses;
- a pair that calls one of its arguments, or that would run its constructor, is added only together
  with an argument check (`pickle_static._argument_check`) and a regression test that keeps every
  other use flagged (`tests/test_allowlist_review_20261019.py`);
- library code was read where it is installed in this container (scikit-learn 1.9.1, scipy 1.18.1,
  pandas 3.0.5, CPython's argparse). torch, transformers, accelerate, ultralytics and xgboost are not
  installed here, and this evaluation may contact only huggingface.co, so their source was not re-read.

## Argument checks

| check | what passes | what stays flagged |
|---|---|---|
| state-only class | `NEWOBJ` with no arguments, then `BUILD` (how protocol 2+ saves a plain instance): only `object.__new__` and `__setstate__` / a `__dict__` update run | calling the class (`REDUCE`, `OBJ`, `INST`, `NEWOBJ` with arguments), `BUILD` on the class object, passing the class as a value |
| enum lookup | `cls(value)` with one `str` or `int` | two or more arguments (the functional API makes a new enum), a non-literal argument, `NEWOBJ` |
| `pandas.core.indexes.base._new_Index` | `_new_Index(Index, {"data": ..., "name": ...})`, as `Index.__reduce__` writes it | any other first argument (it calls `cls.__new__(cls, **d)`), any other key, a non-dict |
| `collections.defaultdict` | no factory, or one imported global (checked against the allowlist like any import; it runs only on a missing key, after loading) | a factory that is not a global, an argument-checked class as factory, extra arguments |

## Decisions

| missing entry (tune files) | decision | why |
|---|---|---|
| `transformers.trainer_utils.IntervalStrategy` (12), `SchedulerType` (12), `HubStrategy` (10), `SaveStrategy` (4), `EvaluationStrategy` (1); `transformers.training_args.OptimizerNames` (9); `accelerate.utils.dataclasses.DistributedType` (2) | added, enum lookup | `str` enums; a member lookup runs `Enum.__new__` and `_missing_` only |
| `transformers.training_args.TrainingArguments` (10), `transformers.training_args_seq2seq.Seq2SeqTrainingArguments` (2) | added, state-only | dataclasses. Rebuilt from state, `__post_init__` (device setup, reading a DeepSpeed config file) never runs; every field value is a global of its own or plain data, and nothing calls a field while loading. Assumes the class defines no `__setstate__` (true as far as I know; not re-read here) |
| `accelerate.state.PartialState` (17) | **left out** | a shared-state singleton whose construction initialises distributed state; not verifiable here. Most `training_args.bin` files still need it, so they stay UNVERIFIABLE |
| `transformers.trainer_pt_utils.AcceleratorConfig` (6) | left out | every file that has it also needs `PartialState` |
| `transformers.deepspeed.*`, `accelerate.utils.dataclasses.DeepSpeedPlugin`, `trl...SFTConfig`, `llava...TrainingArguments`, `yart...RankerTrainingArguments` | left out | one or two files each; DeepSpeed configs read files |
| `argparse.Namespace` (1) | added, state-only | stdlib, no pickling hooks (read) |
| `torch.nn.modules.*` (up to 27 each: SiLU, BatchNorm2d, ModuleList, Sequential, Conv2d, MaxPool2d, Upsample, Identity, Linear, ...) | **left out for now** | every tune file that needs them is an Ultralytics full-model checkpoint that also needs `ultralytics.*` classes, so adding them clears no file. When added, they go in one by one as state-only classes (`torch.save` writes modules with `NEWOBJ` + `BUILD`) |
| `ultralytics.*` (up to 22 each) | left out | third-party classes with their own code, source not available here; two of these checkpoints also import `getattr` (see below) |
| `torchvision.transforms.*`, `torch.nn.modules.loss.*` | left out | only inside Ultralytics checkpoints |
| `xgboost.core.Booster` (19), `xgboost.sklearn.XGBClassifier` (11) / `XGBRegressor` (8), `xgboost.compat.XGBoostLabelEncoder` (8) | **left out (unsafe without review)** | `Booster.__setstate__` hands the raw model bytes to xgboost's native parser |
| `sklearn.preprocessing._encoders.OrdinalEncoder` (12), `sklearn.impute._base.MissingIndicator` (9), `sklearn.model_selection._split.StratifiedKFold` (10), `sklearn.model_selection._search_successive_halving.HalvingGridSearchCV` (6), `sklearn.preprocessing._data.MinMaxScaler` (5), `sklearn.linear_model._logistic.LogisticRegressionCV` (4), `sklearn.tree._classes.ExtraTreeRegressor` (2), and from the 310-file run `CalibratedClassifierCV`, `_CalibratedClassifier`, `_SigmoidCalibration`, `RandomForestRegressor`, `SimpleImputer`, `Lasso`, `MultinomialNB`, `LinearSVC` | added, state-only | scikit-learn 1.9.1: no `__reduce__`, only `BaseEstimator.__setstate__` (version warning, `__dict__` update; read); constructors only store parameters |
| `sklearn.compose._column_transformer.make_column_selector` (3) | added, state-only | `__init__` stores three attributes, `__call__` selects columns; no pickling hooks (read) |
| `builtins.object`, `numpy.number` (2, as `make_column_selector` values) | added | types used as values; calling `object()` makes a bare object, `numpy.number()` raises. `builtins.object` had been scored as a sink only because its module is `builtins` |
| `sklearn._loss._loss.__pyx_unpickle_CyHalfBinomialLoss` (4) | added | same Cython unpickle helper as the already allowed `__pyx_unpickle_CyHalfMultinomialLoss` |
| `sklearn.preprocessing._function_transformer.FunctionTransformer` (2), `sklearn.metrics._scorer.*`, `sklearn.metrics.*_score` | left out | hold or are arbitrary callables |
| `sklearn.ensemble._hist_gradient_boosting.loss.BinaryCrossEntropy`, `sklearn.compose._column_transformer._RemainderColsList` | left out | not in the installed scikit-learn, cannot be checked |
| `scipy.sparse._csr.csr_matrix` (from the 310-file run) | added, state-only | no pickling hooks in scipy 1.18 (read) |
| `pandas.core.indexes.base._new_Index`, `pandas.core.indexes.base.Index` | added, `_new_Index` check; `Index` state-only | `_new_Index` calls its first argument, so only pandas' `Index` is accepted there (pandas 3.0.5 source read) |
| `pandas.core.frame.DataFrame`, `pandas.core.series.Series`, `pandas.core.internals.managers.*`, `pandas._libs.internals._unpickle_block`, `pandas.core.dtypes.dtypes.CategoricalDtype` (7 to 11, all in `dabl` pickles) | left out | `_unpickle_block` and the managers need their own argument checks, and every one of these files also needs `dabl.*` |
| `numpy.ma.core._mareconstruct` / `MaskedArray` (7) | left out | `_mareconstruct` calls its class arguments; needs a check of its own, and the files also need scorers |
| `collections.defaultdict` | added, factory check | the factory runs only on a missing key after loading; as a global it is checked like any import (owner rule: factory checked as global) |
| `gymnasium.*`, `stable_baselines3.*`, `dabl.*`, `autogluon.*`, `imodels.*`, `tiktoken.*`, `__main__.*`, `_loss.*` | left out | third-party or user code; `_loss` is not a scikit-learn path |
| Keras `RandomRotation`, `RandomTranslation`, `RandomZoom`, `RandomContrast`, `RandomFlip` | added (class names) | config is numbers and fixed-choice strings; nested objects are still checked (test) |
| Keras `OrthogonalInitializer`, `CategoricalFocalCrossentropy`, `R2Score`; `keras.src.ops.numpy.Subtract` / `TrueDivide` | added | numbers only / elementwise ops without a callable argument |
| `keras.layers.TFSMLayer` (4) | **left out (unsafe)** | loads a TensorFlow SavedModel from a path at construction |
| Keras custom classes, `builtins.<custom loss>`, `Custom>...` registered names, `loss/metric.<name>` | left out | the author's own code: UNVERIFIABLE by design |

## Not allowlist questions

- **`__builtin__.getattr` in Ultralytics checkpoints** (`Ultralytics/YOLO11/yolo11n-seg.pt`,
  `keremberke/yolov8m-building-segmentation/best.pt`; the Hub's own scanner marks both unsafe, and
  `ScanMe/test-models/THIS_MODEL_IS_BENIGN_ANY_DETECTION_IS_AN_FP.pkl` is the same pattern). The verdict
  is MALICIOUS because `getattr` reaches any attribute; it stays that way (fail closed, never
  overridable). An argument check that accepts only `getattr(<allowlisted class>, <fixed name>)` would
  be possible, but needs the Ultralytics source to know which names. Open question.
- **Value-walk limit**: three large TF-IDF pickles hit the 100,000-step limit of the argument-check value
  walk and were RISKY. The walk now visits each container once per stream (budget 10,000,000 steps), so a
  vocabulary passed to many `BUILD`s costs one walk.
- 20 OpenVINO / CTranslate2 / KenLM `.bin` files in the tune half are not a format safeloadai reads: RISKY "unrecognised
  file format", by design.

## Source review (second pass, same day)

Following the owner's decisions, the torch, torchvision, ultralytics and xgboost
sources were read from PyPI wheels. They were downloaded with
`pip download --no-deps`, unpacked and read, and never installed, imported or run. The
review used the tune half only. The full table, with file:line for each pair and the
sha256 of each wheel, is in
[source-review-20261019.md](source-review-20261019.md).

- **Added as state-only.** `torch.save` writes an `nn.Module` as `NEWOBJ ()` plus
  `BUILD`, and `Module.__setstate__` only updates `__dict__` and fills empty hook dicts.
  On that basis 64 exact pairs were added:
  - 13 `torch.nn` classes;
  - 5 torchvision transforms;
  - 43 ultralytics classes, including 9 old `ultralytics.nn.modules.<Name>` paths
    from 8.0.x;
  - `XGBClassifier`, `XGBRegressor` and `XGBoostLabelEncoder`.
- **Added as an enum lookup.** `torchvision.transforms.functional.InterpolationMode`.
- **`getattr` in Ultralytics checkpoints.** Two forms occur:
  - `getattr(Detect, "forward")`, which comes from ultralytics 8.0.x
    `Segment.__init__`: `self.detect = Detect.forward`;
  - `getattr(<module>, "forward_fuse")`, which comes from `fuse()`.

  Both use a fixed public name, and the result is stored, never called. Under the
  owner's rule both are now CLEAN once their classes are allowlisted. An allowlisted
  class as getattr's target is not treated as "a value passed to a call", because
  getattr never calls its target. A called result stays MALICIOUS, and so does a
  dunder or sink name.
- **Left out, pending the owner's decision:**
  - `xgboost.core.Booster`. Its `__setstate__` hands the file's raw bytes to
    libxgboost's native parser.
  - `ultralytics.utils.IterableSimpleNamespace` and its 8.0.x path. Pickle writes it
    as `REDUCE cls()` plus `BUILD`, which would need a new "call with no arguments"
    rule.
- **Left out because they are not on tune:** RNN, lazy and parametrized modules,
  `BNContrastiveHead` and `AAttn`.
