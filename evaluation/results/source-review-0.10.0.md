# Source review 5 (0.10.0): what still blocked benign tune files

Allowlist and format work for 0.10.0 used the **tune** and **tune-2** splits only (3,372 files
fetched again at their pinned commits: 3,332 benign, 5 malicious, 35 unclear). held-out,
held-out-2 and the new held-out-3 were not looked at for any decision below. Library sources
were read from PyPI archives (`tools/pypi_archives.py`: checked against PyPI's sha256, never
installed, imported or run), except where a fresh virtual environment is named: those were
built only to read `sys.modules` after an import, with no model file anywhere near them.

## What blocked benign tune files (safeloadai 0.9.0)

0.9.0 on the 3,332 benign tune files: 2,786 CLEAN, 465 SUSPICIOUS, 76 UNSUPPORTED, 4 MALICIOUS,
1 error. Items outside the allowlist, counted once per benign file that was not CLEAN:

| item | files | outcome in 0.10.0 |
|---|---|---|
| `xgboost.core.Booster` | 94 | stays UNVERIFIABLE by default (A2); `--validate-boosters` opt-in |
| `_loss.CyHalfBinomialLoss`, `CyHalfSquaredError`, `CyHalfMultinomialLoss`, ... | 28 + 12 + 7 | accepted as the scikit-learn alias only (below) |
| `sklearn.compose._column_transformer._RemainderColsList` | 22 | state-only (reviewed in the 1.5 and 1.6 sources) |
| `sklearn.preprocessing._function_transformer.FunctionTransformer` | 15 | stays off (owner decision A1) |
| `lightgbm.basic.Booster` | 15 | as `xgboost.core.Booster` |
| `lightgbm.sklearn.LGBMClassifier`, `LGBMRegressor` | 11 + 4 | state-only |
| `keras.metrics.SparseTopKCategoricalAccuracy`, `TopKCategoricalAccuracy` | 9 + 5 | Keras class (keras 3.0.5 and 3.12.0) |
| `dill._dill._load_type` | 8 | stays RISKY (D1: dill can carry code) |
| `sklearn.ensemble._hist_gradient_boosting.gradient_boosting.HistGradientBoostingRegressor` | 8 | state-only |
| `sklearn.utils._bunch.Bunch` | 4 | state-only |
| user code (`batteryswap_example.*`, custom Keras layers, `builtins.preprocess_input`, ...) | | the floor: stays blocked |

The 76 UNSUPPORTED files were OpenVINO, Core ML, CTranslate2 and whisper.cpp weights and
KenLM language models with a `.bin` name. Part 1 below.

## No-code formats (Part 1)

Each check follows the reader of the library named, field by field, and refuses whatever that
reader would refuse or read differently. A file that passes is CLEAN ("data-only format, no
code on load"); a file that reads as one of these and as anything else is a polyglot.

* **Core ML weight blobs** (coremltools 9.0, `mil/blob/storage.cpp` and
  `storage_reader.cpp`): 64-byte header, version 2, metadata sentinel `0xDEADBEEF` at every
  64-byte boundary the previous blob ends on, dtypes 1 to 17 with their bit widths, data
  offset = metadata offset + 64, size consistent with the dtype. `padding_size_in_bits` is
  read only for sub-byte types (it must be below 8); for byte types the reader ignores it
  (the field was reserved and uninitialised before iOS 18, and real files hold garbage there).
  An empty blob is refused (`Span::Slice` refuses size 0). Tune: 6 of 6 CLEAN.
* **CTranslate2** (4.6.0 `src/models/model.cc`): binary versions 1 to 6, a spec name the
  library registers, u16-length NUL-terminated ASCII strings, each variable's byte count equal
  to the product of its shape times the item size of its dtype (ids 0 to 5), aliases that name
  existing variables, nothing after the aliases. Tune: 6 of 6 CLEAN.
* **whisper.cpp ggml** (1.8.2 `src/whisper.cpp`): magic `lmgg`, 11 int32 hyperparameters,
  vocabulary 51864 to 51866, the weight type from `ftype % 1000`, the tensor table the
  hyperparameters imply (every tensor exactly once, conv weights in F16 unless the model is
  F32), 1 to 4 dimensions without int32 overflow, no trailing bytes. Tune: 3 of 4 CLEAN; the
  fourth uses ggml type 64 from a fork and is SUSPICIOUS (RISKY) instead of UNSUPPORTED.
* **TFLite associated files**: TFLite Model Maker appends a ZIP of label and vocabulary files
  to the flatbuffer. One plain ZIP whose members are all top-level `.txt` or `.json` files is
  recorded as a note; anything else in the ZIP keeps the file UNVERIFIABLE.
* **KenLM** stays UNSUPPORTED: its binary format has several trie layouts and quantisations
  whose sizes depend on each other, and a partial check would claim more than it reads.

## scikit-learn's `_loss` alias (Part 2)

scikit-learn 1.5 to 1.8 build the Cython loss module with meson under the name `_loss`, so
its classes pickle as `_loss.CyHalfBinomialLoss` and so on. Checked in fresh interpreters
with scikit-learn 1.5.1, 1.6.1, 1.7.2 and 1.8.0: importing any of
`sklearn._loss.loss`, `sklearn.linear_model._stochastic_gradient`,
`sklearn.linear_model._logistic`, `sklearn.ensemble._gb` and
`sklearn.ensemble._hist_gradient_boosting.gradient_boosting` puts the compiled module in
`sys.modules['_loss']`; `sklearn`, `sklearn.base` and `sklearn.pipeline` alone do not. So
`_loss.X` resolves to `sklearn._loss._loss.X` only after one of those modules was imported.

Rule (`static/sklearn_loss.py`): a `_loss` pair is accepted exactly when
`sklearn._loss._loss` has the same name in the allowlist, and only when an earlier import of
the stream is one of those trigger modules. `safe_load` checks the same at load time:
`sys.modules['_loss']` must be the very module object `sklearn._loss._loss`, otherwise
`UnsafeModelError`. A `_loss` module of any other origin is never trusted. Also added:
`CyPinballLoss` and its Cython unpickle helper (1.5.1 to 1.9.1 `_loss.pyx.tp`: one double).

## State-only classes (Part 2)

Accepted only as `NEWOBJ cls ()` followed by BUILD with a dict; calling one, giving NEWOBJ
arguments, or a sink anywhere in the state stays flagged
(`tests/test_allowlist_review_0_10_0.py`).

* scikit-learn 1.5.1, 1.6.1, 1.7.2, 1.8.0, 1.9.1: `HistGradientBoostingRegressor` (no hooks of
  its own or in its base; `BaseEstimator.__setstate__`), `_RemainderColsList` (1.5 and 1.6: a
  `UserList` with three plain attributes, no hooks, no `__setattr__`), `Bunch` (a dict
  subclass; `__setstate__` ignores the state).
* Training arguments: llamafactory 0.9.5 `TrainingArguments`, FlagEmbedding 1.2.11 and 1.4.2
  `RetrieverTrainingArguments` and `EncoderOnlyEmbedderM3TrainingArguments`, ms-swift 3.2.0 and
  3.8.0 `GRPOConfig`, axolotl 0.6.0, 0.8.0 and 0.21.1 `AxolotlTrainingArguments` (both module
  paths). Each is a dataclass over transformers' `TrainingArguments` or trl's configs (reviewed
  in 0.9.0) with no pickling hook, `__setattr__`, `__getattr__` or property setter in its own
  classes; `__post_init__` never runs on unpickling. Left out: axolotl's `DictDefault` (an
  addict dict rebuilt with items, not reviewed) and `axolotl.utils.trainer` (no source on PyPI
  for that path).
* LightGBM 3.3.5 and 4.7.0 `sklearn.py`: `LGBMClassifier`, `LGBMRegressor` (no hooks; the
  Booster they hold is a global of its own).
* pandas 1.4.4 and 3.1.0 `range.py`: `RangeIndex` through `_new_Index`, with exactly the keys
  `__reduce__` writes (`name`, `start`, `stop`, `step`) and int start, stop and step.

## pathlib path classes

A Windows checkpoint holds `pathlib.WindowsPath` objects (ultralytics `train_args`), which
0.9.0 classed as MALICIOUS because `pathlib` is a sink module. CPython 3.8 to 3.14
`Lib/pathlib`: `PurePath.__reduce__` is `(cls, parts)` and constructing a path only parses
strings, with no filesystem access. The six path classes are RISKY (like the class builders),
not sinks; their methods as globals (`Path.write_text`, `Path.unlink`, ...) or reached through
`getattr` stay sinks (`tests/test_pathlib_classes.py`).

CPython 3.13 moved the classes to `pathlib._local` (their `__module__`), so a pickle written
by 3.13 names `pathlib._local.WindowsPath`; 3.8 to 3.12 and 3.14 write `pathlib`. Checked in
3.13.17 (`pathlib`, `pathlib._abc`, `pathlib._local`) and in the 3.14.0 sources
(`pathlib/__init__.py`, `_os.py`, `types.py`): every pathlib module that has one of the six
names holds the same class, and `__reduce__` is still `(cls, tuple(self._raw_paths))`. The
rule therefore matches the root package `pathlib` and the exact class name
(`allowlists.is_path_class`), wherever the class lives inside the package.

The fix changes no measured result. A `pathlib._local` class was a sink before it, so only a
MALICIOUS verdict could move, and no benign held-out, held-out-2 or held-out-3 file was
MALICIOUS. The 18 Hub files of those splits that were MALICIOUS (labelled malicious or
unclear) were fetched again at their pinned commits and scanned with the fixed scanner: all 18
stay MALICIOUS. The lab and mutation corpora give the same verdicts as before.

## Keras top-k metrics

keras 3.0.5 and 3.12.0 `src/metrics/accuracy_metrics.py`: `TopKCategoricalAccuracy` and
`SparseTopKCategoricalAccuracy` are `MeanMetricWrapper` subclasses with a fixed function;
their config is `name`, `dtype`, `k` and, for the sparse one, the bool `from_sorted_ids`.
Already accepted in legacy `.h5` files; now also as Keras 3 objects.

## Left as they are

`FunctionTransformer` (A1), dill (D1), Boosters by default (A2), custom ONNX operator domains
(`com.microsoft`) and TFLite Flex or Edge TPU custom operators (UNVERIFIABLE: the operator
runs native code safeloadai cannot see), `LossScaleOptimizer` and pyarrow-backed pandas
arrays (too few files to review this round), and user code.
