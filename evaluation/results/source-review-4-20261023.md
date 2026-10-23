# Source review 4 (0.9.0): libraries the tune splits need

Allowlist work for 0.9.0 used the **tune** and **tune-2** splits only (430 + 2,945 benign files;
tune-2 is new, `evaluation/splits/hf-tune2.txt`, labels in `evaluation/hf_tune2_labels.tsv`).
held-out and held-out-2 were not looked at for any decision below. Every source was read from
PyPI archives (verified against PyPI's sha256, never installed, imported or run).

## What blocked benign tune files most (safeloadai 0.8.0)

Items outside the allowlist, counted once per benign tune / tune-2 file that was not CLEAN:

| item | files | outcome |
|---|---|---|
| `xgboost.core.Booster` | 94 | stays off (owner decision A2) |
| `trl.trainer.sft_config.SFTConfig` | 61 | policy (trl 1.16.0) |
| `accelerate.utils.dataclasses.DeepSpeedPlugin` | 22 | policy after hook review |
| `sklearn.compose._column_transformer._RemainderColsList` | 22 | not added: not a class in readable source |
| `transformers.integrations.deepspeed.HfTrainerDeepSpeedConfig` | 21 | policy (lazy-module chain rule) |
| `transformers.integrations.deepspeed.HfDeepSpeedConfig` | 17 | policy (lazy-module chain rule) |
| `sentence_transformers.training_args.BatchSamplers`, `MultiDatasetBatchSamplers` | 17 | enum (3.0.0 to 5.3.0 path) |
| `sklearn.isotonic.IsotonicRegression` | 16 | policy after hook review |
| `lightgbm.basic.Booster` | 15 | stays off (owner decision A2, 2026-10-23) |
| `sklearn.preprocessing._function_transformer.FunctionTransformer` | 15 | stays off (owner decision A1) |
| `sentence_transformers.training_args.SentenceTransformerTrainingArguments` | 14 | old path of the 6.2.0 policy class, through the historical-path generator |
| `ultralytics.nn.modules.block.AAttn` | 7 | policy after hook review |
| `trl.trainer.dpo_config.FDivergenceType` | 4 | enum (trl 0.9.6 to 0.28.0) |
| `trl.trainer.dpo_config.DPOConfig` | 3 | policy (trl 1.16.0) |

## New pins and policy scope (`tools/upstream_pins.json`)

* **trl 1.16.0**: `trl.trainer.*_config` modules only (9 dataclasses: SFT, DPO, GRPO, KTO, RLOO,
  reward, distillation, model and base config). Trainers stay out.
* **sentence-transformers 6.2.0**: `base.sampler`, `base.training_args` and the four
  `*.training_args` modules (12 classes). The models stay out.
* `transformers.integrations.deepspeed` and `accelerate.utils.dataclasses` (config objects a
  DeepSpeed `training_args.bin` holds).

## Lazy-module import chains

`transformers.integrations` and `trl.trainer` end with `sys.modules[__name__] = _LazyModule(...)`:
the package replaces its own module entry with a library object that imports submodules on
attribute access. The call is library code (checked like any top-level call); only the store
into `sys.modules` made the chain "not inert". `sources.SourceIndex.inert(lazy=True)` accepts
exactly `sys.modules[__name__] = ...` with `sys` the standard module, and **only for the import
chain of a state-only policy class** (`tools/gen_policies.py`). `inert_modules.json` is computed
without it, so the referenced-only rule does not widen (2,591 transformers modules would have
become inert; they stay out).

## Hooks reviewed (`sources.REVIEWED_HOOKS`)

| hook | sha256 | what it does on a dict-state BUILD |
|---|---|---|
| `sklearn.isotonic.IsotonicRegression.__setstate__` (1.9.1) | `679d16aa…` | `BaseEstimator.__setstate__`, then `_build_f(X_thresholds_, y_thresholds_)`: compares `out_of_bounds` with `"raise"` and stores either a lambda over `y` (not called) or `scipy.interpolate.interp1d(X, y, kind="linear")`. Computation on state values only; nothing the file names is called. |
| `ultralytics.nn.modules.block.AAttn.__setstate__` (8.4.182) | `7e1355f6…` | `Module.__setstate__`, then `all_head_dim = head_dim * num_heads` when missing. |
| `accelerate.utils.dataclasses.DeepSpeedPlugin.selected` setter (1.15.0) | `9a1f3cc3…` | raises `NotImplementedError`; sets nothing. |

## Enums (`allowlists.ENUM_CLASSES`)

Accepted only as `cls(value)` with one str or int (a member lookup). Class bodies are string
constants only, checked in every release that has them:

* `sentence_transformers.base.sampler` (6.2.0) and `sentence_transformers.training_args`
  (3.0.0 to 5.3.0): `BatchSamplers`, `MultiDatasetBatchSamplers`, subclasses of
  `transformers.utils.ExplicitEnum` (str + Enum; `_missing_` raises ValueError).
* `trl.trainer.dpo_config.FDivergenceType` (plain Enum, trl 0.9.6 to 0.28.0; gone in 1.x).

## Look-alike rule

`sentence_transformers` joins `lookalike.GENUINE`: a real, well-known package whose name contains
the allowlisted `transformers`. Its objects are judged like any other library's (UNVERIFIABLE
when unknown) instead of RISKY as an imitation; `transformers_evil` and the like stay RISKY.

## Not added

* `_RemainderColsList`: the index finds no class definition it can read at that path.
* `sklearn.utils._bunch.Bunch` (`__setattr__`, `__getattr__`, `__setstate__`) and
  `sklearn.frozen._frozen.FrozenEstimator` (`__getattr__` delegating to the wrapped
  estimator): not reviewed in this round (5 and 3 files).
* `HistGradientBoostingRegressor`: state-only, but its module calls `_LOSSES.copy()` at import,
  which the inertness analysis does not accept (8 files).
* pandas `RangeIndex`, Arrow-backed arrays and pyarrow helpers: their reduce forms need argument
  checks of their own.
* Keras metrics and layers outside `KERAS_CLASS_PAIRS`, `builtins.*` custom functions, `None.*`:
  the Keras path, not this review.

Each entry has adversarial tests (`tests/test_allowlist_review_20261023.py`): called with
arguments, NEWOBJ with arguments, a marker payload in the state, enum misuse, and neighbouring
names that must stay flagged.
