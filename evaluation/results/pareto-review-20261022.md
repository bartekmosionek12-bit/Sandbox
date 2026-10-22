# joblib and Keras false positives: Pareto review (2026-10-22, 0.8.0)

Method, as for the 0.7.0 allowlist reviews: the Pareto table of the evaluation, **tune
split only**, decides which entries are worth a source review; an entry is added only
with a justification from the library's own source. The held-out split is measured
afterwards and never used to choose.

Files: the benign tune and held-out files that 0.7.1 did not report CLEAN (85 tune, 129
held-out) and the 75 hf-malicious files, re-downloaded at the recorded commits and
sha256 (`evaluation/fetch_pinned_hf.py`) and scanned again with this branch
(`eval-p3-flagged-20261022T065115Z.json`). Every change in this release only accepts
more (state-only classes) or turns a tool failure into ERROR, so a file that was CLEAN
in 0.7.1 stays CLEAN; the other files did not need a rescan.

## What blocks the tune files

**joblib (22 tune files not CLEAN):**

| missing entry | tune files | decision |
|---|---|---|
| `xgboost.core.Booster` | 18 (16 as the only entry) | not added: owner decision (DECISIONS.md, README LIMITATIONS). Its `__setstate__` hands the raw model bytes to libxgboost's native parser (`xgboost/core.py`, `Booster.__setstate__` → `_LIB.XGBoosterUnserializeFromBuffer`), which no source review can cover. Safer alternative documented: `save_model("model.json")`. |
| `__main__.MyPipeline`, `__main__.SVC` | 1 each | not addable: classes from the training script |
| `imodels.tree.figs.FIGSClassifier`, `Node` | 1 | not pinned; `--trust-inert-from imodels` is the way for a user who has it installed |
| `sklearn.compose._column_transformer._RemainderColsList` | 1 (with Booster) | not added: a `collections.UserList` subclass, base not in the indexed sources; it would unblock no file alone |
| `sklearn.preprocessing._function_transformer.FunctionTransformer` | 1 (with Booster) | owner exclusion (stores a callable) |

**Keras (.keras/.h5, 29 tune files not CLEAN):**

| missing entry | tune files | decision |
|---|---|---|
| `keras.layers.TFSMLayer` | 4 | not added: it loads a TensorFlow SavedModel from a path in the config (`keras/src/export/tfsm_layer.py`, `tf.saved_model.load(filepath)`), so the file makes Keras open another file, like `pandas.read_pickle` in a pickle |
| custom losses, metrics and layers (`builtins.binary_focal_loss`, `Custom>GraphConvLayer`, `FocalLoss`, `tornet.*`, `eca_ldnet.*`, `cataract>*`, `CatFLW>*`, `TrigConv2D`, `cost_sensitive_loss`, `builtins._loss`, ...) | 1 or 2 each | not addable: user code that Keras imports or deserialises by name |
| `keras.src.applications.mobilenet_v2.<Lambda globals>` | 1 | not added: a Lambda whose bytecode runs with that module's globals |
| RISKY: `.keras` extension on a pickle or HDF5 file; `keras_self_attention` imitating `keras` | 5 | kept: these rules are about the file, not a missing entry |

**Result: no entry passes review.** Every remaining tune false positive in these two
formats is user code, an owner exclusion, or an object that makes the loader read
another file. The 0.8.0 reductions come from the rule fix in
[docs/OPTIONS.md](../../docs/OPTIONS.md#trust_inert_from) (class bodies editing their
own dict), which was found while explaining `--trust-inert-from`, not from new
entries.

## Held-out before and after (benign files)

CLEAN / soft block (UNVERIFIABLE only) / hard block (RISKY, MALICIOUS) / UNSUPPORTED /
ERROR. "Before" is the 0.7.1 run (`eval-v071-20261021T165118Z.json`); "after" is this
branch.

| held-out | before | after |
|---|---|---|
| all (500) | 371 / 81 / 15 / 33 / 0 | 374 / 79 / 13 / 33 / 1 |
| joblib (37) | 17 / 18 / 2 / 0 / 0 | 17 / 19 / 0 / 0 / 1 |
| Keras .keras/.h5 (156) | 120 / 29 / 7 / 0 / 0 | 120 / 29 / 7 / 0 / 0 |
| pickle (54) | 31 / 22 / 1 / 0 / 0 | 34 / 19 / 1 / 0 / 0 |
| PyTorch (253) | 203 / 12 / 5 / 33 / 0 | 203 / 12 / 5 / 33 / 0 |

False-positive rate on held-out, UNSUPPORTED and ERROR excluded: **96/467 = 20.6 %
before, 92/466 = 19.7 % after.** The three files that became CLEAN are scikit-learn
`ElasticNet`, `LassoCV` and `CountVectorizer` pickles (the class-body rule). The joblib
hard blocks became a soft block (an old-numpy dtype that 0.8.0 reads) and an ERROR
(E304: the emulation ran out of its compute budget, a tool limit, no longer a
SUSPICIOUS reason).

| tune | before | after |
|---|---|---|
| all (431) | 346 / 57 / 9 / 19 / 0 | 346 / 57 / 7 / 19 / 2 |

The two tune ERRORs are E304 as well. No hf-malicious, lab or mutation verdict changed
(hf-malicious: the same 49 MALICIOUS of 49 reviewed malicious files; lab and mutation
corpora in the test suite).
