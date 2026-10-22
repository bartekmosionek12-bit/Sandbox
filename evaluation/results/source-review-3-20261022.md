# Source review 3: pandas, dabl and a scikit-learn scorer (2026-10-22, 0.8.0)

Phase 5, step 3: before the final measurement, take the Pareto table of the **tune split
only**, per format, and review the entries that unblock the most files. An entry is added
only when the library's own source shows that rebuilding it from a pickle runs no code
the file controls, and only in the exact form the library writes, with an argument check
and an adversarial test. Held-out files were not looked at.

Sources: PyPI wheels and sdists, downloaded with `pip download --no-deps` (and the sdist
of pandas for `_libs/internals.pyx`, which wheels do not ship), unpacked and read. Nothing
was installed or imported.

| package | versions read | why these |
|---|---|---|
| pandas | 1.4.4, 3.1.0 | 1.4.x wrote the tune files (scikit-learn 1.1.1 to 1.1.3 era); 3.1.0 is current |
| dabl | 0.2.6.2, 0.3.2 | the last two releases |
| scikit-learn | 1.1.3, 1.9.1 | 1.1.3 wrote the files; `_ThresholdScorer` is gone in 1.9.1 |

## Tune split, per format (0.7.1 run `eval-v071-20261021T165118Z.json`)

| format | tune files not CLEAN | what blocks them | decision |
|---|---|---|---|
| PyTorch | 19 | all UNSUPPORTED: OpenVINO `.bin` weights (16), KenLM n-gram `.bin` (2), CTranslate2 `model.bin` (1). None is a pickle or a zip | no entry can help; UNSUPPORTED is the correct answer for bytes safeloadai cannot read |
| Keras (.keras, .h5) | 29 | `TFSMLayer` (loads another file), custom losses, metrics and layers, a Lambda | unchanged from the [Phase 3 review](pareto-review-20261022.md): nothing addable |
| joblib | 22 | `xgboost.core.Booster` (18), `__main__` classes (2), imodels (1) | unchanged: owner exclusion, user code, not pinned |
| pickle (scikit-learn) | 15 | **11 dabl `clf.pkl` files**: dabl estimators, pandas DataFrame/Series, a scorer; 4 others | reviewed below |

Top entries of the pickle group by tune files that need them (all 11 dabl files need the
same set, so together they unblock all 11):

| entry | tune files needing it | decision |
|---|---|---|
| `pandas.core.frame.DataFrame` | 11 | added, state-only, state keys and values checked |
| `pandas.core.series.Series` | 11 | added, state-only, state keys and values checked |
| `pandas.core.internals.managers.BlockManager` | 11 | added, REDUCE with an argument check |
| `pandas.core.internals.managers.SingleBlockManager` | 11 | added, state-only with pandas' tuple state |
| `pandas._libs.internals._unpickle_block` | 11 | added, REDUCE with an argument check |
| `dabl.preprocessing.EasyPreprocessor` | 11 | added, state-only |
| `dabl.models.SimpleClassifier` | 10 | added, state-only |
| `dabl.models.SimpleRegressor` | 1 | added, state-only |
| `pandas.core.dtypes.dtypes.CategoricalDtype` | 7 | added, state-only, state checked |
| `sklearn.metrics._scorer._ThresholdScorer` | 6 | added, state-only, state checked |
| `sklearn.metrics._ranking.average_precision_score` | 6 | added **only as the scorer's stored `_score_func`**: never called, never passed to a call |
| `numpy.int64`, `CountVectorizer`, `PassiveAggressiveClassifier`, `FunctionTransformer` | 1 | not added: the one file also needs `train_huggingface_pipeline.revert_data` (user code), so no entry would unblock it; FunctionTransformer is an owner exclusion |
| `_loss.CyHalfBinomialLoss` | 1 | not added: a top-level module named `_loss` (scikit-learn 1.8.0 wrote the Cython class under its bare extension name). Any `_loss` module on `sys.path` would be imported; `sklearn._loss._loss.CyHalfBinomialLoss` is already allowlisted |
| `daal4py._daal4py._rebuild` and the sklearnex/onedal classes | 1 | not added: `_rebuild` hands bytes to a native deserialiser |

One tune file (`TasnimMer/callcenter-tfidf`) is an ERROR (E304, emulation compute budget),
not an allowlist question.

## What the source says

**DataFrame and Series** (`NDFrame.__getstate__` / `__setstate__`, pandas 1.4.4
`core/generic.py:2107-2150`, 3.1.0 `core/generic.py:2012-2070`). Pickled by
`object.__reduce_ex__`: NEWOBJ `()` then BUILD with a dict of `_mgr`, `_typ`, `_metadata`,
`attrs`, `_flags` and one key per `_metadata` name (Series: `name`). `__setstate__` sets
each key with `object.__setattr__` and builds `Flags(self, **state["_flags"])`. Because
every key is set, a file could set any attribute (a property such as `index` runs its
setter), so only pandas' own keys are accepted, `_mgr` must be the matching manager
(DataFrame: a `BlockManager` REDUCE; Series: a `SingleBlockManager` rebuilt from state),
`_flags` may hold only `allows_duplicate_labels` with a bool, `_metadata` is a list of
strings, `attrs` a dict, and `name` a scalar or a tuple of scalars.

**BlockManager** (`libinternals.BlockManager`, pandas 1.4.4 `_libs/internals.pyx:670-790`,
3.1.0 `:736-905`). `__reduce__` returns `(type(self), (self.blocks, self.axes))`;
`__cinit__` stores the tuple and `axes.copy()`. Accepted only as REDUCE with a tuple of
blocks made by `_unpickle_block` and a list of exactly two pandas `Index` objects (each
`_new_Index(Index, {data, name})`, which has its own check since 0.7.0).

**_unpickle_block** (1.4.4 `internals.pyx:568`, 3.1.0 `:629`). `Block.__reduce__` returns
`(_unpickle_block, (values, mgr_locs.indexer, ndim))`; it calls `new_block`, which looks
up the block class from `values.dtype` and stores the values (3.1.0 also calls
`maybe_coerce_values` and `BlockPlacement`). Accepted only with a numpy array (numpy's own
`_reconstruct` form or a joblib array), a slice of ints, an int or an int array as the
placement, and ndim 1 or 2. Any other object as values is refused, because its `dtype`
attribute would be read.

**SingleBlockManager** (`BaseBlockManager.__getstate__` / `__setstate__`, pandas 1.4.4
`core/internals/managers.py:1764-1800`, 3.1.0 `:2118-2160`). NEWOBJ `()` then BUILD with
the tuple `(axes, values, items, {"0.14.1": {"axes": [...], "blocks": [{"values",
"mgr_locs"}]}})`. `__setstate__` reads only the `"0.14.1"` part: `ensure_index` on each
axis and `new_block(values, mgr_locs, ndim)` per block. Accepted only with exactly that
tuple: one Index axis, one block whose values are a numpy array and whose placement is a
slice, and the ignored 0.13.1 copy holding only Index objects and arrays.

**CategoricalDtype** (1.4.4 `core/dtypes/dtypes.py:342`, 3.1.0 `:398`). `__setstate__` pops
`categories` and `ordered` into private attributes. Accepted with only those keys, an
Index or None as categories and a bool or None as ordered.

**dabl** (`dabl/models.py`, `dabl/preprocessing.py`, 0.2.6.2 and 0.3.2). `EasyPreprocessor`,
`SimpleClassifier` and `SimpleRegressor` subclass scikit-learn's `BaseEstimator` and
define no `__reduce__`, `__getstate__`, `__setstate__`, `__setattr__`, `__getattr__` or
properties; the `available_if` descriptors on `predict_proba` and `decision_function` run
only on attribute access. Unpickling is `BaseEstimator.__setstate__` (a version check and
a `__dict__` update), as for the scikit-learn estimators already state-only.

**_ThresholdScorer and average_precision_score** (scikit-learn 1.1.3
`metrics/_scorer.py:144-330`). `_BaseScorer.__init__(score_func, sign, kwargs)` stores
`_score_func`, `_sign` and `_kwargs`; no pickling hooks, so NEWOBJ `()` and a dict BUILD.
The score function is called only when the scorer is called, after loading. Accepted
with only those three keys, `_sign` 1 or -1, plain `_kwargs`, and `_score_func` one of the
reviewed score functions (`SCORER_FUNCTIONS`: `average_precision_score`). The function is
on the allowlist only as that stored value: a REDUCE of it, or the function anywhere else
as a value, stays SUSPICIOUS, and the emulation reports a call to it
(`behaviour.allowed_names` leaves it out). In scikit-learn 1.9.1 the class no longer
exists, so loading such a file fails at import.

## Checks and tests

`src/safeloadai/static/allowlists.py` (Phase 5 block) lists each entry with its source
location; `pickle_static._argument_check` and `_build_state_problem` enforce the forms
above. `tests/test_allowlist_review_20261022.py` has the forms pandas, dabl and
scikit-learn write (clean), 39 misuse cases (each class called, wrong or extra state keys,
`Flags` keyword injection, wrong manager, non-array block values, wrong ndim, the score
function called or handed to `defaultdict`, a slot state), 10 cases where a marker sink
(`posix.system("echo MARKER")`) is reached through a new entry (MALICIOUS), an end-to-end
scan and a guest-side check that the emulation flags a called score function. The two
older tests that used `average_precision_score` as their example of a non-allowlisted
function now use `roc_auc_score`, which stays off the allowlist.

## Effect

- Tune (re-downloaded at the recorded commits and sha256): the 11 dabl files are CLEAN;
  the other 7 flagged pickle/joblib tune files are unchanged.
- Detection: hf-malicious 49/49 MALICIOUS or SUSPICIOUS, 0 let through; the lab and
  mutation corpora in the test suite are unchanged (full suite green).
- Held-out: measured once, in the final measurement, never used to choose.
