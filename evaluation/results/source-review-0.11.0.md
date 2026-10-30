# Source review 6 (0.11.0): the next reducible causes on tune

Allowlist and structure work for 0.11.0 used the **tune** and **tune-2** splits only (3,372 files
fetched again at their pinned commits: 3,332 benign, 5 malicious, 35 unclear). held-out,
held-out-2, held-out-3 and the new held-out-4 were not looked at for any decision below.
Library sources were read from PyPI archives (`tools/pypi_archives.py`: checked against PyPI's
sha256, never installed, imported or run).

## What still blocked benign tune files (safeloadai 0.10.0)

0.10.0 on the 3,332 benign tune files: 2,935 CLEAN, 376 SUSPICIOUS, 18 UNSUPPORTED,
2 MALICIOUS, 1 error. Items outside the allowlist, counted once per benign file that was not
CLEAN (a file can have several):

| item | files | outcome in 0.11.0 |
|---|---|---|
| `xgboost.core.Booster`, `lightgbm.basic.Booster` | 94 + 15 | stay UNVERIFIABLE by default (A2); `--validate-boosters` opt-in |
| `.keras` file whose content is HDF5 | 22 | a note when HDF5 is the only reading (N6 below); 14 files CLEAN, the rest have custom objects |
| `sklearn.preprocessing._function_transformer.FunctionTransformer` | 15 | stays off (A1) |
| `dill._dill._load_type` | 8 | stays RISKY (D1) |
| pandas `_new_Index` with `pandas.Index` / `MultiIndex` | 5 | accepted in the exact form pandas writes (below) |
| `keras.src.ops.*`, `__tensor__`, `__ellipsis__`, `__slice__` | 4 + 4 + 3 + 1 | accepted (below) |
| `keras.layers.TextVectorization`, `RandomBrightness` | 4 + 3 | accepted (below) |
| `keras.layers.TFSMLayer` | 4 | stays off: it loads a SavedModel from a path at load time |
| `sklearn.frozen._frozen.FrozenEstimator` | 3 | not reviewed this round (3 files, all with other blockers) |
| `sklearn.linear_model._sgd_fast.Log`, `ModifiedHuber` | 1 + 1 | accepted with the other Cython losses (below) |
| user code (`batteryswap_example.*`, custom Keras layers and losses, `builtins.preprocess_input`, ...) | | the floor: stays blocked |

## Entries

Each is an exact pair or form; anything else keeps its 0.10.0 finding
(`tests/test_allowlist_review_0_11_0.py`, 74 tests including misuse and sinks).

* **pandas `Index` and `MultiIndex`** (pandas 1.4.4, 2.2.3 and 3.0.6 `core/indexes/base.py`
  and `multi.py`). pandas 3 names the classes `pandas.Index` and `pandas.MultiIndex`
  (`@set_module("pandas")`, base.py:323, multi.py:196), so a pickle written by pandas 3 imports
  them under those names. `MultiIndex` adds no pickling hook, `__setattr__` or `__getattr__`
  to `Index`. `MultiIndex.__reduce__` writes `_new_Index(cls, {levels, codes, sortorder,
  names})`; `_new_Index` calls `MultiIndex.__new__`, which stores them. Accepted only through
  `_new_Index` with exactly those four keys, a non-empty list of `_new_Index` levels, a list of
  numpy arrays as codes (one per level), plain scalar names and an `int` or `None` sortorder.
  `pandas.Index` takes `{data, name}` like `pandas.core.indexes.base.Index`. A BlockManager
  with an empty blocks tuple (an empty frame) is accepted like a non-empty one.
* **Keras 3 operations** (keras 3.0.5 and 3.15.1 `src/ops/numpy.py`, `nn.py`, `core.py`):
  `NotEqual`, `LogicalOr`, `Any`, `Concatenate`, `Stack`, `GetItem`, `Cast`, `LeakyRelu`,
  `Gelu`. Each is an `Operation` subclass whose `__init__` takes only numbers, bools or a dtype
  string and whose `call` is fixed tensor maths or indexing; `Operation.from_config` is
  `cls(**config)`.
* **Keras data markers** (keras 3.15.1 `saving/serialization_lib.py`,
  `serialize_keras_object` / `deserialize_keras_object`): `__ellipsis__` (config `{}` or
  `None`), `__slice__` (exactly `start`, `stop`, `step`, each an int or `None`) and
  `__tensor__` (exactly `value` and `dtype`, the dtype one of the backend's names, the value
  nested numbers). Rebuilding one imports nothing and calls only `slice()` or
  `backend.convert_to_tensor`. A marker with a `module`, a `registered_name` or any other form
  stays outside the allowlist.
* **`RandomBrightness`** (keras 3.15.1 `layers/preprocessing/image_preprocessing/
  random_brightness.py`: factor, value_range, seed) and **`CosineDecayRestarts`**
  (`optimizers/schedules/learning_rate_schedule.py`: numbers only).
* **`TextVectorization`** (keras 3.15.1 `layers/preprocessing/text_vectorization.py`) only when
  `standardize` and `split` are one of the built-in strings or `None` (a callable there is
  user code), the vocabulary is `None` or a list of strings (a string is a file path the
  layer reads), `idf_weights` is `None` or a list of numbers and the encoding is `utf-8`.
  Any other config keeps the class unknown.
* **scikit-learn SGD losses** (scikit-learn 1.0.2, 1.3.2 and 1.5.2
  `linear_model/_sgd_fast.pyx[.tp]`): `Log`, `ModifiedHuber`, `SquaredHinge`, `SquaredLoss`,
  `Huber`, `EpsilonInsensitive`, `SquaredEpsilonInsensitive`, next to the reviewed `Hinge`.
  Each is a cdef class holding at most one double, with no `__cinit__`, `__setstate__` or
  `__dealloc__`; `__reduce__` is `(cls, ())` or `(cls, (double,))`, and a non-number argument
  raises `TypeError` in the typed `__init__`.

## Structure (N6)

A file named `.keras` whose bytes are HDF5 from offset 0, with no other reading, was
SUSPICIOUS (RISKY) for the extension mismatch. The loaders:

* Keras 3 (keras 3.15.1 `saving/saving_api.py` `load_model`, lines 161 to 217): a `.keras`
  name that is not a ZIP archive raises `ValueError`. Nothing is loaded.
* tf.keras 2.x (tf_keras 2.15.1 `src/saving/legacy/save.py` 233 to 252, with
  `saving_utils.is_hdf5_filepath`): a path that is not a ZIP archive and opens as HDF5 is read
  by `load_model_from_hdf5`, the same reading safeloadai already analyses for `.h5`.

So no loader reads such a file any other way than the HDF5 analysis does, and the mismatch is
recorded as a note. An HDF5 userblock (content before offset 0 of the HDF5 superblock), any
second reading, or a mismatch on any other extension keeps the old finding (tests).

## Result on tune

0.11.0 on the 419 tune files that 0.10.0 did not find CLEAN: 32 benign files CLEAN (14
`.keras` holding HDF5, 18 for the classes above), 6 benign files from a hard to a soft block
(pandas `MultiIndex` frames with another blocker; HDF5 `.keras` with a custom loss). No
malicious or unclear file changed.
