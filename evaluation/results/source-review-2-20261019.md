# Source review 2: Keras 3 pickling, dill function pickling, ultralytics IterableSimpleNamespace

Method: `pip download --no-deps` from pypi.org only, unzip, read with grep/sed. Nothing installed, imported or executed from the downloads.
Opcode experiments used only stdlib + stand-in classes written in the same script (Python 3.13.16, `python3 -I`).
Stand-in scripts (stdlib only, own classes) were kept in a scratch directory outside the repo.

## Downloaded files (sha256)

| file | sha256 |
|---|---|
| src-review2/keras/keras-3.15.1-py3-none-any.whl (latest) | 836460e480930acbd19bb7a17e62f9ecad40e8a9af9a651fc8d0586a96d27e20 |
| src-review2/keras__3.3.3/keras-3.3.3-py3-none-any.whl | 260df9ef71c6b89eb6816ce1c60f139c38ccdddd16f24e7005d2be127cdef8e4 |
| src-review2/dill/dill-0.4.1-py3-none-any.whl (latest) | 1e1ce33e978ae97fcfcff5638477032b801c46c7c65cf717f95fbc2248f79a9d |
| src-review2/dill__0.3.8/dill-0.3.8-py3-none-any.whl | c36ca9ffb54365bdd2f8eb3eff7d2a21237f8452b57ace88b1ac615b7e815bd7 |
| src-review/ultralytics/ultralytics-8.4.182-py3-none-any.whl (reused) | 11b90b26fa30f878807b0b8c4ed1870eb3c54e7e876a17a936bd92065a7e743b |
| src-review/ultralytics-8.0/ultralytics-8.0.50-py3-none-any.whl (reused) | 60c409292cab97ba9893cf7a60a0b2a385f82c7a7f007206a53c0075737dda57 |

(src-review2 = a scratch directory outside the repo, not committed)

---

## 1. Keras 3

### Where it lives (identical file in 3.3.3 and 3.15.1)
`keras/src/saving/keras_saveable.py`:
- L4 `class KerasSaveable:`
- L16-23
  ```python
  @classmethod
  def _unpickle_model(cls, bytesio):
      import keras.src.saving.saving_lib as saving_lib
      # pickle is not safe regardless of what you do.
      return saving_lib._load_model_from_fileobj(
          bytesio, custom_objects=None, compile=True, safe_mode=False
      )
  ```
- L25-38
  ```python
  def __reduce__(self):
      import keras.src.saving.saving_lib as saving_lib
      buf = io.BytesIO()
      saving_lib._save_model_to_fileobj(self, buf, "h5")
      return (self._unpickle_model, (buf,))
  ```
So the reduce callable is a classmethod bound to `type(self)`. The argument is a **BytesIO object**, not raw bytes. Its stream position sits at the end of the written zip.

### Which classes inherit it
None of the classes below overrides `__reduce__`, `__reduce_ex__` or `__getstate__`. Grepping `keras/src` (tests excluded) finds `__reduce__` only in keras_saveable.py.
- 3.15.1: `Operation(KerasSaveable)` (ops/operation.py:21) → `Layer(BackendLayer, Operation)` (layers/layer.py:71) → `Model(Trainer, base_trainer.Trainer, Layer)` (models/model.py:39) → `Functional(Function, Model)` (models/functional.py:27), `Sequential(Model)` (models/sequential.py:20). Also direct subclasses: `Metric` (metrics/metric.py:12), `Loss` (losses/loss.py:11), `BaseOptimizer` (optimizers/base_optimizer.py:14), and `Cross`/`Feature` (layers/preprocessing/feature_space.py:17,48).
- 3.3.3: `Layer(BackendLayer, Operation, KerasSaveable)` (layers/layer.py:60). Here `Operation` is a plain class (ops/operation.py:16). Model, Functional and Sequential inherit as above (model.py:33, functional.py:26, sequential.py:18).

The GLOBAL in a pickle is the concrete class (for example `keras.src.models.sequential Sequential` or `keras.src.models.functional Functional`). The attribute name is always `_unpickle_model`. `_unpickle_model` always calls `_load_model_from_fileobj`, whatever `cls` is.

### What `_unpickle_model` does
- **3.15.1**: `saving_lib._load_model_from_fileobj` is at saving_lib.py:499.
  - It opens `zipfile.ZipFile(fileobj)` and reads `config.json` (`_safe_zip_read`).
  - It then calls `_model_from_config(config_json, custom_objects, compile, safe_mode)` (L425-437). That function does `json.loads`; with compile=True it keeps `compile_config`. It then runs `deserialize_keras_object(config_dict, custom_objects, safe_mode=safe_mode)` inside `ObjectSharingScope()`.
  - Finally it loads weights from `model.weights.h5` (H5IOStore, with a zip-bomb check) or `model.weights.npz`, plus assets, through `_load_state`.
- **3.3.3**: same flow, inlined in `_load_model_from_fileobj` (saving_lib.py:157-205).
- **safe_mode is hard-coded to False.** The caller's `safe_mode=True` or `SafeModeScope` is not honoured.
  - Lambda layer: `lambda_layer.py` `from_config` L183-221 (3.15.1) / L182-211 (3.3.3) calls `_raise_for_lambda_deserialization(safe_mode)`, which raises only if safe_mode is true. Otherwise it calls `python_utils.func_load` → `marshal.loads(raw_code)` (python_utils.py:95 / :83), giving **arbitrary bytecode execution** when the Lambda is called.
  - serialization_lib also gates `__lambda__` on safe_mode (serialization_lib.py:679-680 in 3.15.1, 641-642 in 3.3.3).
- `custom_objects=None`, so only registered or built-in classes resolve. `compile=True`, so `compile_config` (optimizer, loss, metrics) is deserialized and the model is compiled.

### Opcode form (stand-in `Model` with the same `__reduce__`; Python 3.13)
- Protocols 0 and 1: **pickling fails** with `TypeError: cannot pickle 'BytesIO' object`. Real Keras pickles can only be protocol ≥2.
- **Classmethod is NOT a qualname global at any protocol.** A bound method reduces to `(getattr, (cls, '_unpickle_model'))`:
  - proto 2: `GLOBAL '__builtin__ getattr'`, `GLOBAL '<mod> <Cls>'`, `BINUNICODE '_unpickle_model'`, `TUPLE2`, `REDUCE`
  - proto 3: the same with `GLOBAL 'builtins getattr'`
  - proto 4/5: `STACK_GLOBAL('builtins','getattr')`, `STACK_GLOBAL('<mod>','<Cls>')`, `SHORT_BINUNICODE '_unpickle_model'`, `TUPLE2`, `REDUCE`
- **io.BytesIO is NOT `REDUCE` with a bytes argument.** `BytesIO.__reduce_ex__(2..5)` returns `(copyreg.__newobj__, (_io.BytesIO,), (value_bytes, pos, dict_or_None))`. This is emitted as:
  - `GLOBAL/STACK_GLOBAL '_io BytesIO'`, `EMPTY_TUPLE`, `NEWOBJ`, then the state tuple `(bytes, pos:int, None)` via `TUPLE3`, then `BUILD`. `BytesIO.__setstate__` restores buffer and position.
  - The bytes are `SHORT_BINBYTES`/`BINBYTES` at proto ≥3. At **proto 2** they are `GLOBAL '_codecs encode'` + `BINUNICODE <latin1 str>` + `BINUNICODE 'latin1'` + `TUPLE2` + `REDUCE`.
  - In real Keras, `pos` equals the zip length, because the buffer is not rewound.
- Then `TUPLE1`, `REDUCE`, `STOP`.

Full proto-4 sequence:
```
STACK_GLOBAL builtins.getattr ; STACK_GLOBAL <mod>.<Cls> ; '_unpickle_model' ; TUPLE2 ; REDUCE
STACK_GLOBAL _io.BytesIO ; EMPTY_TUPLE ; NEWOBJ ; BINBYTES <PK..zip> ; BININT pos ; NONE ; TUPLE3 ; BUILD
TUPLE1 ; REDUCE ; STOP
```

**(a) Verdict:** YES, the pattern exists as described in substance: `_unpickle_model(BytesIO(.keras zip))` with safe_mode=False. Correct the details for the scanner:
- the method reference is `builtins.getattr(<cls>, "_unpickle_model")` REDUCE, not STACK_GLOBAL `Model._unpickle_model`
- BytesIO is `NEWOBJ` + `BUILD((bytes, pos, None))`, not `REDUCE` with bytes
- at proto 2 the bytes come via `_codecs.encode`

---

## 2. dill (0.4.1 latest; 0.3.8)

Core helpers live in `dill/_dill.py`. The pickler is a subclass of the pure-Python `pickle._Pickler` (L55, L347). Default protocol is `DEFAULT_PROTOCOL` (settings.py:16). The Unpickler's `find_class` (0.4.1 L437-443) adds three mappings:
- `('__builtin__','__main__')` → the `__main__` dict
- `('__builtin__','NoneType')` → `NoneType`
- module `dill.dill` → `dill._dill`

Helpers are module-level functions, emitted as `GLOBAL 'dill._dill <name>'` / `STACK_GLOBAL('dill._dill', name)`. The module string is memoized, so later helpers use `BINGET` for the module. A scanner must resolve memo references for STACK_GLOBAL operands.

### Plain function (save_function: 0.4.1 L1961-2060; logic identical in 0.3.8)
A function that cannot be located by `module.qualname` (`__main__`, locals, lambdas) is saved as:
`REDUCE(_create_function, (code, globs, name, defaults, closure))`, then `BUILD state` where `state = (fn.__dict__, {'__qualname__', '__module__', '__doc__', '__kwdefaults__', '__annotations__'...})` if any extras exist.
- `globs` is one of:
  - `{'__name__': module}` (then filled by postproc SETITEMS on the memoized dict)
  - the module dict itself, written raw as `GLOBAL '<module> __dict__'` (save_module_dict D4, L1258), `c__builtin__\n__main__\n` (D1) or `c__main__\n__dict__\n` (D3)
- `closure` is a tuple of `REDUCE(_create_cell, (value,))`. Self-references use `_create_cell(_CELL_REF)` followed by postproc `REDUCE(_setattr|setattr, (cell,'cell_contents',f))` + `POP`.
- Postproc emits extra `REDUCE`+`POP` of `dill._dill._setitems`, `builtins.setattr` or `_shims` getattr-reductions.
- A function that can be located is a normal `GLOBAL module qualname`.

### Code object (save_code: 0.4.1 L1172-1236; 0.3.8 identical except no PyPy 17-arg branch)
`REDUCE(_create_code, args)`. The args tuple depends on the Python version:
| Python | tuple layout (dill writes) |
|---|---|
| 3.11+ / 3.12 / 3.13 (`co_exceptiontable`) | `co_lnotab, argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize, flags, code(bytes), consts, names, varnames, filename, name, qualname, firstlineno, linetable, exceptiontable, freevars, cellvars` (19) |
| 3.11a (`co_endlinetable`) | `lnotab, argcount, posonly, kwonly, nlocals, stacksize, flags, code, consts, names, varnames, filename, name, qualname, firstlineno, linetable, endlinetable, columntable, exceptiontable, freevars, cellvars` (21) |
| PyPy 3.11 (0.4.1 only) | `lnotab, ..., qualname, firstlineno, linetable, freevars, cellvars` (18) |
| 3.10 (`co_linetable`) | `lnotab, argcount, posonly, kwonly, nlocals, stacksize, flags, code, consts, names, varnames, filename, name, firstlineno, linetable, freevars, cellvars` (17) |
| 3.8/3.9 | `argcount, posonly, kwonly, nlocals, stacksize, flags, code, consts, names, varnames, filename, name, firstlineno, lnotab, freevars, cellvars` (16) |
| 3.7 | `argcount, kwonly, nlocals, stacksize, flags, code, consts, names, varnames, filename, name, firstlineno, lnotab, freevars, cellvars` (15) |

`_create_code` (0.4.1 L682; 0.3.8 L672):
- If `args[0]` is not an int, it is the leading lnotab and is stripped.
- It pattern-matches the length, then calls `CodeType(...)` directly. bytes fields given as str are `.encode()`d.
- If the layout came from another Python version, it rebuilds fields with defaults and still calls `CodeType(*args)`.
- `co_code` is raw bytecode (BINBYTES), executed when the function is called.

Stdlib mimic, proto 4 (`scripts/d.py`, closure fn): `STACK_GLOBAL dill._dill._create_function ; MARK ; STACK_GLOBAL(BINGET 'dill._dill','_create_code') ; MARK ; b'' lnotab ; ints... ; BINBYTES co_code ; consts tuple ; names ; varnames ; filename ; name ; qualname ; firstlineno ; linetable bytes ; exceptiontable ; freevars ('y',) ; cellvars ; TUPLE ; REDUCE ; {'__name__':'__main__'} ; 'f' ; (1,) defaults ; (REDUCE(_create_cell,(5,)),) ; TUPLE ; REDUCE`.

### What each helper does (0.4.1 line / 0.3.8 line)
| helper | lines | behaviour | danger |
|---|---|---|---|
| `_create_function(fcode, fglobals, fname, fdefaults, fclosure, fdict, fkwdefaults)` | 604 / 595 | `FunctionType(code, globals or {}, ...)`, injects `__builtins__` | builds a function from attacker bytecode; runs when called (e.g. via a later REDUCE) |
| `_create_code(*args)` | 682 / 672 | `CodeType(...)` | arbitrary bytecode |
| `_load_type(name)` | 598 / 589 | `_reverse_typemap[name]`, a fixed table built from builtins + `types` module types + some io/dict-view types (L509-590) | table lookup only; but the table includes `type`, `FunctionType`, `CodeType`, `ModuleType`, `MethodType`, `CellType`, etc. |
| `_create_type(typeobj, *args)` | 601 / 592 | `typeobj(*args)` | **calls any callable** with any args |
| `_create_cell(contents)` | 959 / 925 | returns a closure cell | benign |
| `_get_attr(self, name)` | 1053 / 1016 | `getattr(self, name, None) or getattr(builtins, name)` | **arbitrary getattr**, falls back to builtins (e.g. `eval`) |
| `_getattr(objclass, name, repr_str)` | 1034 / 1000 | **`eval(attr + '.__dict__["'+name+'"]')`** where attr comes from `repr_str.split("'")[3]` | **eval of a pickle-supplied string** |
| `_import_module(import_name, safe=False)` | 1057 / 1020 | `__import__(any name)`, or `getattr(__import__(module),obj)` for dotted names; `__runtime__.` prefix reads sys.modules | **imports any module / resolves attribute** |
| `_eval_repr(repr_str)` | 979 / 945 | `eval(repr_str)` | **arbitrary eval** |
| `_create_ftype(ftypeobj, func, args, kwds)` | 790 / 764 | `ftypeobj(func, *args, **kwds)` | **arbitrary call** |
| `_create_array(f, args, state, npdict)` | 982 / 948 | `f(*args)` then `__setstate__` | **arbitrary call** |
| `_create_namedtuple(name, fieldnames, modulename, defaults)` | 996 / 962 | `_import_module(modulename+'.'+name, safe=True)`, else `collections.namedtuple` | import |
| `_create_filehandle(...)` | 829 / 795 | opens files by name and may **write `fdata` to the path** (FILE_FMODE) | file write/open |
| `_create_capsule` | 1004 / 970 | `__import__` + getattr, then PyCapsule_New from a raw pointer | import / memory |
| `_unmarshal(string)` | 595 / 586 | `marshal.loads` | code object |
| `_setitems(dest, source)` | 1107 / 1070 | dict update | benign |
| `_shims._setattr` / `_delattr` | `_shims.py` | reduce to `getattr(dill._dill, name, setattr/delattr)` | setattr/delattr |
| `_create_lock`, `_create_rlock`, `_create_weakref`, `_create_weakproxy`, `_create_stringi/o`, `_create_dtypemeta`, `_create_typing_tuple` | various | object construction | mostly benign |

Modules are saved as `REDUCE(_import_module, (name,))` (save_module L1711-1753), with a BUILD state of the module dict for `__main__` or non-builtin modules. Types in the typemap are saved as `REDUCE(_load_type, ('FunctionType',))` etc. (save_type L1813). Dynamic classes are saved as `REDUCE(_create_type, (type, name, bases, dict))` (L1893).

**(c) Verdict:** a plain function produces `_create_function`, `_create_code`, `_create_cell` (for closures), sometimes `_import_module` (module globals), `_load_type` (type references), `_setitems`/`setattr` postprocessing, and raw `GLOBAL <mod> __dict__`.
- Can import arbitrary modules: `_import_module`, `_create_namedtuple`, `_create_capsule`.
- Can call arbitrary callables: `_create_type`, `_create_ftype`, `_create_array`.
- Can eval: `_eval_repr`, `_getattr`.
- Arbitrary getattr: `_get_attr`.
- Arbitrary bytecode: `_create_code`, `_create_function`, `_unmarshal`.
- Filesystem: `_create_filehandle`.
- `_load_type` is a closed-table lookup (not arbitrary), but it yields powerful types (type, FunctionType, CodeType).

0.3.8 and 0.4.1 match except for the PyPy 3.11 code branch and a `_getattr` tweak for 3.15.

---

## 3. ultralytics IterableSimpleNamespace

8.4.182 `ultralytics/utils/__init__.py:324-380`. 8.0.50 `ultralytics/yolo/utils/__init__.py:105-126` is identical apart from docstrings and the URL text. Both use `from types import SimpleNamespace`.
```python
class IterableSimpleNamespace(SimpleNamespace):
    def __iter__(self):
        return iter(vars(self).items())
    def __str__(self):
        return "\n".join(f"{k}={v}" for k, v in vars(self).items())
    def __getattr__(self, attr):
        name = self.__class__.__name__
        raise AttributeError(f"""... '{name}' object has no attribute '{attr}' ... {DEFAULT_CFG_PATH} ...""")
    def get(self, key, default=None):
        return getattr(self, key, default)
```
- It defines no `__init__`, `__setattr__`, `__setstate__`, `__reduce__`, `__slots__` or properties. `__getattr__` has no side effects beyond building a string from `__class__.__name__` and a module constant, then raising `AttributeError`.
- Python 3.13 check:
  - `object` has `__getstate__` (added in 3.11) but **no `__setstate__`**.
  - `types.SimpleNamespace` has no `__setstate__`; its own attrs are `__reduce__`, `__replace__`, `__init__`, `__repr__` and comparisons.
  - So BUILD's `getattr(inst, "__setstate__", _NoValue)` (pickle.py `load_build`; the C `_pickle` uses `PyObject_GetOptionalAttr`) falls through to `IterableSimpleNamespace.__getattr__('__setstate__')`. That raises AttributeError, which is swallowed, so BUILD falls back to default state handling.
  - Verified with a stand-in subclass that has the same `__getattr__`: the C and Python unpicklers both call `__getattr__('__setstate__')` exactly once, then succeed.
- Reduce: `SimpleNamespace.__reduce__` (CPython Objects/namespaceobject.c `namespace_reduce`) returns `(type(self), (), self.__dict__)`. Confirmed: `reduce_ex(2)` gives `(<class ISN>, (), {'a':1,'b':[2]})`.
- Opcodes:
  - proto 0: `GLOBAL '<mod> ISN'`, `MARK TUPLE`, `REDUCE`, `MARK DICT ... SETITEM`, `BUILD`
  - proto 2: `GLOBAL`, `EMPTY_TUPLE`, `REDUCE`, `EMPTY_DICT MARK ... SETITEMS`, `BUILD`
  - proto 4: `STACK_GLOBAL`, `EMPTY_TUPLE`, `REDUCE`, `EMPTY_DICT ... SETITEMS`, `BUILD`
  - `REDUCE cls()` runs `SimpleNamespace.__init__` with no kwargs, so there are no side effects.
- BUILD with a dict state does `inst.__dict__[intern(k)] = v` with no setattr. Only a `(dict, slotstate)` 2-tuple state uses `setattr(inst, k, v)` for the slotstate part. Verified: a stand-in `__setattr__` was called only for the slotstate key. IterableSimpleNamespace has no custom `__setattr__`, so even that path is plain `object.__setattr__`.
- `__iter__`/`__str__` are not triggered by unpickling.

**(b) Verdict:** YES. `IterableSimpleNamespace.__getattr__` raises AttributeError for `'__setstate__'` (and for any name) in both 8.4.182 and 8.0.50. BUILD therefore takes the default `__dict__.update` path, and setattr is used only if the state is a `(dict, slotstate)` tuple. Neither path triggers code beyond plain attribute storage.

## 4. Hub files checked against these forms (scan only, nothing loaded)

Both files were read only through safeloadai's own opcode walker under `evaluation/guard.py`.

- **a-01a/dogs-vs-cats-svm `svm_vgg16_cats_dogs.pkl`** (commit `db8b50a7`, sha256 `ddf2b257…`), an uncompressed joblib dict holding an SVC, a StandardScaler, a PCA and a Keras model. The Keras model is exactly the KerasSaveable form: STACK_GLOBAL `builtins getattr`, STACK_GLOBAL `keras.src.models.functional Functional`, `'_unpickle_model'`, TUPLE2, REDUCE (at 3887195); STACK_GLOBAL `_io BytesIO`, EMPTY_TUPLE, NEWOBJ, BINBYTES of 58,933,757 bytes starting `PK\x03\x04` (a `.keras` zip with `metadata.json` first), BININT 58933757, NONE, TUPLE3, BUILD, TUPLE1, REDUCE (at 62821001). No memo GET reaches any of these objects. With rule K1 the file is RISKY: the embedded archive is a plain Keras config without Lambdas (CLEAN on its own).
- **Bingsu/yolo-world-mirror `yolov8s-world.pt`** (commit `414d0eef`) uses one dill helper only, `dill._dill._load_type('set')`, called with an empty list for each module's `_non_persistent_buffers_set`. It carries no `_create_code` or `_create_function`. It was MALICIOUS because the emulator scored every `dill.*` call as code execution; with rule D1 it is RISKY ("pickle written by dill"). `yolov8s-worldv2.pt` from the same repo has no dill at all.
