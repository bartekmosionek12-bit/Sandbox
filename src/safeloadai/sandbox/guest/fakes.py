"""Fake APIs. Runs INSIDE the WASI sandbox only (CPython 3.12, stdlib only).

Every fake records what was asked of it (target name, arguments, a short call
stack) through the host-owned evidence channel, then returns something plausible
so the payload keeps going and shows more of its behaviour. Nothing here decides
whether a call is dangerous: the host classifies the recorded calls.

Fakes cover: os/posix/nt, subprocess, socket, urllib, http, requests, shutil,
ctypes, importlib, pty, runpy, webbrowser, pickle, marshal, the builtins exec /
eval / compile / __import__ / open / getattr, and tensorflow / keras / torch /
numpy with shaped fake tensors.
"""
import builtins as _real_builtins
import sys

MAX_ARG_REPR = 300
MAX_NESTED_EXEC = 4
PAYLOAD_FILES = ("<payload>", "<lambda>", "<string>", "<nested>")

_record = None
_state = {"nested": 0}


def install_recorder(record):
    global _record
    _record = record


def _short(value):
    try:
        text = repr(value)
    except Exception as exc:  # noqa: BLE001
        text = "<unrepresentable %s: %s>" % (type(value).__name__, exc)
    return text if len(text) <= MAX_ARG_REPR else text[:MAX_ARG_REPR] + "..."


def _stack():
    frames = []
    frame = sys._getframe(2)
    while frame is not None and len(frames) < 8:
        code = frame.f_code
        if not code.co_filename.startswith("/in/.guest"):
            frames.append("%s:%s:%s" % (code.co_filename, frame.f_lineno, code.co_name))
        frame = frame.f_back
    return frames


def record_call(target, args=(), kwargs=None, **extra):
    _record("call", target=target, args=[_short(a) for a in args][:16],
            kwargs={str(k): _short(v) for k, v in (kwargs or {}).items()}, stack=_stack(), **extra)


def record_anomaly(what, **fields):
    _record("anomaly", what=what, **fields)


# --- generic recording objects -------------------------------------------------

class FakeObject:
    """Any attribute is another FakeObject; any call is recorded."""

    def __init__(self, name):
        object.__setattr__(self, "_fake_name", name)

    def __getattr__(self, attr):
        if attr.startswith("__") and attr.endswith("__"):
            raise AttributeError(attr)
        return _resolve(self._fake_name + "." + attr)

    def __setattr__(self, attr, value):
        record_call(self._fake_name + ".__setattr__", (attr, value))

    def __call__(self, *args, **kwargs):
        record_call(self._fake_name, args, kwargs)
        return _call_result(self._fake_name, args, kwargs)

    def __setstate__(self, state):
        record_call(self._fake_name + ".__setstate__", (state,))

    def __reduce__(self):
        return (FakeObject, (self._fake_name,))

    def __iter__(self):
        return iter(())

    def __len__(self):
        return 0

    def __bool__(self):
        return True

    def __getitem__(self, key):
        return FakeObject(self._fake_name + "[" + _short(key) + "]")

    def __setitem__(self, key, value):
        record_call(self._fake_name + ".__setitem__", (key, value))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def __repr__(self):
        return "<fake %s>" % self._fake_name

    def __str__(self):
        return ""

    def __fspath__(self):
        return "/fake/" + self._fake_name


class FakeModule(FakeObject):
    def __init__(self, module_name, version=None, /, **attrs):
        FakeObject.__init__(self, module_name)
        object.__setattr__(self, "__name__", module_name)
        object.__setattr__(self, "_fake_attrs", dict(attrs))
        if version is not None:
            object.__setattr__(self, "__version__", version)

    def __getattr__(self, attr):
        attrs = object.__getattribute__(self, "_fake_attrs")
        if attr in attrs:
            return attrs[attr]
        return FakeObject.__getattr__(self, attr)


# --- tensors ------------------------------------------------------------------

class FakeTensor:
    """Shape and dtype are believable; values are never real."""

    def __init__(self, shape=(1,), dtype="float32", name="tensor"):
        self.shape = tuple(int(d) if isinstance(d, int) and d > 0 else 1 for d in (shape or ()))
        self.dtype = dtype
        self.name = name

    ndim = property(lambda self: len(self.shape))

    def _same(self, *args, **kwargs):
        return FakeTensor(self.shape, self.dtype)

    __add__ = __radd__ = __sub__ = __rsub__ = __mul__ = __rmul__ = _same
    __truediv__ = __rtruediv__ = __floordiv__ = __rfloordiv__ = __pow__ = __rpow__ = _same
    __mod__ = __neg__ = __pos__ = __abs__ = __matmul__ = __rmatmul__ = _same
    __lt__ = __le__ = __gt__ = __ge__ = _same
    __and__ = __or__ = __xor__ = __invert__ = _same

    def __eq__(self, other):
        return FakeTensor(self.shape, "bool")

    def __ne__(self, other):
        return FakeTensor(self.shape, "bool")

    def __getitem__(self, key):
        return FakeTensor(self.shape[1:] or (1,), self.dtype)

    def __len__(self):
        return self.shape[0] if self.shape else 0

    def __iter__(self):
        for _ in range(min(len(self), 64)):
            yield FakeTensor(self.shape[1:] or (1,), self.dtype)

    def __bool__(self):
        record_anomaly("tensor value used in a branch", stack=_stack())
        return False

    def __float__(self):
        record_anomaly("tensor value read", how="float", stack=_stack())
        return 0.0

    def __int__(self):
        record_anomaly("tensor value read", how="int", stack=_stack())
        return 0

    def __index__(self):
        return self.__int__()

    def __hash__(self):
        record_anomaly("tensor hashed", stack=_stack())
        return id(self)

    def numpy(self):
        record_anomaly("tensor value read", how="numpy()", stack=_stack())
        return _zeros(self.shape)

    def __getattr__(self, attr):
        if attr.startswith("__"):
            raise AttributeError(attr)
        return _TensorMethod(self, attr)

    def __repr__(self):
        return "<FakeTensor shape=%s dtype=%s>" % (self.shape, self.dtype)


class _TensorMethod:
    def __init__(self, tensor, attr):
        self.tensor, self.attr = tensor, attr

    def __call__(self, *args, **kwargs):
        record_call("Tensor." + self.attr, args, kwargs)
        return FakeTensor(self.tensor.shape, self.tensor.dtype)


def _zeros(shape):
    if not shape:
        return 0.0
    return [_zeros(shape[1:]) for _ in range(min(shape[0], 64))]


def _first_tensor(args, kwargs):
    for value in list(args) + list(kwargs.values()):
        if isinstance(value, FakeTensor):
            return value
        if isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, FakeTensor):
                    return item
    return None


def _call_result(name, args, kwargs):
    leaf = name.rsplit(".", 1)[-1]
    if name.startswith(("tf.", "keras.", "torch.", "numpy.", "np.", "K.", "ops.")):
        tensor = _first_tensor(args, kwargs)
        if tensor is not None:
            if leaf.startswith(("reduce_", "sum", "mean", "max", "min")):
                return FakeTensor((tensor.shape[0],) if tensor.shape else (1,), tensor.dtype)
            return FakeTensor(tensor.shape, tensor.dtype)
        shape = kwargs.get("shape") or (args[0] if args and isinstance(args[0], (list, tuple)) else (1,))
        try:
            return FakeTensor(tuple(shape))
        except TypeError:
            return FakeTensor()
    return FakeObject(name + "()")


# --- named fakes ----------------------------------------------------------------

class FakeFile:
    def __init__(self, path, mode):
        self.path, self.mode = path, mode

    def read(self, *a):
        return b"" if "b" in self.mode else ""

    def readline(self, *a):
        return self.read()

    def readlines(self):
        return []

    def write(self, data):
        record_call("file.write", (self.path, data))
        return len(data) if hasattr(data, "__len__") else 0

    def __iter__(self):
        return iter(())

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def fake_open(file, mode="r", *args, **kwargs):
    record_call("builtins.open", (file, mode) + args, kwargs)
    return FakeFile(_short(file), str(mode))


class FakeEnviron(dict):
    def __getitem__(self, key):
        record_call("os.environ.__getitem__", (key,))
        return ""

    def get(self, key, default=None):
        record_call("os.environ.get", (key,))
        return default

    def __contains__(self, key):
        record_call("os.environ.__contains__", (key,))
        return False


def _fake_os(name):
    import posixpath

    return FakeModule(
        name,
        environ=FakeEnviron(),
        sep="/",
        name="posix",
        path=FakeModule(
            name + ".path",
            join=posixpath.join, basename=posixpath.basename, dirname=posixpath.dirname,
            splitext=posixpath.splitext, normpath=posixpath.normpath,
            expanduser=lambda p: str(p).replace("~", "/home/user", 1),
            exists=_recorded_false(name + ".path.exists"),
            isfile=_recorded_false(name + ".path.isfile"),
            isdir=_recorded_false(name + ".path.isdir"),
        ),
        getcwd=lambda: "/home/user",
        getpid=lambda: 4242,
    )


def _recorded_false(target):
    def check(*args, **kwargs):
        record_call(target, args, kwargs)
        return False

    return check


def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
    record_call("builtins.__import__", (name,), {"fromlist": fromlist} if fromlist else None)
    module = MODULES.get(name) or _module_for(name)
    if fromlist or "." not in name:
        return module
    return MODULES.get(name.split(".", 1)[0]) or _module_for(name.split(".", 1)[0])


def _module_for(name):
    root = name.split(".", 1)[0]
    if root in SAFE_REAL_MODULES:
        return __import__(name, fromlist=["_"]) if "." in name else __import__(name)
    if name not in MODULES:
        MODULES[name] = FakeModule(name)
    return MODULES[name]


def fake_getattr(obj, name, *default):
    record_call("builtins.getattr", (obj, name))
    if isinstance(name, str) and name.startswith("__"):
        # Dunder lookups are how payloads reach the real interpreter around the
        # fakes (__globals__, __subclasses__, __builtins__). Record, do not follow.
        record_anomaly("introspection via getattr", name=name[:100], stack=_stack())
        return FakeObject(_short(obj) + "." + name)
    return _real_builtins.getattr(obj, name, *default)


def _nested(kind, source, globals_=None):
    if _state["nested"] >= MAX_NESTED_EXEC:
        record_anomaly("nested exec/eval depth limit reached")
        return None
    if not isinstance(source, (str, bytes)) and not hasattr(source, "co_code"):
        return None
    _state["nested"] += 1
    try:
        code = source if hasattr(source, "co_code") else _real_builtins.compile(
            source, "<nested>", "eval" if kind == "eval" else "exec")
        scope = fake_globals()
        if isinstance(globals_, dict):
            scope.update({k: v for k, v in globals_.items() if k != "__builtins__"})
        return _real_builtins.eval(code, scope) if kind == "eval" else _real_builtins.exec(code, scope)
    except Exception as exc:  # noqa: BLE001
        record_anomaly("nested code raised", error=type(exc).__name__, detail=str(exc)[:300])
        return None
    finally:
        _state["nested"] -= 1


def fake_eval(source, globals_=None, locals_=None):
    record_call("builtins.eval", (source,))
    return _nested("eval", source, globals_)


def fake_exec(source, globals_=None, locals_=None):
    record_call("builtins.exec", (source,))
    return _nested("exec", source, globals_)


def fake_compile(source, filename="<string>", mode="exec", *args, **kwargs):
    record_call("builtins.compile", (source, filename, mode))
    return _real_builtins.compile(source, "<nested>", mode)


def fake_builtins():
    """A builtins mapping for payload code: real pure functions, fake sinks."""
    table = {k: getattr(_real_builtins, k) for k in dir(_real_builtins) if not k.startswith("_")}
    table.update(
        __import__=fake_import, open=fake_open, eval=fake_eval, exec=fake_exec,
        compile=fake_compile, getattr=fake_getattr, input=lambda *a: "",
        breakpoint=lambda *a, **k: None, exit=_exit_stub, quit=_exit_stub,
        __build_class__=_real_builtins.__build_class__, __name__="builtins",
    )
    return table


def _exit_stub(*args):
    record_call("builtins.exit", args)


def fake_globals(extra=None):
    scope = {"__builtins__": fake_builtins(), "__name__": "payload"}
    scope.update(FRAMEWORK_GLOBALS)
    if extra:
        scope.update(extra)
    return scope


# Modules a payload may legitimately use for pure computation.
SAFE_REAL_MODULES = frozenset({"math", "functools", "itertools", "operator", "collections",
                               "re", "string", "json", "base64", "binascii", "struct", "typing",
                               "abc", "enum", "copy", "numbers", "random", "hashlib", "zlib"})

TF = FakeModule("tf", "2.18.0", Tensor=FakeTensor, float32="float32", int32="int32",
                float16="float16", bool="bool", newaxis=None)
KERAS = FakeModule("keras", "3.15.1")
TORCH = FakeModule("torch", "2.5.1", Tensor=FakeTensor, float32="float32")
NUMPY = FakeModule("numpy", "1.26.4", ndarray=FakeTensor, float32="float32", pi=3.141592653589793)

MODULES = {}
for _name in ("os", "posix", "nt"):
    MODULES[_name] = _fake_os(_name)
for _name in ("subprocess", "socket", "urllib", "urllib.request", "urllib.parse", "http",
              "http.client", "requests", "shutil", "ctypes", "ctypes.util", "importlib",
              "importlib.util", "pty", "runpy", "webbrowser", "pickle", "marshal", "sys",
              "builtins", "code", "pydoc", "timeit", "tempfile", "pathlib", "io", "signal",
              "threading", "multiprocessing", "asyncio", "gc", "inspect", "platform"):
    MODULES.setdefault(_name, FakeModule(_name))
MODULES.update({"tensorflow": TF, "tf": TF, "keras": KERAS, "torch": TORCH, "numpy": NUMPY,
                "np": NUMPY})

FRAMEWORK_GLOBALS = {"tf": TF, "tensorflow": TF, "keras": KERAS, "K": FakeModule("K"),
                     "ops": FakeModule("ops"), "np": NUMPY, "numpy": NUMPY, "torch": TORCH}


def _resolve(dotted):
    if dotted in MODULES:
        return MODULES[dotted]
    if dotted in ("builtins.eval", "__builtin__.eval"):
        return fake_eval
    if dotted in ("builtins.exec", "__builtin__.exec"):
        return fake_exec
    if dotted in ("builtins.compile", "__builtin__.compile"):
        return fake_compile
    if dotted in ("builtins.open", "__builtin__.open", "io.open"):
        return fake_open
    if dotted in ("builtins.__import__", "__builtin__.__import__", "importlib.import_module"):
        return fake_import
    if dotted in ("builtins.getattr", "__builtin__.getattr"):
        return fake_getattr
    return FakeObject(dotted)
