"""Emulation tasks. Runs INSIDE the WASI sandbox only (CPython 3.12, stdlib only).

``pickle``: unpickles each artefact with a ``find_class`` that records every
global the stream asks for and hands back either a real pure type from a short
list or a recording fake. Whatever the stream then calls is recorded by the fakes.

``keras_lambda``: unmarshals Lambda bytecode (only ever here, never on the host),
checks that it is valid bytecode for this interpreter, and calls it on fake
tensors with fake framework globals. Every irregularity is an ``anomaly`` record;
the host maps any anomaly to at least SUSPICIOUS.
"""
import base64
import dis
import io
import json
import marshal
import pickle
import types

import fakes

ARTEFACTS = "/in/artefacts/"

# Real objects find_class may return: pure data types without side effects.
REAL_GLOBALS = {
    ("builtins", n): getattr(__import__("builtins"), n)
    for n in ("dict", "list", "set", "frozenset", "tuple", "int", "float", "complex", "str",
              "bytes", "bytearray", "bool", "slice", "range")
}
REAL_GLOBALS[("collections", "OrderedDict")] = __import__("collections").OrderedDict
REAL_GLOBALS[("_codecs", "encode")] = __import__("_codecs").encode

# Names a Lambda has no business touching; they are how code steps around fakes.
INTROSPECTION_NAMES = frozenset({
    "__subclasses__", "__globals__", "__code__", "__builtins__", "__class__", "__bases__",
    "__mro__", "__base__", "__dict__", "__getattribute__", "__closure__", "__func__",
    "__self__", "__module__", "__loader__", "__spec__", "__import__", "__reduce__",
    "__reduce_ex__", "f_globals", "f_back", "f_locals", "gi_frame", "tb_frame", "co_code",
    "type", "isinstance", "issubclass", "globals", "locals", "vars", "dir", "id",
    "_getframe", "settrace", "setprofile",
})

PROLOGUE_OPS = frozenset({"MAKE_CELL", "COPY_FREE_VARS", "RETURN_GENERATOR", "POP_TOP", "NOP"})
MAX_LAMBDAS = 64


# --- pickle -----------------------------------------------------------------------

class RecordingUnpickler(pickle.Unpickler):
    def __init__(self, file, record):
        super().__init__(file)
        self._record = record

    def find_class(self, module, name):
        real = REAL_GLOBALS.get((module, name))
        self._record("import", module=str(module)[:200], name=str(name)[:200],
                     resolved="real" if real is not None else "fake")
        if real is not None:
            return real
        dotted = str(module) + "." + str(name)
        resolved = fakes._resolve(dotted)
        if type(resolved) is fakes.FakeObject:
            return fakes.fake_class(dotted)  # a type, so NEWOBJ and BUILD work on it
        return resolved

    def persistent_load(self, pid):
        self._record("persistent_id", pid=fakes._short(pid))
        return fakes.FakeObject("persistent_id")


def run_pickle(task, record):
    fakes.install_recorder(record)
    for name in task["files"]:
        with open(ARTEFACTS + name, "rb") as fh:
            data = fh.read()
        stream = io.BytesIO(data)
        limit = int(task.get("max_pickles") or 1)
        loaded = 0
        while loaded < limit and stream.tell() < len(data):
            try:
                RecordingUnpickler(stream, record).load()
            except Exception as exc:  # noqa: BLE001
                fakes.record_anomaly("unpickling raised", file=name, pickle_index=loaded,
                                     error=type(exc).__name__, detail=str(exc)[:300])
                break
            loaded += 1
        record("event", category="pickle", detail="loaded", file=name, pickles=loaded)


# --- keras Lambda -----------------------------------------------------------------

def _code_objects(code):
    stack, seen = [code], []
    while stack:
        current = stack.pop()
        seen.append(current)
        stack.extend(c for c in current.co_consts if isinstance(c, types.CodeType))
    return seen


def _cache_layout_ok(obj):
    """Every instruction must be a real opcode of this interpreter followed by
    exactly its number of zeroed inline CACHE units. Bytecode written by another
    CPython version (different opcode numbers and cache sizes) fails this even
    when it happens to start with RESUME."""
    raw = obj.co_code
    caches = dis._inline_cache_entries
    i = 0
    while i < len(raw):
        op = raw[i]
        name = dis.opname[op]
        if name.startswith("<") or name == "CACHE" or name.startswith("INSTRUMENTED_"):
            return False, "opcode %d (%s) at offset %d" % (op, name, i)
        n = caches[op] if op < len(caches) else 0
        if any(raw[i + 2:i + 2 + 2 * n]):
            return False, "non-zero inline cache after %s at offset %d" % (name, i)
        i += 2 + 2 * n
    return i == len(raw), "trailing partial instruction"


def _check_bytecode(code, path):
    """Return the names the code loads as globals; record anything irregular."""
    globals_used = set()
    ok = True
    for obj in _code_objects(code):
        try:
            instructions = list(dis.get_instructions(obj))
        except Exception as exc:  # noqa: BLE001
            fakes.record_anomaly("bytecode does not disassemble", path=path, code=obj.co_name,
                                 error=type(exc).__name__, detail=str(exc)[:200])
            ok = False
            continue
        layout_ok, problem = _cache_layout_ok(obj)
        if not layout_ok:
            fakes.record_anomaly("bytecode layout invalid for this interpreter (other Python version?)",
                                 path=path, code=obj.co_name, detail=problem)
            ok = False
            continue
        names = [i.opname for i in instructions]
        bad = sorted({n for n in names if n.startswith("<")})
        if bad:
            fakes.record_anomaly("invalid opcodes for this interpreter", path=path, code=obj.co_name,
                                 opcodes=bad[:10])
            ok = False
        prologue = [n for n in names if n not in PROLOGUE_OPS][:1]
        if prologue != ["RESUME"]:
            fakes.record_anomaly("bytecode does not start with RESUME (other Python version?)",
                                 path=path, code=obj.co_name, first=names[:3])
            ok = False
        for ins in instructions:
            if ins.opname in ("LOAD_GLOBAL", "LOAD_NAME", "STORE_GLOBAL", "DELETE_GLOBAL"):
                globals_used.add(str(ins.argval))
        touched = (set(obj.co_names) | set(obj.co_varnames)) & INTROSPECTION_NAMES
        if touched:
            fakes.record_anomaly("introspection names in Lambda", path=path, code=obj.co_name,
                                 names=sorted(touched))
    return globals_used, ok


def _cell(value):
    return (lambda: value).__closure__[0]


def _call_variants(function, shape, arguments):
    tensor = fakes.FakeTensor(shape)
    yield "tensor", lambda: function(tensor, **arguments)
    yield "list", lambda: function([tensor, fakes.FakeTensor(shape)], **arguments)


def _input_shape(entry):
    shape = entry.get("input_shape")
    if isinstance(shape, list) and shape and isinstance(shape[0], list):
        shape = shape[0]  # multi-input layer: use the first input
    if not isinstance(shape, list):
        fakes.record_anomaly("Lambda input shape unknown; using (1, 8)", path=entry.get("path"))
        return (1, 8)
    return tuple(d if isinstance(d, int) and d > 0 else 1 for d in shape)


def _run_one(entry, record):
    path = entry.get("path", "?")
    code_b64 = entry.get("code_b64")
    if not code_b64:
        fakes.record_anomaly("Lambda without bytecode", path=path)
        return
    try:
        code = marshal.loads(base64.b64decode(code_b64))
    except Exception as exc:  # noqa: BLE001
        fakes.record_anomaly("marshal error", path=path, error=type(exc).__name__, detail=str(exc)[:200])
        return
    if not isinstance(code, types.CodeType):
        fakes.record_anomaly("marshalled object is not code", path=path, type=type(code).__name__)
        return
    used, valid = _check_bytecode(code, path)
    if not valid:
        return  # never execute bytecode this interpreter does not understand

    scope = fakes.fake_globals()
    builtin_names = scope["__builtins__"]
    for name in sorted(used):
        if name not in scope and name not in builtin_names:
            fakes.record_anomaly("missing stub for global", path=path, name=name)
            scope[name] = fakes.FakeObject(name)

    closure = None
    if code.co_freevars:
        values = entry.get("closure")
        if isinstance(values, list) and len(values) == len(code.co_freevars):
            closure = tuple(_cell(v) for v in values)  # JSON data from the config
        else:
            fakes.record_anomaly("Lambda closure variables replaced by fakes", path=path,
                                 names=list(code.co_freevars))
            closure = tuple(_cell(fakes.FakeObject(n)) for n in code.co_freevars)
    defaults = entry.get("defaults")
    defaults = tuple(defaults) if isinstance(defaults, list) else None
    try:
        function = types.FunctionType(code, scope, code.co_name, defaults, closure)
    except Exception as exc:  # noqa: BLE001
        fakes.record_anomaly("cannot build Lambda function", path=path, error=type(exc).__name__,
                             detail=str(exc)[:200])
        return

    shape = _input_shape(entry)
    arguments = entry.get("arguments") if isinstance(entry.get("arguments"), dict) else {}
    failures = []
    for variant, call in _call_variants(function, shape, arguments):
        try:
            result = call()
        except Exception as exc:  # noqa: BLE001
            failures.append({"variant": variant, "error": type(exc).__name__, "detail": str(exc)[:200]})
            continue
        record("event", category="lambda", detail="called", path=path, variant=variant,
               result=fakes._short(result))
        return
    fakes.record_anomaly("emulation exception", path=path, attempts=failures)


def run_keras_lambda(task, record):
    fakes.install_recorder(record)
    with open(ARTEFACTS + task["file"], encoding="utf-8") as fh:
        entries = json.load(fh)
    if len(entries) > MAX_LAMBDAS:
        fakes.record_anomaly("too many Lambda layers; emulating the first %d" % MAX_LAMBDAS)
    for entry in entries[:MAX_LAMBDAS]:
        _run_one(entry, record)
