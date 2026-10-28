"""Static analysis of pickle streams. Nothing is ever unpickled here.

Opcodes are read with ``pickletools.genops``, which only decodes the byte stream.
A small stack/memo simulation recovers the module and name behind
``STACK_GLOBAL`` (which takes them from the stack, possibly through the memo).

Scoring, strictest first:

* MALICIOUS: an import of a known code-execution / process / file / network sink
  together with any opcode that calls or constructs an object. ``builtins.getattr``
  is judged use by use instead (``_check_getattr``): MALICIOUS only when its result
  is called or the attribute is a dunder or a sink name.
* SUSPICIOUS: any import outside the exact allowlist (called or not: ``find_class``
  imports the module, and import-time side effects are code execution), an import
  that cannot be resolved, a copyreg extension code, a persistent id outside a
  torch checkpoint, trailing data after the STOP that is not another pickle (a
  trailing pickle is analysed as a reading of its own), or any parse error.
* CLEAN: everything else.

A file may hold several pickles back to back (legacy PyTorch, joblib); all of them
are analysed.
"""
from __future__ import annotations

import base64
import io
import pickletools
import re
from typing import Any

from .. import errors, override
from . import budget as budget_mod
from . import clearance as clearance_mod
from . import sklearn_loss
from .allowlists import (
    ARGUMENT_CHECKED,
    ARRAY_RECONSTRUCTORS,
    BUILD_HOOK_KEYS,
    BUILD_STATE_KEYS,
    CLASS_BUILDERS,
    PATH_CLASSES,
    CLOUDPICKLE_IMPORT,
    CLOUDPICKLE_MODULES,
    CLOUDPICKLE_TYPES,
    DANGEROUS_MODULES,
    DANGEROUS_SYMBOLS,
    DEFAULTDICT,
    DILL_ARRAY,
    DILL_MODULES,
    DILL_SINKS,
    ENUM_CLASSES,
    EXEC_GADGETS,
    GETATTR,
    GUARDED_CALLS,
    KNOWN_GADGETS,
    NUMPY_BIT_GENERATOR_CLASSES,
    NUMPY_BIT_GENERATOR_CTOR,
    NUMPY_BIT_GENERATOR_NAMES,
    PANDAS_BLOCK_MANAGER,
    PANDAS_CATEGORICAL_DTYPE,
    PANDAS_DATAFRAME,
    PANDAS_INDEX_CLASSES,
    PANDAS_INDEX_KEYS,
    PANDAS_NEW_INDEX,
    PANDAS_SERIES,
    PANDAS_SINGLE_BLOCK_MANAGER,
    PANDAS_UNPICKLE_BLOCK,
    PICKLE_GLOBALS,
    SCORER_FUNCTIONS,
    SKLEARN_THRESHOLD_SCORER,
    STATE_ONLY_CLASSES,
    TF_DANGEROUS,
    TORCH_GLOBALS,
    ZERO_ARG_CLASSES,
)
from .lookalike import imitates
from .lookalike import reason as lookalike_reason
from .pickle_vm import (
    Global,
    Machine,
    Obj,
    VMError,
    VMUnmodelled,
    class_of,
    identifier_path,
    plain_reading_imports,
)

SCHEMA_VERSION = "1.1"

# Opcodes recorded as evidence, with what they do at load time.
FLAGGED_OPCODES = {
    "GLOBAL": "imports an object by name (module, qualname)",
    "STACK_GLOBAL": "imports an object by name taken from the stack",
    "INST": "imports a class and calls it (protocol 0)",
    "REDUCE": "calls a callable from the stack",
    "OBJ": "calls a class from the stack",
    "NEWOBJ": "calls cls.__new__",
    "NEWOBJ_EX": "calls cls.__new__ with keyword arguments",
    "BUILD": "calls __setstate__ or updates an object's __dict__",
    "EXT1": "imports through the copyreg extension registry",
    "EXT2": "imports through the copyreg extension registry",
    "EXT4": "imports through the copyreg extension registry",
    "PERSID": "hands an id to the loader's persistent_load",
    "BINPERSID": "hands an id to the loader's persistent_load",
}
CALL_OPCODES = frozenset({"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"})
IMPORT_OPCODES = frozenset({"GLOBAL", "STACK_GLOBAL", "INST"})
EXT_OPCODES = frozenset({"EXT1", "EXT2", "EXT4"})
PERSID_OPCODES = frozenset({"PERSID", "BINPERSID"})

STRING_PUSH_OPCODES = frozenset({
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "SHORT_BINSTRING",
    "BINSTRING", "STRING", "BINBYTES", "SHORT_BINBYTES", "BINBYTES8",
})

# Legacy torch.save writes this number as its first pickle.
TORCH_LEGACY_MAGIC = 0x1950A86A20F9469CFC6C
# ...followed by: protocol version, sys info, the object, the storage keys, raw bytes.
TORCH_LEGACY_PICKLES = 5

MAX_PICKLES = 64
MAX_OPCODES = 5_000_000
MAX_DISASM_CHARS = 200_000
# Opcodes kept one by one in the report (the listing, flagged opcodes); every opcode is
# still counted by name. Bounded so a large pickle does not grow the report without end.
MAX_OPCODE_RECORDS = 100_000

# Strings worth showing as evidence (never used for scoring on their own).
_SUSPICIOUS_STRING = re.compile(
    r"(/bin/|\bsh\b|bash|cmd\.exe|powershell|curl|wget|nc\s|/etc/passwd|\.ssh|"
    r"id_rsa|\.env\b|credentials|https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b|base64|"
    r"__import__|eval\(|exec\()",
    re.IGNORECASE,
)


def _format_arg(arg: Any) -> str | None:
    if arg is None:
        return None
    if isinstance(arg, (tuple, list)):
        return " ".join(str(a) for a in arg)
    if isinstance(arg, (bytes, bytearray)):
        return repr(bytes(arg[:200]))
    if isinstance(arg, str):
        return arg[:200]
    return str(arg)[:200]


def _empty_report(file_name: str, file_format: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "file_name": file_name,
        "file_format": file_format,
        "opcodes": [],
        "opcode_counts": {},
        "flagged_opcodes": [],
        "suspicious_imports": [],
        "unknown_imports": [],
        "imports": [],
        "suspicious_strings": [],
        "raw_disasm": "",
        "static_risk": "clean",
        "reasons": [],
        "notes": [],
        "error": None,
        # failures of safeloadai itself (errors.error dicts); never a verdict
        "tool_errors": [],
        # the reasons that are evidence of a sink (MALICIOUS findings); the rest are RISKY
        "evidence": [],
        "pickle_count": 0,
        # reason text -> {"item", "pair", "explanation"} for the reasons that are UNVERIFIABLE
        "unverifiable": {},
        # reasons that make builtins.getattr uses MALICIOUS (_check_getattr)
        "getattr_malicious": [],
        # bytes after the reading's last STOP: {"start", "length", "looks_like_pickle"}
        "trailing": None,
        # Keras models pickled as an embedded .keras archive (_embedded_keras)
        "embedded_keras": [],
        # dill code objects to emulate, and sink names found in them (_dill_code)
        "dill_code": [],
        "code_malicious": [],
        # imports outside the allowlist accepted by static/clearance.py:
        # {"item", "pair", "pos", "mechanism" ("referenced", "policy", "inert-class", ...), "detail"}
        "cleared": [],
        "profile": None,
    }


def is_dangerous_import(module: str, name: str) -> bool:
    """Known sink: module (or its root) or the name (or its last part) is listed."""
    root = module.split(".", 1)[0]
    leaf = name.rsplit(".", 1)[-1]
    head = name.split(".", 1)[0]
    if (module, name) in CLASS_BUILDERS or (module, name) in PATH_CLASSES:
        return False
    return (
        (module in DILL_MODULES and name in DILL_SINKS)
        or (module, name) in EXEC_GADGETS
        or module in DANGEROUS_MODULES
        or root in DANGEROUS_MODULES
        or name in DANGEROUS_SYMBOLS
        or leaf in DANGEROUS_SYMBOLS
        or head in DANGEROUS_SYMBOLS
    )


def _recorders(report: dict, index_ref: list):
    counts = report["opcode_counts"]

    def on_opcode(opcode, arg, pos):
        name = opcode.name
        counts[name] = counts.get(name, 0) + 1
        if len(report["opcodes"]) < MAX_OPCODE_RECORDS:
            entry = {"name": name, "arg": _format_arg(arg), "pos": pos, "pickle": index_ref[0]}
            report["opcodes"].append(entry)
            if name in FLAGGED_OPCODES:
                report["flagged_opcodes"].append(dict(entry, reason=FLAGGED_OPCODES[name]))
        elif name in FLAGGED_OPCODES and not report["flagged_opcodes"]:
            report["flagged_opcodes"].append({"name": name, "arg": _format_arg(arg), "pos": pos,
                                              "pickle": index_ref[0], "reason": FLAGGED_OPCODES[name]})
        if name in STRING_PUSH_OPCODES and isinstance(arg, str) and _SUSPICIOUS_STRING.search(arg):
            report["suspicious_strings"].append({"value": arg[:200], "pos": pos})

    def on_import(module, qualname, pos, opcode, resolved):
        report["imports"].append(
            {"module": module, "symbol": qualname, "pos": pos, "opcode": opcode, "resolved": resolved}
        )

    return on_opcode, on_import


WALK_PROBLEM = "pickle is not readable"
_WALK_WORDS = (
    (re.compile(r"memo key (.+) not found"),
     "it refers to stored object {0} that it never stored (pickle.load fails there)"),
    (re.compile(r"unpickling stack underflow|could not find MARK"),
     "it takes more values off its stack than it put on (pickle.load fails there)"),
    (re.compile(r"not enough data|exhausted before|ends without STOP|truncated|past the end of the file"),
     "it is truncated: the stream ends in the middle of an opcode or before STOP (pickle.load fails there)"),
    (re.compile(r"at position (\d+), opcode (.+) unknown"),
     "byte {1} at offset {0} is no pickle opcode (pickle.load fails there)"),
    (re.compile(r"frame|FRAME"),
     "its framing is inconsistent ({raw}); a real unpickler fails there or reads different bytes"),
    (re.compile(r"more than (\d+) opcodes"),
     "it has more than {0} opcodes, more than safeloadai reads; the rest is not analysed"),
    (re.compile(r"more than (\d+) pickles"),
     "it holds more than {0} pickles, more than safeloadai reads; the rest is not analysed"),
    (re.compile(r"unsupported pickle protocol"),
     "it asks for a pickle protocol no Python supports (pickle.load fails there)"),
    (re.compile(r"NumpyArrayWrapper|array (data )?at|object array"),
     "a joblib array header or its data is laid out in a way safeloadai cannot verify ({raw})"),
)


def walk_problem(exc: BaseException) -> str | None:
    """A walk failure in plain words, when it says something about the bytes: the stream is
    one a real unpickler rejects or reads differently, or it exceeds a reading limit
    (SUSPICIOUS). ``None`` when the exception is a gap or bug in safeloadai (a tool error)."""
    if isinstance(exc, VMUnmodelled) or not isinstance(exc, (VMError, ValueError)):
        return None
    raw = str(exc)
    for pattern, words in _WALK_WORDS:
        match = pattern.search(raw)
        if match:
            return f"{WALK_PROBLEM}: " + words.format(*match.groups(), raw=raw[:200])
    return f"{WALK_PROBLEM}: it is malformed ({raw[:200]}); a real unpickler rejects it or reads it differently"


def parse_pickle(data: bytes, file_name: str = "<memory>", *, torch: bool = False,
                 file_format: str = "pickle", extra_allowed: frozenset = frozenset(),
                 joblib: bool = True, trailing: str = "nested", depth: int = 0,
                 clearance: clearance_mod.Clearance | None = None, profile_name: str | None = None) -> dict:
    """Analyse pickle bytes and return the parser contract (dict).

    The reading ends at the first STOP, where ``pickle.load`` stops (a legacy PyTorch
    file is the exception: ``torch.load`` reads its five pickles). Any bytes after it
    are trailing data, recorded in ``report["trailing"]`` with a RISKY reason, never
    walked as part of this reading. With ``trailing="nested"`` (the default, used
    inside containers) trailing bytes that look like a pickle are analysed as a reading
    of their own and their findings merged with a prefix; ``trailing="view"`` leaves
    that to the caller (``static.analyze_bytes`` makes them a separate view).

    ``torch=True`` widens the allowlist with the globals a PyTorch checkpoint
    needs and accepts persistent ids (torch stores tensor data out of band).
    ``clearance`` says which classes outside the allowlist are state-only (the pinned
    source policies by default; see static/clearance.py).
    ``profile_name`` is the file name a profile (safeloadai.profiles) is looked up by;
    ``None`` uses ``file_name``, ``""`` looks up none (nested and hidden pickles).
    ``joblib=True`` (the default) reads joblib's NumpyArrayWrapper layout: the raw
    array bytes after each wrapper are skipped, object arrays are walked as nested
    pickles, and the bytes joblib reads as array data are checked for what a plain
    ``pickle.load`` would import from them (parser differential).
    """
    report = _empty_report(file_name, file_format)
    clearance = clearance or clearance_mod.ACTIVE.get()
    legacy_torch = False
    base = PICKLE_GLOBALS | frozenset(extra_allowed)
    allow = base | TORCH_GLOBALS if torch else base
    index_ref = [0]
    on_opcode, on_import = _recorders(report, index_ref)
    calls: list[tuple] = []
    record_call = calls.append
    if clearance.validate_boosters:
        from . import boosters

        record_call = boosters.recorder(calls)
    machine = Machine(data, joblib=joblib, on_import=on_import, on_opcode=on_opcode,
                      on_call=lambda *call: record_call(call), max_opcodes=MAX_OPCODES)
    try:
        while machine.stream.tell() < len(data):
            if index_ref[0] >= MAX_PICKLES:
                raise ValueError(f"more than {MAX_PICKLES} pickles in one file")
            start = machine.stream.tell()
            stopped, first_int = machine.run_one()
            if index_ref[0] == 0 and first_int == TORCH_LEGACY_MAGIC:
                legacy_torch = True
                torch = True
                allow = base | TORCH_GLOBALS
                report["notes"].append("legacy PyTorch serialization (magic number found)")
            index_ref[0] += 1
            if not stopped:
                raise ValueError("pickle ends without STOP")
            if legacy_torch and index_ref[0] == TORCH_LEGACY_PICKLES:
                report["notes"].append(
                    f"{len(data) - machine.stream.tell()} bytes of raw tensor storage after the "
                    "legacy torch pickles (not analysed, never unpickled)"
                )
                break
            if machine.stream.tell() == start or not legacy_torch:
                break
    except (budget_mod.ResourceLimit, MemoryError):
        raise
    except Exception as exc:  # noqa: BLE001 - any parse failure must surface
        problem = walk_problem(exc)
        if problem is None:
            # Not a property of the bytes: an exception the walker does not expect is a bug in
            # safeloadai (a tool error, never a verdict). Nothing after this point was read.
            report["tool_errors"].append(errors.internal("E201", exc))
            report["error"] = "the pickle walker failed (tool error E201); the stream was not fully read"
        else:
            report["error"] = problem
    report["pickle_count"] = index_ref[0]
    if not report["error"] and machine.stream.tell() < len(data) and not legacy_torch:
        _trailing(report, data, machine.stream.tell(), trailing, depth,
                  dict(torch=torch, file_format=file_format, extra_allowed=extra_allowed, joblib=joblib,
                       clearance=clearance, profile_name=""))
    _joblib_findings(report, machine, data, allow)
    handled = _embedded_keras(report, calls, machine.refs)
    _dill_code(report, calls)
    state_only = clearance.is_state_only
    report["reasons"].extend(_check_guarded_calls(calls, state_only))
    report["getattr_malicious"], risky = _check_getattr(calls, allow, _imports_getattr(report), handled)
    report["reasons"].extend(risky)

    def stores_only(obj) -> bool:
        pair = class_of(obj)
        return pair is not None and pair not in GETATTR and (pair in allow or state_only(pair))

    used = clearance_mod.used_globals(calls, machine.uses, stores_only)
    extra = {}
    if torch and not legacy_torch:
        why = clearance_mod.weights_only_ok(report, calls, machine.uses)
        report["weights_only"] = why or "accepted"
        if why is None:
            from .upstream.torch_weights_only import TORCH_VERSION

            detail = f"the stream passes torch {TORCH_VERSION} weights_only rules"
            extra = {(i["module"], i["symbol"]): ("torch-weights-only", detail) for i in report["imports"]}
    if not report["error"] and depth == 0:
        _profile(report, file_name if profile_name is None else profile_name, machine, calls, legacy_torch, extra)
    if not report["error"]:
        sklearn_loss.clear(report, extra)
    if clearance.validate_boosters and not report["error"]:
        boosters.clear(report, calls, machine.uses, machine.globals, extra, record_call.states)
    report["raw_disasm"] = _disasm(data)
    _score(report, allow, torch, clearance, machine.globals, used, extra)
    return report


def _profile(report: dict, name: str, machine: Machine, calls: list[tuple], legacy_torch: bool,
             extra: dict) -> None:
    """Apply a profile for a well-known file (safeloadai.profiles): it accepts its globals
    at their allowed positions, or makes a file that has the name but not the shape RISKY."""
    from .. import profiles

    results = machine.results
    root = (results[3] if len(results) > 3 else None) if legacy_torch else (results[0] if results else None)
    outcome = profiles.evaluate(name, report["imports"], root, calls, machine.uses)
    if outcome is None:
        return
    profile = outcome.profile
    if outcome.mismatch is not None:
        report["reasons"].append(f"file name matches the {profile.name} profile ({profile.producer}), "
                                 f"but its structure does not: {outcome.mismatch}")
        return
    report["profile"] = profile.name
    report["notes"].append(f"matches the {profile.name} profile ({profile.producer})")
    for pair, note in profile.clears.items():
        extra.setdefault(pair, ("profile", f"{profile.name} profile: {note}"))


def _trailing(report: dict, data: bytes, start: int, mode: str, depth: int, options: dict) -> None:
    """Record the bytes after the reading's last STOP; in "nested" mode, analyse them as
    a reading of their own when they look like a pickle."""
    from ..parsing.detect import _looks_like_pickle

    rest = data[start:]
    report["trailing"] = {"start": start, "length": len(rest), "looks_like_pickle": _looks_like_pickle(rest)}
    text = (f"{len(rest)} bytes of trailing data after the pickle's STOP (offset {start}); "
            "pickle.load stops there, a loader that reads on would see them")
    if not report["trailing"]["looks_like_pickle"]:
        report["reasons"].append(text)
        return
    # Another pickle: analysed as a reading of its own, which carries its own findings.
    report["notes"].append(text + "; they hold another pickle, analysed as a reading of its own")
    if mode != "nested":
        return
    if depth + 1 >= MAX_PICKLES:
        report["reasons"].append(f"more than {MAX_PICKLES} readings of trailing data; the rest is not analysed")
        return
    sub = parse_pickle(rest, report["file_name"], trailing="nested", depth=depth + 1, **options)
    prefix = f"trailing data at offset {start}: "
    report["reasons"].extend(prefix + r for r in sub["reasons"])
    report["unverifiable"].update({prefix + k: v for k, v in sub["unverifiable"].items()})
    report["suspicious_strings"].extend(sub["suspicious_strings"])
    report["tool_errors"].extend(sub["tool_errors"])
    report["notes"].extend(prefix + n for n in sub["notes"])
    for key in ("embedded_keras", "dill_code", "code_malicious"):
        report[key].extend(sub[key])
    report.setdefault("_embedded", []).extend(sub.get("_embedded") or [])
    report["trailing"]["report"] = {"static_risk": sub["static_risk"], "pickle_count": sub["pickle_count"]}
    if sub["static_risk"] == "malicious":
        report["trailing_malicious"] = True
        report.setdefault("evidence", []).extend(prefix + r for r in sub.get("evidence") or [])


# Top-level packages a model-loading environment commonly has, besides the
# standard library and whatever is importable here.
_COMMON_TOP_LEVEL = frozenset({
    "numpy", "scipy", "sklearn", "joblib", "pandas", "torch", "tensorflow", "keras", "transformers",
    "diffusers", "dill", "cloudpickle", "xgboost", "lightgbm", "catboost", "skops", "onnx", "requests",
    "urllib3", "yaml", "pip", "setuptools", "IPython", "jax", "flax", "huggingface_hub", "safetensors",
})


def _importable_top_level(module: str) -> bool:
    """Could ``import module`` succeed somewhere this file is loaded? Only the top-level
    name is looked up (find_spec of a top-level name runs no package code)."""
    import importlib.util
    import sys

    top = module.split(".", 1)[0]
    if top in sys.stdlib_module_names or top in sys.builtin_module_names or top in _COMMON_TOP_LEVEL:
        return True
    try:
        return importlib.util.find_spec(top) is not None
    except (ImportError, ValueError):
        return True  # cannot tell: assume it can


def _joblib_findings(report: dict, machine: Machine, data: bytes, allow: frozenset) -> None:
    if not (machine.arrays or machine.object_arrays or machine.legacy_wrappers):
        return
    if report["file_format"] == "pickle":
        report["file_format"] = "joblib"
    report["joblib"] = {"arrays": machine.arrays, "object_arrays": machine.object_arrays,
                        "array_bytes": machine.array_bytes, "legacy_wrappers": machine.legacy_wrappers}
    report["notes"].append(
        f"joblib: {machine.arrays} raw arrays ({machine.array_bytes} bytes, skipped, never read as opcodes), "
        f"{machine.object_arrays} object arrays walked as nested pickles"
    )
    if machine.legacy_wrappers:
        report["reasons"].append(
            "legacy joblib (< 0.10) multi-file format: the arrays live in side files (*.npy, *.z) that "
            "joblib.load opens by name and reads with numpy.load(allow_pickle=True); they are not analysed"
        )
    if machine.first_region is None:
        return
    calls: list[tuple] = []
    found, decided = plain_reading_imports(data, machine.first_region, MAX_OPCODES,
                                           on_call=lambda *call: calls.append(call))
    report["reasons"].extend(f"parser differential: plain pickle.load reading of the joblib array data: {r}"
                             for r in _check_guarded_calls(calls))
    for module, name, pos, opcode in found:
        if module is not None and not _importable_top_level(module):
            break  # pickle.load raises ImportError here; nothing after it runs
        if module is None:
            report["reasons"].append(
                f"parser differential: plain pickle.load would read the joblib array data as opcodes "
                f"and reach {opcode} at {pos} (copyreg extension import)")
        elif (module, name) not in allow:
            # Scored like any other import (a known sink with call opcodes is MALICIOUS).
            report["imports"].append({"module": module, "symbol": name, "pos": pos, "resolved": True,
                                      "opcode": f"{opcode} (plain pickle.load reading of joblib array data)"})
            report["reasons"].append(
                f"parser differential: plain pickle.load would read the joblib array data as opcodes "
                f"and import {module}.{name} ({opcode} at {pos})")
    # The walk follows the plain reading in order and stops at the first import no
    # environment can satisfy (such as a pair stitched together from the outer memo
    # when nested pickle opcodes are read with the outer stack): pickle.load raises
    # ImportError there, so nothing after it can run.
    if not decided:
        report["reasons"].append("parser differential check ran out of budget; plain pickle.load reading "
                                 "of the joblib array data is undecided")


# --- calls to allowlisted helpers that call one of their own arguments -----------------

# Steps of the value walk over all calls of one stream together. Containers are walked
# once per stream (see _guarded_values), so the walk is bounded by the stream's edges,
# which MAX_OPCODES bounds; this is a backstop.
MAX_VALUE_WALK = 10_000_000


def _guarded(value, state_only=None) -> bool:
    return isinstance(value, Global) and (value.pair in GUARDED_CALLS or value.pair in ARGUMENT_CHECKED
                                          or value.pair in GETATTR
                                          or (state_only is not None and state_only(value.pair)))


def _argument_check(how: str, pair: tuple[str, str], args, state_only=None) -> tuple[str | None, int | None]:
    """(reason or None, top-level argument position exempt from the value walk) for one
    call of an ARGUMENT_CHECKED pair (allowlists.py says what each check allows) or of a
    class ``state_only`` accepts."""
    if pair in STATE_ONLY_CLASSES or (state_only is not None and state_only(pair)):
        if how == "newobj" and args == ():
            return None, None
        return (f"is called ({how.upper()} with arguments {_short(args)}); it is accepted only when rebuilt "
                "from its saved state without calling it (NEWOBJ with no arguments)"), None
    if how != "reduce":
        return f"is used through {how.upper()}, not called the way its library pickles it", None
    if pair in ZERO_ARG_CLASSES:
        if args == ():
            return None, None
        return (f"is called with arguments {_short(args)}; it is accepted only as a call with no arguments "
                "(REDUCE cls()) followed by BUILD"), None
    if pair in ENUM_CLASSES:
        if len(args) == 1 and type(args[0]) in (str, int):
            return None, None
        return f"is called with {_short(args)}; only a member lookup with one str or int is accepted", None
    if pair == PANDAS_NEW_INDEX:
        if (len(args) == 2 and isinstance(args[0], Global) and args[0].pair in PANDAS_INDEX_CLASSES
                and isinstance(args[1], dict) and set(args[1]) <= PANDAS_INDEX_KEYS[args[0].pair]):
            return None, 0
        shown = (args[0], sorted(args[1]) if isinstance(args[1], dict) else args[1]) if len(args) == 2 else args
        return (f"is called with arguments pandas never writes ({_short(shown)}; it calls its first argument, "
                "and only pandas.core.indexes.base.Index with a data/name dict is accepted)"), None
    if pair == DEFAULTDICT:
        # The factory runs only on a missing key, after loading; as a global it is checked
        # against the allowlist like any other import.
        if not args or (len(args) == 1 and (args[0] is None or isinstance(args[0], Global))):
            return None, None  # not exempt: an argument-checked global is no factory either
        return f"is given {_short(args)}; only no factory or one imported global is accepted", None
    if pair == PANDAS_UNPICKLE_BLOCK:
        if (len(args) == 3 and _is_ndarray(args[0]) and _is_block_locs(args[1])
                and type(args[2]) is int and args[2] in (1, 2)):
            return None, None
        return (f"is called with {_short(args)}; only (numpy array, slice, ndim 1 or 2) as pandas "
                "writes a block is accepted"), None
    if pair == PANDAS_BLOCK_MANAGER:
        if (len(args) == 2 and isinstance(args[0], tuple) and args[0]
                and all(_is_unpickled_block(b) for b in args[0])
                and isinstance(args[1], list) and len(args[1]) == 2 and all(_is_pandas_index(a) for a in args[1])):
            return None, None
        return (f"is called with {_short(args)}; only (blocks from _unpickle_block, [two pandas Index]) "
                "as pandas writes a DataFrame's manager is accepted"), None
    if pair in SCORER_FUNCTIONS:
        return ("is called; it is accepted only as the score function a scikit-learn scorer stores, "
                "which is not called while loading"), None
    return "has no argument check", None


# --- pandas and scorer shapes (allowlists.py, Phase 5 tune review) -----------------------

NUMPY_RECONSTRUCT = frozenset({("numpy._core.multiarray", "_reconstruct"), ("numpy.core.multiarray", "_reconstruct")})
SLICE = frozenset({("builtins", "slice"), ("__builtin__", "slice")})
PLAIN_SCALARS = (str, int, float, bool, type(None))


def _reduce_of(value, pairs) -> bool:
    return (isinstance(value, Obj) and value.how == "reduce" and isinstance(value.func, Global)
            and value.func.pair in pairs)


def _is_ndarray(value) -> bool:
    """A numpy array as numpy pickles it (_reconstruct(ndarray, ...) + BUILD) or as joblib reads it."""
    if isinstance(value, Obj) and value.how == "array":
        return True
    return (_reduce_of(value, NUMPY_RECONSTRUCT) and isinstance(value.args, tuple) and value.args
            and isinstance(value.args[0], Global) and value.args[0].pair == ("numpy", "ndarray"))


def _is_block_locs(value) -> bool:
    """A block's placement as pandas writes it: mgr_locs.indexer, a slice of ints or an int array."""
    if _reduce_of(value, SLICE):
        return (isinstance(value.args, tuple) and len(value.args) == 3
                and all(a is None or type(a) is int for a in value.args))
    return (type(value) is int) or _is_ndarray(value)


def _is_pandas_index(value) -> bool:
    return _reduce_of(value, {PANDAS_NEW_INDEX})  # its arguments are checked at its own call


def _is_unpickled_block(value) -> bool:
    return _reduce_of(value, {PANDAS_UNPICKLE_BLOCK})  # its arguments are checked at its own call


def _manager_state_ok(state) -> bool:
    """BaseBlockManager.__getstate__ for a SingleBlockManager: (axes, values, items,
    {"0.14.1": {"axes": [Index], "blocks": [{"values": array, "mgr_locs": slice}]}})."""
    if not (isinstance(state, tuple) and len(state) == 4 and isinstance(state[3], dict)
            and set(state[3]) == {"0.14.1"}):
        return False
    first = state[3]["0.14.1"]
    if not (isinstance(first, dict) and set(first) == {"axes", "blocks"}):
        return False
    axes, blocks = first["axes"], first["blocks"]
    if not (isinstance(axes, list) and len(axes) == 1 and _is_pandas_index(axes[0])):
        return False
    if not (isinstance(blocks, list) and len(blocks) == 1 and isinstance(blocks[0], dict)
            and set(blocks[0]) == {"values", "mgr_locs"}):
        return False
    if not (_is_ndarray(blocks[0]["values"]) and _is_block_locs(blocks[0]["mgr_locs"])):
        return False
    old_axes, old_values, old_items = state[:3]  # the 0.13.1 copy, which __setstate__ ignores
    return (isinstance(old_axes, list) and all(_is_pandas_index(a) for a in old_axes)
            and isinstance(old_values, list) and all(_is_ndarray(v) for v in old_values)
            and isinstance(old_items, list) and all(_is_pandas_index(i) for i in old_items))


def _plain_label(value, depth: int = 0) -> bool:
    """A Series name or scorer keyword value: a scalar or a tuple of scalars."""
    if isinstance(value, tuple) and depth == 0:
        return all(_plain_label(v, 1) for v in value)
    return type(value) in PLAIN_SCALARS


def _build_state_problem(pair, state) -> str | None:
    """What is wrong with the BUILD state of an instance of a class in BUILD_STATE_KEYS, or None."""
    keys = BUILD_STATE_KEYS.get(pair)
    if keys is None:
        return None
    extra = sorted(str(k) for k in state if k not in keys)
    if extra:
        return f"has state keys its class never writes ({', '.join(extra)[:120]})"
    if pair in (PANDAS_DATAFRAME, PANDAS_SERIES):
        manager_ok = (_reduce_of(state.get("_mgr"), {PANDAS_BLOCK_MANAGER}) if pair == PANDAS_DATAFRAME
                      else class_of(state.get("_mgr")) == PANDAS_SINGLE_BLOCK_MANAGER
                      and state["_mgr"].how == "newobj")
        flags = state.get("_flags", {})
        if not (manager_ok and state.get("_typ") in ("dataframe", "series")
                and isinstance(state.get("_metadata", []), list)
                and all(type(m) is str for m in state.get("_metadata", []))
                and isinstance(state.get("attrs", {}), dict)
                and isinstance(flags, dict) and set(flags) <= {"allows_duplicate_labels"}
                and all(type(v) is bool for v in flags.values())
                and _plain_label(state.get("name"))):
            return "has a state pandas never writes (manager, _typ, _metadata, attrs, _flags or name)"
    elif pair == PANDAS_CATEGORICAL_DTYPE:
        categories = state.get("categories")
        if not ((categories is None or _is_pandas_index(categories)) and state.get("ordered") in (True, False, None)):
            return "has a state pandas never writes (categories must be an Index, ordered a bool)"
    elif pair == SKLEARN_THRESHOLD_SCORER:
        func, kwargs = state.get("_score_func"), state.get("_kwargs", {})
        if not (isinstance(func, Global) and func.pair in SCORER_FUNCTIONS and state.get("_sign") in (1, -1)
                and isinstance(kwargs, dict) and all(type(k) is str and _plain_label(v) for k, v in kwargs.items())):
            return ("has a state scikit-learn never writes (_score_func must be a reviewed score function, "
                    "_sign 1 or -1, _kwargs plain values)")
    return None


def _stored_score_function(how: str, func, args) -> bool:
    """A BUILD of a _ThresholdScorer whose state passes _build_state_problem: its _score_func
    is stored, not called, so the value walk skips it."""
    return (how == "build" and class_of(func) == SKLEARN_THRESHOLD_SCORER and isinstance(args, tuple)
            and len(args) == 1 and isinstance(args[0], dict)
            and _build_state_problem(SKLEARN_THRESHOLD_SCORER, args[0]) is None)


def _is_zero_arg_instance(value) -> bool:
    return isinstance(value, Obj) and value.how == "reduce" and class_of(value) in ZERO_ARG_CLASSES


def _rebuilt_instance_use(how: str, func, args, state_only=None) -> str | None:
    """An instance of a state-only or zero-arg class may only receive one BUILD with a
    plain dict state. A (dict, slotstate) state makes pickle call setattr() per slot item,
    and calling the instance runs its __call__."""
    if not isinstance(func, Obj):
        return None
    pair = class_of(func)
    if pair not in STATE_ONLY_CLASSES and pair not in ZERO_ARG_CLASSES and not (
            state_only is not None and pair is not None and pair not in GETATTR and state_only(pair)):
        return None
    name = f"an instance of {pair[0]}.{pair[1]}"
    if how != "build":
        return f"{name} is called ({how.upper()}); it may only be rebuilt from a dict state"
    state = args[0] if isinstance(args, tuple) and args else None
    if pair == PANDAS_SINGLE_BLOCK_MANAGER:
        if _manager_state_ok(state):
            return None
        return f"{name} is given a BUILD state pandas never writes (only the 0.14.1 manager tuple is accepted)"
    if not isinstance(state, dict):
        return (f"{name} is given a {type(state).__name__} BUILD state; only a dict state is accepted "
                "(a slot state makes pickle call setattr)")
    problem = _build_state_problem(pair, state)
    if problem:
        return f"{name} {problem}"
    return None


class _Shown(str):
    def __repr__(self) -> str:
        return str(self)


def _shown(value):
    if isinstance(value, Global):
        return f"{value.module}.{value.name}"
    if isinstance(value, Obj):
        pair = class_of(value)
        return _Shown(f"<{pair[0]}.{pair[1]} {value.how}>" if pair else f"<{value.how}>")
    if isinstance(value, (tuple, list)):
        return type(value)(_shown(v) for v in value)
    return value


def _short(args) -> str:
    text = repr(tuple(_shown(a) for a in args) if isinstance(args, tuple) else _shown(args))
    return text if len(text) <= 120 else text[:117] + "..."


def _is_bit_generator(value) -> bool:
    """A numpy bit-generator instance as numpy pickles it: __bit_generator_ctor(<class or name>)."""
    return (isinstance(value, Obj) and value.how == "reduce" and isinstance(value.func, Global)
            and value.func.pair == NUMPY_BIT_GENERATOR_CTOR and _bit_generator_args_ok(value.args))


def _bit_generator_args_ok(args) -> bool:
    if not isinstance(args, tuple) or len(args) > 1:
        return False
    if not args:
        return True  # numpy's default, MT19937
    first = args[0]
    return (isinstance(first, str) and first in NUMPY_BIT_GENERATOR_NAMES) or (
        isinstance(first, Global) and first.pair in NUMPY_BIT_GENERATOR_CLASSES)


def _generator_args_ok(args) -> bool:
    """__generator_ctor / __randomstate_ctor: (name or instance[, __bit_generator_ctor])."""
    if not isinstance(args, tuple) or not 1 <= len(args) <= 2:
        return False
    first = args[0]
    if not ((isinstance(first, str) and first in NUMPY_BIT_GENERATOR_NAMES) or _is_bit_generator(first)):
        return False
    return len(args) == 1 or (isinstance(args[1], Global) and args[1].pair == NUMPY_BIT_GENERATOR_CTOR)


def _guarded_values(value, skip_top: int | None = None, walk: dict | None = None,
                    state_only=None) -> list[Global]:
    """Guarded globals reachable inside ``value`` (tuples, lists, dicts, sets).
    ``skip_top`` exempts one top-level tuple position (the permitted ctor argument).
    An Obj is not entered: its callable, arguments and state were checked at its own call.

    ``walk`` is shared by every call of one stream: a container already walked for an
    earlier call is not walked again (whatever it holds was reported then, with its final
    contents), so a large vocabulary passed to many BUILDs costs one walk. A top-level
    tuple walked with a position exempt is not marked, so it is walked in full elsewhere."""
    walk = walk if walk is not None else {"seen": set(), "steps": 0}
    seen = walk["seen"]
    found, todo = [], [(value, 0)]
    while todo:
        item, depth = todo.pop()
        walk["steps"] += 1
        if walk["steps"] > MAX_VALUE_WALK:
            found.append(Global("<undecided>", "<walk limit>"))
            break
        if _guarded(item, state_only):
            found.append(item)
            continue
        if isinstance(item, tuple) and depth == 0 and skip_top is not None:
            todo.extend((v, depth + 1) for i, v in enumerate(item) if i != skip_top)
            continue
        if not isinstance(item, (tuple, list, set, frozenset, dict)) or id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, dict):
            todo.extend((v, depth + 1) for kv in item.items() for v in kv)
        else:
            todo.extend((v, depth + 1) for v in item)
    return found


def _check_builds(calls: list[tuple]) -> list[str]:
    """pickle writes one BUILD per object, and its state never sets a hook attribute. A
    state that stores ``__setstate__`` (or another hook) makes the next BUILD on that object,
    or a later copy, call the stored value with an argument the file chooses."""
    reasons = []
    built: set[int] = set()
    for how, func, args, pos in calls:
        if how != "build":
            continue
        state = args[0] if isinstance(args, tuple) and args else args
        if clearance_mod.sets_hook(state):
            parts = state if isinstance(state, tuple) and len(state) == 2 else (state,)
            keys = sorted({key for part in parts if isinstance(part, dict) for key in part
                           if isinstance(key, str) and key in BUILD_HOOK_KEYS})
            reasons.append(f"BUILD at {pos} sets {', '.join(keys)} on the object it rebuilds; "
                           "a later BUILD or lookup would call the stored value")
        if isinstance(func, (Global, Obj)):
            if id(func) in built:
                reasons.append(f"BUILD at {pos} rebuilds the same object a second time (pickle writes one "
                               "BUILD per object; the second calls the object's __setstate__ again)")
            built.add(id(func))
    return reasons


def _check_guarded_calls(calls: list[tuple], state_only=None) -> list[str]:
    """Reasons for every call that uses numpy's ctor helpers other than the way numpy does.

    Values are checked after the walk, so a list or dict filled in after it was passed
    to a call is seen with its final contents.
    """
    reasons = _check_builds(calls)
    walk = {"seen": set(), "steps": 0}
    zero_walk = {"seen": set(), "steps": 0}
    for how, func, args, pos in calls:
        exempt = None
        reason = _rebuilt_instance_use(how, func, args, state_only)
        if reason:
            reasons.append(f"{reason} at {pos}")
        if how != "build":
            for obj in _getattr_results(args, zero_walk, _is_zero_arg_instance):
                pair = class_of(obj)
                reasons.append(f"an instance of {pair[0]}.{pair[1]} is passed to a call at {pos} ({how.upper()}); "
                               "it may only be rebuilt from a dict state and stored")
        if isinstance(func, Global) and func.pair in GETATTR:
            # judged by _check_getattr. getattr never calls its target, so an allowlisted class
            # there (getattr(Detect, "forward"), how pickle writes a function stored on a class)
            # is not a value handed to a caller; the name is still walked.
            exempt = 0 if isinstance(args, tuple) and args and isinstance(args[0], Global) else None
        elif isinstance(func, Global) and (func.pair in ARGUMENT_CHECKED
                                           or (state_only is not None and state_only(func.pair))):
            reason, exempt = _argument_check(how, func.pair, args, state_only)
            if reason:
                reasons.append(f"{func.module}.{func.name} at {pos} {reason}")
        elif _guarded(func):
            name = f"{func.module}.{func.name}"
            if how != "reduce":
                reasons.append(f"{name} at {pos} is used through {how.upper()}, not called the way numpy does")
            elif func.pair == NUMPY_BIT_GENERATOR_CTOR:
                if not _bit_generator_args_ok(args):
                    reasons.append(f"{name} at {pos} is called with arguments numpy never writes "
                                   "(only a numpy bit-generator name or class is accepted)")
            elif not _generator_args_ok(args):
                reasons.append(f"{name} at {pos} is called with arguments numpy never writes (it calls its "
                               "second argument; only a numpy bit generator and __bit_generator_ctor are accepted)")
            else:
                exempt = 1
        if _stored_score_function(how, func, args):
            args = ({k: v for k, v in args[0].items() if k != "_score_func"},)
        for value in _guarded_values(args, skip_top=exempt, walk=walk, state_only=state_only):
            reasons.append(f"{value.module}.{value.name} is passed as a value at {pos} "
                           f"({how.upper()}); it may only be called directly")
    return reasons


# --- Keras 3 models pickled as an embedded .keras archive --------------------------

# keras/src/saving/keras_saveable.py (Keras 3.3.3 to 3.15.1, source review 2 of 2026-10-19):
# KerasSaveable.__reduce__ returns (self._unpickle_model, (BytesIO(<.keras archive>),)), and
# _unpickle_model hands the bytes to saving_lib._load_model_from_fileobj(..., safe_mode=False).
# In opcodes: REDUCE of builtins.getattr(<keras class>, "_unpickle_model") on an _io.BytesIO
# rebuilt by NEWOBJ () + BUILD (value, position, dict-or-None); at protocol 2 the value is
# _codecs.encode(<latin-1 text>, "latin1").
KERAS_UNPICKLE = "_unpickle_model"
BYTES_IO = frozenset({("_io", "BytesIO"), ("io", "BytesIO")})
CODECS_ENCODE = ("_codecs", "encode")


def _embedded_blob(value) -> bytes | None:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, Obj) and value.how == "reduce" and isinstance(value.func, Global) \
            and value.func.pair == CODECS_ENCODE and isinstance(value.args, tuple) and len(value.args) == 2 \
            and isinstance(value.args[0], str) and value.args[1] in ("latin1", "latin-1"):
        try:
            return value.args[0].encode("latin-1")
        except UnicodeEncodeError:
            return None
    return None


def _keras_class(value) -> bool:
    return isinstance(value, Global) and identifier_path(value.module) and identifier_path(value.name) \
        and value.module.split(".", 1)[0] == "keras" and not value.name.startswith("_")


def _match_embedded_keras(func, args):
    """(keras class, getattr result, BytesIO instance, bytes) when a REDUCE is exactly the
    Keras embedded-model form, else None."""
    if not (_is_getattr_result(func) and func.how == "reduce" and isinstance(func.args, tuple)
            and len(func.args) == 2 and _keras_class(func.args[0]) and func.args[1] == KERAS_UNPICKLE):
        return None
    if not (isinstance(args, tuple) and len(args) == 1):
        return None
    bio = args[0]
    if not (isinstance(bio, Obj) and bio.how == "newobj" and isinstance(bio.func, Global)
            and bio.func.pair in BYTES_IO and bio.args == ()):
        return None
    state = bio.state
    if not (isinstance(state, tuple) and len(state) == 3 and isinstance(state[1], int)
            and not isinstance(state[1], bool) and (state[2] is None or state[2] == {})):
        return None
    blob = _embedded_blob(state[0])
    return None if blob is None else (func.args[0], func, bio, blob)


def _embedded_keras(report: dict, calls: list[tuple], refs: dict) -> frozenset:
    """Recognise Keras models pickled as an embedded .keras archive (owner's decision of
    2026-10-19: the form is not evidence of an attack by itself).

    Each match keeps a RISKY reason (the pickle runs the Keras loader with
    safe_mode=False on the bytes, which is never overridable) and hands the bytes to the
    pipeline under ``_embedded``, which analyses them as a Keras file of their own (static
    analysis and Lambda emulation) and takes that verdict. The keras class and the
    BytesIO import are not counted as findings when every use of them is in a match;
    otherwise they are judged as before. Returns the ids of the argument tuples of the
    calls a match accounts for (for _check_getattr)."""
    matches = []
    for how, func, args, pos in calls:
        if how == "reduce":
            found = _match_embedded_keras(func, args)
            if found:
                matches.append((pos, args, *found))
    if not matches:
        return frozenset()
    handled: set[int] = set()
    uses: dict[int, list] = {}  # id of a keras class or BytesIO Global -> [Global, uses in matches]
    all_single = True
    for pos, args, cls, result, bio, blob in matches:
        for value in (cls, bio.func):
            uses.setdefault(id(value), [value, 0])[1] += 1
        if refs.get(id(result), 0) == 0 and refs.get(id(bio), 0) == 0:
            handled.update({id(args), id(result.args)})
        else:
            all_single = False  # the method or the BytesIO is used again elsewhere
        name = f"{cls.module}.{cls.name}.{KERAS_UNPICKLE}"
        report["reasons"].append(
            f"pickle invokes the Keras loader on embedded bytes ({name} at {pos} reads a {len(blob)}-byte "
            "archive with safe_mode=False); the embedded model is analysed as a Keras file of its own")
        report["embedded_keras"].append({"pos": pos, "class": f"{cls.module}.{cls.name}", "length": len(blob)})
        report.setdefault("_embedded", []).append({"pos": pos, "label": f"embedded keras@{pos}", "data": blob})
    # A pair's imports are accounted for when each of its Globals is used only in matches.
    counts: dict[tuple, int] = {}
    for imp in report["imports"]:
        if imp["opcode"] in IMPORT_OPCODES and imp["resolved"]:
            pair = (imp["module"], imp["symbol"])
            counts[pair] = counts.get(pair, 0) + 1
    by_pair: dict[tuple, list[bool]] = {}
    for value, n in uses.values():
        by_pair.setdefault(value.pair, []).append(1 + refs.get(id(value), 0) == n)
    report["_consumed_imports"] = frozenset(
        pair for pair, ok in by_pair.items() if all_single and all(ok) and counts.get(pair) == len(ok))
    return frozenset(handled)


# --- dill: functions pickled with their bytecode -----------------------------------

# dill._dill._create_code(*args) (0.3.8 and 0.4.1, source review 2): an optional leading
# co_lnotab, then the CodeType fields of the writing Python. On 3.11 to 3.13 (18 fields):
# argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize, flags, code, consts,
# names, varnames, filename, name, qualname, firstlineno, linetable, exceptiontable,
# freevars, cellvars.
CODE_FIELDS_311 = 18
MAX_DILL_CODE = 64


class _NotData(ValueError):
    pass


def _code_json(value, depth: int = 0):
    """A field of a code object as tagged JSON for the sandbox (tuple, bytes, frozenset and
    nested code objects are tagged); anything that is not plain data is refused."""
    if depth > 32:
        raise _NotData("nested too deep")
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (bytes, bytearray)):
        return {"b": base64.b64encode(bytes(value)).decode()}
    if isinstance(value, tuple):
        return {"t": [_code_json(v, depth + 1) for v in value]}
    if isinstance(value, frozenset):
        return {"fs": [_code_json(v, depth + 1) for v in value]}
    if _is_code(value):
        return {"code": [_code_json(v, depth + 1) for v in _code_fields(value.args)]}
    if _is_latin1_bytes(value):  # protocol 0-2 bytes: _codecs.encode(text, "latin1")
        return {"b": base64.b64encode(value.args[0].encode("latin-1")).decode()}
    raise _NotData(f"{_describe(value)} is not plain data")


def _is_dill(value, name: str) -> bool:
    return isinstance(value, Obj) and value.how == "reduce" and isinstance(value.func, Global) \
        and value.func.module in DILL_MODULES and value.func.name == name


def _is_latin1_bytes(value) -> bool:
    if not (isinstance(value, Obj) and value.how == "reduce" and isinstance(value.func, Global)
            and value.func.pair == ("_codecs", "encode") and isinstance(value.args, tuple)
            and len(value.args) == 2 and isinstance(value.args[0], str) and value.args[1] in ("latin1", "latin-1")):
        return False
    try:
        value.args[0].encode("latin-1")
    except UnicodeEncodeError:
        return False
    return True


def _is_cloudpickle(value, name: str) -> bool:
    return isinstance(value, Obj) and value.how == "reduce" and isinstance(value.func, Global) \
        and value.func.module in CLOUDPICKLE_MODULES and value.func.name == name


def _is_code_type(func) -> bool:
    """cloudpickle's ``_builtin_type("CodeType")``: the constructor of a code object."""
    return _is_cloudpickle(func, "_builtin_type") and func.args == ("CodeType",)


def _is_code(value) -> bool:
    """A code object as dill (``_create_code(...)``) or cloudpickle
    (``_builtin_type("CodeType")(...)``) writes it."""
    if not (isinstance(value, Obj) and value.how == "reduce" and isinstance(value.args, tuple)):
        return False
    return _is_dill(value, "_create_code") or _is_code_type(value.func)


def _code_fields(args: tuple) -> tuple:
    return args[1:] if args and not isinstance(args[0], int) else args


def _code_strings(fields: tuple) -> list[str]:
    """co_names and string constants (with those of nested code objects) on the 3.11+
    layout; every string in a tuple on any other layout."""
    out, todo = [], []
    if len(fields) == CODE_FIELDS_311:
        todo += [fields[7], fields[8]]
    else:
        todo += [f for f in fields if isinstance(f, tuple)]
    while todo:
        item = todo.pop()
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, (tuple, frozenset)):
            todo.extend(item)
        elif _is_code(item):
            nested = _code_fields(item.args)
            todo += [nested[7], nested[8]] if len(nested) == CODE_FIELDS_311 else \
                [f for f in nested if isinstance(f, tuple)]
    return out


def _code_maker(how: str, func, args) -> tuple[str, str] | None:
    """(library, helper) when this call builds a code object: dill's ``_create_code`` or
    cloudpickle's ``_builtin_type("CodeType")``."""
    if isinstance(func, Global) and func.module in DILL_MODULES and func.name == "_create_code":
        return func.module, "_create_code"
    if _is_code_type(func):
        return func.func.module, '_builtin_type("CodeType")'
    return None


def _dill_code(report: dict, calls: list[tuple]) -> None:
    """Functions dill or cloudpickle pickled with their bytecode (owner's decisions of
    2026-10-19 and 2026-10-23: treated like a Keras Lambda). Each code object is a RISKY
    reason ("file carries executable Python code"); sink names among its co_names or string
    constants are MALICIOUS. The fields go to the pipeline under ``dill_code``, which
    rebuilds the function inside the WASI sandbox and calls it on fakes, like a Lambda.
    The helpers both libraries rebuild a pickle with are checked here too: dill's
    ``_create_array`` and cloudpickle's ``_builtin_type`` and ``subimport`` by argument."""
    functions = {}
    helpers: dict[str, set] = {"dill": set(), "cloudpickle": set()}
    for how, func, args, pos in calls:
        if not isinstance(func, Global):
            continue
        library = "dill" if func.module in DILL_MODULES else \
            "cloudpickle" if func.module in CLOUDPICKLE_MODULES else None
        if library is None:
            continue
        helpers[library].add(func.name)
        reduce = how == "reduce" and isinstance(args, tuple)
        if func.name in ("_create_function", "_make_function") and reduce and args and _is_code(args[0]):
            functions.setdefault(id(args[0].args), (args, pos))
        elif library == "dill" and func.name == DILL_ARRAY:
            f = args[0] if reduce and args else None
            if not (isinstance(f, Global) and f.pair in ARRAY_RECONSTRUCTORS):
                report["reasons"].append(f"{func.module}.{DILL_ARRAY} at {pos} calls its first argument "
                                         f"({_describe(f) if reduce and args else how.upper()}), "
                                         f"not numpy's array reconstructor")
        elif library == "cloudpickle" and func.name == "_builtin_type":
            name = args[0] if reduce and len(args) == 1 else None
            if name not in CLOUDPICKLE_TYPES:
                report["reasons"].append(f"{func.module}._builtin_type at {pos} looks up "
                                         f"{_describe(name) if name is not None else 'an attribute'} "
                                         f"of the types module by name")
        elif library == "cloudpickle" and func.name == CLOUDPICKLE_IMPORT:
            name = args[0] if reduce and len(args) == 1 and isinstance(args[0], str) else None
            if name is None or not identifier_path(name):
                report["reasons"].append(f"{func.module}.{CLOUDPICKLE_IMPORT} at {pos} imports a module "
                                         f"whose name is not a constant")
            elif name.split(".")[0] in DANGEROUS_MODULES:
                report["reasons"].append(f"{func.module}.{CLOUDPICKLE_IMPORT} at {pos} imports {name}")
    for library, names in helpers.items():
        if names:
            report["reasons"].append(
                f"pickle written by {library}: {library}.load rebuilds it with {library}'s own helpers ("
                + ", ".join(sorted(names)) + ")")
    for how, func, args, pos in calls:
        maker = _code_maker(how, func, args)
        if maker is None:
            continue
        where = f"{maker[0]}.{maker[1]}"
        if how != "reduce" or not isinstance(args, tuple):
            report["reasons"].append(f"{where} at {pos} is used through {how.upper()}")
            continue
        fields = _code_fields(args)
        name = fields[11] if len(fields) == CODE_FIELDS_311 and isinstance(fields[11], str) else "?"
        library = "dill" if maker[0] in DILL_MODULES else "cloudpickle"
        report["reasons"].append(f"file carries executable Python code ({where} at {pos} "
                                 f"builds code object {name!r}; it runs when the function is called)")
        tokens = sorted({s for s in _code_strings(fields) if s in TF_DANGEROUS or s in DANGEROUS_SYMBOLS})
        if tokens:
            report["code_malicious"].append(f"{library} code object {name!r} at {pos} names the sink(s) "
                                            + ", ".join(tokens))
        if len(report["dill_code"]) >= MAX_DILL_CODE:
            report["reasons"].append(f"more than {MAX_DILL_CODE} pickled code objects; the rest is not emulated")
            continue
        entry = {"path": f"{library} code@{pos}", "name": name, "layout": len(fields), "sink_tokens": tokens,
                 "input_shape": [1, 8]}
        try:
            entry["code_fields"] = [_code_json(v) for v in fields]
        except _NotData as exc:
            entry["code_fields"] = None
            report["reasons"].append(f"{library} code object {name!r} at {pos} has a field that is not plain "
                                     f"data ({exc}); not emulated")
        made = functions.get(id(args))
        if made:
            fn_args = made[0]
            for key, index in (("defaults", 3), ("closure", 4)):
                value = fn_args[index] if len(fn_args) > index else None
                if key == "closure" and isinstance(value, tuple):
                    value = tuple(v.args[0] if (_is_dill(v, "_create_cell") or _is_cloudpickle(v, "_make_cell"))
                                  and v.args else v for v in value)
                try:
                    entry[key] = _code_json(value)
                except _NotData:
                    entry[key] = None
        report["dill_code"].append(entry)


# --- builtins.getattr: how pickle writes a bound method -----------------------------

def _imports_getattr(report: dict) -> bool:
    """Does the stream itself (not a parser-differential reading) import getattr?"""
    return any((imp["module"], imp["symbol"]) in GETATTR and imp["opcode"] in IMPORT_OPCODES
               for imp in report["imports"])


def _is_getattr_result(value) -> bool:
    return isinstance(value, Obj) and isinstance(value.func, Global) and value.func.pair in GETATTR


def _getattr_target_ok(target, allow: frozenset) -> bool:
    """An instance of an allowlisted class, or an allowlisted class itself."""
    if isinstance(target, Global):
        pair = target.pair
    elif isinstance(target, Obj) and not _is_getattr_result(target):
        pair = class_of(target)
    else:
        return False
    return pair is not None and pair in allow and pair not in GETATTR and not is_dangerous_import(*pair)


def _describe(value) -> str:
    if isinstance(value, Global):
        return f"{value.module}.{value.name}"
    if isinstance(value, Obj):
        pair = class_of(value)
        return f"an instance of {pair[0]}.{pair[1]}" if pair else f"a {value.how.upper()} result"
    return _short((value,))[1:-2] if not isinstance(value, str) else repr(value[:60])


def _getattr_results(value, walk: dict, match=None) -> list[Obj]:
    """getattr results (or Objs ``match`` accepts) inside ``value`` (tuples, lists, dicts,
    sets; other Objs are not entered: their own calls were checked when they were made)."""
    match = match or _is_getattr_result
    found, todo = [], [value]
    while todo:
        item = todo.pop()
        walk["steps"] += 1
        if walk["steps"] > MAX_VALUE_WALK:
            break
        if match(item):
            found.append(item)
            continue
        if not isinstance(item, (tuple, list, set, frozenset, dict)) or id(item) in walk["seen"]:
            continue
        walk["seen"].add(id(item))
        todo.extend(v for kv in item.items() for v in kv) if isinstance(item, dict) else todo.extend(item)
    return found


def _check_getattr(calls: list[tuple], allow: frozenset, imported: bool,
                   handled: frozenset = frozenset()) -> tuple[list[str], list[str]]:
    """(MALICIOUS reasons, RISKY reasons) for every use of builtins.getattr.

    ``getattr(obj, "name")`` is how pickle writes a bound method. It is accepted only
    for an object or class from the allowlist and a constant name without a leading
    underscore, when nothing uses the result while loading. Using the result is calling
    it or passing it, at any depth, as an argument of any call (a defaultdict factory,
    a numpy ctor helper, another getattr, ...); only storing it in a BUILD state is not a
    use. A used result, a dunder name or a sink name is evidence (MALICIOUS); every other
    use is RISKY. Calls in ``handled`` (ids of their argument tuples) belong to a Keras
    embedded-model pattern and are judged by _embedded_keras instead.
    """
    malicious, risky = [], []
    used = False
    walk = {"seen": set(), "steps": 0}
    for how, func, args, pos in calls:
        if id(args) in handled:
            used = used or (isinstance(func, Global) and func.pair in GETATTR)
            continue
        if _is_getattr_result(func):
            malicious.append(f"the result of builtins.getattr({_short(func.args)[1:-1]}) is called "
                             f"({how.upper()} at {pos})")
            continue
        if how != "build":
            for result in _getattr_results(args, walk):
                target = (f"{func.module}.{func.name}" if isinstance(func, Global) else _describe(func))
                malicious.append(f"the result of builtins.getattr({_short(result.args)[1:-1]}) is passed as an "
                                 f"argument to {target} ({how.upper()} at {pos})")
        if not (isinstance(func, Global) and func.pair in GETATTR):
            continue
        used = True
        where = f"{func.module}.{func.name} at {pos}"
        if how not in ("reduce", "obj", "inst"):
            risky.append(f"{where} is used through {how.upper()}, not called the way pickle writes a method")
            continue
        if not isinstance(args, tuple) or len(args) != 2:
            risky.append(f"{where} is called with {_short(args)}; pickle writes a method as getattr(obj, name)")
            continue
        target, name = args
        if not isinstance(name, str):
            risky.append(f"{where} is given an attribute name that is not a constant string ({_describe(name)})")
            continue
        if name.startswith("__") and name.endswith("__"):
            malicious.append(f"{where} reads the dunder attribute {name!r} of {_describe(target)}")
            continue
        if name in DANGEROUS_SYMBOLS:
            malicious.append(f"{where} reads the sink attribute {name!r} of {_describe(target)}")
            continue
        if isinstance(target, Global) and is_dangerous_import(*target.pair):
            malicious.append(f"{where} reads {name!r} of the sink {_describe(target)}")
            continue
        if name.startswith("_"):
            risky.append(f"{where} reads the private attribute {name!r} of {_describe(target)}")
            continue
        if not _getattr_target_ok(target, allow):
            risky.append(f"{where} reads {name!r} of {_describe(target)}, which is not built from "
                         "allowlisted classes")
    if imported and not used:
        risky.append("builtins.getattr is imported but never called the way pickle writes a method")
    return malicious, risky


class _ListingFull(Exception):
    pass


class _CappedListing(io.StringIO):
    """A StringIO that stops the listing at MAX_DISASM_CHARS: pickletools.dis writes one
    pickle in full, and a large pickle would otherwise be rendered entirely in memory."""

    def write(self, text: str) -> int:
        room = MAX_DISASM_CHARS - self.tell()
        if len(text) > room:
            super().write(text[:max(room, 0)])
            raise _ListingFull
        return super().write(text)


def _disasm(data: bytes) -> str:
    """Human-readable listing for the dashboard (pickletools.dis does not execute)."""
    out = _CappedListing()
    try:
        stream = io.BytesIO(data)
        for _ in range(MAX_PICKLES):
            if stream.tell() >= len(data):
                break
            pickletools.dis(stream, out=out, annotate=1)
    except _ListingFull:
        pass
    except Exception as exc:  # noqa: BLE001
        out = io.StringIO(out.getvalue())
        out.seek(0, io.SEEK_END)
        out.write(f"\n[disassembly stopped: {exc}]\n")
    return out.getvalue()[:MAX_DISASM_CHARS]


def _cleared_import(imp: dict, clearance, globals_at: dict | None, used: set[int] | None, error=None,
                    extra: dict | None = None):
    """(mechanism, detail) when an import outside the allowlist is accepted (clearance.py)."""
    pair = (imp["module"], imp["symbol"])
    if extra and pair in extra:
        return extra[pair]
    found = clearance.state_only(pair)
    if found:
        return found  # its uses are checked by _check_guarded_calls like STATE_ONLY_CLASSES
    value = (globals_at or {}).get(imp["pos"])
    if used is None or value is None or id(value) in used or error:
        return None
    if clearance_mod.referenced_ok(*pair):
        return ("referenced", "only referenced (stored, never called) global of an inert library module")
    return None


def _score(report: dict, allow: frozenset, torch: bool,
           clearance: clearance_mod.Clearance | None = None, globals_at: dict | None = None,
           used: set[int] | None = None, extra: dict | None = None) -> None:
    reasons: list[str] = report["reasons"]
    clearance = clearance or clearance_mod.DEFAULT
    cleared: list[dict] = report.setdefault("cleared", [])
    names = {o["name"] for o in report["flagged_opcodes"]}
    has_call = bool(names & CALL_OPCODES)

    for imp in report["imports"]:
        module, qualname = imp["module"], imp["symbol"]
        if not imp["resolved"] or module is None or qualname is None:
            reasons.append(f"{imp['opcode']} at {imp['pos']}: import name could not be resolved")
            report["unknown_imports"].append(imp)
            continue
        if (module, qualname) in allow:
            continue
        if (module, qualname) in GETATTR and imp["opcode"] in IMPORT_OPCODES:
            continue  # judged use by use in _check_getattr
        if (module, qualname) in report.get("_consumed_imports", ()) and imp["opcode"] in IMPORT_OPCODES:
            continue  # only used to load an embedded Keras model (_embedded_keras)
        if is_dangerous_import(module, qualname):
            report["suspicious_imports"].append({"module": module, "symbol": qualname, "pos": imp["pos"]})
            continue
        if imp["opcode"] in IMPORT_OPCODES:
            how = _cleared_import(imp, clearance, globals_at, used, report["error"], extra)
            if how:
                cleared.append({"item": f"{module}.{qualname}", "pair": [module, qualname], "pos": imp["pos"],
                                "mechanism": how[0], "detail": how[1]})
                continue
        report["unknown_imports"].append(imp)

    if names & EXT_OPCODES:
        reasons.append("copyreg extension opcode (EXT1/2/4) imports through a global registry")
    if names & PERSID_OPCODES and not torch:
        reasons.append("persistent id outside a PyTorch checkpoint")
    if report["error"]:
        reasons.append(report["error"])
    if report["pickle_count"] == 0 and not report["error"]:
        reasons.append("no pickle found")

    for imp in report["suspicious_imports"]:
        reasons.append(f"import of a known sink: {imp['module']}.{imp['symbol']}")
    unverifiable = report.setdefault("unverifiable", {})
    for imp in report["unknown_imports"]:
        if imp["module"] is not None:
            reason = f"import outside the allowlist: {imp['module']}.{imp['symbol']}"
            reasons.append(reason)
            if (imp["module"], imp["symbol"]) in KNOWN_GADGETS:
                continue
            ref = imitates(imp["module"])
            if ref:
                reasons.append(lookalike_reason(imp["module"], ref))
                continue
            unverifiable[reason] = {"item": f"{imp['module']}.{imp['symbol']}",
                                    "pair": [imp["module"], imp["symbol"]],
                                    "explanation": override.pickle_global(imp["module"], imp["symbol"])}

    getattr_malicious = (report.get("getattr_malicious") or []) + (report.get("code_malicious") or [])
    reasons.extend(getattr_malicious)
    # The reasons that are evidence of a sink: only these are MALICIOUS findings. Everything
    # else next to them (trailing data, a second reading, an unknown import) stays RISKY.
    evidence = report.setdefault("evidence", [])
    if report["suspicious_imports"] and has_call:
        evidence.extend(f"import of a known sink: {imp['module']}.{imp['symbol']}"
                        for imp in report["suspicious_imports"])
    evidence.extend(getattr_malicious)
    if (report["suspicious_imports"] and has_call) or getattr_malicious or report.get("trailing_malicious"):
        report["static_risk"] = "malicious"
    elif reasons:
        report["static_risk"] = "suspicious"
    else:
        report["static_risk"] = "clean"


def parse_file(path: str) -> dict:
    import os

    with open(path, "rb") as fh:
        data = fh.read()
    return parse_pickle(data, file_name=os.path.basename(path))
