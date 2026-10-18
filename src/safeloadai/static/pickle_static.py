"""Static analysis of pickle streams. Nothing is ever unpickled here.

Opcodes are read with ``pickletools.genops``, which only decodes the byte stream.
A small stack/memo simulation recovers the module and name behind
``STACK_GLOBAL`` (which takes them from the stack, possibly through the memo).

Scoring, strictest first:

* MALICIOUS: an import of a known code-execution / process / file / network sink
  together with any opcode that calls or constructs an object.
* SUSPICIOUS: any import outside the exact allowlist (called or not: ``find_class``
  imports the module, and import-time side effects are code execution), an import
  that cannot be resolved, a copyreg extension code, a persistent id outside a
  torch checkpoint, trailing bytes after the last pickle, or any parse error.
* CLEAN: everything else.

A file may hold several pickles back to back (legacy PyTorch, joblib); all of them
are analysed.
"""
from __future__ import annotations

import io
import pickletools
import re
from typing import Any

from .. import override
from .allowlists import (
    DANGEROUS_MODULES,
    DANGEROUS_SYMBOLS,
    GUARDED_CALLS,
    KNOWN_GADGETS,
    NUMPY_BIT_GENERATOR_CLASSES,
    NUMPY_BIT_GENERATOR_CTOR,
    NUMPY_BIT_GENERATOR_NAMES,
    PICKLE_GLOBALS,
    TORCH_GLOBALS,
)
from .pickle_vm import Global, Machine, Obj, plain_reading_imports

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
    return str(arg)


def _empty_report(file_name: str, file_format: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "file_name": file_name,
        "file_format": file_format,
        "opcodes": [],
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
        "pickle_count": 0,
        # reason text -> {"item", "pair", "explanation"} for the reasons that are UNVERIFIABLE
        "unverifiable": {},
    }


def is_dangerous_import(module: str, name: str) -> bool:
    """Known sink: module (or its root) or the name (or its last part) is listed."""
    root = module.split(".", 1)[0]
    leaf = name.rsplit(".", 1)[-1]
    head = name.split(".", 1)[0]
    return (
        module in DANGEROUS_MODULES
        or root in DANGEROUS_MODULES
        or name in DANGEROUS_SYMBOLS
        or leaf in DANGEROUS_SYMBOLS
        or head in DANGEROUS_SYMBOLS
    )


def _recorders(report: dict, index_ref: list):
    def on_opcode(opcode, arg, pos):
        name = opcode.name
        arg_str = _format_arg(arg)
        entry = {"name": name, "arg": arg_str, "pos": pos, "pickle": index_ref[0]}
        report["opcodes"].append(entry)
        if name in FLAGGED_OPCODES:
            report["flagged_opcodes"].append(dict(entry, reason=FLAGGED_OPCODES[name]))
        if name in STRING_PUSH_OPCODES and isinstance(arg, str) and _SUSPICIOUS_STRING.search(arg):
            report["suspicious_strings"].append({"value": arg[:200], "pos": pos})

    def on_import(module, qualname, pos, opcode, resolved):
        report["imports"].append(
            {"module": module, "symbol": qualname, "pos": pos, "opcode": opcode, "resolved": resolved}
        )

    return on_opcode, on_import


def parse_pickle(data: bytes, file_name: str = "<memory>", *, torch: bool = False,
                 file_format: str = "pickle", extra_allowed: frozenset = frozenset(),
                 joblib: bool = True) -> dict:
    """Analyse pickle bytes and return the parser contract (dict).

    ``torch=True`` widens the allowlist with the globals a PyTorch checkpoint
    needs and accepts persistent ids (torch stores tensor data out of band).
    ``joblib=True`` (the default) reads joblib's NumpyArrayWrapper layout: the raw
    array bytes after each wrapper are skipped, object arrays are walked as nested
    pickles, and the bytes joblib reads as array data are checked for what a plain
    ``pickle.load`` would import from them (parser differential).
    """
    report = _empty_report(file_name, file_format)
    base = PICKLE_GLOBALS | frozenset(extra_allowed)
    allow = base | TORCH_GLOBALS if torch else base
    index_ref = [0]
    on_opcode, on_import = _recorders(report, index_ref)
    calls: list[tuple] = []
    machine = Machine(data, joblib=joblib, on_import=on_import, on_opcode=on_opcode,
                      on_call=lambda *call: calls.append(call), max_opcodes=MAX_OPCODES)
    try:
        legacy_torch = False
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
            if machine.stream.tell() == start:
                break
    except Exception as exc:  # noqa: BLE001 - any parse failure must surface
        report["error"] = f"opcode walk failed: {type(exc).__name__}: {exc}"
    report["pickle_count"] = index_ref[0]
    _joblib_findings(report, machine, data, allow)
    report["reasons"].extend(_check_guarded_calls(calls))

    report["raw_disasm"] = _disasm(data)
    _score(report, allow, torch)
    return report


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

MAX_VALUE_WALK = 100_000


def _guarded(value) -> bool:
    return isinstance(value, Global) and value.pair in GUARDED_CALLS


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


def _guarded_values(value, skip_top: int | None = None) -> list[Global]:
    """Guarded globals reachable inside ``value`` (tuples, lists, dicts, sets).
    ``skip_top`` exempts one top-level tuple position (the permitted ctor argument).
    An Obj is not entered: its callable, arguments and state were checked at its own call."""
    found, seen, todo, steps = [], set(), [(value, 0)], 0
    while todo:
        item, depth = todo.pop()
        steps += 1
        if steps > MAX_VALUE_WALK:
            found.append(Global("<undecided>", "<walk limit>"))
            break
        if _guarded(item):
            found.append(item)
            continue
        if id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, tuple) and depth == 0 and skip_top is not None:
            todo.extend((v, depth + 1) for i, v in enumerate(item) if i != skip_top)
        elif isinstance(item, (tuple, list, set, frozenset)):
            todo.extend((v, depth + 1) for v in item)
        elif isinstance(item, dict):
            todo.extend((v, depth + 1) for kv in item.items() for v in kv)
    return found


def _check_guarded_calls(calls: list[tuple]) -> list[str]:
    """Reasons for every call that uses numpy's ctor helpers other than the way numpy does.

    Values are checked after the walk, so a list or dict filled in after it was passed
    to a call is seen with its final contents.
    """
    reasons = []
    for how, func, args, pos in calls:
        exempt = None
        if _guarded(func):
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
        for value in _guarded_values(args, skip_top=exempt):
            reasons.append(f"{value.module}.{value.name} is passed as a value at {pos} "
                           f"({how.upper()}); it may only be called directly")
    return reasons


def _disasm(data: bytes) -> str:
    """Human-readable listing for the dashboard (pickletools.dis does not execute)."""
    out = io.StringIO()
    try:
        stream = io.BytesIO(data)
        for _ in range(MAX_PICKLES):
            if stream.tell() >= len(data) or out.tell() > MAX_DISASM_CHARS:
                break
            pickletools.dis(stream, out=out, annotate=1)
    except Exception as exc:  # noqa: BLE001
        out.write(f"\n[disassembly stopped: {exc}]\n")
    return out.getvalue()[:MAX_DISASM_CHARS]


def _score(report: dict, allow: frozenset, torch: bool) -> None:
    reasons: list[str] = report["reasons"]
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
        if is_dangerous_import(module, qualname):
            report["suspicious_imports"].append({"module": module, "symbol": qualname, "pos": imp["pos"]})
        else:
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
            unverifiable[reason] = {"item": f"{imp['module']}.{imp['symbol']}",
                                    "pair": [imp["module"], imp["symbol"]],
                                    "explanation": override.pickle_global(imp["module"], imp["symbol"])}

    if report["suspicious_imports"] and has_call:
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
