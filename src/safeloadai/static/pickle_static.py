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
are analysed. The output follows ``schemas/parser.schema.json``.
"""
from __future__ import annotations

import io
import pickletools
import re
from typing import Any

from .allowlists import DANGEROUS_MODULES, DANGEROUS_SYMBOLS, PICKLE_GLOBALS, TORCH_GLOBALS

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
_PUT_OPCODES = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})
_GET_OPCODES = frozenset({"GET", "BINGET", "LONG_BINGET"})
_MARK = object()

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


def _apply_stack_effect(opcode, stack: list) -> None:
    """Pop and push per the opcode's documented stack effect; values are unknown."""
    before = opcode.stack_before
    if pickletools.markobject in before:
        while stack:
            if stack.pop() is _MARK:
                break
        for _ in range(before.index(pickletools.markobject)):
            if stack:
                stack.pop()
    else:
        for _ in before:
            if stack:
                stack.pop()
    for item in opcode.stack_after:
        stack.append(_MARK if item is pickletools.markobject else None)


def _walk_one(stream: io.BytesIO, report: dict, index: int) -> tuple[bool, Any]:
    """Walk one pickle up to its STOP. Returns (reached_stop, first_int_value)."""
    stack: list = []
    memo: dict = {}
    first_int = None
    reached_stop = False
    for opcode, arg, pos in pickletools.genops(stream):
        name = opcode.name
        if len(report["opcodes"]) >= MAX_OPCODES:
            raise ValueError(f"more than {MAX_OPCODES} opcodes")
        arg_str = _format_arg(arg)
        entry = {"name": name, "arg": arg_str, "pos": pos, "pickle": index}
        report["opcodes"].append(entry)
        if name in FLAGGED_OPCODES:
            report["flagged_opcodes"].append(dict(entry, reason=FLAGGED_OPCODES[name]))
        if first_int is None and name in ("LONG1", "LONG4", "LONG", "INT", "BININT", "BININT1",
                                          "BININT2"):
            first_int = arg
        if name in STRING_PUSH_OPCODES and isinstance(arg, str) and _SUSPICIOUS_STRING.search(arg):
            report["suspicious_strings"].append({"value": arg[:200], "pos": pos})

        module = qualname = None
        resolved = True
        if name in STRING_PUSH_OPCODES:
            stack.append(arg if isinstance(arg, str) else None)
        elif name == "MEMOIZE":
            memo[len(memo)] = stack[-1] if stack else None
        elif name in _PUT_OPCODES:
            memo[arg] = stack[-1] if stack else None
        elif name in _GET_OPCODES:
            stack.append(memo.get(arg))
        elif name == "STACK_GLOBAL":
            qualname = stack.pop() if stack else None
            module = stack.pop() if stack else None
            stack.append(None)
            if not (isinstance(module, str) and isinstance(qualname, str)):
                resolved = False
                module = qualname = None
        else:
            if name in ("GLOBAL", "INST") and arg_str:
                parts = arg_str.replace("\n", " ").split()
                if len(parts) == 2:
                    module, qualname = parts
                else:
                    resolved = False
            _apply_stack_effect(opcode, stack)

        if name in IMPORT_OPCODES:
            report["imports"].append(
                {"module": module, "symbol": qualname, "pos": pos, "opcode": name, "resolved": resolved}
            )
        if name == "STOP":
            reached_stop = True
    return reached_stop, first_int


def parse_pickle(data: bytes, file_name: str = "<memory>", *, torch: bool = False,
                 file_format: str = "pickle", extra_allowed: frozenset = frozenset()) -> dict:
    """Analyse pickle bytes and return the parser contract (dict).

    ``torch=True`` widens the allowlist with the globals a PyTorch checkpoint
    needs and accepts persistent ids (torch stores tensor data out of band).
    """
    report = _empty_report(file_name, file_format)
    base = PICKLE_GLOBALS | frozenset(extra_allowed)
    allow = base | TORCH_GLOBALS if torch else base
    stream = io.BytesIO(data)
    try:
        index = 0
        legacy_torch = False
        while stream.tell() < len(data):
            if index >= MAX_PICKLES:
                raise ValueError(f"more than {MAX_PICKLES} pickles in one file")
            start = stream.tell()
            _, first_int = _walk_one(stream, report, index)
            if index == 0 and first_int == TORCH_LEGACY_MAGIC:
                legacy_torch = True
                torch = True
                allow = base | TORCH_GLOBALS
                report["notes"].append("legacy PyTorch serialization (magic number found)")
            index += 1
            if legacy_torch and index == TORCH_LEGACY_PICKLES:
                report["notes"].append(
                    f"{len(data) - stream.tell()} bytes of raw tensor storage after the "
                    "legacy torch pickles (not analysed, never unpickled)"
                )
                break
            if stream.tell() == start:
                break
        report["pickle_count"] = index
    except Exception as exc:  # noqa: BLE001 - any parse failure must surface
        report["error"] = f"opcode walk failed: {type(exc).__name__}: {exc}"

    report["raw_disasm"] = _disasm(data)
    _score(report, allow, torch)
    return report


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
    for imp in report["unknown_imports"]:
        if imp["module"] is not None:
            reasons.append(f"import outside the allowlist: {imp['module']}.{imp['symbol']}")

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
