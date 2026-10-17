"""Static analysis of ``.keras`` archives. Keras is never imported here.

The archive is opened with :class:`~safeloadai.parsing.zipsafe.SafeZip`;
``config.json`` and ``metadata.json`` are read, ``model.weights.h5`` never is.
The config is walked iteratively (no recursion, bounded depth) and every
serialized object, i.e. every dict with a ``class_name``, is checked against exact
allowlists:

* ``(module, class_name)``: module in ``KERAS_MODULES`` and class in
  ``KERAS_CLASSES``. No prefix matching: ``tf_evil_pkg`` or ``kerasx`` are unknown.
* ``registered_name``: absent, equal to the class name, or a Keras container.
  ``package>Name`` means a custom object the loader would have to supply.
* functions (``class_name == "function"``): exact ``(module, name)`` pair.
* code-carrying layers (``Lambda``, ``TFOpLambda``, ``SlicingOpLambda``).

Lambda bytecode is never unmarshalled on the host. The base64 payload is decoded
to bytes and scanned for marshal string tokens naming known sinks; that is a
byte search, not deserialization. Behaviour of the code is the sandbox's job.

Scoring: a sink token in Lambda bytecode or a dangerous function / TF op ->
MALICIOUS. Any other finding (Lambda present, unknown object, custom object,
archive problem, parse error, depth limit) -> SUSPICIOUS. Otherwise CLEAN.
"""
from __future__ import annotations

import base64
import binascii
import json
import os

from ..parsing.zipsafe import SafeZip, ZipRefused
from .allowlists import (
    KERAS_CLASSES,
    KERAS_CODE_LAYERS,
    KERAS_FUNCTIONS,
    KERAS_MODULES,
    TF_DANGEROUS,
    TF_OP_ALLOWED,
)

SCHEMA_VERSION = "1.1"
CONFIG_CANDIDATES = ("config.json", "model.json")
METADATA_NAME = "metadata.json"
EXPECTED_MEMBERS = frozenset({"config.json", "metadata.json", "model.weights.h5"})
MAX_DEPTH = 200
MAX_NODES = 1_000_000
MAX_CONFIG_BYTES = 16 * 1024 * 1024
KERAS_CONTAINERS = frozenset({"Functional", "Sequential", "Model"})


def _empty_report(file_name: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "file_name": file_name,
        "file_format": "keras",
        "opcodes": [],
        "flagged_opcodes": [],
        "suspicious_imports": [],
        "unknown_imports": [],
        "lambdas": [],
        "metadata": None,
        "raw_disasm": "",
        "static_risk": "clean",
        "reasons": [],
        "notes": [],
        "error": None,
    }


def marshal_sink_tokens(code: bytes) -> list[str]:
    """Sink names stored as marshal string objects inside ``code``.

    marshal writes short ASCII strings as one type byte (``z``/``Z``, or ``a``/``A``
    for longer ones, optionally with the 0x80 ref flag), a length, then the bytes.
    Matching that exact framing finds names in ``co_names``/``co_consts`` without
    unmarshalling anything.
    """
    found = []
    for token in sorted(TF_DANGEROUS):
        raw = token.encode()
        if len(raw) > 255:
            continue
        short = [bytes([t, len(raw)]) + raw for t in (0x7A, 0x5A, 0xFA, 0xDA)]
        long_ = [bytes([t]) + len(raw).to_bytes(4, "little") + raw for t in (0x61, 0x41, 0xE1, 0xC1)]
        if any(p in code for p in short + long_):
            found.append(token)
    return found


def _lambda_code(config: dict) -> bytes | None:
    """Raw bytes of the marshalled function in a Lambda config, if any."""
    function = config.get("function")
    candidate = None
    if isinstance(function, dict):
        inner = function.get("config")
        if isinstance(inner, dict):
            candidate = inner.get("code")
    elif isinstance(function, list) and function:
        candidate = function[0]  # legacy [code, defaults, closure]
    elif isinstance(function, str) and len(function) > 16:
        candidate = function
    if not isinstance(candidate, str):
        return None
    try:
        return base64.b64decode(candidate.encode(), validate=False)
    except (binascii.Error, ValueError):
        return None


def _lambda_context(node: dict, config: dict) -> dict:
    """What the emulator needs to call a Lambda: arguments, defaults, closure, input shape."""
    function = config.get("function")
    inner = function.get("config") if isinstance(function, dict) else None
    inner = inner if isinstance(inner, dict) else {}
    if isinstance(function, list) and len(function) == 3:
        inner = {"defaults": function[1], "closure": function[2]}
    build = node.get("build_config") if isinstance(node.get("build_config"), dict) else {}
    arguments = config.get("arguments")
    return {
        "arguments": arguments if isinstance(arguments, dict) else {},
        "defaults": inner.get("defaults"),
        "closure": inner.get("closure"),
        "input_shape": build.get("input_shape"),
    }


def _check_object(node: dict, path: str, report: dict) -> None:
    class_name = node.get("class_name")
    module = node.get("module")
    registered = node.get("registered_name")
    report["opcodes"].append({"name": class_name, "arg": path, "pos": 0})

    if class_name == "__lambda__":
        # The marshalled function inside a Lambda layer's config, already captured
        # with its layer. Anywhere else it is code in an unexpected place.
        if any(path == lam["path"] + ".config.function" for lam in report["lambdas"]):
            return
        report["unknown_imports"].append({"module": str(module), "symbol": "__lambda__", "pos": None,
                                          "path": path})
        return

    if class_name == "function":
        name = node.get("config")
        pair = (module, name)
        if pair in KERAS_FUNCTIONS:
            return
        entry = {"module": str(module), "symbol": str(name), "pos": None, "path": path}
        if isinstance(name, str) and (name in TF_DANGEROUS or str(module).split(".")[0] in
                                      ("os", "posix", "subprocess", "builtins", "socket")):
            report["suspicious_imports"].append(entry)
        else:
            report["unknown_imports"].append(entry)
        return

    if class_name in KERAS_CODE_LAYERS:
        reason = f"{path}: {class_name} layer carries executable Python"
        report["flagged_opcodes"].append({"name": class_name, "arg": path, "pos": 0, "reason": reason})
        config = node.get("config") if isinstance(node.get("config"), dict) else {}
        if class_name == "Lambda":
            code = _lambda_code(config)
            tokens = marshal_sink_tokens(code) if code else []
            report["lambdas"].append({
                "path": path,
                "has_code": code is not None,
                "code_b64": base64.b64encode(code).decode() if code else None,
                "sink_tokens": tokens,
                **_lambda_context(node, config),
            })
            for token in tokens:
                report["suspicious_imports"].append(
                    {"module": "keras.layers.Lambda", "symbol": token, "pos": None, "path": path}
                )
        else:
            op = config.get("function")
            if isinstance(op, str) and op not in TF_OP_ALLOWED:
                entry = {"module": "tf", "symbol": op, "pos": None, "path": path}
                parts = set(op.replace("__", ".").split("."))
                if parts & TF_DANGEROUS:
                    report["suspicious_imports"].append(entry)
                else:
                    report["unknown_imports"].append(entry)
        if module is not None and module not in KERAS_MODULES:
            report["unknown_imports"].append({"module": str(module), "symbol": class_name, "pos": None,
                                              "path": path})
        return

    known_class = class_name in KERAS_CLASSES
    known_module = module is None or module in KERAS_MODULES
    if not (known_class and known_module):
        report["unknown_imports"].append(
            {"module": str(module), "symbol": str(class_name), "pos": None, "path": path}
        )
    if registered is not None and registered != class_name and registered not in KERAS_CONTAINERS:
        report["unknown_imports"].append(
            {"module": str(registered), "symbol": "registered_name", "pos": None, "path": path}
        )


def _walk(config, report: dict) -> None:
    stack = [(config, "", 0)]
    nodes = 0
    while stack:
        node, path, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise ValueError(f"config has more than {MAX_NODES} nodes")
        if depth > MAX_DEPTH:
            raise ValueError(f"config nesting deeper than {MAX_DEPTH} levels")
        if isinstance(node, list):
            for i, item in enumerate(node):
                stack.append((item, f"{path}[{i}]", depth + 1))
        elif isinstance(node, dict):
            if isinstance(node.get("class_name"), str):
                _check_object(node, path, report)
            for key, value in node.items():
                stack.append((value, f"{path}.{key}" if path else str(key), depth + 1))


def _read_json(zf: SafeZip, name: str):
    raw = zf.read(name)
    try:
        return json.loads(raw.decode("utf-8"))
    except RecursionError as exc:
        raise ValueError(f"{name}: nesting too deep for the JSON parser") from exc


def parse_keras(data: bytes, file_name: str = "<memory>") -> dict:
    report = _empty_report(file_name)
    reasons: list[str] = report["reasons"]
    try:
        with SafeZip(data, max_member_bytes=MAX_CONFIG_BYTES) as zf:
            reasons.extend(f"archive: {p}" for p in zf.inventory.problems)
            unexpected = [n for n in zf.names if n not in EXPECTED_MEMBERS and not n.startswith("assets/")]
            if unexpected:
                report["notes"].append(f"unexpected archive members: {', '.join(unexpected[:20])}")
            config_name = next((n for n in CONFIG_CANDIDATES if n in zf.names), None)
            if config_name is None:
                raise ValueError("archive has no config.json")
            if METADATA_NAME in zf.names:
                meta = _read_json(zf, METADATA_NAME)
                report["metadata"] = meta if isinstance(meta, dict) else None
            config = _read_json(zf, config_name)
    except (ZipRefused, ValueError, UnicodeDecodeError) as exc:
        report["error"] = str(exc)
        reasons.append(str(exc))
        report["static_risk"] = "suspicious"
        return report

    report["raw_disasm"] = json.dumps(config, indent=1)[:200_000]
    try:
        _walk(config, report)
    except ValueError as exc:
        report["error"] = str(exc)
        reasons.append(str(exc))

    for lam in report["lambdas"]:
        reasons.append(
            f"{lam['path']}: Lambda layer"
            + (" with marshalled bytecode" if lam["has_code"] else "")
            + (f"; sink names in bytecode: {', '.join(lam['sink_tokens'])}" if lam["sink_tokens"] else "")
        )
    for imp in report["suspicious_imports"]:
        reasons.append(f"{imp.get('path')}: known sink {imp['module']}.{imp['symbol']}")
    for imp in report["unknown_imports"]:
        reasons.append(f"{imp.get('path')}: object outside the allowlist {imp['module']}.{imp['symbol']}")
    for flag in report["flagged_opcodes"]:
        if flag["name"] != "Lambda":
            reasons.append(flag["reason"])

    if report["suspicious_imports"]:
        report["static_risk"] = "malicious"
    elif reasons:
        report["static_risk"] = "suspicious"
    else:
        report["static_risk"] = "clean"
    return report


def parse_file(path: str) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()
    return parse_keras(data, file_name=os.path.basename(path))
