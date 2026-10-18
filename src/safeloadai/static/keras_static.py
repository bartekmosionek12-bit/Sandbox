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

Legacy HDF5 files (``keras2=True``, see ``h5_static``) use tf.keras 2.x
serialization: objects carry no ``module``, so their ``class_name`` must be in the
explicit ``KERAS2_CLASSES`` set; Lambda layers may also name a function to look up
in a module's globals (``function_type == "function"``) or carry marshalled code
in ``output_shape``; activation strings must name a built-in activation.

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
    DANGEROUS_MODULES,
    DANGEROUS_SYMBOLS,
    KERAS2_CLASSES,
    KERAS_ACTIVATION_NAMES,
    KERAS_CLASSES,
    KERAS_CODE_LAYERS,
    KERAS_FUNCTIONS,
    KERAS_METRIC_NAMES,
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
        "input_shape": build.get("input_shape") or _inbound_shape(node),
    }


def _inbound_shape(node: dict):
    """Input shape from a Keras 3 functional node (``__keras_tensor__`` argument), used
    when there is no build_config (legacy HDF5 written by Keras 3)."""
    nodes = node.get("inbound_nodes")
    if not (isinstance(nodes, list) and nodes and isinstance(nodes[0], dict)):
        return None
    args = nodes[0].get("args")
    first = args[0] if isinstance(args, list) and args else None
    if isinstance(first, dict) and first.get("class_name") == "__keras_tensor__":
        config = first.get("config")
        return config.get("shape") if isinstance(config, dict) else None
    return None


def _entry(module, symbol, path: str) -> dict:
    return {"module": str(module), "symbol": str(symbol), "pos": None, "path": path}


def _is_dangerous(module, name) -> bool:
    top = str(module).split(".")[0]
    return top in DANGEROUS_MODULES or str(name) in TF_DANGEROUS or str(name) in DANGEROUS_SYMBOLS


def _keras2_lambda(config: dict, path: str, report: dict) -> None:
    """tf.keras 2.x Lambda fields that resolve code outside the marshalled bytecode."""
    module = config.get("module")
    function = config.get("function")
    if config.get("function_type") == "function":
        # Keras 2 looks the name up in the globals of sys.modules[module] and calls it.
        target = report["suspicious_imports"] if _is_dangerous(module, function) else report["unknown_imports"]
        target.append(_entry(module, function, path + ".config.function"))
    elif module not in (None, "__main__"):
        # The Lambda's globals are that module's namespace.
        target = report["suspicious_imports"] if _is_dangerous(module, "") else report["unknown_imports"]
        target.append(_entry(module, "<Lambda globals>", path + ".config.module"))
    shape_type = config.get("output_shape_type")
    if shape_type == "lambda":
        shape = config.get("output_shape")
        code = _lambda_code({"function": shape}) if isinstance(shape, (list, str)) else None
        tokens = marshal_sink_tokens(code) if code else []
        for token in tokens:
            report["suspicious_imports"].append(_entry("keras.layers.Lambda.output_shape", token, path))
        report["unknown_imports"].append(_entry("keras.layers.Lambda", "output_shape code", path))
    elif shape_type == "function":
        shape_module = config.get("output_shape_module")
        shape = config.get("output_shape")
        target = report["suspicious_imports"] if _is_dangerous(shape_module, shape) else report["unknown_imports"]
        target.append(_entry(shape_module, shape, path + ".config.output_shape"))


def _check_activations(node: dict, path: str, report: dict) -> None:
    config = node.get("config")
    if not isinstance(config, dict):
        return
    for key in ("activation", "recurrent_activation"):
        value = config.get(key)
        if isinstance(value, str) and value not in KERAS_ACTIVATION_NAMES:
            report["unknown_imports"].append(_entry("activation", value, f"{path}.config.{key}"))


def _check_object(node: dict, path: str, report: dict, keras2: bool = False) -> None:
    class_name = node.get("class_name")
    module = node.get("module")
    registered = node.get("registered_name")
    report["opcodes"].append({"name": class_name, "arg": path, "pos": 0})
    if keras2:
        _check_activations(node, path, report)

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
        what = ("calls a TensorFlow function by name" if class_name == "TFOpLambda"
                else "carries executable Python")
        reason = f"{path}: {class_name} layer {what}"
        report["flagged_opcodes"].append({"name": class_name, "arg": path, "pos": 0, "reason": reason})
        config = node.get("config") if isinstance(node.get("config"), dict) else {}
        if class_name == "Lambda" and keras2:
            _keras2_lambda(config, path, report)
        if class_name == "Lambda" and not (keras2 and config.get("function_type") == "function"):
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

    if keras2 and "module" not in node:
        known_class, known_module = class_name in KERAS2_CLASSES, True
    else:
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


def _walk(config, report: dict, keras2: bool = False, prefix: str = "") -> None:
    stack = [(config, prefix, 0)]
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
                _check_object(node, path, report, keras2)
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

    try:
        report["raw_disasm"] = json.dumps(config, indent=1)[:200_000]
    except RecursionError:
        report["raw_disasm"] = "<config nested too deeply to render>"
    try:
        _walk(config, report)
    except ValueError as exc:
        report["error"] = str(exc)
        reasons.append(str(exc))
    return finalize(report)


def walk_config(config, report: dict, *, keras2: bool = False, prefix: str = "") -> None:
    """Check one decoded config (``keras2`` for legacy HDF5); limit errors go to the report."""
    try:
        _walk(config, report, keras2, prefix)
    except ValueError as exc:
        report["error"] = str(exc)
        report["reasons"].append(str(exc))


def _loss_metric_names(value, path: str, report: dict, depth: int = 0) -> None:
    if depth > 20:
        raise ValueError(f"{path}: nested too deeply")
    if isinstance(value, str):
        if value not in KERAS_METRIC_NAMES:
            report["unknown_imports"].append(_entry("loss/metric", value, path))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _loss_metric_names(item, f"{path}[{i}]", report, depth + 1)
    elif isinstance(value, dict):
        if isinstance(value.get("class_name"), str):
            config = value.get("config")
            fn = config.get("fn") if isinstance(config, dict) else None
            if fn is not None:
                _loss_metric_names(fn, f"{path}.config.fn", report, depth + 1)
            return  # the class itself is checked by the config walk
        for key, item in value.items():
            _loss_metric_names(item, f"{path}.{key}", report, depth + 1)


def check_training_config(config, report: dict) -> None:
    """Losses, metrics and the optimizer a Keras 2 ``compile`` would rebuild. Names
    that are not built-in need ``custom_objects``: SUSPICIOUS."""
    if not isinstance(config, dict):
        report["reasons"].append("training_config is not a JSON object")
        return
    walk_config(config, report, keras2=True, prefix="training_config")
    try:
        for key in ("loss", "metrics", "weighted_metrics"):
            if config.get(key) is not None:
                _loss_metric_names(config[key], f"training_config.{key}", report)
    except ValueError as exc:
        report["reasons"].append(str(exc))
    optimizer = config.get("optimizer_config")
    if optimizer is not None and not (isinstance(optimizer, dict) and isinstance(optimizer.get("class_name"), str)):
        report["unknown_imports"].append(_entry("optimizer", type(optimizer).__name__, "training_config"))


def finalize(report: dict) -> dict:
    """Turn the collected findings into reasons and the static risk."""
    reasons: list[str] = report["reasons"]
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
