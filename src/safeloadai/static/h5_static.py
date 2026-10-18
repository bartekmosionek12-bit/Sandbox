"""Static analysis of legacy Keras HDF5 files (``.h5``) from the metadata the sandbox read.

The host never parses HDF5: ``sandbox.read_h5_metadata`` runs the stdlib reader
(``shared/hdf5_meta.py``) inside the WASI sandbox and returns the root attributes
``model_config``, ``training_config``, ``keras_version`` and ``backend`` plus a
summary of the file's structure. This module only decodes those JSON strings and
runs the Keras config checks on them (``keras_static`` with ``keras2=True``).
Weight datasets are never read by anyone.

SUSPICIOUS: the reader failed or refused the structure, reported a problem
(external links or data, virtual datasets, dense storage, duplicate or non-string
attributes, limits), an attribute is not valid UTF-8 JSON, or the config / training
config names anything outside the allowlists. MALICIOUS: as for ``.keras``.
"""
from __future__ import annotations

import json

from . import keras_static

MAX_CONFIG_BYTES = keras_static.MAX_CONFIG_BYTES


def _empty_report(file_name: str) -> dict:
    report = keras_static._empty_report(file_name)
    report["file_format"] = "h5"
    report["h5"] = None
    return report


def _decode_json(raw: bytes, name: str, report: dict):
    if len(raw) > MAX_CONFIG_BYTES:
        report["reasons"].append(f"{name} is {len(raw)} bytes (limit {MAX_CONFIG_BYTES})")
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except RecursionError:
        report["reasons"].append(f"{name}: nesting too deep for the JSON parser")
    except (UnicodeDecodeError, ValueError) as exc:
        report["reasons"].append(f"{name} is not valid UTF-8 JSON: {str(exc)[:200]}")
    return None


def parse_h5_metadata(meta: dict, file_name: str = "<memory>") -> dict:
    report = _empty_report(file_name)
    reasons: list[str] = report["reasons"]
    if meta.get("failed"):
        report["error"] = str(meta["failed"])
        reasons.append(report["error"])
        report["static_risk"] = "suspicious"
        return report
    report["h5"] = {
        "superblock_version": meta.get("superblock_version"),
        "counts": meta.get("counts"),
        "root_attributes": list(meta.get("root_attr_names") or [])[:100],
    }
    report["notes"].extend(str(n) for n in (meta.get("notes") or [])[:50])
    for problem in meta.get("problems") or []:
        reasons.append(f"HDF5: {problem}")

    values = meta.get("values") or {}
    metadata = {}
    for name in ("keras_version", "backend"):
        if name in values:
            try:
                metadata[name] = values[name].decode("utf-8")[:200]
            except UnicodeDecodeError:
                reasons.append(f"{name} is not valid UTF-8")
    report["metadata"] = metadata or None

    names = set(meta.get("root_attr_names") or [])
    if "model_config" in values:
        config = _decode_json(values["model_config"], "model_config", report)
        if config is not None:
            try:
                report["raw_disasm"] = json.dumps(config, indent=1)[:200_000]
            except RecursionError:
                report["raw_disasm"] = "<config nested too deeply to render>"
            if not (isinstance(config, dict) and isinstance(config.get("class_name"), str)):
                reasons.append("model_config is not a serialized Keras model")
            keras_static.walk_config(config, report, keras2=True)
    elif "model_config" not in names:
        report["notes"].append("no model_config: weights-only file (load_model refuses it; "
                               "load_weights reads only arrays)")
    if "training_config" in values:
        training = _decode_json(values["training_config"], "training_config", report)
        if training is not None:
            keras_static.check_training_config(training, report)
    return keras_static.finalize(report)
