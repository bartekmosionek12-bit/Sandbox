"""Layer 2: static analysis. Reads bytes, never deserializes them."""
from __future__ import annotations

import os

from ..parsing import detect as detect_mod
from .keras_static import parse_keras
from .pickle_static import parse_pickle
from .torch_static import parse_torch_zip

MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024


def analyze_bytes(data: bytes, file_name: str = "<memory>", extra_allowed: frozenset = frozenset()) -> dict:
    """Static report for any supported container, dispatched on content."""
    fmt = detect_mod.detect(data)
    if fmt == detect_mod.KERAS:
        report = parse_keras(data, file_name)
    elif fmt == detect_mod.TORCH:
        report = parse_torch_zip(data, file_name, extra_allowed)
    elif fmt == detect_mod.PICKLE:
        report = parse_pickle(data, file_name, extra_allowed=extra_allowed)
    else:
        report = parse_pickle(b"", file_name, file_format=fmt)
        reason = (
            "legacy HDF5 model: config is parsed inside the sandbox only (not available yet)"
            if fmt == detect_mod.H5
            else "unrecognised file format"
        )
        report["reasons"] = [reason]
        report["error"] = reason
        report["static_risk"] = "suspicious"
    mismatch = detect_mod.extension_mismatch(file_name, fmt)
    if mismatch:
        report["reasons"].append(mismatch)
        if report["static_risk"] == "clean":
            report["static_risk"] = "suspicious"
    return report


def analyze_file(path: str | os.PathLike, extra_allowed: frozenset = frozenset()) -> dict:
    path = os.fspath(path)
    size = os.path.getsize(path)
    if size > MAX_FILE_BYTES:
        report = parse_pickle(b"", os.path.basename(path), file_format="unknown")
        report["reasons"] = [f"file is {size} bytes (limit {MAX_FILE_BYTES})"]
        report["error"] = report["reasons"][0]
        report["static_risk"] = "suspicious"
        return report
    with open(path, "rb") as fh:
        data = fh.read()
    return analyze_bytes(data, os.path.basename(path), extra_allowed)


__all__ = ["analyze_bytes", "analyze_file", "parse_keras", "parse_pickle", "parse_torch_zip"]
