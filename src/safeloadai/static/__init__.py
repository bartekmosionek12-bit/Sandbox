"""Layer 2: static analysis. Reads bytes, never deserializes them.

Legacy HDF5 is the one format whose container is not parsed on the host: its
metadata is read inside the WASI sandbox (``sandbox.read_h5_metadata``) and only
the JSON it returns is analysed here."""
from __future__ import annotations

import os

from ..parsing import decompress
from ..parsing import detect as detect_mod
from .h5_static import parse_h5_metadata
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
    elif fmt == detect_mod.JOBLIB:
        report = _parse_compressed_joblib(data, file_name, extra_allowed)
    elif fmt == detect_mod.H5:
        from ..sandbox import read_h5_metadata

        report = parse_h5_metadata(read_h5_metadata(data), file_name)
    else:
        report = parse_pickle(b"", file_name, file_format=fmt)
        reason = "unrecognised file format"
        report["reasons"] = [reason]
        report["error"] = reason
        report["static_risk"] = "suspicious"
    mismatch = detect_mod.extension_mismatch(file_name, fmt)
    if mismatch:
        report["reasons"].append(mismatch)
        if report["static_risk"] == "clean":
            report["static_risk"] = "suspicious"
    return report


def _parse_compressed_joblib(data: bytes, file_name: str, extra_allowed: frozenset) -> dict:
    """Decompress within limits, then walk the pickle inside. The decompressed stream
    is kept under ``_stream`` (dropped from the report) for the sandbox."""
    try:
        codec, inner = decompress.open_container(data)
    except Exception as exc:  # noqa: BLE001 - a codec failure of any kind fails closed
        if not isinstance(exc, decompress.DecompressionRefused):
            exc = decompress.DecompressionRefused(f"decompression failed: {type(exc).__name__}: {exc}")
        report = parse_pickle(b"", file_name, file_format=detect_mod.JOBLIB)
        report["reasons"] = [str(exc)]
        report["error"] = str(exc)
        report["static_risk"] = "suspicious"
        report["compression"] = decompress.detect(data)
        return report
    report = parse_pickle(inner, file_name, file_format=detect_mod.JOBLIB, extra_allowed=extra_allowed)
    report["compression"] = codec
    report["decompressed_size"] = len(inner)
    report["_stream"] = inner
    if codec == "compat":
        report["notes"].append("legacy joblib ZF container (joblib < 0.10)")
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


__all__ = ["analyze_bytes", "analyze_file", "parse_h5_metadata", "parse_keras", "parse_pickle", "parse_torch_zip"]
