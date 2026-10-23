"""Layer 2: static analysis. Reads bytes, never deserializes them.

Legacy HDF5 is the one format whose container is not parsed on the host: its
metadata is read inside the WASI sandbox (``sandbox.read_h5_metadata``) and only
the JSON it returns is analysed here."""
from __future__ import annotations

import dataclasses
import os

from .. import errors
from ..parsing import decompress
from ..parsing import detect as detect_mod
from ..parsing import views as views_mod
from . import budget as budget_mod
from .h5_static import parse_h5_metadata
from .keras_static import parse_keras
from .pickle_static import parse_pickle
from .torch_static import parse_torch_zip

MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024


def analyze_bytes(data: bytes, file_name: str = "<memory>", extra_allowed: frozenset = frozenset()) -> dict:
    """Static report for any supported container, dispatched on content.

    Every reading a loader could make of the bytes (``parsing.views``) is analysed. The
    report is the one for the reading the user's loader most likely performs; the others
    are kept under ``_extra_views`` as ``(view, report)`` pairs for the pipeline, which
    gives each its own static and emulation layers. A file with more than one reading,
    or with bytes in front of an archive or superblock that no reading explains, is at
    least SUSPICIOUS (RISKY)."""
    try:
        with budget_mod.scope(budget_mod.limit_for(len(data))):
            return _analyze_bytes(data, file_name, extra_allowed)
    except (budget_mod.ResourceLimit, MemoryError) as exc:  # the scanner's availability, never a crash
        report = parse_pickle(b"", file_name, file_format=detect_mod.detect(data))
        report["tool_errors"].append(errors.error("E105", str(exc) or type(exc).__name__))
        report["reasons"] = ["the static analysis stopped at its memory limit; the file was not fully read"]
        report["static_risk"] = "suspicious"
        return report


def _analyze_bytes(data: bytes, file_name: str, extra_allowed: frozenset) -> dict:
    views = views_mod.find_views(data)
    primary = views_mod.primary_view(views, file_name)
    report = _analyze_view(primary, data, file_name, extra_allowed)
    report["views"] = [v.describe() for v in views]
    report["_view"] = primary
    others = [v for v in views if v is not primary]
    if others:
        listed = ", ".join(f"{v.fmt} at offset {v.start} ({v.loader})" for v in views)
        report["reasons"].append(f"file is readable as more than one format: {listed}; every reading is analysed")
        report["_extra_views"] = [(v, _analyze_view(v, data, file_name, extra_allowed)) for v in others]
    views = _trailing_views(views, primary, report, data, file_name, extra_allowed)
    report["views"] = [v.describe() for v in views]
    _leading_bytes(views, data, report)
    mismatch = detect_mod.extension_mismatch(file_name, views_mod.detected_format(primary))
    if mismatch and report.get("unsupported"):
        report["notes"].append(mismatch)  # implied by UNSUPPORTED: no reading in any format
    elif mismatch:
        report["reasons"].append(mismatch)
    if report["reasons"] and report["static_risk"] == "clean":
        report["static_risk"] = "suspicious"
    return report


# The tool error code for an unexpected exception while reading each format (errors.py).
INTERNAL_CODES = {detect_mod.KERAS: "E202", detect_mod.H5: "E203", detect_mod.TORCH: "E204",
                  detect_mod.PICKLE: "E201", detect_mod.JOBLIB: "E205"}


def _analyze_view(view: views_mod.View | None, data: bytes, file_name: str, extra_allowed: frozenset) -> dict:
    """The static report of one reading. An exception the readers do not expect is a bug
    in safeloadai, never a statement about the file: it becomes a tool error (E2xx) in
    ``report["tool_errors"]``, and the reading is not CLEAN."""
    from ..sandbox.runtime import RuntimeIntegrityError

    fmt = view.fmt if view else detect_mod.UNKNOWN
    try:
        return _read_view(view, fmt, data, file_name, extra_allowed)
    except (RuntimeIntegrityError, budget_mod.ResourceLimit, MemoryError):
        raise
    except Exception as exc:  # noqa: BLE001 - a reader bug fails closed as a tool error
        report = parse_pickle(b"", file_name, file_format=fmt)
        report["tool_errors"].append(errors.internal(INTERNAL_CODES.get(fmt, "E200"), exc))
        report["static_risk"] = "suspicious"
        return report


def _read_view(view, fmt: str, data: bytes, file_name: str, extra_allowed: frozenset) -> dict:
    part = view.slice(data) if view else data
    if fmt == detect_mod.KERAS:
        return parse_keras(part, file_name)
    if fmt == detect_mod.TORCH:
        return parse_torch_zip(part, file_name, extra_allowed)
    if fmt == detect_mod.PICKLE:
        return parse_pickle(part, file_name, extra_allowed=extra_allowed, trailing="view")
    if fmt == detect_mod.JOBLIB:
        return _parse_compressed_joblib(part, file_name, extra_allowed)
    if fmt == detect_mod.H5:
        from ..sandbox import read_h5_metadata

        report = parse_h5_metadata(read_h5_metadata(part), file_name)
        if view.start:
            report["notes"].append(f"HDF5 superblock at offset {view.start} (after a user block)")
        return report
    report = parse_pickle(b"", file_name, file_format=detect_mod.UNKNOWN)
    refused = _refused_archive(data) if view is None else None
    if refused:
        # Bytes that look like a ZIP archive the archive reader refuses (CVE-2025-1944/1945
        # style tricks among them): a loader with a laxer reader may still open it. RISKY.
        reason = f"ZIP archive refused: {refused}"
        report["static_risk"] = "suspicious"
    elif view is None:
        # No reading at all: pickle.load fails before it can import or call anything
        # (detect._looks_like_pickle), and the bytes are no ZIP archive or HDF5 file. Nothing
        # can be analysed, which is its own verdict (UNSUPPORTED), never CLEAN.
        reason = UNSUPPORTED_REASON
        report["unsupported"] = True
        report["static_risk"] = "unsupported"
    else:
        # A ZIP archive parses, and a loader can do anything with its members: RISKY.
        reason = "ZIP archive that is neither a Keras nor a PyTorch file"
        report["static_risk"] = "suspicious"
    report["reasons"] = [reason]
    report["error"] = reason
    return report


def _refused_archive(data: bytes) -> str | None:
    from ..parsing.zipsafe import ZIP_MAGIC, SafeZip, ZipRefused

    if not (data.startswith(ZIP_MAGIC) or b"PK\x05\x06" in data[-65_557:]):
        return None
    try:
        with SafeZip(data):
            return None
    except ZipRefused as exc:
        return str(exc) or "invalid archive"


UNSUPPORTED_REASON = ("unrecognised file format: no pickle, joblib, PyTorch, Keras or HDF5 reading of these "
                      "bytes exists, so nothing could be analysed")


MAX_TRAILING_VIEWS = 16


def _trailing_views(views: list, primary, report: dict, data: bytes, file_name: str,
                    extra_allowed: frozenset) -> list:
    """A pickle reading ends at its STOP. Cut every pickle view there; bytes after it that
    no other reading starts at and that look like a pickle become a reading of their own
    (what a loader that reads on, or calls pickle.load again, would see)."""
    pairs = [(primary, report)] + list(report.get("_extra_views") or [])
    views = list(views)
    added = 0
    i = 0
    while i < len(pairs):
        view, rep = pairs[i]
        t = rep.get("trailing")
        if view is None or view.fmt != detect_mod.PICKLE or not t:
            i += 1
            continue
        start = view.start + t["start"]
        cut = dataclasses.replace(view, end=start)
        views = [cut if v is view else v for v in views]
        pairs[i] = (cut, rep)
        if view is primary:
            report["_view"] = primary = cut
        other = next((v for v in views if v.start == start and v is not cut), None)
        if other is not None:
            rep["notes"].append(f"the trailing data at offset {start} is the {other.fmt} reading")
        elif t["looks_like_pickle"] and added < MAX_TRAILING_VIEWS:
            new = views_mod.View(detect_mod.PICKLE, start, len(data),
                                 "data after a pickle's STOP (a loader that reads on, or calls pickle.load again)")
            views.append(new)
            pairs.append((new, _analyze_view(new, data, file_name, extra_allowed)))
            added += 1
        elif t["looks_like_pickle"]:
            rep["reasons"].append(f"more than {MAX_TRAILING_VIEWS} trailing readings; the rest is not analysed")
        i += 1
    extra = pairs[1:]
    if extra:
        report["_extra_views"] = extra
    return views


def _leading_bytes(views: list, data: bytes, report: dict) -> None:
    """Bytes in front of an HDF5 superblock that no other reading starts at. (Data in
    front of a ZIP archive is reported by the archive reader itself.)"""
    if any(v.start == 0 for v in views):
        return
    for view in views:
        if view.fmt == detect_mod.H5 and view.start and data[:view.start].strip(b"\0"):
            report["reasons"].append(f"{view.start} unexplained bytes before the HDF5 superblock (user block)")


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
