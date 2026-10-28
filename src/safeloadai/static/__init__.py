"""Layer 2: static analysis. Reads bytes, never deserializes them.

Legacy HDF5 is the one format whose container is not parsed on the host: its
metadata is read inside the WASI sandbox (``sandbox.read_h5_metadata``) and only
the JSON it returns is analysed here."""
from __future__ import annotations

import contextlib
import contextvars
import dataclasses
import hashlib
import os

from .. import errors
from ..parsing import decompress
from ..parsing import detect as detect_mod
from ..parsing import views as views_mod
from . import budget as budget_mod
from . import data_formats, model_formats
from .h5_static import parse_h5_metadata
from .keras_static import parse_keras
from .pickle_static import parse_pickle
from .torch_static import parse_torch_zip

MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024


# Files a loader reads next to the scanned one (0.10.0): the model directory (ONNX external
# data) and the OpenVINO .xml of a .bin or the .bin of an .xml. Set by ``companions``.
_COMPANIONS: contextvars.ContextVar[dict | None] = contextvars.ContextVar("safeloadai_companions", default=None)


def read_companions(path: str) -> dict:
    """What a loader of ``path`` reads beside it: ``dir``, and for an OpenVINO IR the other
    file of the pair (``xml``: name, bytes and sha256 of the .xml beside a .bin; ``bin``:
    name, bytes and sha256 of the .bin beside an .xml). A link, a missing file or one over
    the size limit is left out (the scan then sees no pair)."""
    directory = os.path.dirname(os.path.abspath(path))
    stem, ext = os.path.splitext(path)
    out: dict = {"dir": directory}
    other = {".bin": (".xml", "xml", model_formats.MAX_COMPANION_BYTES),
             ".xml": (".bin", "bin", MAX_FILE_BYTES)}.get(ext.lower())
    if other is None:
        return out
    for suffix in dict.fromkeys((other[0], other[0].upper())):
        candidate = stem + suffix
        if os.path.isfile(candidate) and not os.path.islink(candidate) and os.path.getsize(candidate) <= other[2]:
            with open(candidate, "rb") as fh:
                raw = fh.read(other[2] + 1)
            if len(raw) <= other[2]:
                out[other[1]] = {"name": os.path.basename(candidate), "data": raw,
                                 "sha256": hashlib.sha256(raw).hexdigest()}
            break
    return out


@contextlib.contextmanager
def companions(found: dict | None):
    token = _COMPANIONS.set(found)
    try:
        yield
    finally:
        _COMPANIONS.reset(token)


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
    views = views_mod.find_views(data, file_name)
    views = _openvino_weights(views, data, file_name)
    primary = views[0] if views and views[0].fmt == detect_mod.OPENVINO_BIN else views_mod.primary_view(views, file_name)
    report = _analyze_view(primary, data, file_name, extra_allowed)
    report["views"] = [v.describe() for v in views]
    report["_view"] = primary
    others = [v for v in views if v is not primary]
    if others and report.get("data_only") and _only_unverifiable(report):
        views, others = _drop_accidental(views, others, data, file_name, extra_allowed, report)
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
    elif mismatch and report.get("data_only") and report["static_risk"] == "clean" and len(views) == 1:
        # The only reading is a valid data-only file: whatever loader the name suggests either
        # reads it as data or fails before it can import or call anything.
        report["notes"].append(mismatch)
    elif mismatch:
        report["reasons"].append(mismatch)
    if report["reasons"] and report["static_risk"] == "clean":
        report["static_risk"] = "suspicious"
    return report


def _only_unverifiable(report: dict) -> bool:
    """A valid data-only or no-code reading: CLEAN, or blocked only by UNVERIFIABLE operators."""
    if report["static_risk"] == "clean":
        return True
    return (report["static_risk"] == "suspicious" and not report.get("error")
            and set(report["reasons"]) <= set(report.get("unverifiable") or {}))


def _openvino_weights(views: list, data: bytes, file_name: str) -> list:
    """A ``.bin`` with an OpenVINO ``.xml`` beside it is also the weights reading of that IR.
    It comes first when the only other readings are offset-0 pickle or joblib readings
    (raw weights decode as a few pickle opcodes by chance; ``_drop_accidental`` keeps them
    when they import anything); next to any other reading it is one reading among several."""
    found = _COMPANIONS.get() or {}
    xml = found.get("xml")
    if not file_name.lower().endswith(".bin") or not xml or not model_formats.looks_like_openvino_xml(xml["data"]):
        return views
    weights = views_mod.View(detect_mod.OPENVINO_BIN, 0, len(data),
                             f"openvino.Core.read_model ({xml['name']} beside it)")
    if all(v.start == 0 and v.fmt in (detect_mod.PICKLE, detect_mod.JOBLIB) for v in views):
        return [weights, *views]
    return [*views, weights]


# Opcodes through which pickle.load imports (and so can later call) anything chosen by the
# file: by name, or through a persistent id. (EXT1/2/4 look a class up in copyreg's
# extension registry, which is empty unless the loading process itself filled it: the file
# can only pick one of the classes that process registered.)
PICKLE_IMPORT_OPCODES = frozenset({"GLOBAL", "STACK_GLOBAL", "INST", "PERSID", "BINPERSID"})
EXT_OPCODES = frozenset({"EXT1", "EXT2", "EXT4"})


def _drop_accidental(views: list, others: list, data: bytes, file_name: str, extra_allowed: frozenset,
                     report: dict) -> tuple[list, list]:
    """Next to a valid data-only reading, drop an offset-0 pickle or joblib reading that
    imports nothing: the first bytes of a safetensors file are a header length, and they
    decode as a few pickle opcodes or a compressor's magic number by chance in a few percent
    of files. Without an opcode that imports a class the file names, pickle.load can call
    nothing; it fails or returns plain data. The reading is kept (and the file is RISKY) for
    any import or persistent id, an EXT opcode in a stream that reads to its end, data after
    a STOP that looks like another pickle, or a stream that decompresses."""
    kept = []
    for view in others:
        if view.start == 0 and view.fmt in (detect_mod.PICKLE, detect_mod.JOBLIB):
            rep = _analyze_view(view, data, file_name, extra_allowed)
            counts = rep.get("opcode_counts") or {}
            fails = bool(rep.get("error"))
            if (not rep.get("tool_errors") and not rep.get("evidence") and not rep.get("decompressed_size")
                    and not PICKLE_IMPORT_OPCODES & set(counts) and (fails or not EXT_OPCODES & set(counts))
                    and not (rep.get("trailing") or {}).get("looks_like_pickle")):
                outcome = "loading fails there" if fails else "they hold plain data and import nothing"
                report["notes"].append(f"the first bytes also decode as {sum(counts.values())} {view.fmt} "
                                       f"opcode(s), and {outcome}: not a reading")
                continue
        kept.append(view)
    return [v for v in views if v in kept or v not in others], kept


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
    if fmt in detect_mod.DATA_ONLY:
        return _data_only(part, fmt, file_name)
    if fmt in detect_mod.NO_CODE:
        return _no_code(part, fmt, file_name)
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


def _data_only(data: bytes, fmt: str, file_name: str) -> dict:
    """A data-only reading (static/data_formats.py): CLEAN when the structure is exactly what
    the format allows, RISKY for any inconsistency. A chat template that reaches Python
    internals is RISKY, and MALICIOUS when it also names a command sink."""
    report = parse_pickle(b"", file_name, file_format=fmt)
    report["reasons"] = []
    report["data_only"] = True
    try:
        facts = data_formats.CHECKS[fmt](data)
    except data_formats.Invalid as exc:
        reason = f"invalid {fmt} structure: {exc}"
        report.update(static_risk="suspicious", reasons=[reason], error=reason)
        return report
    templates = facts.pop("templates", [])
    report["data_format"] = facts
    report["static_risk"] = "clean"
    for template in templates:
        reason, sink = data_formats.template_findings(template)
        if reason:
            report["reasons"].append(reason)
            if sink:
                report["evidence"].append(reason)
                report["static_risk"] = "malicious"
            elif report["static_risk"] == "clean":
                report["static_risk"] = "suspicious"
    report["notes"].append(f"{data_formats.DATA_ONLY_REASON} ({data_formats.LOADERS[fmt]})")
    return report


def _no_code(data: bytes, fmt: str, file_name: str) -> dict:
    """A reading in a model format that runs no code (static/model_formats.py): CLEAN when the
    structure is exactly what the format allows and every operator is standard, RISKY for
    any inconsistency, UNVERIFIABLE (naming the domain or operator) for custom operators."""
    report = parse_pickle(b"", file_name, file_format=fmt)
    report["reasons"] = []
    report["data_only"] = True
    report["clean_reason"] = model_formats.NO_CODE_REASON
    found = _COMPANIONS.get() or {}
    try:
        facts = _check_no_code(data, fmt, found, report)
    except data_formats.Invalid as exc:
        reason = f"invalid {fmt} structure: {exc}"
        report.update(static_risk="suspicious", reasons=[reason], error=reason)
        return report
    report["data_format"] = facts
    report["static_risk"] = "clean"
    for item in facts.pop("unverifiable", []):
        report["reasons"].append(item.reason)
        report["unverifiable"][item.reason] = {"item": item.item, "explanation": item.explanation}
        report["static_risk"] = "suspicious"
    for reason in facts.pop("risky", []):
        report["reasons"].append(reason)
        report["static_risk"] = "suspicious"
    report["notes"].append(f"{model_formats.NO_CODE_REASON} ({model_formats.LOADERS[fmt]})")
    return report


def _check_no_code(data: bytes, fmt: str, found: dict, report: dict) -> dict:
    if fmt == detect_mod.ONNX:
        return model_formats.check_onnx(data, found.get("dir"))
    if fmt == detect_mod.OPENVINO_BIN:
        xml = found["xml"]
        report["companions"] = [{"file": xml["name"], "sha256": xml["sha256"], "role": "OpenVINO IR (.xml)"}]
        try:
            facts = model_formats.check_openvino_xml(xml["data"], len(data))
        except data_formats.Invalid as exc:
            raise data_formats.Invalid(f"{xml['name']}: {exc}") from None
        report["notes"].append(f"weights of {xml['name']} (sha256 {xml['sha256']}): OpenVINO reads only the "
                               "ranges its Const layers name")
        return facts
    if fmt == detect_mod.OPENVINO_XML:
        weights = found.get("bin")
        facts = model_formats.check_openvino_xml(data, len(weights["data"]) if weights else None)
        facts["risky"] = []
        if weights:
            report["companions"] = [{"file": weights["name"], "sha256": weights["sha256"],
                                     "role": "OpenVINO weights (.bin)"}]
            readings = views_mod.find_views(weights["data"], weights["name"])
            if readings:
                listed = ", ".join(f"{v.fmt} at offset {v.start}" for v in readings)
                facts["risky"].append(f"the weights file {weights['name']} is also readable as {listed}; "
                                      f"scan {weights['name']} itself")
        return facts
    return model_formats.CHECKS[fmt](data)


def _refused_archive(data: bytes) -> str | None:
    from ..parsing.zipsafe import ZIP_MAGIC, SafeZip, ZipRefused

    if not (data.startswith(ZIP_MAGIC) or b"PK\x05\x06" in data[-65_557:]):
        return None
    try:
        with SafeZip(data):
            return None
    except ZipRefused as exc:
        return str(exc) or "invalid archive"


UNSUPPORTED_REASON = ("unrecognised file format: no pickle, joblib, PyTorch, Keras, HDF5, safetensors, GGUF, "
                      "NumPy, ONNX, TFLite, Flax msgpack, OpenVINO or Core ML weights reading of these bytes exists, so nothing "
                      "could be analysed")


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
    with companions(read_companions(path)):
        return _analyze_file(path, extra_allowed)


def _analyze_file(path: str, extra_allowed: frozenset) -> dict:
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
