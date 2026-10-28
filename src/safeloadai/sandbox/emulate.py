"""Host entry points for fake-API emulation. The untrusted bytes only reach the
guest as read-only artefacts; nothing here deserialises them."""
from __future__ import annotations

import base64
import json
import math

from .. import errors
from .host import GuestRun, Limits, run_guest


def emulate_pickle(streams: list[bytes], *, max_pickles: int = 1, joblib: bool = False,
                   limits: Limits | None = None) -> GuestRun:
    """Unpickle each stream inside the sandbox with recording ``find_class``.

    ``joblib=True`` uses joblib's reading (raw array bytes after each
    NumpyArrayWrapper are skipped, object arrays read as nested pickles)."""
    artefacts = {f"stream{i}.pkl": data for i, data in enumerate(streams)}
    task = {"kind": "pickle", "files": sorted(artefacts), "max_pickles": max(1, int(max_pickles)),
            "joblib": bool(joblib)}
    return run_guest(task, artefacts, limits)


def emulate_keras_lambdas(lambdas: list[dict], *, limits: Limits | None = None) -> GuestRun:
    """Call each Lambda (entries from the static Keras report) on fake tensors."""
    fields = ("path", "code_b64", "code_fields", "arguments", "defaults", "closure", "input_shape")
    entries = [{k: lam.get(k) for k in fields} for lam in lambdas]
    artefacts = {"lambdas.json": json.dumps(entries).encode("utf-8")}
    return run_guest({"kind": "keras_lambda", "file": "lambdas.json"}, artefacts, limits)


H5_CHUNK = 45 * 1024  # must match guest/tasks.py


def read_h5_metadata(data: bytes, *, limits: Limits | None = None, reader_limits: dict | None = None) -> dict:
    """Root attributes and structure of a legacy Keras HDF5 file, read INSIDE the sandbox.

    Returns the guest's metadata with ``values`` (attribute name -> bytes) rebuilt
    from the chunk records, or ``{"failed": reason}`` when the reader did not finish
    cleanly. The values are untrusted data, like the file itself."""
    task = {"kind": "h5_meta", "file": "model.h5", "limits": reader_limits or {}}
    run = run_guest(task, {"model.h5": data}, limits)
    if run.tampered:
        return {"failed": "evidence channel tampered with during the HDF5 metadata read", "tampered": True}
    failure = errors.guest_error(run.status, run.problems, layer="static")
    if failure is not None:
        # The sandbox, not the file, failed: a tool error (E3xx), never a verdict.
        return {"failed": failure["message"], "tool_error": failure, "unavailable": run.status == "unavailable"}
    anomalies = [e for e in run.events if e.get("kind") == "anomaly"]
    if anomalies:
        # The reader turns every structure it refuses into a "refused" summary; an exception
        # that escapes it is a bug in the reader (E203), not a statement about the file.
        detail = "; ".join(f"{a.get('error')}: {a.get('detail')}" for a in anomalies[:3])
        return {"failed": "HDF5 metadata reader raised: " + detail,
                "tool_error": errors.error("E203", detail)}
    if not run.completed:
        return {"failed": "HDF5 metadata reader did not complete: " + "; ".join(run.problems[:5])}
    metas = [e for e in run.events if e.get("kind") == "h5_meta"]
    if len(metas) != 1:
        return {"failed": f"HDF5 metadata reader sent {len(metas)} summaries"}
    if metas[0].get("refused"):
        return {"failed": "HDF5 structure refused: " + str(metas[0]["refused"])}
    meta = metas[0].get("meta")
    if not isinstance(meta, dict) or not isinstance(meta.get("sizes"), dict):
        return {"failed": "HDF5 metadata summary is malformed"}
    chunks: dict[str, list] = {}
    for event in run.events:
        if event.get("kind") == "h5_attr":
            chunks.setdefault(str(event.get("name")), []).append(event)
    values = {}
    for name, size in meta["sizes"].items():
        parts = chunks.pop(name, [])
        expected = math.ceil(size / H5_CHUNK) if isinstance(size, int) and size >= 0 else -1
        if [p.get("index") for p in parts] != list(range(expected)):
            return {"failed": f"HDF5 attribute {name!r} arrived incomplete"}
        try:
            value = b"".join(base64.b64decode(p.get("data", ""), validate=True) for p in parts)
        except ValueError:
            return {"failed": f"HDF5 attribute {name!r} is not valid base64"}
        if len(value) != size:
            return {"failed": f"HDF5 attribute {name!r} is {len(value)} bytes, summary says {size}"}
        values[name] = value
    if chunks:
        return {"failed": "HDF5 attribute chunks without a summary entry: " + ", ".join(sorted(chunks))[:200]}
    meta["values"] = values
    meta["timings_ms"] = run.timings_ms
    return meta


# The booster validator walks every byte in Python: measured on the tune samples (up to
# 51 MB of xgboost JSON) at well under this per byte; a payload over the ceiling stays
# UNVERIFIABLE (the validation "failed", never "valid").
BOOSTER_FUEL_PER_BYTE = 4096
BOOSTER_MEMORY_PER_BYTE = 24
# the guest holds the payload and its parsed form in a 32-bit address space; above this a
# model is left UNVERIFIABLE without trying (137 MB of UBJSON ran out of guest memory)
MAX_BOOSTER_BYTES = 64 << 20


def validate_boosters(items: list[tuple[str, bytes]], *, limits: Limits | None = None) -> dict:
    """Validate Booster model bytes INSIDE the sandbox (``--validate-boosters``).

    ``items`` are (library, payload) pairs. Returns ``{"results": [...]}`` with one
    ``{"summary": ...}`` or ``{"invalid": reason}`` per item, or ``{"failed": reason}``
    when the validator itself did not finish cleanly (then nothing counts as valid)."""
    from .host import MAX_FUEL, MAX_GUEST_MEMORY, MAX_WALL_SECONDS

    size = sum(len(p) for _, p in items)
    if size > MAX_BOOSTER_BYTES:
        return {"failed": f"{size} bytes of model data, more than the validator reads ({MAX_BOOSTER_BYTES})"}
    artefacts = {f"booster{i}.bin": payload for i, (_, payload) in enumerate(items)}
    task = {"kind": "booster_check",
            "items": [{"file": f"booster{i}.bin", "library": library} for i, (library, _) in enumerate(items)]}
    if limits is None:
        base = Limits()
        fuel = min(MAX_FUEL, base.fuel + BOOSTER_FUEL_PER_BYTE * size)
        limits = Limits(fuel=fuel, wall_seconds=min(MAX_WALL_SECONDS, base.wall_seconds * fuel / base.fuel),
                        memory_bytes=min(MAX_GUEST_MEMORY, base.memory_bytes + BOOSTER_MEMORY_PER_BYTE * size))
    run = run_guest(task, artefacts, limits)
    if run.tampered:
        return {"failed": "evidence channel tampered with during the booster validation", "tampered": True}
    failure = errors.guest_error(run.status, run.problems, layer="static")
    if failure is not None:
        return {"failed": failure["message"], "tool_error": failure}
    anomalies = [e for e in run.events if e.get("kind") == "anomaly"]
    if anomalies:
        detail = "; ".join(f"{a.get('error')}: {a.get('detail')}" for a in anomalies[:3])
        return {"failed": "booster validator raised: " + detail}
    if not run.completed:
        return {"failed": "booster validator did not complete: " + "; ".join(run.problems[:5])}
    results = [e for e in run.events if e.get("kind") == "booster"]
    if [r.get("index") for r in results] != list(range(len(items))):
        return {"failed": f"booster validator sent {len(results)} results for {len(items)} items"}
    out = []
    for r in results:
        if isinstance(r.get("summary"), dict) and "invalid" not in r:
            out.append({"summary": r["summary"]})
        else:
            out.append({"invalid": str(r.get("invalid") or "no summary")})
    return {"results": out, "timings_ms": run.timings_ms}
