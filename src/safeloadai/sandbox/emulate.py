"""Host entry points for fake-API emulation. The untrusted bytes only reach the
guest as read-only artefacts; nothing here deserialises them."""
from __future__ import annotations

import base64
import json
import math

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
    fields = ("path", "code_b64", "arguments", "defaults", "closure", "input_shape")
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
    if run.status == "unavailable":
        return {"failed": "WASI sandbox unavailable: " + "; ".join(run.problems), "unavailable": True}
    if run.tampered:
        return {"failed": "evidence channel tampered with during the HDF5 metadata read", "tampered": True}
    if not run.completed or run.status != "ok":
        return {"failed": f"HDF5 metadata reader did not complete (status {run.status}): "
                          + "; ".join(run.problems[:5])}
    anomalies = [e for e in run.events if e.get("kind") == "anomaly"]
    if anomalies:
        return {"failed": "HDF5 metadata reader raised: "
                          + "; ".join(f"{a.get('error')}: {a.get('detail')}" for a in anomalies[:3])}
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
