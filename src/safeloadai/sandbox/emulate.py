"""Host entry points for fake-API emulation. The untrusted bytes only reach the
guest as read-only artefacts; nothing here deserialises them."""
from __future__ import annotations

import json

from .host import GuestRun, Limits, run_guest


def emulate_pickle(streams: list[bytes], *, max_pickles: int = 1, limits: Limits | None = None) -> GuestRun:
    """Unpickle each stream inside the sandbox with recording ``find_class``."""
    artefacts = {f"stream{i}.pkl": data for i, data in enumerate(streams)}
    task = {"kind": "pickle", "files": sorted(artefacts), "max_pickles": max(1, int(max_pickles))}
    return run_guest(task, artefacts, limits)


def emulate_keras_lambdas(lambdas: list[dict], *, limits: Limits | None = None) -> GuestRun:
    """Call each Lambda (entries from the static Keras report) on fake tensors."""
    fields = ("path", "code_b64", "arguments", "defaults", "closure", "input_shape")
    entries = [{k: lam.get(k) for k in fields} for lam in lambdas]
    artefacts = {"lambdas.json": json.dumps(entries).encode("utf-8")}
    return run_guest({"kind": "keras_lambda", "file": "lambdas.json"}, artefacts, limits)
