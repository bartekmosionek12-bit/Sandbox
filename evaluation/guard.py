"""Host-execution guard for evaluation runs (the equivalent of tests/conftest.py's guard).

While active, the evaluation process cannot deserialize a model or start a process
by accident: it fails loudly instead.

* Framework loaders cannot even be imported (torch, tensorflow, keras, h5py,
  joblib, scikit-learn, numpy, transformers, ...): a scan never needs them.
* ``pickle.load``/``pickle.loads`` raise.
* ``os.system``, the ``exec*``/``spawn*`` family, ``fork`` and ``posix_spawn`` raise.
* ``subprocess.Popen`` only starts the safeloadai sandbox runner, or an executable
  explicitly allowed by the caller (the other scanners being compared, which run
  as their own processes and are static scanners).
* Sockets connect to loopback only.

``activate()`` returns a function that undoes everything (used by the tests).
"""
from __future__ import annotations

import importlib.abc
import os
import pickle
import socket
import subprocess
import sys

BLOCKED_MODULES = frozenset({
    "torch", "tensorflow", "keras", "tf_keras", "h5py", "joblib", "sklearn", "skops", "numpy",
    "transformers", "diffusers", "dill", "cloudpickle", "onnx", "onnxruntime", "jax", "flax", "pandas",
})
_OS_NAMES = ("system", "popen", "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp",
             "execlpe", "spawnv", "spawnve", "spawnl", "spawnle", "spawnvp", "spawnvpe", "spawnlp",
             "spawnlpe", "posix_spawn", "posix_spawnp", "fork", "forkpty", "startfile")
_LOOPBACK = ("127.0.0.1", "::1", "localhost")


class GuardError(RuntimeError):
    """Something tried to deserialize, import a framework loader, start a process or connect out."""


def _refuse(what: str):
    def refuse(*args, **kwargs):
        raise GuardError(f"evaluation guard: {what} refused ({args[:1]!r})")

    return refuse


class _BlockLoaders(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in BLOCKED_MODULES:
            raise GuardError(f"evaluation guard: import of {fullname!r} refused (framework loader)")
        return None


def activate(allowed_executables: tuple[str, ...] = ()) -> callable:
    from safeloadai.sandbox.host import RUNNER_ARGV

    already = sorted(m for m in sys.modules if m.split(".")[0] in BLOCKED_MODULES)
    if already:
        raise GuardError(f"evaluation guard: framework modules already imported: {', '.join(already[:5])}")
    saved: list[tuple[object, str, object]] = []

    def patch(obj, name, value):
        if hasattr(obj, name):
            saved.append((obj, name, getattr(obj, name)))
            setattr(obj, name, value)

    native = sys.modules.get("posix") or sys.modules.get("nt")
    for module in (os, native):
        for name in _OS_NAMES:
            patch(module, name, _refuse(f"{module.__name__}.{name}"))
    patch(pickle, "load", _refuse("pickle.load"))
    patch(pickle, "loads", _refuse("pickle.loads"))

    allowed = {os.path.realpath(p) for p in allowed_executables}
    real_popen = subprocess.Popen

    def guarded_popen(args, *a, **kw):
        argv = [args] if isinstance(args, (str, bytes, os.PathLike)) else list(args)
        if argv != RUNNER_ARGV and os.path.realpath(os.fspath(argv[0])) not in allowed:
            raise GuardError(f"evaluation guard: process {argv[:3]!r} refused")
        return real_popen(args, *a, **kw)

    patch(subprocess, "Popen", guarded_popen)

    real_connect = socket.socket.connect

    def connect(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if host not in _LOOPBACK:
            raise GuardError(f"evaluation guard: connection to {address!r} refused")
        return real_connect(self, address)

    patch(socket.socket, "connect", connect)
    finder = _BlockLoaders()
    sys.meta_path.insert(0, finder)

    def deactivate():
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
        for obj, name, value in reversed(saved):
            setattr(obj, name, value)

    return deactivate
