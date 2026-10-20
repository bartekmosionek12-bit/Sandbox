"""Public API: ``scan`` and ``safe_load``.

``safe_load`` scans a private read-only copy of the file and loads that same
copy only when the verdict is CLEAN. The loaders enforce the policy again on
their own, so a wrong verdict does not turn into code execution by itself:

* pickle: an Unpickler whose ``find_class`` resolves only exact allowlisted
  ``(module, qualname)`` pairs and raises for anything else;
* joblib: the same restricted ``find_class`` in a reader that follows joblib's
  array layout itself (shared/joblib_layout.py, numpy only; joblib is never
  imported), with the same decompression limits as the scan;
* PyTorch: ``torch.load(..., weights_only=True)``;
* Keras: ``keras.saving.load_model(..., safe_mode=True)``, which refuses Lambda
  bytecode even when the scan found it harmless.

``accept_unverified`` is the informed override (see ``override.py``): it names the
exact UNVERIFIABLE items accepted for this one file, and works only when every
reason on the file is UNVERIFIABLE. Accepted pickle globals are added, as exact
pairs, to the restricted unpickler for this load only.
"""
from __future__ import annotations

import contextlib
import hashlib
import os
import pickle
import shutil
import tempfile
from collections.abc import Iterable, Iterator, Mapping
from typing import Any

from . import override
from .parsing import decompress
from .parsing import detect as detect_mod
from .pipeline import scan
from .report import Report
from .shared import joblib_layout
from .static.allowlists import PICKLE_GLOBALS


class UnsafeModelError(Exception):
    """Refusal to load a model file. ``report`` is the scan report, if one exists."""

    def __init__(self, message: str, report: Report | None = None):
        super().__init__(message)
        self.report = report
        self.verdict = report.verdict if report is not None else None


class RestrictedUnpickler(pickle.Unpickler):
    """Resolves only exact allowlisted globals; everything else is refused before import."""

    def __init__(self, file, allowed: frozenset[tuple[str, str]], **kwargs):
        super().__init__(file, **kwargs)
        self._allowed = allowed

    def find_class(self, module: str, name: str):
        if (module, name) not in self._allowed:
            raise UnsafeModelError(f"global {module}.{name} is not on the allowlist")
        return super().find_class(module, name)


@contextlib.contextmanager
def _private_copy(path: str | os.PathLike) -> Iterator[str]:
    """Scan and load the same private, read-only copy (closes the TOCTOU window)."""
    source = os.fspath(path)
    directory = tempfile.mkdtemp(prefix="safeloadai-")
    try:
        staged = os.path.join(directory, os.path.basename(source))
        with open(source, "rb") as src, open(staged, "xb") as dst:
            shutil.copyfileobj(src, dst)
        os.chmod(staged, 0o400)
        yield staged
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_pickle(path: str, allowed: frozenset[tuple[str, str]], **kwargs) -> Any:
    """Read every pickle in the file with the restricted unpickler; one object -> that object."""
    objects = []
    with open(path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        while fh.tell() < size:
            objects.append(RestrictedUnpickler(fh, allowed, **kwargs).load())
    return objects[0] if len(objects) == 1 else objects


class _ArrayWrapper:
    """What the restricted joblib reader builds for joblib.numpy_pickle.NumpyArrayWrapper."""


def _real_dtype(value):
    import numpy as np

    if not isinstance(value, np.dtype):
        raise joblib_layout.LayoutError("array dtype is not a numpy.dtype")
    _cls, args, state = value.__reduce__()
    return args[0], state


class _RestrictedPlainUnpickler(pickle._Unpickler):
    """Pure-Python unpickler with the exact-pair find_class (joblib's nested reader)."""

    def __init__(self, file, allowed: frozenset[tuple[str, str]]):
        super().__init__(file)
        self._allowed = allowed

    def find_class(self, module: str, name: str):
        if (module, name) not in self._allowed:
            raise UnsafeModelError(f"global {module}.{name} is not on the allowlist")
        if (module, name) == joblib_layout.WRAPPER:
            return _ArrayWrapper
        return super().find_class(module, name)


class RestrictedJoblibUnpickler(_RestrictedPlainUnpickler):
    """joblib's NumpyUnpickler reading, with the exact-pair find_class."""

    dispatch = pickle._Unpickler.dispatch.copy()

    def __init__(self, file, allowed: frozenset[tuple[str, str]]):
        super().__init__(file, allowed)
        self.file_handle = file

    def load_build(self):
        import numpy as np

        pickle._Unpickler.load_build(self)
        wrapper = self.stack[-1]
        if not isinstance(wrapper, _ArrayWrapper):
            return
        frame = self._unframer.current_frame
        if frame is not None and frame.tell() < len(frame.getbuffer()):
            raise UnsafeModelError("joblib array data inside a pickle frame")
        attrs = wrapper.__dict__
        try:
            plan = joblib_layout.plan(attrs, _real_dtype, _real_dtype)
        except joblib_layout.LayoutError as exc:
            raise UnsafeModelError(f"joblib array: {exc}") from exc
        if plan.hasobject:
            array = _RestrictedPlainUnpickler(self.file_handle, self._allowed).load()
            if not isinstance(array, np.ndarray):
                raise UnsafeModelError("joblib object array did not unpickle to an ndarray")
        else:
            dtype = attrs["dtype"]
            if dtype.itemsize != plan.itemsize:
                raise UnsafeModelError("joblib array dtype size differs from the scanned layout")
            if plan.padding:
                pad = self.file_handle.read(1)
                if len(pad) != 1 or len(self.file_handle.read(pad[0])) != pad[0]:
                    raise UnsafeModelError("joblib array padding is truncated")
            data = self.file_handle.read(plan.nbytes)
            if len(data) != plan.nbytes:
                raise UnsafeModelError("joblib array data is truncated")
            array = np.frombuffer(data, dtype=dtype).copy()
            array = array.reshape(plan.shape[::-1]).T if plan.order == "F" else array.reshape(plan.shape)
            if not array.dtype.isnative:
                array = array.byteswap().view(array.dtype.newbyteorder("="))
        self.stack[-1] = array

    dispatch[pickle.BUILD[0]] = load_build


def load_joblib(path: str, allowed: frozenset[tuple[str, str]]) -> Any:
    """Read a joblib file (compressed or not) with the restricted joblib reader."""
    import io

    with open(path, "rb") as fh:
        data = fh.read()
    try:
        _codec, inner = decompress.open_container(data)
    except decompress.DecompressionRefused as exc:
        raise UnsafeModelError(str(exc)) from exc
    return RestrictedJoblibUnpickler(io.BytesIO(inner), allowed).load()


def load_torch(path: str, extra: Iterable[tuple[str, str]] = (), **kwargs) -> Any:
    """torch.load(weights_only=True). ``extra``: exact pairs the scan cleared (static/clearance.py),
    added only for this call through torch.serialization.safe_globals."""
    try:
        import torch
    except ImportError as exc:
        raise ImportError("loading a PyTorch file needs the 'torch' package") from exc
    kwargs["weights_only"] = True
    extra = sorted(set(extra))
    if not extra:
        return torch.load(path, **kwargs)
    import importlib

    objects = []
    for module, name in extra:
        value = importlib.import_module(module)
        for part in name.split("."):
            value = getattr(value, part)
        objects.append(value)
    with torch.serialization.safe_globals(objects):
        return torch.load(path, **kwargs)


def cleared_pairs(report) -> frozenset[tuple[str, str]]:
    """Pairs outside the allowlist that the scan's static layers accepted (only referenced,
    state-only by policy, ...): the restricted loaders must resolve them too."""
    pairs = set()
    for layer in report.layers:
        for entry in (layer.details or {}).get("cleared") or []:
            pairs.add(tuple(entry["pair"]))
    return frozenset(pairs)


def load_keras(path: str, **kwargs) -> Any:
    try:
        import keras
    except ImportError as exc:
        raise ImportError("loading a Keras file needs the 'keras' package") from exc
    kwargs["safe_mode"] = True
    return keras.saving.load_model(path, **kwargs)


def safe_load(path: str | os.PathLike, *, judge: bool = False, deep: bool = False,
              allow: Iterable[tuple[str, str]] = (),
              accept_unverified: Iterable[str] | Mapping[str, Iterable[str]] | None = None,
              **loader_kwargs) -> Any:
    """Load ``path`` only if ``scan`` says CLEAN, or SUSPICIOUS with only UNVERIFIABLE
    reasons that ``accept_unverified`` names one by one; otherwise raise UnsafeModelError.

    ``accept_unverified`` is a list of items (it applies to this file) or a mapping
    ``{sha256: [items]}`` (only the entry for this file's sha256 applies). There is no
    switch that accepts everything.
    """
    allow = tuple((str(m), str(n)) for m, n in allow)
    name = os.path.basename(os.fspath(path))
    with _private_copy(path) as staged:
        report = scan(staged, judge=judge, deep=deep, allow=allow)
        if not report.clean:
            items = override.items_for(report, accept_unverified)
            if items is not None:
                override.apply(report, items, how="api")
            if not report.accepted:
                refused = (report.override or {}).get("refused_because")
                raise UnsafeModelError(
                    f"{name}: {report.verdict.value}; " + "; ".join(report.reasons[:5])
                    + (f" (override refused: {refused})" if refused else ""),
                    report,
                )
        if _sha256(staged) != report.sha256:
            raise UnsafeModelError("file changed between scan and load", report)
        allow = allow + tuple(override.accepted_pickle_pairs(report)) + tuple(cleared_pairs(report))
        fmt = report.file_format
        if fmt == detect_mod.JOBLIB:
            return load_joblib(staged, PICKLE_GLOBALS | frozenset(allow))
        if fmt == detect_mod.PICKLE:
            allowed = PICKLE_GLOBALS | frozenset(allow)
            if any("legacy PyTorch" in str(n) for n in report.layer("static").details.get("notes", [])):
                return load_torch(staged, cleared_pairs(report), **loader_kwargs)
            return load_pickle(staged, allowed, **loader_kwargs)
        if fmt == detect_mod.TORCH:
            return load_torch(staged, cleared_pairs(report), **loader_kwargs)
        if fmt == detect_mod.KERAS:
            return load_keras(staged, **loader_kwargs)
        raise UnsafeModelError(f"no loader for format {fmt!r}", report)


__all__ = ["RestrictedJoblibUnpickler", "RestrictedUnpickler", "UnsafeModelError", "load_joblib", "load_keras",
           "load_pickle", "load_torch",
           "safe_load", "scan"]
