"""Locating and verifying the CPython-on-WASI runtime used by the sandbox.

The runtime ships as the separate package ``safeloadai-runtime`` (installed as a
pinned dependency of safeloadai). The library never downloads anything.

Resolution order:

1. ``$SAFELOADAI_WASI_PYTHON`` (development override). When it is set it is the
   only candidate: a missing file there is not silently replaced by another one.
2. ``safeloadai_runtime.path()``.

Every time the runtime is loaded its SHA-256 is checked against ``PINNED`` below,
which is safeloadai's own copy of the hash (not the runtime package's). A mismatch
raises :class:`RuntimeIntegrityError` and the scan is refused; it never degrades to
a verdict. A missing runtime raises :class:`RuntimeUnavailable`, which the sandbox
turns into a SUSPICIOUS emulation layer. The verified hash is cached per process,
keyed by (path, size, mtime, inode), so repeated scans do not rehash 26 MB. The
runner child process hashes the bytes it actually compiles once more, which closes
the window between this check and the read.

Compiled modules are cached because compiling the 26 MB runtime takes seconds
(AUDIT.md section 5). A compiled module is native code that wasmtime loads
without verification, so the cache is used only when the directory is owned by
the current user and not writable by anyone else; otherwise we compile in memory.
The cache lives in the platform's per-user cache directory (see
:func:`cache_candidates`); when one candidate cannot be created, written or is not
private, the next one is tried, and the errors are kept for ``safeloadai doctor``.
"""
from __future__ import annotations

import getpass
import hashlib
import os
import re
import stat
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

RUNTIME_ENV = "SAFELOADAI_WASI_PYTHON"
HOME_ENV = "SAFELOADAI_HOME"
RUNTIME_PACKAGE = "safeloadai-runtime"
RUNTIME_MODULE = "safeloadai_runtime"


@dataclass(frozen=True)
class RuntimeSpec:
    name: str
    python_version: str
    file_name: str
    sha256: str
    size: int
    source_url: str
    package_version: str


PINNED = RuntimeSpec(
    name="CPython 3.12.0 for WASI (VMware Wasm Labs build 20231211-040d5a6)",
    python_version="3.12.0",
    file_name="python-3.12.0.wasm",
    sha256="e5dc5a398b07b54ea8fdb503bf68fb583d533f10ec3f930963e02b9505f7a763",
    size=26_267_204,
    source_url=(
        "https://github.com/vmware-labs/webassembly-language-runtimes/releases/download/"
        "python%2F3.12.0%2B20231211-040d5a6/python-3.12.0.wasm"
    ),
    package_version="0.1.0",
)


class RuntimeUnavailable(RuntimeError):
    """No runtime is installed, so the dynamic layer cannot run (scans fail closed)."""


class RuntimeIntegrityError(RuntimeError):
    """The runtime file does not match the pinned SHA-256. Scanning is refused."""


_verified: dict[tuple, str] = {}
_lock = threading.Lock()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def candidate() -> tuple[Path, str]:
    """(path, source) of the runtime to use; source is "env" or "package"."""
    override = os.environ.get(RUNTIME_ENV)
    if override:
        return Path(override).expanduser(), "env"
    try:
        import safeloadai_runtime
    except ImportError as exc:
        raise RuntimeUnavailable(
            f"the {RUNTIME_PACKAGE} package is not installed ({exc}); "
            f"run `safeloadai doctor` for how to fix it"
        ) from exc
    return Path(safeloadai_runtime.path()), "package"


def _cache_key(path: Path, st: os.stat_result) -> tuple:
    return (str(path), st.st_size, st.st_mtime_ns, st.st_ino, st.st_dev)


def verify(path: Path, spec: RuntimeSpec = PINNED, *, source: str = "file") -> None:
    """Raise RuntimeIntegrityError unless ``path`` has the pinned size and SHA-256."""
    path = Path(path)
    st = path.stat()
    key = _cache_key(path, st)
    with _lock:
        if _verified.get(key) == spec.sha256:
            return
    if st.st_size != spec.size:
        raise RuntimeIntegrityError(
            f"WASI runtime at {path} ({source}) is {st.st_size} bytes, expected {spec.size}; "
            "refusing to scan with an unverified runtime (run `safeloadai doctor`)"
        )
    actual = sha256_file(path)
    if actual != spec.sha256:
        raise RuntimeIntegrityError(
            f"WASI runtime at {path} ({source}) has sha256 {actual}, expected {spec.sha256}; "
            "refusing to scan with an unverified runtime (run `safeloadai doctor`)"
        )
    with _lock:
        _verified[key] = actual


def locate(spec: RuntimeSpec = PINNED) -> Path:
    """Path to the verified runtime.

    Raises RuntimeUnavailable when there is none and RuntimeIntegrityError when the
    file exists but is not the pinned one.
    """
    path, source = candidate()
    if not path.is_file():
        where = f"${RUNTIME_ENV}" if source == "env" else f"the {RUNTIME_PACKAGE} package"
        raise RuntimeUnavailable(
            f"no WASI runtime at {path} (from {where}); run `safeloadai doctor` for how to fix it"
        )
    verify(path, spec, source=source)
    return path


def clear_cache() -> None:
    """Forget verified hashes (tests, or after replacing the runtime in-process)."""
    with _lock:
        _verified.clear()


def private_dir(path: Path) -> bool:
    """True if ``path`` exists, is ours and is not writable by group or others."""
    try:
        st = path.stat()
    except OSError:
        return False
    if not stat.S_ISDIR(st.st_mode):
        return False
    if os.name == "nt":
        # Windows permissions are ACLs that os.stat does not report; the cache lives
        # in the user's profile, which is private to that user by default.
        return True
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        return False
    return not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


@dataclass(frozen=True)
class CacheAttempt:
    """A cache location that could not be used, and why."""

    path: Path
    error: str


@dataclass(frozen=True)
class CompiledCache:
    """Where compiled modules go: ``path`` is None when every candidate failed."""

    path: Path | None
    attempts: tuple[CacheAttempt, ...] = ()


def _username() -> str:
    try:
        name = getpass.getuser()
    except Exception:  # noqa: BLE001 - no user name in the environment or the password database
        name = ""
    return re.sub(r"[^A-Za-z0-9._-]", "_", name) or "user"


def cache_candidates(platform: str | None = None) -> list[Path]:
    """Base directories to try for the cache, in order (each gets a ``compiled`` subdirectory).

    ``$SAFELOADAI_HOME`` overrides everything and is then the only candidate.
    Windows: %LOCALAPPDATA%, %APPDATA%, then %TEMP%\\safeloadai-<user> (TEMP is per user
    on Windows). macOS: ~/Library/Caches. Elsewhere: $XDG_CACHE_HOME, then ~/.cache.
    POSIX never falls back to a shared temporary directory.
    """
    override = os.environ.get(HOME_ENV)
    if override:
        return [Path(override).expanduser()]
    platform = platform or sys.platform
    found: list[Path] = []
    if platform == "win32":
        for var in ("LOCALAPPDATA", "APPDATA"):
            if os.environ.get(var):
                found.append(Path(os.environ[var]) / "safeloadai")
        temp = os.environ.get("TEMP") or os.environ.get("TMP")
        if temp:
            found.append(Path(temp) / f"safeloadai-{_username()}")
    elif platform == "darwin":
        found.append(Path.home() / "Library" / "Caches" / "safeloadai")
    else:
        xdg = os.environ.get("XDG_CACHE_HOME")
        if xdg and os.path.isabs(xdg):  # the XDG spec says to ignore a relative path
            found.append(Path(xdg) / "safeloadai")
        found.append(Path.home() / ".cache" / "safeloadai")
    unique: list[Path] = []
    for path in found:
        if path not in unique:
            unique.append(path)
    return unique


def _describe(exc: OSError) -> str:
    return f"{type(exc).__name__} {exc}"


def _try_cache_dir(base: Path) -> tuple[Path | None, str | None]:
    path = base / "compiled"
    try:
        # Both directories the privacy check looks at are created 0700, so a umask such
        # as 002 (Ubuntu's default for users) does not make a fresh cache group-writable.
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.mkdir(exist_ok=True, mode=0o700)
    except OSError as exc:
        return None, _describe(exc)
    if not (private_dir(path) and private_dir(path.parent)):
        return None, "not private: it and its parent must be owned by you and not writable by group or others"
    try:
        fd, probe = tempfile.mkstemp(dir=path, prefix=".probe-")
        os.close(fd)
        os.unlink(probe)
    except OSError as exc:
        return None, _describe(exc)
    return path, None


def compiled_cache_dir() -> CompiledCache:
    """The first usable cache directory (created 0700), with the candidates that failed.

    A directory is usable when it can be created, is private (see :func:`private_dir`)
    and a file can be written in it. With no usable candidate ``path`` is None and
    modules are compiled in memory. The location never affects verdicts: entries are
    keyed by the runtime's sha256, the engine config and the wasmtime version.
    """
    attempts: list[CacheAttempt] = []
    for base in cache_candidates():
        path, error = _try_cache_dir(base)
        if path is not None:
            return CompiledCache(path, tuple(attempts))
        attempts.append(CacheAttempt(base / "compiled", error or "unusable"))
    return CompiledCache(None, tuple(attempts))
