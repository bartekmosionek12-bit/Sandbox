"""Locating and pinning the CPython-on-WASI runtime used by the sandbox.

The library never downloads anything by itself. The runtime is looked up at
``$SAFELOADAI_WASI_PYTHON`` or in the user cache directory, and is used only if
its SHA-256 matches the pinned value below. Distribution of the runtime is an
open owner decision (DECISIONS.md, D3).

Compiled modules are cached because compiling the 26 MB runtime takes seconds
(AUDIT.md section 5). A compiled module is native code that wasmtime loads
without verification, so the cache is used only when the directory is owned by
the current user and not writable by anyone else; otherwise we compile in memory.
"""
from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

RUNTIME_ENV = "SAFELOADAI_WASI_PYTHON"
HOME_ENV = "SAFELOADAI_HOME"


@dataclass(frozen=True)
class RuntimeSpec:
    name: str
    python_version: str
    file_name: str
    sha256: str
    size: int
    source_url: str


# Measured in the audit (AUDIT.md section 5). Used for development and tests until
# D3 settles how a pinned build ships.
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
)


class RuntimeUnavailable(RuntimeError):
    """No verified runtime is available, so the dynamic layer cannot run."""


def home_dir() -> Path:
    base = os.environ.get(HOME_ENV)
    if base:
        return Path(base).expanduser()
    xdg = os.environ.get("XDG_CACHE_HOME")
    return (Path(xdg) if xdg else Path.home() / ".cache") / "safeloadai"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def locate(spec: RuntimeSpec = PINNED) -> Path:
    """Path to a runtime whose hash matches ``spec``, or RuntimeUnavailable."""
    candidates = []
    if os.environ.get(RUNTIME_ENV):
        candidates.append(Path(os.environ[RUNTIME_ENV]).expanduser())
    candidates.append(home_dir() / "runtime" / spec.file_name)
    for path in candidates:
        if not path.is_file():
            continue
        actual = sha256_file(path)
        if actual != spec.sha256:
            raise RuntimeUnavailable(
                f"WASI runtime at {path} has sha256 {actual}, expected {spec.sha256}"
            )
        return path
    raise RuntimeUnavailable(
        f"no WASI runtime found (set {RUNTIME_ENV} or place {spec.file_name} in "
        f"{home_dir() / 'runtime'}); expected sha256 {spec.sha256}"
    )


def private_dir(path: Path) -> bool:
    """True if ``path`` exists, is ours and is not writable by group or others."""
    try:
        st = path.stat()
    except OSError:
        return False
    if not stat.S_ISDIR(st.st_mode):
        return False
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        return False
    return not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


def compiled_cache_dir() -> Path | None:
    """Directory for compiled modules, created 0700, or None if it is not private."""
    path = home_dir() / "compiled"
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        return None
    return path if private_dir(path) and private_dir(path.parent) else None
