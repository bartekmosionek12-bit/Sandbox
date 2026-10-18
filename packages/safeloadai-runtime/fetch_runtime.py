"""Build-time step: download the pinned WASI runtime into the package source tree.

    python packages/safeloadai-runtime/fetch_runtime.py

This is the only place the ``.wasm`` is ever downloaded. It runs before
``python -m build`` (by a release or CI job, never by pip at install time). The
download is written to a temporary file, checked against the pinned size and
SHA-256, and moved into place only if both match; any mismatch exits non-zero
so the build fails. The build backend (``_build_backend.py``) checks the file
again and never downloads.
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "src"))

import safeloadai_runtime as spec  # noqa: E402

TARGET = HERE / "src" / "safeloadai_runtime" / spec.FILE_NAME


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(path: Path) -> str | None:
    """None if ``path`` is the pinned runtime, else what is wrong with it."""
    if not path.is_file():
        return f"{path} does not exist"
    size = path.stat().st_size
    if size != spec.SIZE:
        return f"{path} is {size} bytes, expected {spec.SIZE}"
    actual = sha256_file(path)
    if actual != spec.SHA256:
        return f"{path} has sha256 {actual}, expected {spec.SHA256}"
    return None


def fetch(target: Path = TARGET) -> None:
    if verify(target) is None:
        print(f"ok    {target} already matches sha256 {spec.SHA256}")
        return
    fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=".download-", suffix=".wasm")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(spec.SOURCE_URL, timeout=120) as resp:  # noqa: S310
            received = 0
            while chunk := resp.read(1 << 20):
                received += len(chunk)
                if received > spec.SIZE:
                    raise SystemExit(f"download is larger than the pinned {spec.SIZE} bytes; refusing")
                out.write(chunk)
        problem = verify(tmp)
        if problem:
            raise SystemExit(f"downloaded runtime rejected: {problem}")
        os.replace(tmp, target)
        print(f"ok    {target} sha256 {spec.SHA256}")
    finally:
        tmp.unlink(missing_ok=True)


if __name__ == "__main__":
    fetch()
