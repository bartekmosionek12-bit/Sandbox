"""The pinned CPython-on-WASI runtime used by safeloadai's sandbox, as package data.

This package only ships the file. It never downloads anything, at install time or
at run time, and it does not verify the file itself: safeloadai checks the
SHA-256 against its own pinned copy of ``SHA256`` every time it loads the runtime.
"""
from __future__ import annotations

from pathlib import Path

__version__ = "0.1.0"

PYTHON_VERSION = "3.12.0"
FILE_NAME = "python-3.12.0.wasm"
SHA256 = "e5dc5a398b07b54ea8fdb503bf68fb583d533f10ec3f930963e02b9505f7a763"
SIZE = 26_267_204
SOURCE_URL = (
    "https://github.com/vmware-labs/webassembly-language-runtimes/releases/download/"
    "python%2F3.12.0%2B20231211-040d5a6/python-3.12.0.wasm"
)
BUILD = "VMware Wasm Labs webassembly-language-runtimes, python/3.12.0+20231211-040d5a6"


def path() -> Path:
    """Location of the bundled ``.wasm`` file (it may be missing in a broken install)."""
    return Path(__file__).resolve().with_name(FILE_NAME)


__all__ = ["BUILD", "FILE_NAME", "PYTHON_VERSION", "SHA256", "SIZE", "SOURCE_URL", "path"]
