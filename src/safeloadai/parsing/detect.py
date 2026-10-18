"""Format detection by content, not by file extension.

The extension is only a hint. A mismatch between what the name says and what the
bytes are is reported, because a ``.keras`` that is really a pickle (or the other
way round) is either broken or crafted.
"""
from __future__ import annotations

import os

from . import decompress
from .zipsafe import ZIP_MAGIC, SafeZip, ZipRefused

HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"

PICKLE = "pickle"
JOBLIB = "joblib"
TORCH = "torch"
KERAS = "keras"
H5 = "h5"
UNKNOWN = "unknown"

EXTENSION_HINTS = {
    ".pkl": {PICKLE, JOBLIB},
    ".pickle": {PICKLE, JOBLIB},
    ".joblib": {PICKLE, JOBLIB},
    ".pt": {TORCH, PICKLE},
    ".pth": {TORCH, PICKLE},
    ".bin": {TORCH, PICKLE},
    ".keras": {KERAS},
    ".h5": {H5},
    ".hdf5": {H5},
}

SUPPORTED_EXTENSIONS = tuple(EXTENSION_HINTS)


def _looks_like_pickle(data: bytes) -> bool:
    # Protocol 2+ starts with PROTO; protocol 0/1 starts with an opcode such as
    # '(' MARK, ']' EMPTY_LIST, '}' EMPTY_DICT, 'c' GLOBAL, 'I'/'K' ints...
    return bool(data) and (data[:1] == b"\x80" or data[:1] in b"(]}ccIKJLSVXNF)\x88\x89.")


def detect(data: bytes) -> str:
    """Container format of the bytes: pickle, joblib (compressed), torch, keras, h5 or unknown.

    An uncompressed joblib file is a pickle stream; the pickle walker reports it as
    joblib once it meets joblib's array wrappers.
    """
    if data.startswith(HDF5_MAGIC):
        return H5
    if data.startswith(ZIP_MAGIC) or b"PK\x05\x06" in data[-65_557:]:
        try:
            with SafeZip(data) as zf:
                names = zf.names
        except ZipRefused:
            return UNKNOWN
        if "config.json" in names or "model.json" in names:
            return KERAS
        if any(n == "data.pkl" or n.endswith("/data.pkl") for n in names):
            return TORCH
        return UNKNOWN
    if decompress.detect(data) is not None:
        return JOBLIB
    if _looks_like_pickle(data):
        return PICKLE
    return UNKNOWN


def extension_mismatch(path: str, detected: str) -> str | None:
    """A note when the extension promises a different format than the bytes."""
    ext = os.path.splitext(path)[1].lower()
    expected = EXTENSION_HINTS.get(ext)
    if expected is None or detected in expected:
        return None
    return f"file extension {ext!r} does not match its content (detected: {detected})"
