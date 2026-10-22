"""Seed inputs for the fuzz targets: small valid files of each format, built with the
standard library here or committed under ``fuzz/seeds/<target>/`` (joblib files written
by ``fuzz/make_seeds.py``). Seeds are only read as bytes."""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import pickle
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _files(*folders: str) -> list[bytes]:
    out = []
    for folder in folders:
        if os.path.isdir(folder):
            for name in sorted(os.listdir(folder)):
                with open(os.path.join(folder, name), "rb") as fh:
                    out.append(fh.read())
    return out


def _pickles() -> list[bytes]:
    data = {"a": [1, 2.5, "x", b"y", None, True], "b": (1, 2), "c": {3, 4}, "d": bytearray(b"z")}
    return [pickle.dumps(data, protocol=p) for p in range(6)] + [b"N.", b"\x80\x05K\x01.", b"(lp0\nI1\na."]


def _zip(members: dict[str, bytes], method=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _compressed(raw: bytes) -> list[bytes]:
    out = [zlib.compress(raw), gzip.compress(raw, mtime=0), bz2.compress(raw), lzma.compress(raw),
           lzma.compress(raw, format=lzma.FORMAT_ALONE)]
    body = zlib.compress(raw)
    out.append(b"ZF" + hex(len(raw)).encode().ljust(19) + body)  # joblib < 0.10 container
    return out


def seeds_for(target: str) -> list[bytes]:
    own = os.path.join(HERE, "seeds", target)
    if target == "pickle":
        return _pickles() + _files(own)
    if target == "zipsafe":
        p = _pickles()[2]
        return [_zip({"archive/data.pkl": p, "archive/version": b"3\n"}),
                _zip({"config.json": b"{}", "model.weights.h5": b"\x89HDF"}, zipfile.ZIP_STORED)]
    if target == "hdf5":
        return _files(os.path.join(ROOT, "tests", "fixtures", "h5"))
    if target == "joblib_layout":
        return [bytes(range(256)), b"\x01" * 64, b"\x07\x03\x00\x02f8"]
    if target == "decompress":
        return [s for raw in _pickles()[2:4] + _files(os.path.join(HERE, "seeds", "pickle"))[:2]
                for s in _compressed(raw)]
    raise KeyError(target)
