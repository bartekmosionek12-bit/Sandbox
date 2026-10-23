"""Fuzz targets for safeloadai's own parsers (0.8.0).

Each target takes arbitrary bytes and drives one parser the way the scanner does. A
target fails (raises ``FuzzFinding`` or lets an exception escape) only when the parser
does something it promises not to:

* ``pickle``: the static pickle walker (``parse_pickle``, joblib layout on). It must
  return a report for any bytes, and an exception it does not expect is recorded as a
  tool error (E201); both an escaping exception and an E201 are findings.
* ``zipsafe``: ``SafeZip`` and its member reads may only raise ``ZipRefused``.
* ``hdf5``: the HDF5 metadata reader (``hdf5_meta.read_metadata``, which runs inside
  the WASI sandbox in a scan) may only raise ``Refused``.
* ``joblib_layout``: ``joblib_layout.plan`` on a wrapper state decoded from the bytes
  may only raise ``LayoutError``.
* ``decompress``: ``open_container`` and ``decompress`` for every codec may only raise
  ``DecompressionRefused``, and never return more than the output limit.

Nothing here loads or deserializes anything: these are safeloadai's own readers, which
only parse. The fuzz runner (``fuzz/run.py``) and the tests keep the host-execution
guard on all the same.
"""
from __future__ import annotations

import io
import os

from safeloadai.parsing import decompress as decompress_mod
from safeloadai.parsing.zipsafe import SafeZip, ZipRefused
from safeloadai.shared import hdf5_meta, joblib_layout
from safeloadai.static.pickle_static import parse_pickle

REGRESSIONS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "regressions")


def regression_inputs(target: str) -> list[str]:
    """Saved inputs a fuzzing run found for ``target`` (replayed by tests/test_fuzz.py)."""
    folder = os.path.join(REGRESSIONS, target)
    return sorted(os.path.join(folder, n) for n in os.listdir(folder)) if os.path.isdir(folder) else []


class FuzzFinding(AssertionError):
    """A parser broke its contract on this input."""


def fuzz_pickle(data: bytes) -> None:
    report = parse_pickle(data, "fuzz.pkl")
    if report.get("tool_errors"):
        raise FuzzFinding(f"pickle walker tool error: {report['tool_errors'][0]['message']}")


def fuzz_zipsafe(data: bytes) -> None:
    try:
        with SafeZip(data, max_member_bytes=1 << 20) as archive:
            for name in archive.names[:8]:
                archive.size(name)
                archive.head(name, 64)
                archive.read(name, ignore_crc=True)
    except ZipRefused:
        pass


def fuzz_hdf5(data: bytes) -> None:
    try:
        hdf5_meta.read_metadata(io.BytesIO(data), len(data))
    except hdf5_meta.Refused:
        pass


class _Bytes:
    """A tiny deterministic decoder: turns fuzz bytes into small structured values."""

    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def byte(self) -> int:
        if self.pos >= len(self.data):
            return 0
        self.pos += 1
        return self.data[self.pos - 1]

    def pick(self, options):
        return options[self.byte() % len(options)]

    def integer(self) -> int:
        return self.pick([0, 1, 2, 3, 8, -1, 2**31, 2**63, -(2**63)]) if self.byte() & 1 else self.byte()

    def text(self) -> str:
        return self.pick(["f8", "<f8", ">i4", "|b1", "<U3", "|O", "V8", "|V0", "<c16", "", "x", "<M8", "|S5"])

    def value(self, depth: int = 0):
        kind = self.byte() % (8 if depth < 3 else 4)
        if kind == 0:
            return None
        if kind == 1:
            return self.integer()
        if kind == 2:
            return self.text()
        if kind == 3:
            return self.pick([True, False, 1.5])
        if kind in (4, 5):
            return tuple(self.value(depth + 1) for _ in range(self.byte() % 10))
        if kind == 6:
            return {self.text(): self.value(depth + 1) for _ in range(self.byte() % 4)}
        return self.dtype(depth + 1)

    def dtype(self, depth: int = 0):
        """(descr, state) shaped like what ``pickle_vm.dtype_value`` returns, mostly valid."""
        version = self.pick([3, 4, 4, 5])
        state = [version, self.pick(["<", ">", "|", "=", "?"]),
                 self.value(depth) if self.byte() & 1 else None,
                 tuple(self.text() for _ in range(self.byte() % 3)) if self.byte() & 1 else None,
                 self.value(depth) if self.byte() & 1 else None,
                 self.integer(), self.integer(), self.integer()]
        if version == 4:
            state.append(self.integer())
        return self.text(), tuple(state)


def _layout_dtype(value):
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[1], tuple):
        return value
    raise joblib_layout.LayoutError("not a dtype value")


def fuzz_joblib_layout(data: bytes) -> None:
    source = _Bytes(data)
    attrs = {}
    for key in ("shape", "order", "dtype", "numpy_array_alignment_bytes", "subclass", "allow_mmap"):
        if source.byte() % 8:
            attrs[key] = {"order": lambda: source.pick(["C", "F", "K"]), "dtype": source.dtype,
                          "shape": lambda: tuple(source.integer() for _ in range(source.byte() % 5))
                          }.get(key, source.value)()
    try:
        joblib_layout.plan(attrs if source.byte() % 16 else source.value(), _layout_dtype, _layout_dtype)
    except joblib_layout.LayoutError:
        pass


def fuzz_decompress(data: bytes) -> None:
    limit = 1 << 20
    try:
        _, inner = decompress_mod.open_container(data, max_output=limit)
        if len(inner) > max(limit, len(data)):
            raise FuzzFinding(f"open_container returned {len(inner)} bytes over the {limit}-byte limit")
    except decompress_mod.DecompressionRefused:
        pass
    for codec in ("zlib", "gzip", "bz2", "lzma", "xz", "lz4"):
        try:
            out = decompress_mod.decompress(data, codec, max_output=limit)
            if len(out) > limit:
                raise FuzzFinding(f"{codec}: {len(out)} bytes over the {limit}-byte limit")
        except decompress_mod.DecompressionRefused:
            pass


TARGETS = {
    "pickle": fuzz_pickle,
    "zipsafe": fuzz_zipsafe,
    "hdf5": fuzz_hdf5,
    "joblib_layout": fuzz_joblib_layout,
    "decompress": fuzz_decompress,
}
