"""Defensive reading of ZIP containers (.keras, PyTorch zip).

Nothing here interprets member contents. The module only answers "which members
exist" and "give me the bytes of this one member", and refuses when the archive
looks crafted: too many members, names that escape the archive root, duplicate
names, data in front of the first local header (polyglot files), encrypted
members, or members whose declared size or compression ratio is out of bounds.

Limits are checked against the central directory BEFORE anything is
decompressed, and the read itself is capped again, so a lying header cannot
make us allocate more than ``max_member_bytes``.
"""
from __future__ import annotations

import io
import posixpath
import zipfile
import zlib
from dataclasses import dataclass, field

DEFAULT_MAX_MEMBERS = 10_000
DEFAULT_MAX_MEMBER_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_RATIO = 200

ZIP_MAGIC = b"PK\x03\x04"


class ZipRefused(Exception):
    """The archive (or one member) is refused; the message says why."""


@dataclass
class ZipInventory:
    names: list[str]
    problems: list[str] = field(default_factory=list)
    leading_bytes: int = 0


def _name_problem(name: str) -> str | None:
    if not name:
        return "empty member name"
    if "\x00" in name:
        return f"member name contains NUL: {name!r}"
    if "\\" in name:
        return f"member name contains a backslash: {name!r}"
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        return f"absolute member name: {name!r}"
    parts = name.split("/")
    if ".." in parts:
        return f"member name escapes the archive root: {name!r}"
    if posixpath.normpath(name).startswith(".."):
        return f"member name escapes the archive root: {name!r}"
    return None


class SafeZip:
    """Read-only view of a ZIP held in memory, with limits."""

    def __init__(
        self,
        data: bytes,
        *,
        max_members: int = DEFAULT_MAX_MEMBERS,
        max_member_bytes: int = DEFAULT_MAX_MEMBER_BYTES,
        max_ratio: int = DEFAULT_MAX_RATIO,
    ) -> None:
        self.max_member_bytes = max_member_bytes
        self.max_ratio = max_ratio
        try:
            self._zf = zipfile.ZipFile(io.BytesIO(data))
        except (zipfile.BadZipFile, ValueError, OSError) as exc:
            raise ZipRefused(f"not a valid ZIP archive: {exc}") from exc

        infos = self._zf.infolist()
        if len(infos) > max_members:
            raise ZipRefused(f"archive has {len(infos)} members (limit {max_members})")

        problems: list[str] = []
        seen: set[str] = set()
        for info in infos:
            problem = _name_problem(info.filename)
            if problem:
                problems.append(problem)
            if info.filename in seen:
                problems.append(f"duplicate member name: {info.filename!r}")
            seen.add(info.filename)
            if info.flag_bits & 0x1:
                problems.append(f"encrypted member: {info.filename!r}")

        leading = min((i.header_offset for i in infos), default=0)
        if leading > 0:
            problems.append(f"{leading} bytes of data before the first ZIP entry (polyglot file)")

        self._infos = {i.filename: i for i in infos}
        self.crc_mismatches: dict[str, tuple[int, int]] = {}
        self.inventory = ZipInventory(names=[i.filename for i in infos], problems=problems,
                                      leading_bytes=leading)

    def __enter__(self) -> SafeZip:
        return self

    def __exit__(self, *exc) -> None:
        self._zf.close()

    @property
    def names(self) -> list[str]:
        return self.inventory.names

    def size(self, name: str) -> int:
        info = self._infos.get(name)
        if info is None:
            raise ZipRefused(f"member not found: {name!r}")
        return info.file_size

    def head(self, name: str, n: int) -> bytes:
        """The first ``n`` bytes of one member (no size limit applies to a head read)."""
        info = self._infos.get(name)
        if info is None:
            raise ZipRefused(f"member not found: {name!r}")
        try:
            with self._zf.open(info) as fh:
                return fh.read(n)
        except (zipfile.BadZipFile, OSError, EOFError, NotImplementedError, RuntimeError) as exc:
            raise ZipRefused(f"member {name!r} cannot be read: {exc}") from exc

    def read(self, name: str, *, ignore_crc: bool = False) -> bytes:
        """Bytes of one member, refused if it is too large or too compressed.

        ``ignore_crc=True`` reads a member whose CRC-32 does not match the archive
        instead of refusing it, and records the mismatch in ``crc_mismatches`` (name ->
        (recorded, computed)). Use it only for a reader that does not check CRC-32
        either (PyTorch's), so that the bytes that reader would use get analysed."""
        info = self._infos.get(name)
        if info is None:
            raise ZipRefused(f"member not found: {name!r}")
        if info.file_size > self.max_member_bytes:
            raise ZipRefused(
                f"member {name!r} declares {info.file_size} bytes "
                f"(limit {self.max_member_bytes})"
            )
        if info.compress_size and info.file_size / info.compress_size > self.max_ratio:
            raise ZipRefused(
                f"member {name!r} compression ratio "
                f"{info.file_size // max(info.compress_size, 1)}:1 exceeds {self.max_ratio}:1"
            )
        out = bytearray()
        try:
            with self._zf.open(info) as fh:
                if ignore_crc:
                    if not hasattr(fh, "_expected_crc"):
                        raise ZipRefused(f"member {name!r}: cannot read without the CRC-32 check here")
                    fh._expected_crc = None  # checked below, against the same recorded value
                while chunk := fh.read(1 << 20):
                    out += chunk
                    if len(out) > self.max_member_bytes:
                        raise ZipRefused(f"member {name!r} exceeds {self.max_member_bytes} bytes")
        except (zipfile.BadZipFile, OSError, EOFError, NotImplementedError, RuntimeError) as exc:
            raise ZipRefused(f"member {name!r} cannot be read: {exc}") from exc
        if ignore_crc:
            computed = zlib.crc32(out) & 0xFFFFFFFF
            if computed != info.CRC:
                self.crc_mismatches[name] = (info.CRC, computed)
        return bytes(out)
