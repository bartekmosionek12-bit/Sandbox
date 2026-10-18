"""joblib's compressed containers, decompressed in a streaming way with hard limits.

Detection mirrors ``joblib.numpy_pickle_utils._detect_compressor``: the legacy ``ZF``
prefix first, then the registered compressors in joblib's order (zlib, gzip, bz2,
lzma, xz, lz4), each by its magic prefix. Decompression is the standard library's
C codecs (lz4 only when the optional ``lz4`` package is installed). It is not
deserialisation: the output is only handed to the pickle walker and the sandbox.

Limits, checked while decompressing (never after):

* output at most ``max_output`` bytes;
* once the output passes ``ratio_floor`` bytes, output/input at most ``max_ratio``;
* xz/lzma decoders get a memory limit for their dictionary;
* exactly one compressed stream: data after its end is refused (joblib writes one,
  and a second stream is a place where readers could disagree).
"""
from __future__ import annotations

import bz2
import lzma
import zlib

DEFAULT_MAX_OUTPUT = 1024 * 1024 * 1024
DEFAULT_MAX_RATIO = 1000
DEFAULT_RATIO_FLOOR = 1024 * 1024
LZMA_MEMLIMIT = 256 * 1024 * 1024
CHUNK_IN = 64 * 1024
CHUNK_OUT = 1024 * 1024

ZFILE_PREFIX = b"ZF"
ZFILE_HEADER = 2 + 19  # "ZF" + hex length padded to len(hex(2**64))

# (name, magic) in joblib's registration order.
COMPRESSORS = (
    ("zlib", b"\x78"),
    ("gzip", b"\x1f\x8b"),
    ("bz2", b"BZ"),
    ("lzma", b"\x5d\x00"),
    ("xz", b"\xfd\x37\x7a\x58\x5a"),
    ("lz4", b"\x04\x22\x4d\x18"),
)


class DecompressionRefused(Exception):
    """The container is refused; the message says why."""


class Unsupported(DecompressionRefused):
    """A codec this installation cannot decode (lz4 without the lz4 package)."""


def detect(data: bytes) -> str | None:
    """'compat', a compressor name, or None for an uncompressed file."""
    if data.startswith(ZFILE_PREFIX):
        return "compat"
    for name, magic in COMPRESSORS:
        if data.startswith(magic):
            return name
    return None


def _decompressor(name: str):
    if name == "zlib":
        return zlib.decompressobj(zlib.MAX_WBITS)
    if name == "gzip":
        return zlib.decompressobj(31)
    if name == "bz2":
        return bz2.BZ2Decompressor()
    if name == "lzma":
        return lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=LZMA_MEMLIMIT)
    if name == "xz":
        return lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=LZMA_MEMLIMIT)
    if name == "lz4":
        try:
            import lz4.frame
        except ImportError as exc:
            raise Unsupported("lz4-compressed joblib file, but the optional 'lz4' package is not installed "
                              "(pip install 'safeloadai[lz4]'); not analysed") from exc
        return lz4.frame.LZ4FrameDecompressor()
    raise DecompressionRefused(f"unknown compressor {name!r}")


def _pull(d, name: str, data: bytes) -> bytes:
    """Decompress ``data`` (may be empty) with at most CHUNK_OUT bytes of output."""
    if name in ("zlib", "gzip"):
        return d.decompress(data, CHUNK_OUT)
    return d.decompress(data, max_length=CHUNK_OUT)


def _more_pending(d, name: str) -> bool:
    if name in ("zlib", "gzip"):
        return bool(d.unconsumed_tail)
    return not d.needs_input and not d.eof


def decompress(data: bytes, name: str, *, max_output: int | None = None, max_ratio: int | None = None,
               ratio_floor: int | None = None, expected_size: int | None = None) -> bytes:
    """Decompress one complete stream of codec ``name`` within the limits
    (module defaults, read at call time, for any limit not given)."""
    max_output = DEFAULT_MAX_OUTPUT if max_output is None else max_output
    max_ratio = DEFAULT_MAX_RATIO if max_ratio is None else max_ratio
    ratio_floor = DEFAULT_RATIO_FLOOR if ratio_floor is None else ratio_floor
    try:
        d = _decompressor(name)
    except (lzma.LZMAError, ValueError) as exc:
        raise DecompressionRefused(f"{name}: {exc}") from exc
    cap = max_output if expected_size is None else min(max_output, expected_size)
    out = bytearray()
    consumed = 0

    def take(chunk: bytes) -> None:
        out.extend(chunk)
        if len(out) > cap:
            if expected_size is not None and len(out) > expected_size:
                raise DecompressionRefused(f"{name}: output exceeds the declared {expected_size} bytes")
            raise DecompressionRefused(f"{name}: output exceeds {max_output} bytes (decompression bomb limit)")
        if len(out) > ratio_floor and len(out) > max_ratio * max(consumed, 1):
            raise DecompressionRefused(
                f"{name}: compression ratio above {max_ratio}:1 after {len(out)} bytes (decompression bomb limit)")

    try:
        pos = 0
        while pos < len(data) and not d.eof:
            block = data[pos:pos + CHUNK_IN]
            pos += len(block)
            consumed = pos
            take(_pull(d, name, block))
            while _more_pending(d, name) and not d.eof:
                tail = d.unconsumed_tail if name in ("zlib", "gzip") else b""
                take(_pull(d, name, tail))
        while _more_pending(d, name) and not d.eof:
            take(_pull(d, name, d.unconsumed_tail if name in ("zlib", "gzip") else b""))
    except DecompressionRefused:
        raise
    except (zlib.error, OSError, EOFError, lzma.LZMAError, ValueError, RuntimeError) as exc:
        raise DecompressionRefused(f"{name}: corrupt compressed data: {type(exc).__name__}: {exc}") from exc
    if not d.eof:
        raise DecompressionRefused(f"{name}: compressed stream is truncated (no end of stream)")
    trailing = len(d.unused_data or b"") + (len(data) - pos)
    if trailing:
        raise DecompressionRefused(f"{name}: {trailing} bytes after the end of the compressed stream")
    return bytes(out)


def open_container(data: bytes, **limits) -> tuple[str | None, bytes]:
    """(codec, pickle bytes) for a joblib file; (None, data) if it is not compressed."""
    name = detect(data)
    if name is None:
        return None, data
    if name == "compat":
        header = data[2:ZFILE_HEADER].decode("ascii", "replace").strip()
        try:
            length = int(header, 16)
        except ValueError as exc:
            raise DecompressionRefused(f"legacy joblib ZF header without a valid length: {header!r}") from exc
        body = data[ZFILE_HEADER:]
        if body.startswith(b" "):
            body = body[1:]
        inner = decompress(body, "zlib", expected_size=length, **limits)
        if len(inner) != length:
            raise DecompressionRefused(f"legacy joblib ZF data is {len(inner)} bytes, header says {length}")
        return name, inner
    return name, decompress(data, name, **limits)
