"""Data-only formats: safetensors, GGUF and NumPy ``.npy`` / ``.npz`` without object arrays
(0.9.0). Their loaders run no code from the file: they read a header, then copy bytes into
tensors. A file whose structure is exactly what the format allows is CLEAN with the reason
``data-only format, no code on load``; any inconsistency (offsets, sizes, overflow, data
after the end, a dtype that needs pickle) makes it RISKY, because a file that is not what
it claims to be may be read differently by another loader (and a NumPy object array is a
pickle: ``numpy.load(allow_pickle=True)`` unpickles it).

Everything is read here with ``struct`` and ``json`` (or ``ast.literal_eval`` for the NumPy
header, which is a Python literal); nothing is loaded by a framework. Counts and lengths
in a header are checked against the bytes that are really there before anything is
allocated, and every walk charges the scan's host-memory budget (``budget.py``).

What each loader checks is the reference (sources read, never imported):

* safetensors 0.8.0 ``safetensors/src/tensor.rs``: an 8-byte little-endian header length
  of at most 100,000,000, a JSON object, tensors whose ``data_offsets`` follow each other
  from 0 with no gap, each exactly ``prod(shape) * bitsize / 8`` bytes (a whole number of
  bytes), and a buffer that ends exactly where the last tensor ends.
* GGUF (gguf 0.19.0 ``gguf_reader.py`` and ``constants.py``): magic, version 1 to 3, key and
  value records of 13 value types, tensor records (name, at most 4 dimensions, a GGML type
  with its block and type size, an offset), a data section at the next multiple of
  ``general.alignment`` (a power of two, 32 by default), each tensor at an aligned offset
  inside the file.
* NumPy ``numpy/lib/format.py``: magic, version 1.0, 2.0 or 3.0, a header dict with exactly
  ``descr``, ``fortran_order`` and ``shape``, and ``prod(shape) * itemsize`` bytes of data
  after it. ``.npz`` is a ZIP archive of ``.npy`` members (``numpy.savez``), read with
  the scanner's own ZIP reader and its limits.
"""
from __future__ import annotations

import ast
import json
import math
import re
import struct

from ..parsing.detect import GGUF, NPY, NPY_MAGIC, NPZ, SAFETENSORS, SAFETENSORS_MAX_HEADER
from ..parsing.detect import data_only_format as detect
from . import budget as budget_mod

DATA_ONLY_REASON = "data-only format, no code on load"

# safetensors 0.8.0 Dtype::bitsize
SAFETENSORS_BITS = {
    "BOOL": 8, "F4": 4, "F6_E2M3": 6, "F6_E3M2": 6, "U8": 8, "I8": 8, "F8_E5M2": 8, "F8_E4M3": 8,
    "F8_E8M0": 8, "F8_E4M3FNUZ": 8, "F8_E5M2FNUZ": 8, "I16": 16, "U16": 16, "F16": 16, "BF16": 16,
    "I32": 32, "U32": 32, "F32": 32, "C64": 64, "F64": 64, "I64": 64, "U64": 64,
}

GGUF_DEFAULT_ALIGNMENT = 32
GGUF_MAX_DIMS = 4
GGUF_MAX_NESTING = 8
# gguf 0.19.0 GGUFValueType: type -> struct format of a scalar (8 STRING and 9 ARRAY apart)
GGUF_SCALARS = {0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f", 7: "?", 10: "Q", 11: "q", 12: "d"}
GGUF_STRING, GGUF_ARRAY = 8, 9
QK_K = 256
# gguf 0.19.0 GGML_QUANT_SIZES: GGML type -> (block size, bytes per block)
GGML_SIZES = {
    0: (1, 4), 1: (1, 2), 2: (32, 18), 3: (32, 20), 6: (32, 22), 7: (32, 24), 8: (32, 34), 9: (32, 40),
    10: (256, 2 + 2 + QK_K // 16 + QK_K // 4), 11: (256, 2 + QK_K // 4 + QK_K // 8 + 12),
    12: (256, 2 + 2 + QK_K // 2 + 12), 13: (256, 2 + 2 + QK_K // 2 + QK_K // 8 + 12),
    14: (256, 2 + QK_K // 2 + QK_K // 4 + QK_K // 16), 15: (256, 4 + QK_K + QK_K // 8),
    16: (256, 2 + QK_K // 4), 17: (256, 2 + QK_K // 4 + QK_K // 32), 18: (256, 2 + QK_K // 4 + QK_K // 8),
    19: (256, 2 + QK_K // 8 + QK_K // 16), 20: (32, 18), 21: (256, 2 + QK_K // 4 + QK_K // 8 + QK_K // 32 + 4),
    22: (256, 2 + QK_K // 4 + QK_K // 16), 23: (256, 2 + 2 + QK_K // 2 + QK_K // 64), 24: (1, 1), 25: (1, 2),
    26: (1, 4), 27: (1, 8), 28: (1, 8), 29: (256, QK_K // 8 + QK_K // 16 + QK_K // 32), 30: (1, 2),
    34: (256, 2 + 4 * 13), 35: (256, 2 + 64), 39: (32, 17), 40: (64, 36), 41: (128, 18),
}
# A chat template is Jinja text that chat front ends render; rendered without a sandbox
# (llama-cpp-python before 0.2.72, CVE-2024-34359) it can reach Python. These markers are
# how a template climbs from a value to Python internals or a sink.
TEMPLATE_KEYS = ("tokenizer.chat_template",)
TEMPLATE_INTERNALS = re.compile(r"__(class|mro|base|bases|subclasses|globals|builtins|init|import|getattribute|"
                                r"reduce|reduce_ex|code|dict)__")
TEMPLATE_SINKS = re.compile(r"\b(popen|system|subprocess|__import__|eval|exec|check_output|import_module)\b")

NPY_MAX_HEADER = 10_000  # numpy.lib.format: headers above this need max_header_size (numpy >= 1.24)
NPY_KINDS = re.compile(r"^[<>|=]?([?bBhHiIlLqQpPefdgFDGSUVmMa]|[biufcSUVaOmM]\d+)(\[[A-Za-z0-9]+\])?$")
NPY_SIZES = {"?": 1, "b": 1, "B": 1, "h": 2, "H": 2, "i": 4, "I": 4, "l": 8, "L": 8, "q": 8, "Q": 8, "p": 8,
             "P": 8, "e": 2, "f": 4, "d": 8, "g": 16, "F": 8, "D": 16, "G": 32}
NPY_MAX_FIELDS = 10_000


class Invalid(Exception):
    """The structure is not what the format allows."""


def _charge(amount: int) -> None:
    budget_mod.current().charge(amount)


def _reject_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise Invalid(f"header repeats the key {key!r} (loaders disagree on which one counts)")
        out[key] = value
    return out


# --- safetensors ----------------------------------------------------------------------

def check_safetensors(data: bytes) -> dict:
    """Facts of a valid safetensors file; Invalid otherwise."""
    if len(data) < 8:
        raise Invalid("shorter than the 8-byte header length")
    (n,) = struct.unpack_from("<Q", data, 0)
    if n > SAFETENSORS_MAX_HEADER:
        raise Invalid(f"header length {n} is above safetensors' limit of {SAFETENSORS_MAX_HEADER}")
    if 8 + n > len(data):
        raise Invalid(f"header length {n} runs past the end of the file ({len(data)} bytes)")
    raw = data[8:8 + n]
    if not raw.startswith(b"{"):
        raise Invalid("header does not start with '{'")
    _charge(16 * n)
    try:
        header = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, ValueError) as exc:
        raise Invalid(f"header is not a UTF-8 JSON object: {exc}") from None
    if not isinstance(header, dict):
        raise Invalid("header is not a JSON object")
    metadata = header.pop("__metadata__", None)
    if metadata is not None and not (isinstance(metadata, dict)
                                     and all(isinstance(v, str) for v in metadata.values())):
        raise Invalid("__metadata__ is not a map of strings")
    tensors = []
    for name, info in header.items():
        if not isinstance(info, dict) or set(info) != {"dtype", "shape", "data_offsets"}:
            raise Invalid(f"tensor {name!r}: expected exactly dtype, shape and data_offsets")
        dtype, shape, offsets = info["dtype"], info["shape"], info["data_offsets"]
        if dtype not in SAFETENSORS_BITS:
            raise Invalid(f"tensor {name!r}: unknown dtype {dtype!r}")
        if not (isinstance(shape, list) and all(type(d) is int and d >= 0 for d in shape)):
            raise Invalid(f"tensor {name!r}: shape is not a list of non-negative integers")
        if not (isinstance(offsets, list) and len(offsets) == 2 and all(type(o) is int and o >= 0 for o in offsets)):
            raise Invalid(f"tensor {name!r}: data_offsets is not two non-negative integers")
        bits = math.prod(shape) * SAFETENSORS_BITS[dtype]
        if bits % 8:
            raise Invalid(f"tensor {name!r}: {bits} bits is not a whole number of bytes")
        tensors.append((offsets[0], offsets[1], bits // 8, name))
    tensors.sort()
    position = 0
    for start, end, size, name in tensors:
        if start != position or end < start:
            raise Invalid(f"tensor {name!r}: data_offsets [{start}, {end}] do not follow the previous tensor "
                          f"(expected to start at {position})")
        if end - start != size:
            raise Invalid(f"tensor {name!r}: {end - start} bytes of data for a tensor of {size} bytes")
        position = end
    buffer = len(data) - 8 - n
    if position != buffer:
        if position > buffer:
            raise Invalid(f"tensors need {position} bytes of data, the file has {buffer}")
        raise Invalid(f"{buffer - position} bytes after the last tensor (trailing data)")
    return {"tensors": len(tensors), "header_bytes": n, "data_bytes": buffer}


# --- GGUF -----------------------------------------------------------------------------

class _Reader:
    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def take(self, fmt: str):
        size = struct.calcsize("<" + fmt)
        if self.pos + size > len(self.data):
            raise Invalid(f"record at offset {self.pos} runs past the end of the file")
        value = struct.unpack_from("<" + fmt, self.data, self.pos)
        self.pos += size
        return value[0] if len(value) == 1 else value

    def skip(self, size: int, what: str) -> None:
        if size < 0 or self.pos + size > len(self.data):
            raise Invalid(f"{what} at offset {self.pos} ({size} bytes) runs past the end of the file")
        self.pos += size

    def string(self, len_fmt: str, what: str) -> bytes:
        length = self.take(len_fmt)
        start = self.pos
        self.skip(length, what)
        return self.data[start:self.pos]


def _gguf_value(r: _Reader, vtype: int, count_fmt: str, depth: int, keep: bool):
    if vtype in GGUF_SCALARS:
        value = r.take(GGUF_SCALARS[vtype])
        if vtype == 7 and value not in (0, 1):
            raise Invalid(f"boolean at offset {r.pos - 1} is {value}")
        return value
    if vtype == GGUF_STRING:
        raw = r.string(count_fmt, "string")
        _charge(len(raw) if keep else 0)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise Invalid(f"string ending at offset {r.pos} is not UTF-8") from None
        return text if keep else None
    if vtype == GGUF_ARRAY:
        if depth >= GGUF_MAX_NESTING:
            raise Invalid(f"arrays nested deeper than {GGUF_MAX_NESTING}")
        etype = r.take("I")
        count = r.take(count_fmt)
        if etype in GGUF_SCALARS:
            r.skip(count * struct.calcsize("<" + GGUF_SCALARS[etype]), "array")
            _charge(64)
            return None
        if etype not in (GGUF_STRING, GGUF_ARRAY):
            raise Invalid(f"array of unknown value type {etype}")
        minimum = struct.calcsize("<" + count_fmt) + (4 if etype == GGUF_ARRAY else 0)
        if count * minimum > len(r.data) - r.pos:
            raise Invalid(f"array of {count} items cannot fit in the {len(r.data) - r.pos} bytes left")
        for _ in range(count):
            _charge(budget_mod.OPCODE_COST)
            _gguf_value(r, etype, count_fmt, depth + 1, False)
        return None
    raise Invalid(f"unknown value type {vtype} at offset {r.pos - 4}")


def check_gguf(data: bytes) -> dict:
    """Facts of a valid GGUF file; Invalid otherwise. ``templates`` holds the chat
    templates (strings the caller checks)."""
    r = _Reader(data, 4)
    version = r.take("I")
    if version not in (1, 2, 3):
        raise Invalid(f"GGUF version {version} (1 to 3 are defined)")
    count_fmt = "I" if version == 1 else "Q"
    tensor_count, kv_count = r.take(count_fmt), r.take(count_fmt)
    if kv_count * 12 > len(data) or tensor_count * 24 > len(data):
        raise Invalid(f"{kv_count} key/value and {tensor_count} tensor records cannot fit in {len(data)} bytes")
    alignment = GGUF_DEFAULT_ALIGNMENT
    templates: list[str] = []
    keys = set()
    for _ in range(kv_count):
        _charge(budget_mod.OPCODE_COST)
        try:
            key = r.string(count_fmt, "key").decode("utf-8")
        except UnicodeDecodeError:
            raise Invalid(f"key ending at offset {r.pos} is not UTF-8") from None
        if key in keys:
            raise Invalid(f"key {key!r} appears twice")
        keys.add(key)
        vtype = r.take("I")
        keep = key == "general.alignment" or key in TEMPLATE_KEYS or key.startswith("tokenizer.chat_template.")
        value = _gguf_value(r, vtype, count_fmt, 0, keep)
        if key == "general.alignment":
            if vtype != 4 or not value or value & (value - 1):
                raise Invalid(f"general.alignment is {value!r} (a power of two, as uint32)")
            alignment = value
        elif keep and isinstance(value, str):
            templates.append(value)
    tensors = []
    names = set()
    for _ in range(tensor_count):
        _charge(budget_mod.OPCODE_COST)
        name = r.string(count_fmt, "tensor name")
        if name in names:
            raise Invalid(f"tensor {name!r} appears twice")
        names.add(name)
        n_dims = r.take("I")
        if not 1 <= n_dims <= GGUF_MAX_DIMS:
            raise Invalid(f"tensor {name!r}: {n_dims} dimensions (1 to {GGUF_MAX_DIMS})")
        dims = [r.take(count_fmt) for _ in range(n_dims)]
        ggml_type = r.take("I")
        offset = r.take("Q")
        if ggml_type not in GGML_SIZES:
            raise Invalid(f"tensor {name!r}: unknown GGML type {ggml_type}; its size cannot be verified")
        block, type_size = GGML_SIZES[ggml_type]
        if dims[0] % block:
            raise Invalid(f"tensor {name!r}: first dimension {dims[0]} is not a multiple of the block size {block}")
        size = math.prod(dims[1:]) * (dims[0] // block) * type_size
        if offset % alignment:
            raise Invalid(f"tensor {name!r}: offset {offset} is not a multiple of the alignment {alignment}")
        tensors.append((offset, size, name))
    start = r.pos + (-r.pos % alignment)
    end = start
    for offset, size, name in sorted(tensors):
        if start + offset < end:
            raise Invalid(f"tensor {name!r} at data offset {offset} overlaps the previous tensor")
        end = start + offset + size
        if end > len(data):
            raise Invalid(f"tensor {name!r} ({size} bytes at data offset {offset}) runs past the end of the file")
    if not tensors:
        end = min(start, len(data))
    left = len(data) - end
    if left >= alignment or data[end:].strip(b"\0"):
        raise Invalid(f"{left} bytes after the last tensor (trailing data)")
    return {"version": version, "tensors": tensor_count, "keys": kv_count, "alignment": alignment,
            "templates": templates}


def template_findings(template: str) -> tuple[str | None, bool]:
    """(reason, sink) for a chat template that reaches Python internals, else (None, False)."""
    internals = sorted(set(TEMPLATE_INTERNALS.findall(template)))
    if not internals:
        return None, False
    sinks = sorted(set(TEMPLATE_SINKS.findall(template)))
    reason = ("chat template reaches Python internals (" + ", ".join(f"__{n}__" for n in internals) + ")"
              + (f" and names {', '.join(sinks)}" if sinks else "")
              + "; a front end that renders it without a sandbox runs code (template injection)")
    return reason, bool(sinks)


# --- NumPy ----------------------------------------------------------------------------

def _itemsize(descr, depth: int = 0) -> int:
    """Bytes per item of a NumPy array description; Invalid for an object dtype or a
    description this reader does not know."""
    if depth > 16:
        raise Invalid("dtype nested deeper than 16")
    if isinstance(descr, str):
        if "O" in descr.lstrip("<>|="):
            raise Invalid(f"dtype {descr!r} holds Python objects: loading it unpickles them (allow_pickle)")
        if not NPY_KINDS.match(descr):
            raise Invalid(f"dtype {descr!r} is not one this reader knows")
        body = descr.lstrip("<>|=").split("[", 1)[0]
        if body in NPY_SIZES:
            return NPY_SIZES[body]
        kind, digits = body[0], body[1:]
        if kind in "mM":
            return int(digits or 8)
        if kind == "U":
            return 4 * int(digits)
        return int(digits)
    if isinstance(descr, list):
        if len(descr) > NPY_MAX_FIELDS:
            raise Invalid(f"more than {NPY_MAX_FIELDS} fields")
        total = 0
        names = set()
        for field in descr:
            if not isinstance(field, tuple) or len(field) not in (2, 3):
                raise Invalid(f"field {field!r} is not (name, dtype[, shape])")
            name = field[0][1] if isinstance(field[0], tuple) and len(field[0]) == 2 else field[0]
            if not isinstance(name, str) or name in names:
                raise Invalid(f"field name {field[0]!r} is not a new string")
            names.add(name)
            size = _itemsize(field[1], depth + 1)
            if len(field) == 3:
                shape = field[2] if isinstance(field[2], tuple) else (field[2],)
                if not all(type(d) is int and d >= 0 for d in shape):
                    raise Invalid(f"field {name!r}: shape {field[2]!r}")
                size *= math.prod(shape)
            total += size
        return total
    raise Invalid(f"dtype description {descr!r} is neither a string nor a list of fields")


def check_npy(data: bytes) -> dict:
    """Facts of a valid ``.npy`` without object arrays; Invalid otherwise."""
    if len(data) < 10:
        raise Invalid("shorter than the NumPy magic and header length")
    major, minor = data[6], data[7]
    if (major, minor) not in ((1, 0), (2, 0), (3, 0)):
        raise Invalid(f"format version {major}.{minor} (1.0, 2.0 and 3.0 are defined)")
    if major == 1:
        (hlen,) = struct.unpack_from("<H", data, 8)
        start = 10
    else:
        if len(data) < 12:
            raise Invalid("shorter than the NumPy magic and header length")
        (hlen,) = struct.unpack_from("<I", data, 8)
        start = 12
    if hlen > NPY_MAX_HEADER:
        raise Invalid(f"header of {hlen} bytes (numpy refuses more than {NPY_MAX_HEADER} by default)")
    if start + hlen > len(data):
        raise Invalid("header runs past the end of the file")
    raw = data[start:start + hlen]
    try:
        text = raw.decode("utf-8" if major == 3 else "latin1")
    except UnicodeDecodeError:
        raise Invalid("header is not UTF-8") from None
    if not text.endswith("\n"):
        raise Invalid("header does not end with a newline")
    try:
        header = ast.literal_eval(text.strip())
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        raise Invalid("header is not a Python literal") from None
    if not isinstance(header, dict) or set(header) != {"descr", "fortran_order", "shape"}:
        raise Invalid("header is not a dict of exactly descr, fortran_order and shape")
    if not isinstance(header["fortran_order"], bool):
        raise Invalid("fortran_order is not a boolean")
    shape = header["shape"]
    if not (isinstance(shape, tuple) and all(type(d) is int and d >= 0 for d in shape)):
        raise Invalid(f"shape {shape!r} is not a tuple of non-negative integers")
    size = math.prod(shape) * _itemsize(header["descr"])
    body = len(data) - start - hlen
    if body != size:
        if body < size:
            raise Invalid(f"array needs {size} bytes of data, the file has {body}")
        raise Invalid(f"{body - size} bytes after the array data (trailing data)")
    return {"version": f"{major}.{minor}", "shape": list(shape), "data_bytes": size}


def check_npz(data: bytes) -> dict:
    """Facts of a valid ``.npz`` (a ZIP archive whose members are all valid ``.npy``)."""
    from ..parsing.zipsafe import SafeZip, ZipRefused

    try:
        with SafeZip(data) as zf:
            names = zf.names
            if not names:
                raise Invalid("archive has no members")
            if zf.inventory.leading_bytes:
                raise Invalid(f"{zf.inventory.leading_bytes} bytes before the first ZIP entry")
            for name in names:
                if not name.endswith(".npy"):
                    raise Invalid(f"member {name!r} is not a .npy array")
                member = zf.read(name)
                try:
                    check_npy(member) if member.startswith(NPY_MAGIC) else _raise(f"{name!r} is not a .npy array")
                except Invalid as exc:
                    raise Invalid(f"member {name!r}: {exc}") from None
    except ZipRefused as exc:
        raise Invalid(f"ZIP archive refused: {exc}") from None
    return {"members": len(names)}


def _raise(message: str):
    raise Invalid(message)


CHECKS = {SAFETENSORS: check_safetensors, GGUF: check_gguf, NPY: check_npy, NPZ: check_npz}
LOADERS = {SAFETENSORS: "safetensors.safe_open / load_file", GGUF: "gguf / llama.cpp",
           NPY: "numpy.load (allow_pickle=False)", NPZ: "numpy.load (.npz, allow_pickle=False)"}

__all__ = ["CHECKS", "DATA_ONLY_REASON", "LOADERS", "Invalid", "check_gguf", "check_npy", "check_npz",
           "check_safetensors", "detect", "template_findings"]
