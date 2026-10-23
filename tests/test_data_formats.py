"""Data-only formats (0.9.0): safetensors, GGUF and NumPy .npy / .npz without object arrays.

Valid structure -> CLEAN with the reason "data-only format, no code on load"; any
inconsistency -> RISKY; a pickle hidden in the same bytes (a polyglot) -> never CLEAN.
Fixtures are built here byte by byte (no framework is imported)."""
from __future__ import annotations

import io
import json
import math
import pickle
import struct
import zipfile

import pytest

from safeloadai import Verdict, scan
from safeloadai.parsing import views
from safeloadai.static import analyze_bytes, data_formats
from safeloadai.static.data_formats import DATA_ONLY_REASON, Invalid

MARKER = "SAFELOADAI_TEST_MARKER"


# --- builders -------------------------------------------------------------------------

def safetensors(tensors=None, *, metadata=None, extra=b"", header_pad=b"", raw_header=None) -> bytes:
    tensors = tensors if tensors is not None else {"w": ("F32", [2, 3]), "b": ("BF16", [3])}
    bits = data_formats.SAFETENSORS_BITS
    header, offset, body = {}, 0, b""
    for name, (dtype, shape) in tensors.items():
        size = bits[dtype] * math.prod(shape) // 8
        header[name] = {"dtype": dtype, "shape": shape, "data_offsets": [offset, offset + size]}
        body += bytes(range(size % 256)) + b"\1" * (size - size % 256)
        offset += size
    if metadata is not None:
        header["__metadata__"] = metadata
    raw = raw_header if raw_header is not None else json.dumps(header).encode() + header_pad
    return struct.pack("<Q", len(raw)) + raw + body + extra


def _gguf_str(s: bytes) -> bytes:
    return struct.pack("<Q", len(s)) + s


def gguf(*, kvs=(), tensors=(("t", [32, 2], 0),), alignment=None, version=3, extra=b"", bad_offset=None) -> bytes:
    """tensors: (name, dims, ggml type); type 0 is F32 (block 1, 4 bytes)."""
    sizes = data_formats.GGML_SIZES
    kv = b""
    kv_count = len(kvs) + (alignment is not None)
    if alignment is not None:
        kv += _gguf_str(b"general.alignment") + struct.pack("<II", 4, alignment)
    for key, value in kvs:
        kv += _gguf_str(key.encode()) + struct.pack("<I", 8) + _gguf_str(value.encode())
    align = alignment or 32
    info, offset, layout = b"", 0, []
    for name, dims, gtype in tensors:
        block, tsize = sizes[gtype]
        size = tsize * (dims[0] // block) * math.prod(dims[1:])
        offset += -offset % align
        info += _gguf_str(name.encode()) + struct.pack("<I", len(dims)) + b"".join(struct.pack("<Q", d) for d in dims)
        info += struct.pack("<IQ", gtype, offset if bad_offset is None else bad_offset)
        layout.append((offset, size))
        offset += size
    head = b"GGUF" + struct.pack("<IQQ", version, len(tensors), kv_count) + kv + info
    head += b"\0" * (-len(head) % align)
    data = bytearray(offset)
    for start, size in layout:
        data[start:start + size] = b"\2" * size
    return head + bytes(data) + extra


def npy(descr="<f4", shape=(2, 3), *, extra=b"", version=(1, 0), body=None, header=None) -> bytes:
    text = header if header is not None else repr({"descr": descr, "fortran_order": False, "shape": shape})
    prefix = 10 if version == (1, 0) else 12
    text += " " * (-(prefix + len(text) + 1) % 64) + "\n"
    raw = text.encode("latin1")
    length = struct.pack("<H", len(raw)) if version == (1, 0) else struct.pack("<I", len(raw))
    if body is None:
        itemsize = data_formats._itemsize(descr) if "O" not in descr else 8
        body = b"\3" * (itemsize * math.prod(shape))
    return b"\x93NUMPY" + bytes(version) + length + raw + body + extra


def npz(members: dict[str, bytes], *, leading=b"") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return leading + buf.getvalue()


def _scan(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return scan(path)


def _static(data, name):
    return analyze_bytes(data, name)


# --- valid files are CLEAN ------------------------------------------------------------

VALID = {
    "model.safetensors": safetensors(metadata={"format": "pt"}),
    "empty.safetensors": safetensors({}),
    "sub.safetensors": safetensors({"q": ("F4", [4]), "x": ("BOOL", [3]), "s": ("F8_E4M3", [0])}),
    "model.gguf": gguf(kvs=[("general.name", "tiny")]),
    "aligned.gguf": gguf(tensors=(("a", [32], 0), ("b", [64, 3], 1), ("q", [256], 12)), alignment=64),
    "no-tensors.gguf": gguf(tensors=()),
    "templated.gguf": gguf(kvs=[("tokenizer.chat_template", "{% for m in messages %}{{ m['content'] }}{% endfor %}")]),
    "array.npy": npy(),
    "scalar.npy": npy("<i8", ()),
    "record.npy": npy([("a", "<f8"), ("b", "<i4", (2,))], (3,)),
    "unicode.npy": npy("<U5", (2,), version=(3, 0)),
    "v2.npy": npy("|u1", (7,), version=(2, 0)),
    "arrays.npz": npz({"a.npy": npy(), "b.npy": npy("<i2", (4,))}),
}


@pytest.mark.parametrize("name", sorted(VALID))
def test_valid_structure_is_clean_static(name):
    report = _static(VALID[name], name)
    assert report["static_risk"] == "clean", report["reasons"]
    assert report["data_only"] is True
    assert report["reasons"] == []


@pytest.mark.wasi
@pytest.mark.parametrize("name", ["model.safetensors", "model.gguf", "array.npy", "arrays.npz"])
def test_valid_structure_is_clean_scan(tmp_path, name):
    report = _scan(tmp_path, name, VALID[name])
    assert report.verdict is Verdict.CLEAN
    assert report.reasons == [DATA_ONLY_REASON]


def test_valid_file_with_another_extension_is_clean_with_a_note():
    report = _static(VALID["model.safetensors"], "pytorch_model.bin")
    assert report["static_risk"] == "clean"
    assert any("does not match its content" in n for n in report["notes"])


def test_views_and_primary():
    assert [(v.fmt, v.start) for v in views.find_views(VALID["model.gguf"])] == [("gguf", 0)]
    assert [v.fmt for v in views.find_views(VALID["arrays.npz"])] == ["npz"]
    assert views.primary_view(views.find_views(VALID["array.npy"]), "x.npy").fmt == "npy"


# --- inconsistencies are RISKY --------------------------------------------------------

def _shifted_offsets() -> bytes:
    header = {"w": {"dtype": "F32", "shape": [2], "data_offsets": [4, 12]}}
    raw = json.dumps(header).encode()
    return struct.pack("<Q", len(raw)) + raw + b"\0" * 12


def _overlap() -> bytes:
    header = {"a": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]},
              "b": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}}
    raw = json.dumps(header).encode()
    return struct.pack("<Q", len(raw)) + raw + b"\0" * 4


INVALID = {
    "trailing.safetensors": safetensors(extra=b"\x80\x04N."),
    "short.safetensors": safetensors()[:-1],
    "offsets.safetensors": _shifted_offsets(),
    "overlap.safetensors": _overlap(),
    "huge-dims.safetensors": safetensors(raw_header=json.dumps(
        {"w": {"dtype": "F64", "shape": [2**40, 2**40], "data_offsets": [0, 8]}}).encode()),
    "dtype.safetensors": safetensors(raw_header=json.dumps(
        {"w": {"dtype": "OBJ", "shape": [1], "data_offsets": [0, 8]}}).encode()),
    "dupkey.safetensors": safetensors(raw_header=b'{"a": {"dtype": "U8", "shape": [0], "data_offsets": [0, 0]}, '
                                                 b'"a": {"dtype": "U8", "shape": [0], "data_offsets": [0, 0]}}'),
    "extra-field.safetensors": safetensors(raw_header=json.dumps(
        {"w": {"dtype": "U8", "shape": [0], "data_offsets": [0, 0], "code": "x"}}).encode()),
    "metadata.safetensors": safetensors(metadata={"n": 1}),
    "notjson.safetensors": safetensors(raw_header=b"{not json"),
    "trailing.gguf": gguf(extra=b"\x80\x04N." + b"\0" * 64),
    "short.gguf": gguf()[:-4],
    "misaligned.gguf": gguf(bad_offset=3),
    "overrun.gguf": gguf(bad_offset=1 << 40),
    "version.gguf": gguf(version=9),
    "alignment.gguf": gguf(alignment=48),
    "block.gguf": gguf(tensors=(("q", [100], 12),)),
    "count.gguf": b"GGUF" + struct.pack("<IQQ", 3, 1 << 60, 1 << 60),
    "object.npy": npy("|O", (2,), body=pickle.dumps(["a", "b"])),
    "object-field.npy": npy([("a", "<f8"), ("b", "|O")], (1,), body=b"\3" * 16),
    "trailing.npy": npy(extra=b"\x80\x04N."),
    "short.npy": npy()[:-1],
    "header.npy": npy(header="{'descr': '<f4', 'fortran_order': False, 'shape': (2,), 'x': 1}"),
    "call.npy": npy(header="__import__('os').system('echo')"),
    "version.npy": npy(version=(9, 0)),
    "member.npz": npz({"a.npy": npy(), "code.pkl": pickle.dumps(1)}),
    "object.npz": npz({"a.npy": npy("|O", (1,), body=pickle.dumps([MARKER]))}),
    "leading.npz": npz({"a.npy": npy()}, leading=b"junk" * 4),
}


@pytest.mark.parametrize("name", sorted(INVALID))
def test_inconsistent_structure_is_risky(name):
    report = _static(INVALID[name], name)
    assert report["static_risk"] in ("suspicious", "malicious"), report
    assert report["reasons"], name


@pytest.mark.parametrize("name", ["object.npy", "object.npz", "object-field.npy"])
def test_object_arrays_name_pickle(name):
    with pytest.raises(Invalid, match="Python objects"):
        data_formats.CHECKS[name.rsplit(".", 1)[1]](INVALID[name])


@pytest.mark.wasi
@pytest.mark.parametrize("name", ["trailing.safetensors", "misaligned.gguf", "object.npy"])
def test_inconsistent_structure_scans_risky(tmp_path, name):
    report = _scan(tmp_path, name, INVALID[name])
    assert report.verdict is Verdict.SUSPICIOUS
    assert report.category == "RISKY"


# --- polyglots: a pickle in the same bytes is never CLEAN -----------------------------

def _payload() -> bytes:
    return b"cposix\nsystem\n(S'echo " + MARKER.encode() + b"'\ntR."


def test_pickle_after_valid_safetensors_is_not_clean():
    data = VALID["model.safetensors"] + _payload()
    report = _static(data, "model.safetensors")
    assert report["static_risk"] != "clean"


def test_pickle_hidden_in_gguf_kv_and_after_data():
    data = gguf(kvs=[("general.name", "x")], extra=_payload())
    assert _static(data, "m.gguf")["static_risk"] != "clean"


def test_zip_with_pickle_and_npy_members_is_not_npz():
    data = npz({"a.npy": npy(), "data.pkl": _payload()})
    assert _static(data, "x.npz")["static_risk"] != "clean"


def test_pickle_at_offset_zero_with_data_only_suffix():
    # A pickle with a safetensors file appended: pickle.load runs the payload.
    data = _payload() + VALID["model.safetensors"]
    report = _static(data, "model.safetensors")
    assert report["static_risk"] != "clean"


def test_npy_and_pickle_readings_of_one_file():
    # The NumPy magic is not a pickle opcode that can start a stream, so an .npy is never
    # also a pickle at offset 0; an object array's pickle is reported as an object dtype.
    assert not views.pickle_at_start(VALID["array.npy"])
    report = _static(INVALID["object.npy"], "x.npy")
    assert "Python objects" in report["reasons"][0]


@pytest.mark.wasi
def test_polyglot_scan_is_not_clean(tmp_path):
    report = _scan(tmp_path, "model.safetensors", VALID["model.safetensors"] + _payload())
    assert report.verdict is not Verdict.CLEAN


# --- GGUF chat templates --------------------------------------------------------------

def test_template_reaching_internals_is_risky():
    t = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    report = _static(gguf(kvs=[("tokenizer.chat_template", t)]), "m.gguf")
    assert report["static_risk"] == "suspicious"
    assert "template injection" in report["reasons"][0]


def test_template_with_sink_is_malicious():
    t = "{{ cycler.__init__.__globals__.os.popen('echo " + MARKER + "').read() }}"
    report = _static(gguf(kvs=[("tokenizer.chat_template", t)]), "m.gguf")
    assert report["static_risk"] == "malicious"


def test_named_template_variant_is_checked():
    t = "{{ x.__globals__ }}"
    report = _static(gguf(kvs=[("tokenizer.chat_template.tool_use", t)]), "m.gguf")
    assert report["static_risk"] == "suspicious"


# --- limits ---------------------------------------------------------------------------

def test_safetensors_header_limit():
    data = struct.pack("<Q", data_formats.SAFETENSORS_MAX_HEADER + 1) + b"{" + b" " * 16
    assert views.find_views(data) == []  # not even a safetensors reading: UNSUPPORTED
    with pytest.raises(Invalid, match="limit"):
        data_formats.check_safetensors(data)


def test_npy_header_limit():
    data = b"\x93NUMPY\x02\x00" + struct.pack("<I", 20_000) + b" " * 20_000
    with pytest.raises(Invalid, match="refuses"):
        data_formats.check_npy(data)


def test_gguf_nested_arrays_are_bounded():
    nested = struct.pack("<I", 9) + struct.pack("<IQ", 9, 1)
    for _ in range(data_formats.GGUF_MAX_NESTING):
        nested += struct.pack("<IQ", 9, 1)
    data = b"GGUF" + struct.pack("<IQQ", 3, 0, 1) + _gguf_str(b"k") + nested + b"\0" * 64
    with pytest.raises(Invalid):
        data_formats.check_gguf(data)


def test_budget_stops_a_huge_header(monkeypatch):
    from safeloadai.static import budget

    monkeypatch.setattr(budget, "limit_for", lambda size: 1000)
    report = _static(safetensors(header_pad=b" " * 5000), "m.safetensors")
    assert report["static_risk"] == "suspicious"
    assert report["tool_errors"][0]["code"] == "E105"


# --- header bytes that decode as pickle opcodes by chance -----------------------------

def _with_length_prefix(first: bytes, header: bytes) -> bytes:
    """A safetensors file whose 8-byte header length starts with ``first`` (padding the
    header with spaces until the length's low bytes are ``first``)."""
    want = int.from_bytes(first.ljust(2, b"\0")[:2], "little")
    pad = (want - len(header)) % 65536
    raw = header + b" " * pad
    assert struct.pack("<Q", len(raw))[:len(first)] == first
    return struct.pack("<Q", len(raw)) + raw


@pytest.mark.parametrize("first", [b".", b"K", b"\x82", b"x\x9c"])
def test_accidental_pickle_or_joblib_reading_is_dropped(first):
    data = _with_length_prefix(first, b'{"__metadata__": {"a": "b"}}')
    report = _static(data, "m.safetensors")
    assert report["static_risk"] == "clean", report["reasons"]
    assert [v["format"] for v in report["views"]] == ["safetensors"]


def test_pickle_reading_that_imports_is_kept():
    # 'c' (GLOBAL) as the length's low byte; JSON allows newlines between tokens, so
    # GLOBAL reads "<length bytes>{"__metadata__":" as the module and the next line as the name.
    data = _with_length_prefix(b"c", b'{"__metadata__":\n{"m": "x"}\n}')
    assert data[:1] == b"c"
    report = _static(data, "m.safetensors")
    assert [v["format"] for v in report["views"]] == ["pickle", "safetensors"]
    assert report["static_risk"] != "clean"
