"""Model formats that run no code on load (0.10.0): ONNX, TFLite, Flax msgpack and
OpenVINO IR (static/model_formats.py).

Valid structure with standard operators -> CLEAN "format runs no code on load"; a custom
operator domain or layer -> UNVERIFIABLE naming it; any inconsistency, an external-data
path that leaves the model directory, or an XML DTD -> RISKY; a pickle or archive reading
in the same bytes (a polyglot) -> never CLEAN. The valid fixtures were written with each
format's own writer (tools/make_model_format_fixtures.py); every variant here is made from
their bytes or from the small encoders below. No framework is imported."""
from __future__ import annotations

import io
import math
import os
import shutil
import struct
import zipfile

import pytest

from safeloadai import Verdict, scan
from safeloadai.parsing import detect, views
from safeloadai.static import analyze_bytes, companions, model_formats, read_companions
from safeloadai.static.data_formats import Invalid
from safeloadai.static.model_formats import NO_CODE_REASON

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures", "model_formats")
MARKER = "SAFELOADAI_TEST_MARKER"


def fixture(name: str) -> bytes:
    with open(os.path.join(FIXTURES, name), "rb") as fh:
        return fh.read()


def _payload() -> bytes:
    return b"cposix\nsystem\n(S'echo " + MARKER.encode() + b"'\ntR."


def _torch_zip_payload() -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("archive/data.pkl", _payload())
    return out.getvalue()


def _static(data: bytes, name: str, found: dict | None = None) -> dict:
    with companions(found):
        return analyze_bytes(data, name)


def _copy(tmp_path, *names: str) -> str:
    for name in names:
        shutil.copy(os.path.join(FIXTURES, name), tmp_path / name)
    return str(tmp_path / names[0])


# --- a protobuf encoder for ONNX variants ---------------------------------------------

def _varint(n: int) -> bytes:
    n &= (1 << 64) - 1
    out = b""
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out += bytes([byte | 0x80])
        else:
            return out + bytes([byte])


def f_int(number: int, value: int) -> bytes:
    return _varint(number << 3) + _varint(value)


def f_len(number: int, payload: bytes | str) -> bytes:
    payload = payload.encode() if isinstance(payload, str) else payload
    return _varint(number << 3 | 2) + _varint(len(payload)) + payload


def onnx_model(*, nodes=None, initializers=None, opsets=(("", 17),), ir=8, extra=b"", graph_extra=b"") -> bytes:
    if nodes is None:
        nodes = [f_len(1, "X") + f_len(1, "W") + f_len(2, "Y") + f_len(4, "MatMul")]
    if initializers is None:
        initializers = [tensor()]
    graph = b"".join(f_len(1, n) for n in nodes) + f_len(2, "g") + b"".join(f_len(5, t) for t in initializers)
    model = f_int(1, ir) + f_len(2, "tests") + b"".join(f_len(8, f_len(1, d) + f_int(2, v)) for d, v in opsets)
    return model + f_len(7, graph + graph_extra) + extra


def tensor(*, raw: bytes | None = None, dims=(2, 3), dtype=1, external=None, location=None) -> bytes:
    body = b"".join(f_int(1, d) for d in dims) + f_int(2, dtype) + f_len(8, "W")
    if external is not None:
        body += b"".join(f_len(13, f_len(1, k) + f_len(2, v)) for k, v in external) + f_int(14, 1)
    else:
        body += f_len(9, raw if raw is not None else bytes(24))
    return body


# --- ONNX -----------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["tiny.onnx", "tiny_function.onnx"])
def test_valid_onnx_is_clean(name):
    report = _static(fixture(name), name)
    assert report["file_format"] == detect.ONNX and report["static_risk"] == "clean", report["reasons"]
    assert any(NO_CODE_REASON in n for n in report["notes"])


def test_onnx_detected_by_content_without_the_extension():
    assert detect.no_code_format(fixture("tiny.onnx"), "model.bin") == detect.ONNX
    assert _static(fixture("tiny.onnx"), "model.bin")["static_risk"] == "clean"


def test_encoder_model_is_clean():
    assert model_formats.check_onnx(onnx_model())["nodes"] == 1


@pytest.mark.wasi
def test_valid_onnx_scans_clean(tmp_path):
    report = scan(_copy(tmp_path, "tiny.onnx"))
    assert report.verdict is Verdict.CLEAN and report.reasons == [NO_CODE_REASON]


def test_custom_domain_is_unverifiable_and_named():
    report = _static(fixture("tiny_custom_domain.onnx"), "m.onnx")
    assert report["static_risk"] == "suspicious"
    items = [meta["item"] for meta in report["unverifiable"].values()]
    assert items == ["onnx-domain:com.example"]


def test_declared_but_unused_custom_domain_is_unverifiable():
    data = onnx_model(opsets=(("", 17), ("com.microsoft", 1)))
    facts = model_formats.check_onnx(data)
    assert [u.item for u in facts["unverifiable"]] == ["onnx-domain:com.microsoft"]


def test_node_domain_not_declared_is_risky():
    node = f_len(1, "X") + f_len(2, "Y") + f_len(4, "Relu") + f_len(7, "com.example")
    with pytest.raises(Invalid, match="does not declare"):
        model_formats.check_onnx(onnx_model(nodes=[node]))


def test_custom_domain_inside_a_subgraph_is_found():
    inner = f_len(1, f_len(1, "X") + f_len(2, "Z") + f_len(4, "Evil") + f_len(7, "com.example")) + f_len(2, "body")
    attribute = f_len(1, "then_branch") + f_int(20, 5) + f_len(6, inner)
    node = f_len(1, "C") + f_len(2, "Y") + f_len(4, "If") + f_len(5, attribute)
    facts = model_formats.check_onnx(onnx_model(nodes=[node], opsets=(("", 17), ("com.example", 1))))
    assert [u.item for u in facts["unverifiable"]] == ["onnx-domain:com.example"]


@pytest.mark.wasi
def test_custom_domain_can_be_accepted_for_the_file(tmp_path):
    from safeloadai import override

    report = scan(_copy(tmp_path, "tiny_custom_domain.onnx"))
    assert report.unverifiable_only and report.unverifiable_items == ["onnx-domain:com.example"]
    assert override.apply(report, ["onnx-domain:com.example"], how="api")


@pytest.mark.parametrize("location", ["/etc/passwd", "\\\\server\\share\\w", "C:\\weights.bin", "../w.bin",
                                      "sub/../../w.bin", "..\\w.bin", "~/w.bin", "", "a\0b"])
def test_external_data_outside_the_model_directory_is_risky(location):
    data = onnx_model(initializers=[tensor(external=[("location", location)])])
    report = _static(data, "m.onnx")
    assert report["static_risk"] == "suspicious" and "location" in report["reasons"][0]


def test_external_data_relative_path_is_clean():
    data = onnx_model(initializers=[tensor(external=[("location", "weights/w.bin"), ("offset", "0"),
                                                     ("length", "24")])])
    assert _static(data, "m.onnx")["static_risk"] == "clean"


@pytest.mark.parametrize("external", [[("offset", "0")], [("location", "w"), ("location", "x")],
                                      [("location", "w"), ("basepath", "/tmp")], [("location", "w"), ("evil", "1")],
                                      [("location", "w"), ("offset", "-1")]])
def test_malformed_external_data_is_risky(external):
    with pytest.raises(Invalid):
        model_formats.check_onnx(onnx_model(initializers=[tensor(external=external)]))


def test_external_data_through_a_symlink_is_risky(tmp_path):
    target = tmp_path / "outside"
    target.mkdir()
    (target / "secret").write_bytes(bytes(24))
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    os.symlink(target / "secret", model_dir / "w.bin")
    data = onnx_model(initializers=[tensor(external=[("location", "w.bin")])])
    with pytest.raises(Invalid, match="link"):
        model_formats.check_onnx(data, str(model_dir))


@pytest.mark.wasi
def test_external_data_fixture_scans_clean(tmp_path):
    report = scan(_copy(tmp_path, "tiny_external.onnx", "tiny_external.onnx.data"))
    assert report.verdict is Verdict.CLEAN


@pytest.mark.parametrize("data", [
    pytest.param(onnx_model(initializers=[tensor(raw=bytes(23))]), id="raw-data-short"),
    pytest.param(onnx_model(initializers=[tensor(raw=bytes(25))]), id="raw-data-long"),
    pytest.param(onnx_model(initializers=[tensor(dtype=99)]), id="unknown-dtype"),
    pytest.param(onnx_model(extra=f_int(99, 1)), id="unknown-model-field"),
    pytest.param(onnx_model(graph_extra=f_int(77, 1)), id="unknown-graph-field"),
    pytest.param(onnx_model(ir=99), id="ir-version"),
    pytest.param(onnx_model()[:-5], id="truncated"),
    pytest.param(onnx_model(extra=f_len(7, b"")), id="two-graphs"),
    pytest.param(onnx_model(opsets=()), id="no-opset"),
    pytest.param(onnx_model(opsets=(("", 17), ("", 13))), id="opset-twice"),
    pytest.param(onnx_model(nodes=[f_len(1, "X") + f_len(2, "Y")]), id="node-without-op"),
    pytest.param(onnx_model(extra=_varint(2 << 3 | 3)), id="group-wire-type"),
    pytest.param(onnx_model(extra=f_len(1, b"x")), id="wrong-wire-type"),
])
def test_malformed_onnx_is_not_clean(data):
    with pytest.raises(Invalid):
        model_formats.check_onnx(data)
    assert _static(data, "m.onnx")["static_risk"] != "clean"


def test_deep_nesting_is_bounded():
    graph = f_len(1, f_len(1, "X") + f_len(2, "Y") + f_len(4, "Relu"))
    for _ in range(model_formats.MAX_DEPTH + 2):
        node = f_len(4, "If") + f_len(5, f_len(1, "g") + f_len(6, graph))
        graph = f_len(1, node)
    data = f_int(1, 8) + f_len(8, f_len(1, "") + f_int(2, 17)) + f_len(7, graph)
    with pytest.raises(Invalid, match="deeper"):
        model_formats.check_onnx(data)


@pytest.mark.parametrize("make", [
    pytest.param(lambda d: _payload() + d, id="pickle-prepended"),
    pytest.param(lambda d: d + _payload(), id="pickle-appended"),
    pytest.param(lambda d: d + _torch_zip_payload(), id="torch-zip-appended"),
])
def test_onnx_polyglot_is_not_clean(make):
    report = _static(make(fixture("tiny.onnx")), "m.onnx")
    assert report["static_risk"] != "clean"


@pytest.mark.wasi
def test_onnx_with_pickle_prepended_is_malicious(tmp_path):
    path = tmp_path / "m.onnx"
    path.write_bytes(_payload() + fixture("tiny.onnx"))
    assert scan(str(path)).verdict is Verdict.MALICIOUS


# --- TFLite ---------------------------------------------------------------------------

def test_valid_tflite_is_clean():
    report = _static(fixture("tiny.tflite"), "m.tflite")
    assert report["file_format"] == detect.TFLITE and report["static_risk"] == "clean", report["reasons"]


@pytest.mark.wasi
def test_valid_tflite_scans_clean(tmp_path):
    assert scan(_copy(tmp_path, "tiny.tflite")).verdict is Verdict.CLEAN


def test_custom_tflite_operator_is_unverifiable():
    report = _static(fixture("tiny_custom.tflite"), "m.tflite")
    assert [m["item"] for m in report["unverifiable"].values()] == ["tflite-custom-op:MyFancyOp"]


def _tflite_offsets(data: bytes) -> dict:
    """Positions of a few fields of the tiny model, found with the validator's own reader."""
    fb = model_formats._Flat(data, len(data))
    model = fb.table(fb.u32(0))
    subgraph = fb.tables(model, 2)[0]
    operator = fb.tables(subgraph, 3)[0]
    tensor_ = fb.tables(subgraph, 0)[1]  # the one with buffer 1 (a default 0 is not stored)
    return {"version": fb.field(model, 0, 4), "op_input": fb.vector(operator, 1, 4)[0],
            "tensor_buffer": fb.field(tensor_, 2, 4), "root": 0}


def _patch(data: bytes, at: int, fmt: str, value) -> bytes:
    out = bytearray(data)
    struct.pack_into(fmt, out, at, value)
    return bytes(out)


@pytest.mark.parametrize("field,value", [("version", 2), ("op_input", 7), ("tensor_buffer", 9),
                                         ("root", 10_000), ("root", 3)])
def test_inconsistent_tflite_is_risky(field, value):
    data = fixture("tiny.tflite")
    patched = _patch(data, _tflite_offsets(data)[field], "<I", value)
    with pytest.raises(Invalid):
        model_formats.check_tflite(patched)
    assert _static(patched, "m.tflite")["static_risk"] != "clean"


def test_truncated_tflite_is_not_clean():
    data = fixture("tiny.tflite")
    for cut in (8, 40, len(data) // 2, len(data) - 4):
        assert _static(data[:cut], "m.tflite")["static_risk"] != "clean"


@pytest.mark.parametrize("make", [
    pytest.param(lambda d: _payload() + d, id="pickle-prepended"),
    pytest.param(lambda d: d + _torch_zip_payload(), id="torch-zip-appended"),
])
def test_tflite_polyglot_is_not_clean(make):
    assert _static(make(fixture("tiny.tflite")), "m.tflite")["static_risk"] != "clean"


# --- Flax msgpack ---------------------------------------------------------------------

def test_valid_flax_checkpoint_is_clean():
    report = _static(fixture("flax_model.msgpack"), "flax_model.msgpack")
    assert report["file_format"] == detect.MSGPACK and report["static_risk"] == "clean", report["reasons"]


@pytest.mark.wasi
def test_valid_flax_checkpoint_scans_clean(tmp_path):
    assert scan(_copy(tmp_path, "flax_model.msgpack")).verdict is Verdict.CLEAN


def test_msgpack_needs_its_extension():
    assert detect.no_code_format(fixture("flax_model.msgpack"), "model.bin") is None


def _mp_ext(code: int, payload: bytes) -> bytes:
    return b"\xc7" + bytes([len(payload)]) + struct.pack(">b", code) + payload


def _mp_str(s: str) -> bytes:
    return bytes([0xA0 | len(s)]) + s.encode()


def _mp_array(shape, dtype: str, buffer: bytes) -> bytes:
    body = bytes([0x93]) + bytes([0x90 | len(shape)]) + bytes(shape) + _mp_str(dtype)
    return _mp_ext(1, body + b"\xc4" + bytes([len(buffer)]) + buffer)


@pytest.mark.parametrize("data", [
    pytest.param(b"\x81" + _mp_str("a") + _mp_ext(5, b"\x00"), id="unknown-ext"),
    pytest.param(b"\x81" + _mp_str("a") + b"\xd6\xff" + bytes(4), id="timestamp-ext"),
    pytest.param(b"\x81" + _mp_str("a") + _mp_array([2], "object", bytes(16)), id="object-dtype"),
    pytest.param(b"\x81" + _mp_str("a") + _mp_array([2], "float32", bytes(7)), id="short-buffer"),
    pytest.param(b"\x81" + _mp_str("a") + b"\xc0" + b"\x00", id="trailing-data"),
    pytest.param(b"\x82" + _mp_str("a") + b"\x01" + _mp_str("a") + b"\x02", id="duplicate-key"),
    pytest.param(b"\x81" + b"\x91\x01" + b"\x01", id="array-key"),
    pytest.param(b"\x81" + _mp_str("a") + b"\xdc\xff\xff", id="array-count-past-end"),
    pytest.param(b"\x81" + _mp_str("a") + b"\xc1", id="never-used-byte"),
    pytest.param(b"\x91\x01", id="top-level-array"),
])
def test_malformed_flax_checkpoint_is_risky(data):
    with pytest.raises(Invalid):
        model_formats.check_msgpack(data)
    assert _static(data, "flax_model.msgpack")["static_risk"] != "clean"


def test_msgpack_nesting_is_bounded():
    data = b"\x81\xa1a" * (model_formats.MAX_DEPTH + 5) + b"\xc0"
    with pytest.raises(Invalid, match="deeper"):
        model_formats.check_msgpack(data)


@pytest.mark.parametrize("make", [
    pytest.param(lambda d: _payload() + d, id="pickle-prepended"),
    pytest.param(lambda d: d + _torch_zip_payload(), id="torch-zip-appended"),
])
def test_msgpack_polyglot_is_not_clean(make):
    assert _static(make(fixture("flax_model.msgpack")), "flax_model.msgpack")["static_risk"] != "clean"


# --- OpenVINO IR ----------------------------------------------------------------------

def _pair(xml: bytes | None = None, weights: bytes | None = None) -> dict:
    found = {"dir": FIXTURES}
    if xml is not None:
        found["xml"] = {"name": "openvino_model.xml", "data": xml, "sha256": "0" * 64}
    if weights is not None:
        found["bin"] = {"name": "openvino_model.bin", "data": weights, "sha256": "0" * 64}
    return found


def test_openvino_pair_is_clean():
    xml, weights = fixture("openvino_model.xml"), fixture("openvino_model.bin")
    report = _static(weights, "openvino_model.bin", _pair(xml=xml))
    assert report["file_format"] == detect.OPENVINO_BIN and report["static_risk"] == "clean", report["reasons"]
    assert report["companions"][0]["file"] == "openvino_model.xml"
    report = _static(xml, "openvino_model.xml", _pair(weights=weights))
    assert report["file_format"] == detect.OPENVINO_XML and report["static_risk"] == "clean", report["reasons"]


@pytest.mark.wasi
def test_openvino_pair_scans_clean(tmp_path):
    path = _copy(tmp_path, "openvino_model.bin", "openvino_model.xml")
    assert scan(path).verdict is Verdict.CLEAN
    assert scan(str(tmp_path / "openvino_model.xml")).verdict is Verdict.CLEAN


def test_bin_without_its_xml_stays_unsupported(tmp_path):
    path = _copy(tmp_path, "openvino_model.bin")
    assert read_companions(path).get("xml") is None
    assert _static(fixture("openvino_model.bin"), "openvino_model.bin", {"dir": str(tmp_path)})["unsupported"]


def test_companion_xml_that_is_a_link_is_ignored(tmp_path):
    path = _copy(tmp_path, "openvino_model.bin")
    os.symlink(os.path.join(FIXTURES, "openvino_model.xml"), tmp_path / "openvino_model.xml")
    assert read_companions(path).get("xml") is None


def _xml(text: str) -> bytes:
    return fixture("openvino_model.xml").decode().replace(*text.split("=>", 1)).encode() if "=>" in text else text


@pytest.mark.parametrize("change,item", [
    ('type="Add" version="opset1"=>type="EvilOp" version="opset1"', "openvino-op:opset1.EvilOp"),
    ('type="Add" version="opset1"=>type="Add" version="extension"', "openvino-op:extension.Add"),
    ('type="Add" version="opset1"=>type="NonMaxSuppressionIEInternal" version="ie_internal_opset"',
     "openvino-op:ie_internal_opset.NonMaxSuppressionIEInternal"),
])
def test_layer_outside_the_standard_opsets_is_unverifiable(change, item):
    report = _static(fixture("openvino_model.bin"), "openvino_model.bin", _pair(xml=_xml(change)))
    assert report["static_risk"] == "suspicious"
    assert [m["item"] for m in report["unverifiable"].values()] == [item]


@pytest.mark.parametrize("change", [
    'offset="0" size="16"=>offset="8" size="16"',
    'offset="0" size="16"=>offset="0" size="12"',
    'offset="0" size="16"=>offset="-4" size="16"',
    'element_type="f32" shape="1, 4"=>element_type="object" shape="1, 4"',
    '<net name="tiny" version="11">=>'
    '<!DOCTYPE net [<!ENTITY x SYSTEM "file:///etc/passwd">]><net name="tiny" version="11">',
    '<net name="tiny" version="11">=><!DOCTYPE net><net name="tiny" version="11">',
    '<net name="tiny" version="11">=><net name="tiny" version="7">',
    '<edges>=><edges><edge from-layer="9" from-port="0" to-layer="2" to-port="0" />',
    '<rt_info>=><evil /><rt_info>',
    '</net>=></net><net/>',
])
def test_inconsistent_openvino_ir_is_risky(change):
    report = _static(fixture("openvino_model.bin"), "openvino_model.bin", _pair(xml=_xml(change)))
    assert report["static_risk"] == "suspicious" and report.get("error"), report["reasons"]


def test_const_region_larger_than_its_tensor_is_read_like_openvino():
    # XmlDeserializer::set_constant_num_buffer throws only when size < the tensor's bytes;
    # openvino_tokenizers writes size 1 for an empty u8 tensor (DECISIONS.md, 0.10.0).
    weights = fixture("openvino_model.bin") + bytes(8)
    xml = _xml('offset="0" size="16"=>offset="0" size="24"')
    report = _static(weights, "openvino_model.bin", _pair(xml=xml))
    assert report["static_risk"] == "clean", report["reasons"]
    empty = _xml('element_type="f32" shape="1, 4" offset="0" size="16"'
                 '=>element_type="u8" shape="0" offset="0" size="1"')
    assert _static(fixture("openvino_model.bin"), "openvino_model.bin", _pair(xml=empty))["static_risk"] == "clean"
    past = _xml('offset="0" size="16"=>offset="0" size="40"')
    assert _static(weights, "openvino_model.bin", _pair(xml=past))["static_risk"] == "suspicious"


def test_payload_in_an_oversized_const_region_is_still_caught():
    # The relaxed size covers a pickle at the start of the .bin: the .bin's own pickle reading
    # is analysed as before, so the file is not CLEAN.
    weights = _payload() + bytes(16)
    xml = _xml(f'offset="0" size="16"=>offset="0" size="{len(weights)}"')
    report = _static(weights, "openvino_model.bin", _pair(xml=xml))
    assert report["static_risk"] != "clean"
    assert any(rep["static_risk"] == "malicious" for _view, rep in report.get("_extra_views") or []) \
        or report["static_risk"] == "malicious"


def test_billion_laughs_is_refused_before_expansion():
    bomb = (b'<?xml version="1.0"?><!DOCTYPE net [<!ENTITY a "aaaaaaaaaa">'
            + b"".join(b'<!ENTITY %s "&%s;&%s;&%s;&%s;&%s;&%s;&%s;&%s;&%s;&%s;">' % ((bytes([98 + i]),)
                       + (bytes([97 + i]),) * 10) for i in range(8))
            + b']><net version="11"><layers>&i;</layers></net>')
    with pytest.raises(Invalid, match="DTD"):
        model_formats.check_openvino_xml(bomb, 16)


def test_xml_without_its_bin_is_risky():
    report = _static(fixture("openvino_model.xml"), "openvino_model.xml", {"dir": FIXTURES})
    assert report["static_risk"] == "suspicious" and "no .bin" in report["reasons"][0]


def test_bin_that_is_a_pickle_is_analysed_as_one():
    # A malicious pickle named like the weights, with a valid IR beside it: the pickle reading
    # is analysed as usual (normal analysis), and the file is far from CLEAN.
    report = _static(_payload(), "openvino_model.bin", _pair(xml=fixture("openvino_model.xml")))
    assert report["static_risk"] == "suspicious" and "more than one format" in report["reasons"][-1]
    assert [rep["static_risk"] for _view, rep in report["_extra_views"]] == ["malicious"]


def test_bin_with_appended_torch_zip_is_not_clean():
    data = fixture("openvino_model.bin") + _torch_zip_payload()
    assert _static(data, "openvino_model.bin", _pair(xml=fixture("openvino_model.xml")))["static_risk"] != "clean"


def test_xml_whose_bin_is_also_a_pickle_is_risky():
    weights = _payload() + bytes(16)
    report = _static(fixture("openvino_model.xml"), "openvino_model.xml", _pair(weights=weights))
    assert report["static_risk"] == "suspicious" and "also readable" in " ".join(report["reasons"])


@pytest.mark.wasi
def test_bin_that_is_a_pickle_scans_malicious(tmp_path):
    _copy(tmp_path, "openvino_model.xml")
    (tmp_path / "openvino_model.bin").write_bytes(_payload() + bytes(16))
    assert scan(str(tmp_path / "openvino_model.bin")).verdict is Verdict.MALICIOUS


def test_accidental_pickle_opcodes_in_weights_are_not_a_reading():
    # Raw float weights can start with bytes that decode as a few pickle opcodes that import
    # nothing; next to a valid IR that is not a second reading (static._drop_accidental).
    weights = b"K\x01" * 8  # eight BININT1: plain data, no import
    assert views.pickle_at_start(weights)
    report = _static(weights, "openvino_model.bin", _pair(xml=fixture("openvino_model.xml")))
    assert report["static_risk"] == "clean", report["reasons"]


def test_opset_table_has_the_ir_names():
    opsets = model_formats.openvino_opsets()
    assert {"Const", "Constant", "Parameter", "Result", "Add"} <= opsets["opset1"]
    assert "ReLU" in opsets["opset1"] and len(opsets) == 17


# --- Core ML weights (MIL blob storage weight.bin) ------------------------------------

def coreml_blob(data: bytes, dtype: int = 2, padding: int = 0, reserved: bytes = b"\0" * 32) -> tuple:
    return dtype, data, padding, reserved


def coreml_weights(*blobs, version: int = 2, count: int | None = None, trailer: bytes = b"") -> bytes:
    """A weight.bin laid out like coremltools' StorageWriter: header, then per blob its
    64-byte metadata at the next 64-byte boundary and its data right after it."""
    out = bytearray(struct.pack("<II", len(blobs) if count is None else count, version) + b"\0" * 56)
    for dtype, data, padding, reserved in blobs:
        out += b"\0" * (-len(out) % 64)
        out += struct.pack("<IIQQQ", 0xDEADBEEF, dtype, len(data), len(out) + 64, padding) + reserved
        out += data
    return bytes(out + trailer)


def _two_blobs() -> bytes:
    return coreml_weights(coreml_blob(struct.pack("<3f", 1, 2, 3)), coreml_blob(b"\x12\x34", dtype=8))


def test_valid_coreml_weights_are_clean():
    report = _static(_two_blobs(), "weight.bin")
    assert report["static_risk"] == "clean", report["reasons"]
    assert any(NO_CODE_REASON in n for n in report["notes"])
    assert detect.no_code_format(_two_blobs()) == detect.COREML_WEIGHTS


def test_coreml_weights_from_before_ios18_keep_garbage_in_ignored_fields():
    # the reader never reads the reserved fields, nor padding_size_in_bits of a byte-sized blob
    data = coreml_weights(coreml_blob(b"\0" * 64, dtype=1, padding=4775559792, reserved=b"\xab" * 32))
    assert _static(data, "weight.bin")["static_risk"] == "clean"


@pytest.mark.wasi
def test_coreml_weights_scan_clean(tmp_path):
    path = tmp_path / "weight.bin"
    path.write_bytes(_two_blobs())
    assert scan(str(path)).verdict is Verdict.CLEAN


@pytest.mark.parametrize("data", [
    coreml_weights(coreml_blob(b"\0" * 8), count=2),                        # a blob the file does not have
    coreml_weights(coreml_blob(b"\0" * 8), trailer=b"\0" * 64),            # bytes after the last blob
    coreml_weights(coreml_blob(b"\0" * 8), trailer=b"x"),
    coreml_weights(coreml_blob(b"\0" * 8, dtype=18)),                       # unknown data type
    coreml_weights(coreml_blob(b"\0" * 8, dtype=0)),
    coreml_weights(coreml_blob(b"\0" * 6)),                                  # partial float32
    coreml_weights(coreml_blob(b"\0\0", dtype=8, padding=8)),               # 8 padding bits, sub-byte
    coreml_weights(coreml_blob(b"\0\0", dtype=13, padding=1)),              # 15 bits of 6-bit elements
    coreml_weights(coreml_blob(b"\0\0", dtype=8, padding=2)),               # byte-aligned 4-bit, odd padding
    coreml_weights(coreml_blob(b"")),                                          # empty: Span::Slice refuses it
    coreml_weights(coreml_blob(b"\0" * 8))[:-1],                             # truncated data
    coreml_weights(coreml_blob(b"\0" * 8), coreml_blob(b"\0" * 8))[:100],   # truncated metadata
])
def test_malformed_coreml_weights_are_risky(data):
    report = _static(data, "weight.bin")
    assert report["static_risk"] == "suspicious" and report["error"], report["reasons"]


def test_espresso_blob_v1_is_not_taken_for_coreml_weights():
    report = _static(coreml_weights(coreml_blob(b"\0" * 8), version=1), "weight.bin")
    assert report["unsupported"] and report["static_risk"] != "clean"


def _patched(data: bytes, offset: int, fmt: str, value: int) -> bytes:
    out = bytearray(data)
    struct.pack_into(fmt, out, offset, value)
    return bytes(out)


def test_coreml_metadata_must_be_where_the_reader_walks():
    data = _two_blobs()
    assert _static(_patched(data, 64 + 16, "<Q", 192), "weight.bin")["error"]   # data not right after metadata
    assert _static(_patched(data, 8, "<Q", 1), "weight.bin")["error"]           # reserved header field
    second = 128 + 64  # align64(128 + 12)
    assert _static(_patched(data, second, "<I", 0), "weight.bin")["error"]      # second sentinel gone


def test_payload_in_the_alignment_gap_of_coreml_weights_is_caught():
    data = bytearray(_two_blobs())
    data[128 + 12:128 + 12 + 5] = b"cos\ns"  # between the first blob's data and the next metadata
    assert _static(bytes(data), "weight.bin")["static_risk"] == "suspicious"


@pytest.mark.wasi
def test_coreml_weights_with_a_pickle_in_front_are_malicious(tmp_path):
    path = tmp_path / "weight.bin"
    path.write_bytes(_payload() + _two_blobs())
    assert scan(str(path)).verdict is Verdict.MALICIOUS


def test_pickle_with_coreml_weights_after_stop_is_not_clean():
    data = _payload() + _two_blobs()
    assert _static(data, "weight.bin")["static_risk"] != "clean"


# --- CTranslate2 model.bin -------------------------------------------------------------

def _ct2_string(text: str, raw: bytes | None = None) -> bytes:
    raw = text.encode() + b"\0" if raw is None else raw
    return struct.pack("<H", len(raw)) + raw


def ct2_model(variables=(("w", (2, 3), 0, None),), aliases=(("w2", "w"),), *, version: int = 6,
              spec: str = "TransformerSpec", trailer: bytes = b"") -> bytes:
    """A model.bin laid out like ModelSpec._serialize: (name, shape, type id, bytes or None)."""
    out = struct.pack("<I", version)
    if version >= 2:
        out += _ct2_string(spec) + struct.pack("<I", 7)
    out += struct.pack("<I", len(variables))
    for name, shape, dtype, data in variables:
        item = (4, 1, 2, 4, 2, 2)[dtype] if dtype < 6 else 1
        if data is None:
            data = b"\0" * (math.prod(shape) * item)
        out += _ct2_string(name) + struct.pack(f"<B{len(shape)}I", len(shape), *shape)
        if version >= 4:
            out += struct.pack("<BI", dtype, len(data))
        else:
            out += struct.pack("<BI", item, len(data) // item)
        out += data
    if version >= 3:
        out += struct.pack("<I", len(aliases))
        for alias, target in aliases:
            out += _ct2_string(alias) + _ct2_string(target)
    return out + trailer


@pytest.mark.parametrize("data", [ct2_model(), ct2_model(version=3), ct2_model(version=2, aliases=()),
                                  ct2_model(spec="WhisperSpec", variables=(("s", (), 0, None),
                                                                           ("e", (0, 4), 4, None)), aliases=())])
def test_valid_ctranslate2_model_is_clean(data):
    report = _static(data, "model.bin")
    assert report["static_risk"] == "clean", report["reasons"]
    assert detect.no_code_format(data) == detect.CTRANSLATE2


@pytest.mark.wasi
def test_ctranslate2_model_scans_clean(tmp_path):
    path = tmp_path / "model.bin"
    path.write_bytes(ct2_model())
    assert scan(str(path)).verdict is Verdict.CLEAN


@pytest.mark.parametrize("data", [
    ct2_model(trailer=b"\0"),                                          # bytes after the aliases
    ct2_model(variables=(("w", (2, 3), 0, b"\0" * 28),)),             # more bytes than the shape holds
    ct2_model(variables=(("w", (2, 3), 0, b"\0" * 20),)),             # fewer
    ct2_model(variables=(("w", (2,), 6, b"\0\0"),)),                   # unknown data type
    ct2_model(variables=(("w", (1,), 0, None), ("w", (1,), 0, None))),  # a name twice
    ct2_model(aliases=(("w2", "missing"),)),
    ct2_model(aliases=(("w", "w"),)),
    ct2_model()[:-3],                                                    # truncated
    ct2_model().replace(_ct2_string("w2"), _ct2_string("", b"w2")),      # no NUL: the runtime over-reads
    ct2_model().replace(_ct2_string("w2"), _ct2_string("", b"w\x002\0")),
    ct2_model().replace(_ct2_string("w2"), _ct2_string("", b"")),
    ct2_model().replace(_ct2_string("w2"), _ct2_string("", "w\u00e9".encode() + b"\0")),
])
def test_malformed_ctranslate2_model_is_risky(data):
    report = _static(data, "model.bin")
    assert report["static_risk"] == "suspicious" and report["error"], report["reasons"]


@pytest.mark.parametrize("data", [ct2_model(spec="EvilSpec"), ct2_model(version=7)])
def test_unknown_ctranslate2_spec_or_version_is_not_taken_for_one(data):
    assert detect.no_code_format(data) is None
    assert _static(data, "model.bin")["unsupported"]
    with pytest.raises(Invalid):
        model_formats.check_ctranslate2(data)


def test_payload_after_ctranslate2_aliases_is_caught():
    report = _static(ct2_model(trailer=_payload()), "model.bin")
    assert report["static_risk"] != "clean"


@pytest.mark.wasi
def test_ctranslate2_model_with_a_pickle_in_front_is_malicious(tmp_path):
    path = tmp_path / "model.bin"
    path.write_bytes(_payload() + ct2_model())
    assert scan(str(path)).verdict is Verdict.MALICIOUS


# --- whisper.cpp legacy ggml model -----------------------------------------------------

WHISPER_H = dict(n_vocab=51864, n_audio_ctx=2, n_audio_state=32, n_audio_head=1, n_audio_layer=1, n_text_ctx=2,
                 n_text_state=32, n_text_head=1, n_text_layer=1, n_mels=2, ftype=1)


def ggml_whisper(*, drop: str = "", extra=(), retype: dict | None = None, reshape: dict | None = None,
                 trailer: bytes = b"", vocab=(b"a", b""), **hparams) -> bytes:
    """A whisper.cpp model laid out like convert-pt-to-ggml.py and whisper-quantize write it."""
    h = {**WHISPER_H, **hparams}
    out = model_formats.GGML_MAGIC + struct.pack("<11i", *h.values())
    out += struct.pack("<ii", 2, 3) + b"\0" * 24
    out += struct.pack("<i", len(vocab)) + b"".join(struct.pack("<I", len(w)) + w for w in vocab)
    wtype = model_formats.GGML_FTYPES.get(h["ftype"] % 1000, 1)
    tensors = list(model_formats._whisper_tensors(h, wtype).items()) + list(extra)
    for name, (shape, ttype) in tensors:
        if name == drop:
            continue
        ttype = (retype or {}).get(name, ttype)
        ne = (reshape or {}).get(name) or tuple(shape[:max([1] + [i + 1 for i, n in enumerate(shape) if n != 1])])
        block, size = model_formats.GGML_TYPES.get(ttype, (1, 1))
        raw = name.encode()
        out += struct.pack(f"<iii{len(ne)}i", len(ne), len(raw), ttype, *ne) + raw
        out += b"\0" * (math.prod(shape) // block * size)
    return out + trailer


@pytest.mark.parametrize("ftype", [0, 1, 1008, 7])
def test_valid_ggml_whisper_model_is_clean(ftype):
    data = ggml_whisper(ftype=ftype)
    assert detect.no_code_format(data) == detect.GGML_WHISPER
    report = _static(data, "ggml-model.bin")
    assert report["static_risk"] == "clean", report["reasons"]


@pytest.mark.wasi
def test_ggml_whisper_model_scans_clean(tmp_path):
    path = tmp_path / "ggml-model.bin"
    path.write_bytes(ggml_whisper())
    assert scan(str(path)).verdict is Verdict.CLEAN


@pytest.mark.parametrize("data", [
    ggml_whisper(trailer=b"\0"),                                                       # bytes after the tensors
    ggml_whisper(trailer=_payload()),
    ggml_whisper(drop="decoder.ln.bias"),                                              # a tensor missing
    ggml_whisper(extra=[("decoder.ln.bias", ((32, 1, 1), 0))]),                        # one twice
    ggml_whisper(extra=[("evil", ((1, 1, 1), 0))]),                                    # one the model has not
    ggml_whisper(retype={"decoder.blocks.0.attn.key.weight": 64}),                     # a type id past ggml's
    ggml_whisper(retype={"decoder.blocks.0.attn.key.weight": 0}),                      # f32 where f16 is read
    ggml_whisper(reshape={"decoder.ln.bias": (16, 2)}),
    ggml_whisper(reshape={"decoder.ln.bias": (32, 1, 1, 1, 1)}),                       # five dimensions
    ggml_whisper(n_text_state=16),                                                     # widths differ
    ggml_whisper(vocab=[b"a"] * 3)[:-1],                                               # truncated
    ggml_whisper(ftype=2, n_audio_state=48, n_text_state=48),                          # rows not whole q4_0 blocks
])
def test_malformed_ggml_whisper_model_is_risky(data):
    report = _static(data, "ggml-model.bin")
    assert report["static_risk"] == "suspicious" and report["error"], report["reasons"]


@pytest.mark.parametrize("data", [ggml_whisper(n_vocab=60000), ggml_whisper(ftype=24), ggml_whisper()[:40]])
def test_unknown_ggml_variants_are_not_taken_for_whisper(data):
    assert detect.no_code_format(data) is None
    assert _static(data, "ggml-model.bin")["unsupported"]


@pytest.mark.wasi
def test_ggml_whisper_model_with_a_pickle_in_front_is_malicious(tmp_path):
    path = tmp_path / "ggml-model.bin"
    path.write_bytes(_payload() + ggml_whisper())
    assert scan(str(path)).verdict is Verdict.MALICIOUS


def _with_zip(data: bytes, members: dict) -> bytes:
    out = io.BytesIO()
    out.write(data)
    with zipfile.ZipFile(out, "a") as zf:  # what tflite_support's MetadataPopulator does
        for name, body in members.items():
            zf.writestr(name, body)
    return out.getvalue()


def test_tflite_with_associated_files_appended_is_clean():
    data = _with_zip(fixture("tiny.tflite"), {"labels.txt": "cat\ndog\n", "metadata.json": "{}"})
    report = _static(data, "model.tflite")
    assert report["static_risk"] == "clean", report["reasons"]
    assert any("TFLite associated files" in n for n in report["notes"])


@pytest.mark.parametrize("members", [
    {"labels.txt": "a", "data.pkl": _payload()},           # a pickle beside the labels
    {"archive/data.pkl": _payload()},                      # a PyTorch reading
    {"labels.txt": "a", "run.py": "print(1)"},
    {"dir/labels.txt": "a"},
    {"inner.zip": b"PK\x05\x06" + b"\0" * 18},
])
def test_other_archives_appended_to_tflite_stay_a_second_reading(members):
    report = _static(_with_zip(fixture("tiny.tflite"), members), "model.tflite")
    assert report["static_risk"] != "clean", report["notes"]


@pytest.mark.wasi
def test_payload_in_an_archive_appended_to_tflite_is_malicious(tmp_path):
    path = tmp_path / "model.tflite"
    path.write_bytes(_with_zip(fixture("tiny.tflite"), {"archive/data.pkl": _payload()}))
    assert scan(str(path)).verdict is Verdict.MALICIOUS


# --- every no-code format: random bytes never pass ------------------------------------

@pytest.mark.parametrize("fmt,check", [("onnx", model_formats.check_onnx), ("tflite", model_formats.check_tflite),
                                       ("msgpack", model_formats.check_msgpack),
                                       ("coreml", model_formats.check_coreml_weights),
                                       ("ct2", model_formats.check_ctranslate2),
                                       ("ggml", model_formats.check_ggml_whisper)])
def test_mutated_fixtures_never_crash(fmt, check):
    import random

    built = {"coreml": _two_blobs, "ct2": ct2_model, "ggml": lambda: ggml_whisper(n_vocab=51864)}
    data = built[fmt]() if fmt in built else fixture({"onnx": "tiny.onnx", "tflite": "tiny.tflite",
                                                         "msgpack": "flax_model.msgpack"}[fmt])
    rng = random.Random(1234)
    for _ in range(400):
        mutated = bytearray(data)
        for _ in range(rng.randint(1, 4)):
            mutated[rng.randrange(len(mutated))] = rng.randrange(256)
        try:
            check(bytes(mutated))
        except Invalid:
            pass
