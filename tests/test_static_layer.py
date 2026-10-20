"""Static layer: container parsing, exact allowlists, scoring (milestone 2)."""
from __future__ import annotations

import io
import json
import pickle
import zipfile

import pytest

from safeloadai import static
from safeloadai.parsing import detect
from safeloadai.parsing.zipsafe import SafeZip, ZipRefused
from safeloadai.static import keras_static, pickle_static, torch_static
from safeloadai.static.pickle_static import TORCH_LEGACY_MAGIC


def _zip(members: dict[str, bytes], prefix: bytes = b"") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return prefix + buf.getvalue()


def _keras(layers: list[dict]) -> bytes:
    config = {"module": "keras", "class_name": "Sequential", "registered_name": None,
              "config": {"layers": layers}}
    return _zip({"config.json": json.dumps(config).encode(),
                 "metadata.json": b'{"keras_version": "3.15.1"}'})


DENSE = {"module": "keras.layers", "class_name": "Dense", "registered_name": None,
         "config": {"units": 2, "activation": "relu",
                    "kernel_initializer": {"module": "keras.initializers",
                                           "class_name": "GlorotUniform", "config": {},
                                           "registered_name": None}}}


# --- zip safety ----------------------------------------------------------------

def test_zip_member_over_limit_is_refused_before_reading():
    zf = SafeZip(_zip({"big": b"\0" * 2048}), max_member_bytes=1024)
    with pytest.raises(ZipRefused, match="declares"):
        zf.read("big")


def test_zip_compression_ratio_is_capped():
    zf = SafeZip(_zip({"bomb": b"\0" * (1 << 20)}), max_ratio=50)
    with pytest.raises(ZipRefused, match="ratio"):
        zf.read("bomb")


def test_zip_duplicate_names_are_reported():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf, pytest.warns(UserWarning):
        zf.writestr("config.json", b"{}")
        zf.writestr("config.json", b"{}")
    assert any("duplicate" in p for p in SafeZip(buf.getvalue()).inventory.problems)


def test_zip_with_leading_bytes_is_reported_as_polyglot():
    data = _zip({"config.json": b"{}"}, prefix=b"\x80\x02N.")
    assert any("polyglot" in p for p in SafeZip(data).inventory.problems)


def test_not_a_zip_is_refused():
    with pytest.raises(ZipRefused):
        SafeZip(b"hello")


# --- format detection ------------------------------------------------------------

@pytest.mark.parametrize(
    "data, fmt",
    [
        (pickle.dumps({"a": 1}, protocol=4), detect.PICKLE),
        (b"\x89HDF\r\n\x1a\n" + b"\0" * 16, detect.H5),
        (_zip({"config.json": b"{}"}), detect.KERAS),
        (_zip({"archive/data.pkl": b"\x80\x02}."}), detect.TORCH),
        (b"just text", detect.UNKNOWN),
    ],
)
def test_detect_by_content(data, fmt):
    assert detect.detect(data) == fmt


def test_extension_mismatch_is_suspicious():
    report = static.analyze_bytes(pickle.dumps([1, 2], protocol=4), "model.keras")
    assert report["static_risk"] == "suspicious"
    assert any("does not match" in r for r in report["reasons"])


def test_h5_is_suspicious_until_sandbox_parsing_exists():
    report = static.analyze_bytes(b"\x89HDF\r\n\x1a\n" + b"\0" * 16, "model.h5")
    assert report["static_risk"] == "suspicious"


# --- pickle --------------------------------------------------------------------

@pytest.mark.parametrize("protocol", [0, 2, 4, 5])
def test_plain_containers_are_clean(protocol):
    data = pickle.dumps({"w": [1.0, 2.0], "s": {1, 2}, "b": b"x", "c": 1j}, protocol=protocol)
    assert pickle_static.parse_pickle(data)["static_risk"] == "clean"


def test_ext_opcode_is_suspicious():
    assert pickle_static.parse_pickle(b"\x80\x02\x82\x01.")["static_risk"] == "suspicious"


def test_persistent_id_outside_torch_is_suspicious():
    assert pickle_static.parse_pickle(b"\x80\x02K\x01Q.")["static_risk"] == "suspicious"


def test_trailing_garbage_after_stop_is_suspicious():
    data = pickle.dumps([1], protocol=2) + b"not a pickle"
    assert pickle_static.parse_pickle(data)["static_risk"] == "suspicious"


def test_dangerous_import_without_call_is_suspicious_not_malicious():
    report = pickle_static.parse_pickle(b"cposix\nsystem\n.")
    assert report["static_risk"] == "suspicious"


def test_suspicious_strings_are_recorded_as_evidence():
    data = b"\x80\x02X\x13\x00\x00\x00curl http://1.2.3.4q\x00."
    report = pickle_static.parse_pickle(data)
    assert report["suspicious_strings"] and report["static_risk"] == "clean"


def test_legacy_torch_stream_accepts_raw_storage_tail():
    magic = pickle.dumps(TORCH_LEGACY_MAGIC, protocol=2)
    parts = [magic] + [pickle.dumps(x, protocol=2) for x in (1001, {"little_endian": True},
                                                            {"w": 1}, ["0"])]
    data = b"".join(parts) + b"\x00\x01\x02 raw tensor bytes"
    report = pickle_static.parse_pickle(data)
    assert report["static_risk"] == "clean"
    assert report["pickle_count"] == 5


# --- torch zip -------------------------------------------------------------------

TORCH_TENSOR_PKL = (
    b"\x80\x02ctorch._utils\n_rebuild_tensor_v2\n("
    b"(X\x07\x00\x00\x00storage" b"ctorch\nFloatStorage\n" b"X\x01\x00\x00\x000X\x03\x00\x00\x00cpu"
    b"K\x04tQK\x00K\x04\x85K\x01\x85\x89ccollections\nOrderedDict\n)Rtq\x00R."
)


def test_torch_zip_with_tensor_rebuild_is_clean():
    report = torch_static.parse_torch_zip(_zip({"archive/data.pkl": TORCH_TENSOR_PKL,
                                                "archive/data/0": b"\0" * 16}))
    assert report["static_risk"] == "clean", report["reasons"]


def test_torch_globals_are_not_allowed_in_plain_pickles():
    assert pickle_static.parse_pickle(TORCH_TENSOR_PKL)["static_risk"] == "suspicious"


def test_torchscript_archive_is_suspicious():
    data = _zip({"archive/data.pkl": b"\x80\x02}.", "archive/code/__torch__.py": b"x = 1",
                 "archive/constants.pkl": b"\x80\x02).", })
    assert torch_static.parse_torch_zip(data)["static_risk"] == "suspicious"


# --- keras ---------------------------------------------------------------------

def test_standard_keras_model_is_clean():
    report = keras_static.parse_keras(_keras([DENSE]))
    assert report["static_risk"] == "clean", report["reasons"]
    assert report["metadata"] == {"keras_version": "3.15.1"}


def test_keras_function_outside_allowlist_is_malicious():
    layer = dict(DENSE, config={"activation": {"module": "os", "class_name": "function",
                                               "config": "system", "registered_name": "function"}})
    assert keras_static.parse_keras(_keras([layer]))["static_risk"] == "malicious"


def test_keras_activation_function_in_allowlist_is_clean():
    layer = dict(DENSE, config={"activation": {"module": "keras.activations", "class_name": "function",
                                               "config": "relu", "registered_name": "function"}})
    assert keras_static.parse_keras(_keras([layer]))["static_risk"] == "clean"


def test_custom_registered_name_is_suspicious():
    layer = dict(DENSE, registered_name="my_pkg>Dense")
    assert keras_static.parse_keras(_keras([layer]))["static_risk"] == "suspicious"


def test_tfoplambda_with_io_function_is_malicious():
    layer = {"module": "keras.layers", "class_name": "TFOpLambda", "registered_name": None,
             "config": {"function": "io.write_file"}}
    assert keras_static.parse_keras(_keras([layer]))["static_risk"] == "malicious"


def test_lambda_without_sink_tokens_is_suspicious_pending_emulation():
    import base64

    code = base64.b64encode(b"\xe3" + b"\0" * 40 + b"\xfa\x03abs").decode()
    layer = {"module": "keras.layers", "class_name": "Lambda", "registered_name": None,
             "config": {"function": {"class_name": "__lambda__", "config": {"code": code}}}}
    report = keras_static.parse_keras(_keras([layer]))
    assert report["static_risk"] == "suspicious"
    assert report["lambdas"][0]["has_code"]


def test_marshal_sink_tokens_match_exact_framing_only():
    assert keras_static.marshal_sink_tokens(b"\xda\x06system") == ["system"]
    assert keras_static.marshal_sink_tokens(b"filesystem_name") == []


def test_lambda_function_object_outside_lambda_layer_is_flagged():
    import io as _io
    import json as _json
    import zipfile as _zipfile

    model = {"module": "keras", "class_name": "Functional", "registered_name": "Functional", "config": {
        "layers": [{"module": "keras.layers", "class_name": "Dense", "registered_name": None,
                    "config": {"activation": {"class_name": "__lambda__", "config": {"code": "AAAA"}}}}]}}
    buf = _io.BytesIO()
    with _zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.json", _json.dumps(model))
        zf.writestr("metadata.json", _json.dumps({"keras_version": "3.15.1"}))
    report = keras_static.parse_keras(buf.getvalue())
    assert report["static_risk"] != "clean"
    assert any(i["symbol"] == "__lambda__" for i in report["unknown_imports"])


def _keras_with_loss(module: str, name: str) -> bytes:
    config = {"module": "keras", "class_name": "Sequential", "registered_name": None,
              "config": {"layers": [DENSE]},
              "compile_config": {"loss": {"module": module, "class_name": "function",
                                          "config": name, "registered_name": "function"}}}
    return _zip({"config.json": json.dumps(config).encode(),
                 "metadata.json": b'{"keras_version": "3.15.1"}'})


# The custom loss and metric names of the six MALICIOUS false positives in the 2026-10-19 Hub run.
HUB_CUSTOM_FUNCTIONS = ["binary_focal_loss", "stage4_loss_without_none", "psnr_metric", "ssim_metric",
                        "mae_metric", "_loss"]


@pytest.mark.parametrize("name", HUB_CUSTOM_FUNCTIONS)
def test_keras_custom_loss_saved_under_builtins_is_unverifiable_not_malicious(name):
    # Keras records a user's own loss as builtins.<name>; Python's builtins has no such name.
    report = keras_static.parse_keras(_keras_with_loss("builtins", name))
    assert report["static_risk"] == "suspicious", report["reasons"]
    assert not any("known sink" in r for r in report["reasons"]), report["reasons"]
    (meta,) = report["unverifiable"].values()
    assert meta["item"] == f"builtins.{name}"
    assert "custom_objects" in meta["explanation"]


def test_keras_custom_metric_list_under_builtins_is_unverifiable():
    config = {"module": "keras", "class_name": "Sequential", "registered_name": None,
              "config": {"layers": [DENSE]},
              "compile_config": {"metrics": [{"module": "builtins", "class_name": "function", "config": n,
                                              "registered_name": "function"} for n in HUB_CUSTOM_FUNCTIONS[2:5]]}}
    report = keras_static.parse_keras(_zip({"config.json": json.dumps(config).encode(),
                                            "metadata.json": b'{"keras_version": "3.15.1"}'}))
    assert report["static_risk"] == "suspicious", report["reasons"]
    assert len(report["unverifiable"]) == 3


@pytest.mark.parametrize("name", ["eval", "exec", "compile", "__import__", "getattr", "open", "breakpoint"])
def test_keras_real_builtin_function_stays_malicious(name):
    report = keras_static.parse_keras(_keras_with_loss("builtins", name))
    assert report["static_risk"] == "malicious", report["reasons"]


def test_pickle_builtins_name_stays_a_known_sink():
    # pickle resolves builtins.<name> in Python's builtins, so the Keras rule does not apply.
    data = b"\x80\x02cbuiltins\nbinary_focal_loss\n)R."
    report = pickle_static.parse_pickle(data)
    assert report["static_risk"] == "malicious", report["reasons"]


def _torch_zip_bad_crc(data_pkl: bytes) -> bytes:
    """A stored torch zip whose data.pkl bytes do not match the recorded CRC-32."""
    placeholder = b"\xa5" * len(data_pkl)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("archive/data.pkl", placeholder)
        zf.writestr("archive/version", b"3\n")
    return buf.getvalue().replace(placeholder, data_pkl, 1)


def test_torch_member_with_bad_crc_is_analysed_and_risky():
    # torch's reader does not check CRC-32, so the bytes are analysed, and the mismatch stays RISKY.
    report = torch_static.parse_torch_zip(_torch_zip_bad_crc(b"\x80\x02]q\x00."))
    assert report["static_risk"] == "suspicious", report["reasons"]
    assert any("CRC-32 of member 'archive/data.pkl'" in r for r in report["reasons"]), report["reasons"]
    assert report["pickle_count"] == 1


def test_torch_member_with_bad_crc_still_finds_the_payload():
    report = torch_static.parse_torch_zip(_torch_zip_bad_crc(b"\x80\x02cposix\nsystem\n(S'echo MARKER'\ntR."))
    assert report["static_risk"] == "malicious", report["reasons"]


def test_keras_member_with_bad_crc_is_still_refused():
    # zipfile, which Keras uses, checks CRC-32: such a .keras does not load, and is refused.
    placeholder = b"\xa5" * 20
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("config.json", placeholder)
        zf.writestr("metadata.json", b'{"keras_version": "3.15.1"}')
    report = keras_static.parse_keras(buf.getvalue().replace(placeholder, b'{"class_name": "X"} ', 1))
    assert report["static_risk"] == "suspicious"
    assert any("Bad CRC-32" in r for r in report["reasons"]), report["reasons"]


@pytest.mark.parametrize("module, name", [("pandas.io.pickle", "read_pickle"), ("pandas", "read_pickle"),
                                          ("pandas.io.pytables", "read_hdf"), ("keras.saving", "load_model")])
def test_a_loader_of_another_pickle_is_a_sink(module, name):
    # The Hub's 017_poc_picklescan_bypass_pandas_read_pickle_nested_ACE.joblib calls
    # pandas.read_pickle on a second file: the nested pickle is never analysed.
    data = (b"\x80\x04\x8c" + bytes([len(module)]) + module.encode() + b"\x8c" + bytes([len(name)])
            + name.encode() + b"\x93\x8c\x09poc/x.pkl\x85R.")
    assert pickle_static.parse_pickle(data)["static_risk"] == "malicious"
