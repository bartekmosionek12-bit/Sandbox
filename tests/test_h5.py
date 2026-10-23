"""Legacy Keras HDF5 (.h5): the sandboxed metadata reader and the Keras 2 config checks.

Fixtures in tests/fixtures/h5/ were written by tf.keras 2.15, Keras 3 and h5py
(tools/make_h5_fixtures.py); no framework is imported here and no file is loaded.
Payload fixtures only run ``echo MARKER`` and only ever reach the sandbox. Unit
tests call the stdlib reader directly on these fixtures and on mutated copies of
them; ``scan`` itself only ever runs the reader inside the WASI sandbox.
"""
from __future__ import annotations

import io
import json
import random
import struct
from pathlib import Path

import pytest

from safeloadai import Verdict, scan
from safeloadai.sandbox import emulate as sandbox_emulate
from safeloadai.sandbox import read_h5_metadata, runtime
from safeloadai.shared import hdf5_meta
from safeloadai.static import analyze_bytes
from safeloadai.static.h5_static import parse_h5_metadata

FIXTURES = Path(__file__).with_name("fixtures") / "h5"
wasi = pytest.mark.wasi

BENIGN = [
    "k2_sequential.h5", "k2_sequential_fixedstr.h5", "k2_functional_cnn.h5", "k2_functional_cnn_latest.h5",
    "k2_rnn_uncompiled.h5", "k2_weights_only.h5", "k2_many_layers.h5", "k3_sequential.h5",
    "k3_sequential_latest.h5", "s_soft_link.h5", "s_hardlink_cycle.h5",
]
STRUCTURE = {
    "s_external_link.h5": "external link",
    "s_external_data.h5": "external files",
    "s_virtual_dataset.h5": "virtual dataset",
    "s_dense_attrs.h5": "dense storage",
    "s_dense_links.h5": "dense link storage",
}


def _data(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _read(data: bytes, **limits) -> dict:
    return hdf5_meta.read_metadata(io.BytesIO(data), len(data), limits=limits or None)


def _write(tmp_path, data: bytes, name: str = "model.h5") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _attr_message(data: bytes, name: bytes = b"model_config"):
    """Offsets of a v1 attribute message in a v0 file: (datatype, data) positions."""
    at = data.index(name + b"\x00")
    body = at - 8
    version, _, name_size, type_size, space_size = struct.unpack_from("<BBHHH", data, body)
    assert version == 1

    def pad(n):
        return (n + 7) // 8 * 8

    dtype = at + pad(name_size)
    value = dtype + pad(type_size) + pad(space_size)
    return dtype, value


# -- the reader ------------------------------------------------------------------


def test_lookup3_matches_the_reference_vectors():
    # Test vectors from lookup3.c (driver5) / HDF5's H5_checksum_lookup3.
    assert hdf5_meta.lookup3(b"") == 0xDEADBEEF
    assert hdf5_meta.lookup3(b"Four score and seven years ago") == 0x17770551
    assert hdf5_meta.lookup3(b"Four score and seven years ago", 1) == 0xCD628161


@pytest.mark.parametrize("name", ["k2_sequential.h5", "k2_functional_cnn_latest.h5", "k2_sequential_fixedstr.h5",
                                  "k3_sequential_latest.h5"])
def test_reader_returns_the_root_attributes(name):
    meta = _read(_data(name))
    assert meta["problems"] == []
    config = json.loads(meta["values"]["model_config"])
    assert config["class_name"] in ("Sequential", "Functional")
    assert json.loads(meta["values"]["training_config"])["loss"]
    assert meta["values"]["keras_version"] in (b"2.15.0", b"3.15.1")
    assert meta["counts"]["datasets"] > 0


def test_reader_supports_superblock_v0_and_v3():
    assert _read(_data("k2_functional_cnn.h5"))["superblock_version"] == 0
    latest = _read(_data("k2_functional_cnn_latest.h5"))
    assert latest["superblock_version"] == 3
    assert latest["values"] == _read(_data("k2_functional_cnn.h5"))["values"]


def test_weights_only_file_has_no_model_config():
    meta = _read(_data("k2_weights_only.h5"))
    assert "model_config" not in meta["values"]
    assert "layer_names" in meta["root_attr_names"]


@pytest.mark.parametrize("name,expected", sorted(STRUCTURE.items()))
def test_reader_reports_structures_it_refuses(name, expected):
    problems = _read(_data(name))["problems"]
    assert any(expected in p for p in problems), problems


def test_soft_links_and_hard_link_cycles_are_survived():
    assert _read(_data("s_soft_link.h5"))["counts"]["soft_links"] == 1
    assert _read(_data("s_hardlink_cycle.h5"))["problems"] == []


def test_object_limit_is_a_problem_not_a_crash():
    meta = _read(_data("k2_many_layers.h5"), max_objects=10)
    assert any("more than 10 objects" in p for p in meta["problems"])


def test_attribute_size_limit():
    meta = _read(_data("k2_many_layers.h5"), max_attr_bytes=1000)
    assert "model_config" not in meta["values"]
    assert any("model_config" in p and "limit 1000" in p for p in meta["problems"])


def test_huge_declared_vlen_attribute_is_refused_without_reading_it():
    data = bytearray(_data("k2_sequential.h5"))
    _, value = _attr_message(data)
    struct.pack_into("<I", data, value, 0x7FFFFFFF)
    meta = _read(bytes(data))
    assert "model_config" not in meta["values"]
    assert any("2147483647 bytes" in p for p in meta["problems"])


def test_huge_declared_fixed_string_is_refused_without_reading_it():
    data = bytearray(_data("k2_sequential_fixedstr.h5"))
    dtype, _ = _attr_message(data)
    assert data[dtype] & 0x0F == 3  # fixed-length string
    struct.pack_into("<I", data, dtype + 4, 0x7FFFFFFF)
    meta = _read(bytes(data))
    assert any("2147483647 bytes" in p for p in meta["problems"])


def test_non_string_and_array_attributes_are_problems():
    data = bytearray(_data("k2_sequential_fixedstr.h5"))
    dtype, _ = _attr_message(data)
    data[dtype] = (data[dtype] & 0xF0) | 0  # class 0: integer
    meta = _read(bytes(data))
    assert any("is not a string" in p for p in meta["problems"])


def test_nul_inside_a_string_is_a_problem():
    data = bytearray(_data("k2_sequential_fixedstr.h5"))
    _, value = _attr_message(data)
    data[value + 5] = 0
    assert any("NUL" in p for p in _read(bytes(data))["problems"])


def test_duplicate_root_attribute_is_a_problem():
    data = bytearray(_data("k2_sequential_fixedstr.h5"))
    at = data.index(b"keras_version\x00")
    data[at:at + 13] = b"model_config\x00"  # the name field reads up to its first NUL
    meta = _read(bytes(data))
    assert any("more than once" in p for p in meta["problems"])


def test_truncated_and_corrupt_files_are_refused():
    data = _data("k2_functional_cnn.h5")
    with pytest.raises(hdf5_meta.Refused, match="truncated"):
        _read(data[: len(data) // 2])
    latest = bytearray(_data("k2_functional_cnn_latest.h5"))
    latest[latest.index(b"OHDR") + 10] ^= 0xFF
    with pytest.raises(hdf5_meta.Refused, match="checksum"):
        _read(bytes(latest))
    with pytest.raises(hdf5_meta.Refused):
        _read(hdf5_meta.SIGNATURE + b"\x00" * 8)


def test_mutated_files_raise_only_refused():
    """Random byte flips and truncations: the reader returns or raises Refused, nothing else."""
    rng = random.Random(20261018)
    sources = [_data(n) for n in ("k2_sequential.h5", "k2_functional_cnn_latest.h5", "s_dense_links.h5")]
    for _ in range(400):
        data = bytearray(rng.choice(sources))
        for _ in range(rng.randint(1, 8)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        if rng.random() < 0.2:
            data = data[: rng.randrange(len(data))]
        try:
            _read(bytes(data))
        except hdf5_meta.Refused:
            pass


# -- Keras 2 config checks --------------------------------------------------------


def _meta(config: dict, training: dict | None = None) -> dict:
    values = {"model_config": json.dumps(config).encode(), "keras_version": b"2.15.0"}
    if training is not None:
        values["training_config"] = json.dumps(training).encode()
    return {"superblock_version": 0, "root_attr_names": list(values), "values": values,
            "counts": {}, "problems": [], "notes": []}


def _seq(*layers) -> dict:
    return {"class_name": "Sequential", "config": {"name": "s", "layers": list(layers)}}


DENSE2 = {"class_name": "Dense", "config": {"units": 2, "activation": "relu",
                                            "kernel_initializer": {"class_name": "GlorotUniform",
                                                                   "config": {"seed": None}}}}


def test_keras2_mapping_is_exact():
    assert parse_h5_metadata(_meta(_seq(DENSE2)))["static_risk"] == "clean"
    for bad in ("Densex", "tf_Dense", "keras.layers.Dense"):
        layer = {"class_name": bad, "config": {}}
        assert parse_h5_metadata(_meta(_seq(layer)))["static_risk"] == "suspicious", bad


def test_keras2_custom_activation_is_suspicious():
    layer = {"class_name": "Dense", "config": {"units": 2, "activation": "my_activation"}}
    report = parse_h5_metadata(_meta(_seq(layer)))
    assert report["static_risk"] == "suspicious"
    assert any("my_activation" in r for r in report["reasons"])


def test_keras2_named_lambda_function_in_a_dangerous_module_is_malicious():
    layer = {"class_name": "Lambda", "config": {"function": "system", "function_type": "function",
                                                "module": "os"}}
    assert parse_h5_metadata(_meta(_seq(layer)))["static_risk"] == "malicious"
    other = {"class_name": "Lambda", "config": {"function": "helper", "function_type": "function",
                                                "module": "my_project.layers"}}
    assert parse_h5_metadata(_meta(_seq(other)))["static_risk"] == "suspicious"


def test_keras2_lambda_globals_module_and_output_shape_code():
    globs = {"class_name": "Lambda", "config": {"function": ["AAAA", None, None], "function_type": "lambda",
                                                "module": "subprocess"}}
    assert parse_h5_metadata(_meta(_seq(globs)))["static_risk"] == "malicious"
    shape = {"class_name": "Lambda", "config": {"function": ["AAAA", None, None], "function_type": "lambda",
                                                "module": "__main__", "output_shape": ["AAAA", None, None],
                                                "output_shape_type": "lambda"}}
    report = parse_h5_metadata(_meta(_seq(shape)))
    assert report["static_risk"] == "suspicious"
    assert any("output_shape code" in r for r in report["reasons"])


@pytest.mark.parametrize("training", [
    {"loss": "my_loss"},
    {"loss": {"out": "my_loss"}},
    {"loss": "mse", "metrics": [["my_metric"]]},
    {"loss": "mse", "metrics": [[{"class_name": "MeanMetricWrapper", "config": {"fn": "my_fn"}}]]},
    {"loss": "mse", "optimizer_config": {"class_name": "MyOptimizer", "config": {}}},
    {"loss": "mse", "optimizer_config": "adam"},
])
def test_custom_training_objects_are_suspicious(training):
    assert parse_h5_metadata(_meta(_seq(DENSE2), training))["static_risk"] == "suspicious"


def test_builtin_training_config_is_clean():
    training = {"loss": "categorical_crossentropy",
                "metrics": [[{"class_name": "MeanMetricWrapper", "config": {"fn": "categorical_accuracy"}}]],
                "optimizer_config": {"class_name": "Custom>Adam", "config": {"learning_rate": 0.001}}}
    assert parse_h5_metadata(_meta(_seq(DENSE2), training))["static_risk"] == "clean"


def test_invalid_json_and_failed_reader_are_suspicious():
    meta = _meta(_seq(DENSE2))
    meta["values"]["model_config"] = b"{not json"
    assert parse_h5_metadata(meta)["static_risk"] == "suspicious"
    failed = parse_h5_metadata({"failed": "HDF5 structure refused: x"})
    assert failed["static_risk"] == "suspicious" and failed["error"]


# -- end to end (inside the sandbox) ------------------------------------------------


@wasi
@pytest.mark.parametrize("name", BENIGN)
def test_benign_h5_models_are_clean(name):
    report = scan(FIXTURES / name)
    assert report.verdict is Verdict.CLEAN, report.reasons
    assert report.file_format == "h5"


@wasi
def test_benign_lambda_h5_is_risky_never_clean():
    # Owner decision L1 (2026-10-22): Lambda bytecode is never CLEAN, whatever emulation saw.
    report = scan(FIXTURES / "k3_lambda_benign.h5")
    assert report.verdict is Verdict.SUSPICIOUS and report.category == "RISKY", report.reasons


@wasi
def test_cve_2024_3660_lambda_marker_is_malicious():
    report = scan(FIXTURES / "k2_lambda_marker.h5")
    assert report.verdict is Verdict.MALICIOUS
    assert any("subprocess" in r for r in report.reasons)


@wasi
def test_named_os_system_lambda_is_malicious():
    report = scan(FIXTURES / "k2_lambda_os_system.h5")
    assert report.verdict is Verdict.MALICIOUS
    assert any("os.system" in r for r in report.reasons)


@wasi
@pytest.mark.parametrize("name", ["k2_custom_objects.h5", "k2_custom_loss.h5"])
def test_custom_objects_are_suspicious(name):
    report = scan(FIXTURES / name)
    assert report.verdict is Verdict.SUSPICIOUS
    assert any("my_custom_loss" in r for r in report.reasons)


@wasi
def test_benign_keras2_lambda_is_not_clean():
    # Bytecode of another Python version and no input shape: emulation cannot vouch for it.
    assert scan(FIXTURES / "k2_lambda_benign.h5").verdict is Verdict.SUSPICIOUS


@wasi
@pytest.mark.parametrize("name,expected", sorted(STRUCTURE.items()))
def test_structures_outside_the_model_are_suspicious(name, expected):
    report = scan(FIXTURES / name)
    assert report.verdict is Verdict.SUSPICIOUS
    assert any(expected in r for r in report.reasons), report.reasons


@wasi
def test_malformed_and_truncated_files_are_suspicious(tmp_path):
    data = _data("k2_functional_cnn.h5")
    for blob in (data[: len(data) // 2], hdf5_meta.SIGNATURE + b"\xff" * 64, data[:200]):
        report = scan(_write(tmp_path, blob))
        assert report.verdict is Verdict.SUSPICIOUS
        assert any("HDF5" in r for r in report.reasons), report.reasons


@wasi
def test_huge_attribute_is_suspicious_without_crash(tmp_path):
    data = bytearray(_data("k2_sequential.h5"))
    _, value = _attr_message(data)
    struct.pack_into("<I", data, value, 0x7FFFFFFF)
    report = scan(_write(tmp_path, bytes(data)))
    assert report.verdict is Verdict.SUSPICIOUS
    assert any("limit" in r for r in report.reasons)


@wasi
def test_attribute_larger_than_one_record_is_reassembled():
    data = _data("k2_many_layers.h5")
    meta = read_h5_metadata(data)
    assert len(meta["values"]["model_config"]) > sandbox_emulate.H5_CHUNK
    assert meta["values"] == _read(data)["values"]


@wasi
def test_scan_reads_hdf5_only_inside_the_sandbox(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("HDF5 parsed on the host")

    monkeypatch.setattr(hdf5_meta, "read_metadata", refuse)
    tasks = []
    real = sandbox_emulate.run_guest
    monkeypatch.setattr(sandbox_emulate, "run_guest", lambda task, *a, **k: tasks.append(task["kind"]) or
                        real(task, *a, **k))
    assert analyze_bytes(_data("k2_sequential.h5"), "m.h5")["static_risk"] == "clean"
    assert tasks == ["h5_meta"]


def test_missing_runtime_makes_h5_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv(runtime.RUNTIME_ENV, str(tmp_path / "absent.wasm"))
    report = scan(FIXTURES / "k2_sequential.h5")
    assert report.status == "error" and report.verdict is None and not report.clean
    assert report.error["code"] == "E301" and "sandbox unavailable" in report.error["message"]


@wasi
def test_safe_load_does_not_load_h5():
    from safeloadai import UnsafeModelError, safe_load

    with pytest.raises(UnsafeModelError, match="no loader"):
        safe_load(FIXTURES / "k2_sequential.h5")
