"""joblib support: container codecs, the array layout, object arrays, limits, loading.

Fixtures are written with joblib.dump (never loaded with joblib). Payloads are
harmless markers (``echo MARKER``) and only ever reach the WASI sandbox.
"""
from __future__ import annotations

import bz2
import io
import pickle
import subprocess
import sys
import tracemalloc
import zlib

import pytest

np = pytest.importorskip("numpy")
joblib = pytest.importorskip("joblib")

from safeloadai import UnsafeModelError, Verdict, safe_load, scan  # noqa: E402
from safeloadai.parsing import decompress  # noqa: E402
from safeloadai.parsing import detect as detect_mod  # noqa: E402
from safeloadai.pipeline import emulation_layer  # noqa: E402
from safeloadai.static import analyze_bytes  # noqa: E402
from safeloadai.static.pickle_static import parse_pickle  # noqa: E402

CODECS = ["zlib", "gzip", "bz2", "lzma", "xz", "lz4"]


class _Marker:
    """Pickles as a call to subprocess.getoutput('echo MARKER'); never unpickled on the host.

    (os.system itself is replaced by the host guard during tests, so it cannot be
    pickled by reference.)"""

    def __reduce__(self):
        return (subprocess.getoutput, ("echo MARKER",))


class _NoTell(io.RawIOBase):
    """A write-only stream without tell(): joblib then writes arrays without padding."""

    def __init__(self):
        self.buffer = io.BytesIO()

    def writable(self):
        return True

    def write(self, data):
        return self.buffer.write(data)

    def tell(self):
        raise io.UnsupportedOperation("tell")


def _dump(tmp_path, obj, name="m.joblib", **kwargs):
    path = tmp_path / name
    joblib.dump(obj, path, **kwargs)
    return path


def _codec_available(codec):
    if codec == "lz4":
        pytest.importorskip("lz4.frame")


def _model():
    sklearn = pytest.importorskip("sklearn")  # noqa: F841
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    rng = np.random.default_rng(0)
    X = rng.random((60, 4))
    y = np.array(["cat", "dog", "fish"] * 20)
    forest = RandomForestClassifier(n_estimators=3, random_state=0).fit(X, y)
    pipe = Pipeline([("scale", StandardScaler()), ("clf", LogisticRegression())]).fit(X, y)
    return X, forest, pipe


# --- static layout ---------------------------------------------------------------

@pytest.mark.parametrize("protocol", [2, 3, 4, 5])
def test_arrays_are_skipped_not_read_as_opcodes(tmp_path, protocol):
    arrays = {"f8": np.arange(10.0), "fortran": np.asfortranarray(np.ones((3, 4))), "u": np.array(["x", "yy"]),
              "rec": np.zeros(3, dtype=[("a", "f4"), ("b", "i8")]), "empty": np.zeros((0, 3)),
              "dt": np.array(["2020-01-01"], dtype="M8[D]"), "big_endian": np.arange(4, dtype=">i4"),
              "sub": np.zeros(2, dtype=("f8", (2, 2)))}
    report = parse_pickle(_dump(tmp_path, arrays, protocol=protocol).read_bytes())
    assert report["static_risk"] == "clean", report["reasons"]
    assert report["file_format"] == "joblib"
    assert report["joblib"]["arrays"] == len(arrays)


def test_object_array_is_walked_as_nested_pickle(tmp_path):
    report = parse_pickle(_dump(tmp_path, {"o": np.array([1, "a", None], dtype=object)}).read_bytes())
    assert report["static_risk"] == "clean", report["reasons"]
    assert report["joblib"]["object_arrays"] == 1


def test_payload_in_object_array_is_malicious(tmp_path):
    hidden = np.array([1.0, _Marker()], dtype=object)
    report = parse_pickle(_dump(tmp_path, {"weights": np.ones(8), "classes": hidden}).read_bytes())
    assert report["static_risk"] == "malicious"
    assert any(i["symbol"] == "getoutput" for i in report["suspicious_imports"])


def test_parser_differential_in_raw_array_bytes(tmp_path):
    # joblib reads these bytes as uint8 data; plain pickle.load would run them.
    program = np.frombuffer(b"cos\nsystem\n(S'echo MARKER'\ntR.", np.uint8)
    out = _NoTell()
    joblib.dump({"a": program.copy()}, out)
    data = out.buffer.getvalue()
    report = parse_pickle(data)
    assert report["static_risk"] == "malicious", report["reasons"]
    assert any("parser differential" in r for r in report["reasons"])


def test_random_array_data_raises_no_differential(tmp_path):
    rng = np.random.default_rng(1)
    report = parse_pickle(_dump(tmp_path, [rng.random(5000) for _ in range(20)]).read_bytes())
    assert report["static_risk"] == "clean", report["reasons"]


def test_truncated_array_data_is_suspicious(tmp_path):
    data = _dump(tmp_path, {"a": np.arange(1000.0)}).read_bytes()
    for cut in (len(data) - 10, len(data) // 2):
        report = parse_pickle(data[:cut])
        assert report["static_risk"] == "suspicious"
        assert report["error"]


def test_wrapper_built_inside_a_frame_is_suspicious(tmp_path):
    data = bytearray(_dump(tmp_path, {"a": np.arange(4.0)}, protocol=4).read_bytes())
    # Grow the first frame so that it covers the array bytes too.
    assert data[2] == pickle.FRAME[0]
    size = int.from_bytes(data[3:11], "little")
    data[3:11] = (size + 16).to_bytes(8, "little")
    report = parse_pickle(bytes(data))
    assert report["static_risk"] == "suspicious"
    assert "frame" in report["error"]


def test_inconsistent_dtype_is_suspicious():
    wrapper = ("joblib.numpy_pickle", "NumpyArrayWrapper")
    stream = (b"\x80\x02c%s\n%s\n)\x81}(X\x05\x00\x00\x00shapeK\x02\x85X\x05\x00\x00\x00orderX\x01\x00\x00\x00C"
              b"X\x05\x00\x00\x00dtypecnumpy\ndtype\nX\x02\x00\x00\x00f8\x89\x88\x87R(K\x03X\x01\x00\x00\x00<"
              b"NNNK\x10J\xff\xff\xff\xffK\x00tbub" % tuple(p.encode() for p in wrapper))
    report = parse_pickle(stream + b"\0" * 16 + b".")
    assert report["static_risk"] == "suspicious"
    assert "fixed-size dtype" in report["error"]


def test_legacy_multi_file_joblib_is_suspicious():
    from joblib.numpy_pickle_compat import NDArrayWrapper

    data = pickle.dumps({"a": NDArrayWrapper("m.pkl_01.npy", np.ndarray)}, protocol=2)
    report = parse_pickle(data)
    assert report["static_risk"] == "suspicious"
    assert any("legacy joblib" in r for r in report["reasons"])


def test_legacy_zf_container_is_read(tmp_path):
    inner = pickle.dumps({"a": 1}, protocol=2)
    data = b"ZF" + hex(len(inner)).encode().ljust(19) + zlib.compress(inner)
    report = analyze_bytes(data, "old.pkl")
    assert report["compression"] == "compat"
    assert report["static_risk"] == "clean", report["reasons"]


# --- codecs -------------------------------------------------------------------------

@pytest.mark.parametrize("codec", CODECS)
def test_each_codec_is_detected_and_decompressed(tmp_path, codec):
    _codec_available(codec)
    path = _dump(tmp_path, {"a": np.arange(100.0), "o": np.array(["x", 2], dtype=object)}, compress=(codec, 3))
    data = path.read_bytes()
    assert detect_mod.detect(data) == detect_mod.JOBLIB
    report = analyze_bytes(data, path.name)
    assert report["compression"] == codec
    assert report["static_risk"] == "clean", report["reasons"]


@pytest.mark.parametrize("codec", CODECS)
def test_malicious_joblib_is_caught_for_each_codec(tmp_path, codec):
    _codec_available(codec)
    path = _dump(tmp_path, {"a": np.arange(10.0), "payload": _Marker()}, compress=(codec, 3))
    report = analyze_bytes(path.read_bytes(), path.name)
    assert report["static_risk"] == "malicious", report["reasons"]


def test_lz4_without_the_package_is_suspicious(tmp_path, monkeypatch):
    _codec_available("lz4")
    path = _dump(tmp_path, {"a": 1}, compress=("lz4", 3))
    monkeypatch.setitem(sys.modules, "lz4", None)
    monkeypatch.setitem(sys.modules, "lz4.frame", None)
    report = analyze_bytes(path.read_bytes(), path.name)
    assert report["static_risk"] == "suspicious"
    assert "lz4" in report["reasons"][0] and "not installed" in report["reasons"][0]


@pytest.mark.parametrize("codec", ["zlib", "gzip", "bz2", "xz"])
def test_corrupt_or_truncated_compressed_joblib_is_suspicious(tmp_path, codec):
    data = _dump(tmp_path, {"a": np.random.default_rng(2).random(2000)}, compress=(codec, 3)).read_bytes()
    corrupt = bytearray(data)
    for i in range(len(corrupt) // 2, len(corrupt) // 2 + 64):
        corrupt[i] ^= 0x5A
    for broken in (bytes(corrupt), data[: len(data) // 2], data + b"trailing"):
        report = analyze_bytes(broken, "m.joblib")
        assert report["static_risk"] == "suspicious", codec


def test_decompression_bomb_ratio_is_refused_without_memory_blowup():
    c = bz2.BZ2Compressor(9)
    bomb = b"".join(c.compress(b"\0" * (1 << 20)) for _ in range(256)) + c.flush()  # 256 MiB -> ~200 bytes
    tracemalloc.start()
    try:
        report = analyze_bytes(bomb, "bomb.joblib")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert report["static_risk"] == "suspicious"
    assert "decompression bomb" in report["reasons"][0]
    assert peak < 32 * 1024 * 1024


def test_decompression_output_cap(monkeypatch):
    monkeypatch.setattr(decompress, "DEFAULT_MAX_OUTPUT", 4 * 1024 * 1024)
    monkeypatch.setattr(decompress, "DEFAULT_MAX_RATIO", 10**9)
    c = zlib.compressobj(9)
    bomb = b"".join(c.compress(b"\0" * (1 << 20)) for _ in range(16)) + c.flush()
    report = analyze_bytes(bomb, "bomb.joblib")
    assert report["static_risk"] == "suspicious"
    assert "exceeds 4194304 bytes" in report["reasons"][0]


# --- sandbox and scan ---------------------------------------------------------------

@pytest.mark.wasi
def test_emulation_reproduces_array_skipping(tmp_path):
    path = _dump(tmp_path, {"a": np.arange(50.0), "b": np.ones((4, 4)), "o": np.array(["x", 1], dtype=object)})
    data = path.read_bytes()
    report = parse_pickle(data)
    layer = emulation_layer(data, report, frozenset())
    assert layer.verdict is Verdict.CLEAN, layer.reasons
    assert layer.details["completed"]


@pytest.mark.wasi
def test_emulation_flags_payload_in_object_array(tmp_path):
    path = _dump(tmp_path, {"o": np.array([_Marker()], dtype=object)}, compress=("gzip", 3))
    data = path.read_bytes()
    report = analyze_bytes(data, path.name)
    layer = emulation_layer(data, report, frozenset())
    assert layer.verdict is Verdict.MALICIOUS
    assert any("subprocess.getoutput" in r for r in layer.reasons)


@pytest.mark.wasi
@pytest.mark.parametrize("compress", [0, ("zlib", 3), ("xz", 3)])
def test_real_sklearn_models_are_clean_and_load(tmp_path, compress):
    X, forest, pipe = _model()
    path = _dump(tmp_path, {"forest": forest, "pipe": pipe}, compress=compress)
    report = scan(path)
    assert report.verdict is Verdict.CLEAN, report.reasons
    assert report.file_format == "joblib"
    loaded = safe_load(path)
    assert (loaded["forest"].predict(X) == forest.predict(X)).all()
    assert (loaded["pipe"].predict(X) == pipe.predict(X)).all()


@pytest.mark.wasi
def test_malicious_joblib_scan_and_safe_load_refuse(tmp_path):
    path = _dump(tmp_path, {"a": np.arange(3.0), "p": _Marker()}, compress=("bz2", 3))
    assert scan(path).verdict is Verdict.MALICIOUS
    with pytest.raises(UnsafeModelError):
        safe_load(path)


def test_restricted_joblib_loader_refuses_unlisted_globals(tmp_path):
    from safeloadai.api import load_joblib
    from safeloadai.static.allowlists import PICKLE_GLOBALS

    path = _dump(tmp_path, {"a": np.arange(3.0), "o": np.array([_Marker()], dtype=object)})
    with pytest.raises(UnsafeModelError, match="not on the allowlist"):
        load_joblib(str(path), PICKLE_GLOBALS)
