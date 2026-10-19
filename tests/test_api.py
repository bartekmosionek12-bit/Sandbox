"""scan() / safe_load() with the emulation layer replaced (no WASI runtime needed).

Pickles here are benign and built with pickle.dumps on the host; payload samples
are only ever scanned, never loaded.
"""
import json
import pickle
import sys

import pytest
from corpus.build_corpus import MARKER_CMD, P2, STOP, call, g, s

from safeloadai import UnsafeModelError, Verdict, api, safe_load, scan
from safeloadai.sandbox import runtime


def _write(path, obj):
    path.write_bytes(pickle.dumps(obj, protocol=4))
    return str(path)


def test_clean_pickle_loads(tmp_path, fake_emulation):
    path = _write(tmp_path / "m.pkl", {"w": [1, 2, 3]})
    assert safe_load(path) == {"w": [1, 2, 3]}


def test_pathlib_path_accepted(tmp_path, fake_emulation):
    path = tmp_path / "m.pkl"
    _write(path, [1])
    assert safe_load(path) == [1]


def test_static_malicious_sample_is_blocked(tmp_path, fake_emulation):
    target = tmp_path / "evil.pkl"
    target.write_bytes(P2 + call(g("posix", "system"), s(MARKER_CMD)) + STOP)
    with pytest.raises(UnsafeModelError) as info:
        safe_load(str(target))
    assert info.value.verdict is Verdict.MALICIOUS


def test_emulation_finding_blocks_load(tmp_path, fake_emulation):
    fake_emulation.verdict = Verdict.SUSPICIOUS
    path = _write(tmp_path / "m.pkl", {"a": 1})
    with pytest.raises(UnsafeModelError) as info:
        safe_load(path)
    assert info.value.verdict is Verdict.SUSPICIOUS


def test_missing_runtime_fails_closed(tmp_path, monkeypatch):
    def missing():
        raise runtime.RuntimeUnavailable("no runtime in this test")

    monkeypatch.setattr(runtime, "locate", missing)
    report = scan(_write(tmp_path / "m.pkl", {"a": 1}))
    assert report.verdict is Verdict.SUSPICIOUS
    assert report.layer("emulation").ran is False


def test_scan_then_swap_loads_scanned_copy(tmp_path, fake_emulation):
    original = tmp_path / "m.pkl"
    _write(original, "scanned")
    fake_emulation.side_effect = lambda data: _write(original, "swapped")
    assert safe_load(str(original)) == "scanned"


def test_allow_pair_extends_scan_and_loader(tmp_path, fake_emulation):
    sys.modules.pop("_import_marker", None)
    path = tmp_path / "m.pkl"
    path.write_bytes(b"c_import_marker\nVALUE\n.")
    assert scan(str(path)).verdict is Verdict.SUSPICIOUS
    assert "_import_marker" not in sys.modules
    assert safe_load(str(path), allow=[("_import_marker", "VALUE")]) == "imported"


def test_restricted_unpickler_refuses_before_import(tmp_path):
    sys.modules.pop("_import_marker", None)
    path = tmp_path / "m.pkl"
    path.write_bytes(b"c_import_marker\nVALUE\n.")
    with pytest.raises(UnsafeModelError):
        api.load_pickle(str(path), frozenset())
    assert "_import_marker" not in sys.modules


def test_unknown_format_is_refused(tmp_path, fake_emulation):
    path = tmp_path / "model.bin"
    path.write_bytes(b"\x00\x01 not a model")
    with pytest.raises(UnsafeModelError):
        safe_load(str(path))


def test_report_json_round_trip(tmp_path, fake_emulation):
    report = scan(_write(tmp_path / "m.pkl", {"a": 1}))
    data = json.loads(report.to_json())
    assert data["verdict"] == "CLEAN" and data["file_format"] == "pickle"
    assert [layer["name"] for layer in data["layers"]] == ["static", "emulation"]
    assert data["sha256"] == report.sha256 and "total" in data["timings_ms"]
