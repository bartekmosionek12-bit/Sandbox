"""pathlib path classes are not known sinks; their methods are (0.10.0, DECISIONS.md)."""
from __future__ import annotations

import pytest

from safeloadai import Verdict, scan
from safeloadai.static import analyze_bytes

MARKER = "SAFELOADAI_TEST_MARKER"


def _s(text: str) -> bytes:
    raw = text.encode()
    return b"\x8c" + bytes([len(raw)]) + raw


def _global(module: str, name: str) -> bytes:
    return _s(module) + _s(name) + b"\x93"


def windows_path(*parts: str) -> bytes:
    """What PureWindowsPath.__reduce__ writes: (cls, parts)."""
    return _global("pathlib", "WindowsPath") + b"(" + b"".join(_s(p) for p in parts) + b"tR"


@pytest.mark.parametrize("cls", ["WindowsPath", "PosixPath", "Path", "PurePath", "PureWindowsPath"])
def test_building_a_path_is_risky_not_malicious(cls):
    data = b"\x80\x04" + _global("pathlib", cls) + b"(" + _s("C:\\runs") + b"tR."
    report = analyze_bytes(data, "best.pt")
    assert report["static_risk"] == "suspicious"
    assert not report["evidence"] and not report["unverifiable"], report["reasons"]


@pytest.mark.wasi
def test_a_windows_checkpoint_path_is_suspicious_not_malicious(tmp_path):
    path = tmp_path / "args.pkl"
    path.write_bytes(b"\x80\x04}" + _s("save_dir") + windows_path("C:\\", "runs", "train") + b"s.")
    assert scan(str(path)).verdict is Verdict.SUSPICIOUS


@pytest.mark.parametrize("name", ["Path.write_text", "Path.unlink", "Path.open", "WindowsPath.write_bytes"])
def test_path_methods_as_globals_stay_malicious(name):
    data = b"\x80\x04" + _global("pathlib", name) + b"(" + windows_path("x") + _s(MARKER) + b"tR."
    assert analyze_bytes(data, "m.pkl")["static_risk"] == "malicious"


@pytest.mark.wasi
def test_a_method_reached_through_getattr_on_a_path_is_not_clean(tmp_path):
    path = tmp_path / "m.pkl"
    getattr_ = _global("builtins", "getattr")
    path.write_bytes(b"\x80\x04" + getattr_ + b"(" + windows_path("out.txt") + _s("write_text") + b"tR("
                     + _s(MARKER) + b"tR.")
    report = scan(str(path))
    assert report.verdict is Verdict.MALICIOUS, report.reasons
