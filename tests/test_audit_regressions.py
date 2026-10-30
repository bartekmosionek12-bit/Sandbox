"""Regression tests for the holes found in AUDIT.md (section 3.2).

Each test reproduces one hole. Tests for holes that are still open are marked
``xfail(strict=True)``: they fail today, and an unexpected pass turns into a test
failure, so the marker has to be removed in the commit that fixes the hole.

No test here deserializes a payload on the host. Payload bytes are built by hand
and only ever reach the static parsers, or loaders whose output is checked to be
a refusal (see the host-execution guard in conftest.py).
"""
from __future__ import annotations

import io
import json
import os
import sys
import types
import zipfile

import pytest
from conftest import sandbox_report

from safeloadai import UnsafeModelError, api, verdict
from safeloadai import docker_sandbox as sandbox
from safeloadai import static as static_mod
from safeloadai.report import Verdict
from safeloadai.static import keras_static as parser_keras
from safeloadai.static import pickle_static as parser


def _open(hole: str):
    return pytest.mark.xfail(strict=True, reason=f"audit {hole}: open")


def _risk(data: bytes) -> str:
    return parser.parse_pickle(data)["static_risk"]


def _keras_zip(config: dict | bytes, extra: dict[str, bytes] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        raw = config if isinstance(config, bytes) else json.dumps(config).encode()
        zf.writestr("config.json", raw)
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.15.1"}))
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
    return buf.getvalue()


def _keras_layer_model(module: str, class_name: str) -> dict:
    layer = {"module": module, "class_name": class_name, "config": {}, "registered_name": None}
    return {
        "module": "keras",
        "class_name": "Functional",
        "config": {"layers": [layer]},
        "registered_name": "Functional",
    }


# --- S1: allowlist by capital letter ---------------------------------------

# REDUCE(scipy.io.FortranFile, ("/tmp/safeloadai_marker", "w")) - truncates the path.
FORTRANFILE = (
    b"\x80\x02cscipy.io\nFortranFile\n"
    b"X\x16\x00\x00\x00/tmp/safeloadai_marker"
    b"X\x01\x00\x00\x00w\x86R."
)


def test_s1_scipy_fortranfile_is_not_clean():
    assert _risk(FORTRANFILE) != "clean"


def test_s1_any_capitalised_sklearn_symbol_is_not_allowlisted():
    data = b"\x80\x02csklearn.made_up\nAnyClass\n)R."
    assert _risk(data) != "clean"


# --- S2: imports and object-construction opcodes outside the allowlist -----

def test_s2_global_without_call_is_not_clean():
    # find_class imports the module; importing `antigravity` opens a browser.
    assert _risk(b"cantigravity\nfly\n.") != "clean"


def test_s2_stack_global_without_call_is_not_clean():
    data = b"\x80\x04\x8c\x0bantigravity\x94\x8c\x03fly\x94\x93."
    assert _risk(data) != "clean"


def test_s2_newobj_on_unknown_class_is_not_clean():
    assert _risk(b"\x80\x02cfoo.bar\nBaz\n)\x81.") != "clean"


def test_s2_newobj_ex_on_unknown_class_is_not_clean():
    assert _risk(b"\x80\x04cfoo.bar\nBaz\n)}\x92.") != "clean"


def test_s2_build_on_unknown_class_is_not_clean():
    assert _risk(b"\x80\x02cfoo.bar\nBaz\n}b.") != "clean"


# --- S3: Keras module matching by prefix and by namespace ------------------

@pytest.mark.parametrize("module", ["tf_evil_pkg", "kerasx", "tensorflow_backdoor"])
def test_s3_keras_module_prefix_is_not_trusted(module):
    report = parser_keras.parse_keras(_keras_zip(_keras_layer_model(module, "Dense")))
    assert report["static_risk"] != "clean"


def test_s3_keras_namespace_function_outside_allowlist_is_not_clean():
    report = parser_keras.parse_keras(_keras_zip(_keras_layer_model("keras.utils", "get_file")))
    assert report["static_risk"] != "clean"


# --- S4: a clean detonation never lowers the static verdict -----------------

def test_s4_clean_detonation_cannot_lower_static_suspicious():
    final, _ = verdict.final_verdict({"static_risk": "suspicious"}, sandbox_report())
    assert final is Verdict.SUSPICIOUS


def test_s4_clean_detonation_cannot_lower_static_malicious():
    final, _ = verdict.final_verdict({"static_risk": "malicious"}, sandbox_report())
    assert final is Verdict.MALICIOUS


@pytest.mark.parametrize("event_type", ["file_write", "code_exec"])
def test_s4_detonation_evidence_always_affects_verdict(event_type):
    events = [{"type": event_type, "detail": "open('/home/user/.bashrc', mode='w')"}]
    final, _ = verdict.final_verdict({"static_risk": "clean"}, sandbox_report(events=events))
    assert final is not Verdict.CLEAN


# --- S5: evidence must not be forgeable from inside the sandbox ------------

def test_s5_forged_result_line_does_not_erase_evidence(monkeypatch, tmp_path):
    sample = tmp_path / "m.pkl"
    sample.write_bytes(b"\x80\x04N.")
    forged = (
        '@@EVENT@@ {"type": "os_system", "detail": "echo MARKER", "blocked": null}\n'
        '@@RESULT@@ {"load_succeeded": true, "duration_ms": 1, "error": null, "events": []}\n'
    )

    class Proc:
        returncode, stdout, stderr = 0, forged, ""

    monkeypatch.setattr(sandbox, "docker_status", lambda: (True, "Docker test"))
    monkeypatch.setattr(sandbox, "ensure_image", lambda **kw: None)
    monkeypatch.setattr(sandbox.subprocess, "run", lambda cmd, **kw: Proc())
    report = sandbox.detonate_in_docker(str(sample))
    final, _ = verdict.final_verdict({"static_risk": "clean"}, report)
    assert final is Verdict.MALICIOUS


# --- S6: loaders must enforce the allowlist themselves ---------------------

def _allow_everything(monkeypatch):
    """The scan says CLEAN whatever the file holds: the loader must still refuse."""
    from safeloadai.report import LayerResult, Report

    def clean_scan(path, **kw):
        import hashlib

        data = open(path, "rb").read()
        fmt = static_mod.analyze_bytes(data, os.path.basename(path))["file_format"]
        return Report(path=path, file_name=os.path.basename(path), sha256=hashlib.sha256(data).hexdigest(),
                      size=len(data), file_format=fmt, verdict=Verdict.CLEAN, reasons=[],
                      layers=[LayerResult("static", Verdict.CLEAN)], timings_ms={}, version="test")

    monkeypatch.setattr(api, "scan", clean_scan)


def test_s6_pickle_loader_refuses_non_allowlisted_global(monkeypatch, tmp_path):
    # Even when the scan says yes, the loader must not import arbitrary modules.
    # `tests/_import_marker.py` records its own import; if the loader imported it,
    # the restricted loader is missing.
    sys.modules.pop("_import_marker", None)
    path = tmp_path / "m.pkl"
    path.write_bytes(b"c_import_marker\nVALUE\n.")
    _allow_everything(monkeypatch)
    with pytest.raises(UnsafeModelError):
        api.safe_load(str(path))
    assert "_import_marker" not in sys.modules


def test_s6_keras_loader_uses_safe_mode(monkeypatch, tmp_path):
    calls = []
    fake = types.ModuleType("keras")
    fake.saving = types.SimpleNamespace(load_model=lambda p, **kw: calls.append(kw) or "model")
    monkeypatch.setitem(sys.modules, "keras", fake)
    _allow_everything(monkeypatch)
    path = tmp_path / "m.keras"
    path.write_bytes(_keras_zip(_keras_layer_model("keras.layers", "Dense")))
    api.safe_load(str(path))
    assert calls and calls[0].get("safe_mode") is True


def test_s6_keras_loader_safe_mode_cannot_be_overridden(monkeypatch, tmp_path):
    calls = []
    fake = types.ModuleType("keras")
    fake.saving = types.SimpleNamespace(load_model=lambda p, **kw: calls.append(kw) or "model")
    monkeypatch.setitem(sys.modules, "keras", fake)
    _allow_everything(monkeypatch)
    path = tmp_path / "m.keras"
    path.write_bytes(_keras_zip(_keras_layer_model("keras.layers", "Dense")))
    api.safe_load(str(path), safe_mode=False)
    assert calls[0]["safe_mode"] is True


# --- S7: size limits, zip bombs, recursion, member names -------------------

def test_s7_zip_bomb_config_is_refused_without_decompressing():
    import tracemalloc

    data = _keras_zip(b" " * (100 * 1024 * 1024))
    tracemalloc.start()
    try:
        report = parser_keras.parse_keras(data)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert report["static_risk"] != "clean"
    assert peak < 64 * 1024 * 1024


def test_s7_deeply_nested_config_does_not_escape():
    # Built as text: json.dumps itself hits the recursion limit on Python 3.11.
    raw = ('{"a": [' * 2000 + '{"class_name": "Dense"}' + "]}" * 2000).encode()
    report = parser_keras.parse_keras(_keras_zip(raw))
    assert report["static_risk"] != "clean"


@pytest.mark.parametrize("name", ["../evil.py", "/abs/evil.py", "a/../../evil.py"])
def test_s7_path_traversal_member_names_are_flagged(name):
    clean = _keras_layer_model("keras.layers", "Dense")
    report = parser_keras.parse_keras(_keras_zip(clean, extra={name: b"x"}))
    assert report["static_risk"] != "clean"


# --- S8: PyTorch containers --------------------------------------------------

OS_SYSTEM_PICKLE = b"\x80\x02cposix\nsystem\nX\x0b\x00\x00\x00echo MARKER\x85R."


def _torch_zip(data_pkl: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", data_pkl)
        zf.writestr("archive/version", b"3\n")
    return buf.getvalue()


def test_s8_torch_zip_payload_is_malicious(tmp_path):
    path = tmp_path / "m.pt"
    path.write_bytes(_torch_zip(OS_SYSTEM_PICKLE))
    assert static_mod.analyze_file(str(path))["static_risk"] == "malicious"


def test_s8_second_pickle_in_legacy_stream_is_analysed():
    # Legacy torch files are several pickles back to back; the payload sits in the second.
    data = b"\x80\x02K\x01." + OS_SYSTEM_PICKLE
    assert _risk(data) == "malicious"


