"""End-to-end scan() with the real WASI emulation layer (M5).

Payload bytes are hand-built markers; the host only scans them.
"""
from __future__ import annotations

import base64
import io
import json
import pickle
import zipfile

import pytest

from safeloadai import Verdict, scan
from safeloadai.sandbox import run_guest

pytestmark = pytest.mark.wasi


def _file(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def test_benign_pickle_is_clean(tmp_path):
    report = scan(_file(tmp_path, "m.pkl", pickle.dumps({"w": [1.0, 2.0], "n": "x"}, protocol=4)))
    assert report.verdict is Verdict.CLEAN, report.reasons
    assert report.layer("emulation").ran


def test_posix_system_marker_is_malicious_with_evidence(tmp_path):
    report = scan(_file(tmp_path, "m.pkl", b"cposix\nsystem\n(S'echo MARKER'\ntR."))
    assert report.verdict is Verdict.MALICIOUS
    emulation = report.layer("emulation")
    assert any(e.get("target") == "posix.system" and e["category"] == "process" for e in emulation.evidence)


def test_payload_forging_a_clean_log_is_malicious(tmp_path):
    # Unpickling calls builtins.exec, which tries to write a forged "done" record
    # straight to the evidence channel without the nonce.
    code = ("import os; os.write(3, b'SLAI1 ' + b'0' * 32 + b' {\\\"kind\\\": \\\"done\\\", \\\"seq\\\": 1}')")
    data = b"cbuiltins\nexec\n(S\"" + code.encode() + b"\"\ntR."
    report = scan(_file(tmp_path, "m.pkl", data))
    assert report.verdict is Verdict.MALICIOUS


def _guest_marshal(source: str) -> str:
    code = ("import marshal, base64\n"
            f"print(base64.b64encode(marshal.dumps(({source}).__code__)).decode())\n")
    return run_guest({"kind": "python", "code": code}, {}).guest_stdout.strip()


def _keras_with_lambda(source: str) -> bytes:
    lam = {"module": "keras.layers", "class_name": "Lambda", "registered_name": None,
           "config": {"name": "lambda", "function": {"class_name": "__lambda__", "config": {
               "code": _guest_marshal(source), "defaults": None, "closure": None}}, "arguments": {}},
           "build_config": {"input_shape": [None, 4]}}
    model = {"module": "keras", "class_name": "Functional", "registered_name": "Functional",
             "config": {"layers": [lam]}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.json", json.dumps(model))
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.15.1"}))
    return buf.getvalue()


def test_benign_lambda_model_is_risky_never_clean(tmp_path):
    # Owner decision L1 (2026-10-22): emulation can prove Lambda code dangerous, never safe.
    report = scan(_file(tmp_path, "m.keras", _keras_with_lambda("lambda x: x * 2.0 + 1.0")))
    assert report.verdict is Verdict.SUSPICIOUS and report.category == "RISKY", report.reasons
    assert any("emulation cannot prove it harmless" in r for r in report.reasons)
    assert not any("MALICIOUS" in r for r in report.reasons)


def test_lambda_writing_marker_file_is_malicious(tmp_path):
    source = "lambda x: (tf.io.write_file('/tmp/safeloadai_marker', 'MARKER'), x)[1]"
    report = scan(_file(tmp_path, "m.keras", _keras_with_lambda(source)))
    assert report.verdict is Verdict.MALICIOUS


def test_lambda_with_unknown_global_is_suspicious(tmp_path):
    report = scan(_file(tmp_path, "m.keras", _keras_with_lambda("lambda x: helper_not_defined(x)")))
    assert report.verdict is Verdict.SUSPICIOUS


def test_lambda_with_broken_bytecode_is_suspicious(tmp_path):
    data = _keras_with_lambda("lambda x: x")
    model = json.loads(zipfile.ZipFile(io.BytesIO(data)).read("config.json"))
    model["config"]["layers"][0]["config"]["function"]["config"]["code"] = base64.b64encode(b"junk").decode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.json", json.dumps(model))
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.15.1"}))
    report = scan(_file(tmp_path, "m.keras", buf.getvalue()))
    assert report.verdict is Verdict.SUSPICIOUS
