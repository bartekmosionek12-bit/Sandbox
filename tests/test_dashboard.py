"""The dashboard only renders Report JSON, escaping attacker-controlled text."""
import json

import pytest

flask = pytest.importorskip("flask")

from app.server import app  # noqa: E402

REPORT = {"verdict": "MALICIOUS", "file_name": "<script>alert(1)</script>.pkl", "file_format": "pickle",
          "sha256": "ab", "version": "t", "timings_ms": {"total": 1}, "reasons": ["[static] x"],
          "layers": [{"name": "static", "verdict": "MALICIOUS", "ran": True, "reasons": ["x"], "evidence": []}]}


def test_renders_report_and_escapes_text():
    client = app.test_client()
    resp = client.post("/", data={"text": json.dumps(REPORT)})
    body = resp.get_data(as_text=True)
    assert resp.status_code == 200 and "MALICIOUS" in body
    assert "<script>alert(1)</script>" not in body and "&lt;script&gt;" in body


def test_rejects_non_report_json():
    resp = app.test_client().post("/", data={"text": json.dumps({"hello": 1})})
    assert "Could not read the report" in resp.get_data(as_text=True)
