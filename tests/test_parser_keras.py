"""Testy parsera statycznego .keras."""

from __future__ import annotations

import json
import os
import sys
import zipfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from poc import build_poc_keras  # noqa: E402
from sandbox_rce import parser_keras, pipeline  # noqa: E402

SAMPLES = os.path.join(ROOT, "poc", "samples")


@pytest.fixture(scope="module", autouse=True)
def _samples():
    build_poc_keras.build(SAMPLES)


def _parse(name: str) -> dict:
    return parser_keras.parse_file(os.path.join(SAMPLES, name))


def test_lambda_with_serialized_code_is_malicious():
    report = _parse("evil_lambda.keras")
    assert report["static_risk"] == "malicious"
    assert any(o["name"] == "Lambda" for o in report["flagged_opcodes"])
    assert any(
        "bytecode" in i["symbol"] for i in report["suspicious_imports"]
    ), "nie wykryto zserializowanego kodu w warstwie Lambda"


def test_custom_object_is_flagged():
    """registered_name i moduł spoza Kerasa to ścieżka do cudzego kodu."""
    report = _parse("evil_custom_object.keras")
    assert report["static_risk"] == "suspicious"
    modules = {i["module"] for i in report["suspicious_imports"]}
    assert "attacker_payload.layers" in modules
    assert any("Backdoor" in m for m in modules)


def test_clean_keras_is_clean():
    report = _parse("clean_model.keras")
    assert report["static_risk"] == "clean"
    assert report["flagged_opcodes"] == []
    assert report["suspicious_imports"] == []


def test_contract_shape_matches_pickle_parser():
    """Dashboard i sędzia czytają jeden kontrakt niezależnie od formatu."""
    report = _parse("clean_model.keras")
    for key in (
        "schema_version", "file_name", "file_format", "opcodes",
        "flagged_opcodes", "suspicious_imports", "raw_disasm", "static_risk",
    ):
        assert key in report, f"brak klucza kontraktu: {key}"
    assert report["schema_version"] == "1.0"
    assert report["file_format"] == "keras"


def test_raw_config_is_exposed():
    report = _parse("evil_lambda.keras")
    assert "Lambda" in report["raw_disasm"]
    json.loads(report["raw_disasm"])  # ma być poprawnym JSON-em do pokazania


def test_not_a_zip_does_not_crash(tmp_path):
    path = tmp_path / "broken.keras"
    path.write_bytes(b"to nie jest archiwum")
    report = parser_keras.parse_file(str(path))
    assert report["error"]
    assert report["static_risk"] == "suspicious"


def test_zip_without_config_is_flagged(tmp_path):
    path = tmp_path / "nocfg.keras"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("metadata.json", "{}")
    report = parser_keras.parse_file(str(path))
    assert report["error"]
    assert report["static_risk"] == "suspicious"


def test_parser_does_not_execute_payload(tmp_path):
    """Parser czyta JSON, więc nie może odtworzyć ani wykonać kodu Lambda."""
    marker = "/tmp/pwned_keras"
    if os.path.exists(marker):
        os.unlink(marker)
    _parse("evil_lambda.keras")
    assert not os.path.exists(marker), "parser statyczny wykonał payload"


def test_pipeline_routes_keras_and_skips_detonation(monkeypatch):
    """.keras ma iść do swojego parsera, a brak detonacji ma być powiedziany
    wprost, a nie pokazany jako pusty log."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = pipeline.analyze(os.path.join(SAMPLES, "evil_lambda.keras"))
    assert result["parser"]["file_format"] == "keras"
    assert result["final_verdict"] == "malicious"
    assert result["sandbox"]["detonated"] is False
    assert "nie jest jeszcze zaimplementowana" in result["sandbox"]["skipped_reason"]


def test_pipeline_keras_clean_is_safe(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = pipeline.analyze(os.path.join(SAMPLES, "clean_model.keras"))
    assert result["final_verdict"] == "safe"
