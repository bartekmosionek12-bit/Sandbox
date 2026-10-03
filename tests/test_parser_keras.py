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

# Fixture'y budujemy do katalogu TYMCZASOWEGO, nie do ``poc/samples``.
# Budowanie ich w repo brudziło drzewo robocze przy każdym uruchomieniu
# testów (pliki .keras to archiwa ZIP, więc wychodziła różnica w bajtach),
# a potem ten sam katalog przychodził pullem i git odmawiał scalenia.
# Katalog ``poc/samples`` jest do pokazywania, nie do przebudowy przez testy.
SAMPLES = os.path.join(ROOT, "poc", "samples")
_BUILT: dict[str, str] = {}


@pytest.fixture(scope="module", autouse=True)
def _samples(tmp_path_factory):
    _BUILT["dir"] = str(tmp_path_factory.mktemp("samples_keras"))
    build_poc_keras.build(_BUILT["dir"])


def _sample(name: str) -> str:
    """Ścieżka do fixture'u: najpierw świeżo zbudowany, potem ``poc/samples``.

    ``evil_lambda.keras`` i ``clean_model.keras`` to prawdziwe modele Kerasa,
    generowane raz w kontenerze i trzymane w repo — generator ich nie odtwarza.
    Reszta powstaje przy każdym uruchomieniu testów, więc czytamy ją z katalogu
    tymczasowego: budowanie ich w ``poc/samples`` brudziło drzewo robocze przy
    każdym przebiegu (pliki .keras to archiwa ZIP, więc wychodziła różnica
    w bajtach), a potem ten sam katalog przychodził pullem i git odmawiał
    scalenia.
    """
    fresh = os.path.join(_BUILT["dir"], name)
    return fresh if os.path.exists(fresh) else os.path.join(SAMPLES, name)


def _parse(name: str) -> dict:
    return parser_keras.parse_file(_sample(name))


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


def test_pipeline_routes_keras(monkeypatch):
    """.keras ma iść do swojego parsera. Detonację wyłączamy (detonate=False),
    żeby test był szybki i nie wymagał Dockera — detonacja ma własne testy."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = pipeline.analyze(_sample("evil_lambda.keras"), detonate=False)
    assert result["parser"]["file_format"] == "keras"
    assert result["final_verdict"] == "malicious"
    assert result["sandbox"]["detonated"] is False
    assert result["sandbox"]["skipped_reason"]


def test_pipeline_keras_clean_is_safe(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = pipeline.analyze(_sample("clean_model.keras"), detonate=False)
    assert result["final_verdict"] == "safe"


def _keras_zip(tmp_path, name: str, config: dict):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("config.json", json.dumps(config))
        archive.writestr("metadata.json", "{}")
    return str(path)


# Kształty poniżej są odwzorowaniem tego, co Keras 3.15 faktycznie zapisuje —
# sprawdzone na wygenerowanych modelach, nie wymyślone.

def test_plain_functional_model_is_not_flagged(tmp_path):
    """Keras wpisuje registered_name 'Functional' KAŻDEMU modelowi funkcyjnemu.

    Flagowanie tego dawało 'suspicious' na każdym normalnym modelu, czyli
    fałszywy alarm na wszystkim, co nie jest Sequential.
    """
    config = {
        "module": "keras.src.models.functional",
        "class_name": "Functional",
        "registered_name": "Functional",
        "config": {
            "name": "functional",
            "layers": [
                {
                    "module": "keras.layers",
                    "class_name": "InputLayer",
                    "config": {"batch_shape": [None, 4], "dtype": "float32"},
                    "registered_name": None,
                },
                {
                    "module": "keras.layers",
                    "class_name": "Dense",
                    "config": {"name": "dense", "units": 8},
                    "registered_name": None,
                },
            ],
        },
    }
    report = parser_keras.parse_keras(
        open(_keras_zip(tmp_path, "plain.keras", config), "rb").read()
    )
    assert report["static_risk"] == "clean", report["suspicious_imports"]
    assert report["suspicious_imports"] == []


def test_registered_custom_object_is_still_flagged(tmp_path):
    """Obiekt z @register_keras_serializable ma registered_name 'pakiet>Klasa'
    i module=null — i to musi dalej lecieć jako podejrzane."""
    config = {
        "module": "keras.src.models.functional",
        "class_name": "Functional",
        "registered_name": "Functional",
        "config": {
            "layers": [
                {
                    "module": None,
                    "class_name": "Backdoor",
                    "config": {"name": "backdoor"},
                    "registered_name": "attacker_payload>Backdoor",
                }
            ]
        },
    }
    report = parser_keras.parse_keras(
        open(_keras_zip(tmp_path, "custom.keras", config), "rb").read()
    )
    assert report["static_risk"] == "suspicious"
    assert any(
        i["module"] == "attacker_payload>Backdoor" for i in report["suspicious_imports"]
    )


def test_real_keras3_lambda_shape_is_malicious(tmp_path):
    """Keras 3 serializuje anonimowego lambdę jako class_name '__lambda__'
    z polem 'code' (marshal + base64). To jest realny wektor RCE."""
    config = {
        "module": "keras.src.models.functional",
        "class_name": "Functional",
        "registered_name": "Functional",
        "config": {
            "layers": [
                {
                    "module": "keras.layers",
                    "class_name": "Lambda",
                    "config": {
                        "name": "lambda",
                        "function": {
                            "class_name": "__lambda__",
                            "config": {
                                "code": "4wEAAAAAAAAAAAAAAAMAAAAD",
                                "defaults": None,
                                "closure": None,
                            },
                        },
                    },
                    "registered_name": None,
                }
            ]
        },
    }
    report = parser_keras.parse_keras(
        open(_keras_zip(tmp_path, "lam.keras", config), "rb").read()
    )
    assert report["static_risk"] == "malicious"
