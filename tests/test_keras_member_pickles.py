"""A pickle inside a .keras archive that Keras never reads is never CLEAN (0.11.1,
DECISIONS.md K1: held-out-4 review of a proof of concept that hid os.system there)."""
from __future__ import annotations

import io
import json
import pickle
import zipfile

import pytest

from safeloadai.static.keras_static import parse_keras

DENSE = {"module": "keras", "class_name": "Functional", "registered_name": "Functional",
         "config": {"layers": [{"module": "keras.layers", "class_name": "Dense", "config": {},
                                "registered_name": None}]}}
SYSTEM = b"(cos\nsystem\nVcmd /c whoami\no."  # the bytes of the held-out-4 file, as a marker


def keras(extra: dict[str, bytes], stored: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config.json", json.dumps(DENSE))
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.15.1"}))
        for name, data in extra.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_the_plain_model_is_clean():
    assert parse_keras(keras({}))["static_risk"] == "clean"
    assert parse_keras(keras({"model.weights.npz": b"PK\x05\x06" + bytes(18)}))["static_risk"] == "clean"


@pytest.mark.parametrize("name", ["model.pkl", "assets/model.pkl", "x/y/z.bin", "model.weights.npz"])
def test_a_sink_in_a_member_keras_does_not_read_is_malicious(name):
    report = parse_keras(keras({name: SYSTEM}))
    assert report["static_risk"] == "malicious"
    assert any("os.system" in r and name in r for r in report["evidence"])


def test_a_harmless_pickle_member_is_risky_not_clean():
    report = parse_keras(keras({"extra.pkl": pickle.dumps({"a": [1, 2]}, protocol=4)}))
    assert report["static_risk"] == "suspicious"
    assert any("is a pickle; Keras does not read it" in r for r in report["reasons"])
    assert not report["unverifiable"]  # RISKY: no override accepts it


def test_a_text_member_stays_a_note():
    report = parse_keras(keras({"README.md": b"# my model\n", "assets/vocab.txt": b"a\nb\n"}))
    assert report["static_risk"] == "clean"
    assert any("unexpected archive members" in n for n in report["notes"])


def test_metadata_that_is_a_pickle_is_caught():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.json", json.dumps(DENSE))
        zf.writestr("metadata.json", SYSTEM)
    assert parse_keras(buf.getvalue())["static_risk"] != "clean"


def test_a_member_too_large_to_check_is_not_clean():
    report = parse_keras(keras({"blob.bin": b"\x00" * (16 * 1024 * 1024 + 1)}, stored=True))
    assert report["static_risk"] == "suspicious"
    assert any("too large to check for a pickle" in r for r in report["reasons"])
