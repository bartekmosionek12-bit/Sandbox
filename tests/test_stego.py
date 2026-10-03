"""Testy detektora tensor steganography (LSB w wagach float32).

Fixture'y generujemy w locie; payload jest jawny i nieszkodliwy (nigdzie
nie jest wykonywany). Testy pilnują dwóch rzeczy: że czysty model nie
odpala fałszywego alarmu, a ukryty tekst zostaje znaleziony — i że różnica
suspicious vs malicious zależy od obecności wyzwalacza.
"""

from __future__ import annotations

import io
import os
import pickle
import sys

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from poc import build_poc_stego  # noqa: E402
from sandbox_rce import stego  # noqa: E402


def _clean():
    return build_poc_stego._realistic_weights(8192)


def test_clean_weights_are_not_flagged():
    data = io.BytesIO()
    np.save(data, _clean())
    report = stego.analyze(data.getvalue(), "clean_weights.npy")
    assert report["checked"] is True
    assert report["stego_risk"] == "clean", report["all_arrays"]
    assert report["suspicious_arrays"] == []


def test_hidden_payload_is_detected():
    evil = build_poc_stego._embed_lsb(_clean(), build_poc_stego.HIDDEN_PAYLOAD)
    data = io.BytesIO()
    np.save(data, evil)
    report = stego.analyze(data.getvalue(), "stego_weights.npy")
    assert report["suspicious_arrays"], "nie wykryto ukrytego payloadu w LSB"
    found = report["suspicious_arrays"][0]
    assert found["longest_printable_run"] >= stego.PRINTABLE_RUN_THRESHOLD
    assert any("os" in m["marker"] for m in found["markers"])


def test_stego_without_trigger_is_suspicious_with_trigger_is_malicious():
    evil = build_poc_stego._embed_lsb(_clean(), build_poc_stego.HIDDEN_PAYLOAD)
    data = io.BytesIO()
    np.save(data, evil)
    raw = data.getvalue()
    assert stego.analyze(raw, "x.npy", trigger_present=False)["stego_risk"] == "suspicious"
    assert stego.analyze(raw, "x.npy", trigger_present=True)["stego_risk"] == "malicious"


def test_lsb_bits_reads_mantissa_bit():
    # Dwie wartości różniące się tylko najmłodszym bitem mantysy.
    a = np.array([1.0], dtype=np.float32)
    b = (a.view(np.uint32) | np.uint32(1)).view(np.float32)
    bits = stego._lsb_bits(np.concatenate([a, b]))
    assert list(bits) == [0, 1]


def test_data_only_unpickler_refuses_code():
    """Ekstrakcja z pickle NIE może uruchomić payloadu — unpickler tylko-dane
    odrzuca GLOBAL/REDUCE, więc plik z os.system jest pomijany, nie odpalany."""

    class Evil:
        def __reduce__(self):
            return (os.system, ("echo should-never-run",))

    blob = pickle.dumps(Evil())
    report = stego.analyze(blob, "evil.pkl")
    assert report["stego_risk"] == "clean"
    assert any("GLOBAL/REDUCE" in n or "wykonujące kod" in n for n in report["notes"])


def test_pickle_with_plain_float_weights_is_analyzed():
    """Czysty pickle z wagami (listy floatów) daje się bezpiecznie przeanalizować."""
    weights = {"fc.weight": _clean().tolist()}
    blob = pickle.dumps(weights)
    report = stego.analyze(blob, "clean_model.pkl")
    assert report["checked"] is True
    assert report["stego_risk"] == "clean"
