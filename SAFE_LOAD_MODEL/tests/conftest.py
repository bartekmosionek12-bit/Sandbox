"""Testy działają bez Dockera i bez klucza API.

Detonacja jest podmieniana na atrapę zwracającą gotowy raport. Żaden test
nie wczytuje plików PoC przez pickle.load — zasada projektu: ładunków nie
detonujemy poza kontenerem. Testy, które sprawdzają, że złośliwy plik NIE
został wczytany, podmieniają pickle.load na funkcję, która oblewa test.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SAMPLES = os.path.join(ROOT, "poc", "samples")


@pytest.fixture(autouse=True)
def _no_judge_no_cache(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("SAFELOADAI_CACHE_DIR", raising=False)


def sandbox_report(**overrides):
    report = {
        "schema_version": "1.0",
        "file_name": "sample",
        "detonated": True,
        "detonation_backend": "docker",
        "skipped_reason": None,
        "load_succeeded": True,
        "duration_ms": 10,
        "timed_out": False,
        "events": [],
        "raw_log": "[detoner] /tmp: payload nie utworzył ani nie zmienił żadnego pliku",
        "error": None,
    }
    report.update(overrides)
    return report


@pytest.fixture
def fake_detonation(monkeypatch):
    """Podmienia detonację. Zwraca listę wywołań; raport ustawia się przez .result."""
    from sandbox_rce import sandbox

    class Fake:
        calls = []
        result = sandbox_report()
        side_effect = None

    def fake(path, timeout_s=None, profile="pickle"):
        Fake.calls.append((path, profile))
        if Fake.side_effect:
            Fake.side_effect(path)
        return dict(Fake.result, file_name=os.path.basename(path))

    monkeypatch.setattr(sandbox, "detonate_in_docker", fake)
    return Fake


@pytest.fixture
def forbid_pickle_load(monkeypatch):
    from sandbox_rce import api

    def boom(*a, **k):
        raise AssertionError("pickle.load wywołany na pliku, który miał zostać zablokowany")

    monkeypatch.setattr(api.pickle, "load", boom)
