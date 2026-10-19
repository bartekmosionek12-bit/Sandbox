"""Lab corpus and the PoC samples through the full scan (static + WASI emulation).

Replaces the old root demo scripts (clean/evil pickle and Keras): the same
scenarios, but every payload is only scanned, and anything executed runs inside
the sandbox.
"""
from __future__ import annotations

import os

import pytest
from conftest import SAMPLES
from corpus.build_corpus import build

from safeloadai import Verdict, safe_load, scan

pytestmark = pytest.mark.wasi
RANK = {"CLEAN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    out = tmp_path_factory.mktemp("corpus")
    return str(out), build(str(out))


def test_corpus_verdicts(corpus):
    out, manifest = corpus
    wrong = []
    for entry in manifest:
        report = scan(os.path.join(out, entry["file"]))
        got = report.verdict.value
        ok = got == "CLEAN" if entry["expected"] == "CLEAN" else RANK[got] >= RANK[entry["expected"]]
        if not ok:
            wrong.append((entry["file"], entry["expected"], got, report.reasons[:3]))
    assert not wrong, wrong


@pytest.mark.parametrize("name, expected", [
    ("clean_model.pkl", Verdict.CLEAN),
    ("clean_model.keras", Verdict.CLEAN),
    ("evil_lambda.keras", Verdict.MALICIOUS),
    ("evil_custom_object.keras", Verdict.SUSPICIOUS),
])
def test_poc_samples(name, expected):
    assert scan(os.path.join(SAMPLES, name)).verdict is expected


def test_clean_poc_pickle_loads_through_restricted_loader():
    assert isinstance(safe_load(os.path.join(SAMPLES, "clean_model.pkl")), dict)
