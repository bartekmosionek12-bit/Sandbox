"""Mutation corpus: every encoding and container of the marker payloads is caught,
and the same encodings of benign pickles stay CLEAN."""
from __future__ import annotations

import pytest
from corpus.mutate import mutations

from safeloadai import Verdict, scan
from safeloadai.static import analyze_bytes

MUTATIONS = mutations()
_ORDER = {"clean": 0, "suspicious": 1, "malicious": 2}


def _static_risk(data: bytes, name: str) -> str:
    report = analyze_bytes(data, name)
    risks = [report["static_risk"]] + [r["static_risk"] for _view, r in report.get("_extra_views", [])]
    return max(risks, key=_ORDER.get)


def test_corpus_is_large_and_balanced():
    categories = {category for _n, category, _e, _d in MUTATIONS}
    assert len(MUTATIONS) > 800
    assert any(c.startswith("benign:") for c in categories)
    assert {"nested", "container:h5_userblock", "container:joblib_xz", "encoding:stack_global_memo"} <= categories


def test_static_layer_on_every_mutation():
    wrong = []
    for name, _category, expected, data in MUTATIONS:
        risk = _static_risk(data, name)
        if (expected == "CLEAN") != (risk == "clean") or (expected == "MALICIOUS" and risk != "malicious"):
            wrong.append((name, risk))
    assert not wrong


def _one_per_category():
    seen, out = set(), []
    for name, category, expected, data in MUTATIONS:
        if category not in seen:
            seen.add(category)
            out.append(pytest.param(expected, data, id=name))
    return out


@pytest.mark.wasi
@pytest.mark.parametrize("expected,data", _one_per_category())
def test_full_scan_one_per_category(tmp_path, request, expected, data):
    path = tmp_path / request.node.callspec.id
    path.write_bytes(data)
    assert scan(path).verdict is Verdict(expected)
