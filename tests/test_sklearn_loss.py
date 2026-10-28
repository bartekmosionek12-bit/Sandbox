"""scikit-learn 1.5-1.8 losses pickled as ``_loss.X`` (static/sklearn_loss.py)."""
from __future__ import annotations

import sys
import types

import pytest

from safeloadai import Verdict, scan
from safeloadai import api
from safeloadai.static import analyze_bytes, sklearn_loss

MARKER = "SAFELOADAI_TEST_MARKER"


def _s(text: str) -> bytes:
    raw = text.encode()
    return b"\x8c" + bytes([len(raw)]) + raw


def _global(module: str, name: str) -> bytes:
    return _s(module) + _s(name) + b"\x93"


def loss_pickle(*entries: tuple[str, str, str]) -> bytes:
    """A protocol-4 dict {key: global} where kind "ref" stores the global itself and
    "call" stores global() (the CyHalfBinomialLoss form of scikit-learn 1.6-1.8)."""
    out = b"\x80\x04}"
    for kind, module, name in entries:
        out += _s(f"{kind}:{module}.{name}") + _global(module, name) + (b")R" if kind == "call" else b"") + b"s"
    return out + b"."


TRIGGERED = loss_pickle(("ref", "sklearn.ensemble._gb", "GradientBoostingRegressor"),
                        ("call", "_loss", "CyHalfSquaredError"))


def _cleared(report: dict) -> list[dict]:
    return [c for c in report.get("cleared", []) if c["mechanism"] == sklearn_loss.MECHANISM]


@pytest.mark.parametrize("trigger", sorted(sklearn_loss.TRIGGERS))
def test_loss_after_a_module_that_registers_it_is_cleared(trigger):
    data = loss_pickle(("ref", trigger, "X"), ("call", "_loss", "CyHalfBinomialLoss"))
    report = analyze_bytes(data, "m.pkl")
    assert [c["item"] for c in _cleared(report)] == ["_loss.CyHalfBinomialLoss"]
    assert not any(r.startswith("import outside the allowlist: _loss.") for r in report["reasons"]), report["reasons"]


@pytest.mark.wasi
def test_gradient_boosting_loss_scans_clean(tmp_path):
    path = tmp_path / "gb.pkl"
    path.write_bytes(TRIGGERED)
    report = scan(str(path))
    assert report.verdict is Verdict.CLEAN, report.reasons


@pytest.mark.parametrize("data", [
    loss_pickle(("call", "_loss", "CyHalfBinomialLoss")),                                    # nothing before it
    loss_pickle(("call", "_loss", "CyHalfBinomialLoss"), ("ref", "sklearn._loss.loss", "X")),  # trigger after it
    loss_pickle(("ref", "sklearn.pipeline", "Pipeline"), ("call", "_loss", "CyHalfBinomialLoss")),
    loss_pickle(("ref", "sklearn", "base"), ("call", "_loss", "CyHalfBinomialLoss")),
    # a second _loss global before the trigger: sys.path decides what that one imports
    loss_pickle(("ref", "_loss", "CyHalfSquaredError"), ("ref", "sklearn._loss.loss", "X"),
                ("call", "_loss", "CyHalfBinomialLoss")),
])
def test_loss_without_a_registering_import_first_is_not_cleared(data):
    report = analyze_bytes(data, "m.pkl")
    assert not _cleared(report)
    assert report["static_risk"] == "suspicious"
    assert any(r.startswith("import outside the allowlist: _loss.") for r in report["reasons"])


@pytest.mark.parametrize("name", ["system", "CyHuberLoss", "__pyx_unpickle_CyHuberLoss", "CyHalfBinomialLoss.mro"])
def test_names_not_reviewed_under_sklearn_loss_are_not_cleared(name):
    report = analyze_bytes(loss_pickle(("ref", "sklearn._loss.loss", "X"), ("call", "_loss", name)), "m.pkl")
    assert f"_loss.{name}" not in [c["item"] for c in _cleared(report)]
    assert report["static_risk"] != "clean"


def test_only_the_reviewed_names_alias():
    assert sklearn_loss.NAMES == {"CyHalfBinomialLoss", "CyHalfSquaredError", "CyHalfMultinomialLoss",
                                  "CyPinballLoss", "__pyx_unpickle_CyHalfMultinomialLoss",
                                  "__pyx_unpickle_CyHalfBinomialLoss", "__pyx_unpickle_CyPinballLoss"}


@pytest.mark.wasi
def test_a_payload_next_to_a_cleared_loss_is_still_malicious(tmp_path):
    path = tmp_path / "gb.pkl"
    sink = b"cposix\nsystem\n(S'echo " + MARKER.encode() + b"'\ntR"  # protocol-0 GLOBAL + call
    path.write_bytes(TRIGGERED[:-1] + b"0" + sink + b".")  # pop the dict, then call the sink
    report = scan(str(path))
    assert report.verdict is Verdict.MALICIOUS, report.reasons


def test_safe_load_resolves_loss_only_to_the_scikit_learn_extension(monkeypatch):
    fake = types.ModuleType("_loss")
    fake.CyHalfBinomialLoss = object
    monkeypatch.setitem(sys.modules, "_loss", fake)
    with pytest.raises(api.UnsafeModelError, match="not scikit-learn"):
        api._sklearn_loss_class("CyHalfBinomialLoss")
    real = types.ModuleType("sklearn._loss._loss")
    real.CyHalfBinomialLoss = int
    monkeypatch.setitem(sys.modules, "sklearn._loss._loss", real)
    with pytest.raises(api.UnsafeModelError):
        api._sklearn_loss_class("CyHalfBinomialLoss")  # _loss is still the other module
    monkeypatch.setitem(sys.modules, "_loss", real)
    assert api._sklearn_loss_class("CyHalfBinomialLoss") is int


def test_safe_load_never_imports_loss_from_sys_path(monkeypatch, tmp_path):
    (tmp_path / "_loss.py").write_text(f"open({str(tmp_path / MARKER)!r}, 'w').close()\nCyHalfBinomialLoss = 1\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "_loss", raising=False)
    monkeypatch.delitem(sys.modules, "sklearn._loss._loss", raising=False)
    with pytest.raises(api.UnsafeModelError):
        api._sklearn_loss_class("CyHalfBinomialLoss")
    assert not (tmp_path / MARKER).exists()
