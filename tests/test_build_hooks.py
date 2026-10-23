"""A BUILD state that stores a hook attribute, and a second BUILD on the same object.

pickle writes one BUILD per object and never a state with ``__setstate__`` in it. A file
that does both makes the second BUILD call ``inst.__setstate__(state)``, so the value the
first state stored is called with an argument the file chooses. No allowing rule
(allowlisted or state-only class, referenced-only global) may read that as storing.
"""
from __future__ import annotations

import pytest

from safeloadai import UnsafeModelError, Verdict, safe_load, scan
from safeloadai.static import clearance
from safeloadai.static.pickle_static import is_dangerous_import, parse_pickle
from safeloadai.static.pickle_vm import Global, Obj

P4, STOP = b"\x80\x04", b"."


def s(text: str) -> bytes:
    raw = text.encode()
    return b"\x8c" + bytes([len(raw)]) + raw


def g(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


FUNC = ("sklearn.metrics._ranking", "roc_auc_score")  # a def in an inert sklearn module, not allowlisted
REF = g(*FUNC)
FUNC_NAME = ".".join(FUNC)
REMOVE = ("sklearn.datasets._lfw", "remove")  # os.remove, re-exported by an inert module

TARGETS = {
    "allowlisted-estimator": g("sklearn.linear_model._logistic", "LogisticRegression") + b")\x81",
    "ordereddict": g("collections", "OrderedDict") + b")R",
    "state-only-policy": g("sklearn.ensemble._voting", "VotingRegressor") + b")\x81",
}


def stored_then_called(target: bytes, value: bytes = REF, key: str = "__setstate__", slot: bool = False) -> bytes:
    state = b"}" + s(key) + value + b"s"
    state = b"N" + state + b"\x86" if slot else state
    return P4 + target + state + b"b" + s("argument") + b"b" + STOP


def cleared(report: dict) -> set[str]:
    return {c["item"] for c in report["cleared"]}


@pytest.mark.parametrize("slot", [False, True], ids=["dict-state", "slot-state"])
@pytest.mark.parametrize("target", TARGETS.values(), ids=TARGETS.keys())
def test_hook_stored_by_build_is_not_clean(target, slot):
    report = parse_pickle(stored_then_called(target, slot=slot))
    assert report["static_risk"] != "clean", report["reasons"]
    assert FUNC_NAME not in cleared(report)
    assert any("sets __setstate__" in r for r in report["reasons"]), report["reasons"]
    assert any("second time" in r for r in report["reasons"]), report["reasons"]


@pytest.mark.parametrize("key", sorted(clearance.BUILD_HOOK_KEYS))
def test_every_hook_key_is_flagged(key):
    body = P4 + TARGETS["ordereddict"] + b"}" + s(key) + g("builtins", "str") + b"sb" + STOP
    report = parse_pickle(body)
    assert any(f"sets {key}" in r for r in report["reasons"]), report["reasons"]


def test_second_build_alone_is_flagged():
    report = parse_pickle(P4 + TARGETS["ordereddict"] + b"}" + s("k") + REF + b"sb" + s("x") + b"b" + STOP)
    assert any("second time" in r for r in report["reasons"]), report["reasons"]
    assert FUNC_NAME not in cleared(report)


def test_one_plain_build_stays_clean():
    report = parse_pickle(P4 + TARGETS["state-only-policy"] + b"}" + s("n_jobs") + b"Nsb" + STOP)
    assert report["static_risk"] == "clean", report["reasons"]


def test_used_globals_counts_earlier_states_of_a_rebuilt_object():
    obj, ref = Obj("newobj", Global("collections", "OrderedDict"), ()), Global(*FUNC)
    first = ("build", obj, ({"k": ref},), 1)
    assert clearance.used_globals([first], [], lambda _obj: True) == set()
    assert id(ref) in clearance.used_globals([first, ("build", obj, ("x",), 2)], [], lambda _obj: True)
    hooked = ("build", obj, ({"__setstate__": ref},), 1)
    assert id(ref) in clearance.used_globals([hooked], [], lambda _obj: True)


def test_file_system_reexports_are_sinks():
    assert is_dangerous_import(*REMOVE)
    assert is_dangerous_import("keras.src.utils.file_utils", "rmtree")
    report = parse_pickle(P4 + g(*REMOVE) + s("/tmp/safeloadai_marker") + b"\x85R" + STOP)
    assert report["static_risk"] == "malicious", report["reasons"]


@pytest.mark.wasi
def test_emulation_sees_the_stored_setstate_called(tmp_path):
    """The fakes store a dict state like the real classes do, so the second BUILD reaches
    the stored value in the guest too (independently of the static layer)."""
    path = tmp_path / "model.pkl"
    path.write_bytes(stored_then_called(TARGETS["allowlisted-estimator"]))
    report = scan(path)
    assert report.verdict is not Verdict.CLEAN, report.reasons
    assert any(r.startswith("[emulation]") and FUNC_NAME in r for r in report.reasons), report.reasons


@pytest.mark.wasi
def test_safe_load_refuses_and_nothing_runs(tmp_path):
    pytest.importorskip("sklearn")
    victim = tmp_path / "keep.txt"
    victim.write_text("still here")
    payload = (P4 + TARGETS["allowlisted-estimator"] + b"}" + s("__setstate__") + g(*REMOVE) + b"sb"
               + s(str(victim)) + b"b" + STOP)
    path = tmp_path / "model.pkl"
    path.write_bytes(payload)
    assert scan(path).verdict is Verdict.MALICIOUS
    with pytest.raises(UnsafeModelError):
        safe_load(path)
    assert victim.read_text() == "still here"
