"""builtins.getattr, judged use by use (owner's rule of 2026-10-19, allowlists.GETATTR).

pickle writes a bound method as ``getattr(obj, "name")``. That form is CLEAN for an
object or class from the allowlist and a public constant name, when nothing calls the
result while loading. A called result, a dunder or sink name, or a sink object is
MALICIOUS; any other use is RISKY and cannot be overridden.

Benign objects are only pickled (dumped) here, never loaded.
"""
from __future__ import annotations

import pickle
from collections import OrderedDict

import pytest
from corpus.build_corpus import MARKER_CMD, P2, STOP, call, g, s, sg, tup

from safeloadai import Verdict, scan
from safeloadai.static.pickle_static import parse_pickle

OD = call(g("collections", "OrderedDict"))  # an instance of an allowlisted class
DETECT = g("mypkg.heads", "Detect")  # outside the allowlist


def _getattr(obj: bytes, name: str, *, module: str = "builtins", stack: bool = False) -> bytes:
    fn = sg(module, "getattr") if stack else g(module, "getattr")
    return call(fn, obj, s(name))


def _risk(body: bytes) -> tuple[str, list[str]]:
    report = parse_pickle(P2 + body + STOP)
    return report["static_risk"], report["reasons"]


def _scan(tmp_path, body: bytes, name: str = "x.pkl"):
    path = tmp_path / name
    path.write_bytes(P2 + body + STOP)
    return scan(str(path))


# --- what pickle itself writes is clean ---------------------------------------------------

@pytest.mark.parametrize("protocol", [2, 4, 5])
def test_pickled_method_of_allowlisted_object_is_clean(protocol, tmp_path):
    data = pickle.dumps({"callback": OrderedDict(a=1).keys}, protocol=protocol)
    assert b"getattr" in data
    report = parse_pickle(data)
    assert report["static_risk"] == "clean", report["reasons"]
    path = tmp_path / "method.pkl"
    path.write_bytes(data)
    result = scan(str(path))
    assert result.verdict is Verdict.CLEAN, result.findings


@pytest.mark.parametrize("module,stack", [("builtins", False), ("__builtin__", False), ("builtins", True)])
def test_method_of_allowlisted_class_is_clean(module, stack):
    risk, reasons = _risk(_getattr(g("collections", "OrderedDict"), "fromkeys", module=module, stack=stack))
    assert risk == "clean", reasons


# --- evidence stays MALICIOUS -------------------------------------------------------------

def test_called_result_is_malicious(tmp_path):
    body = call(_getattr(OD, "keys"))
    risk, reasons = _risk(body)
    assert risk == "malicious"
    assert any("is called" in r for r in reasons)
    assert _scan(tmp_path, body).verdict is Verdict.MALICIOUS


def test_called_result_outside_allowlist_is_malicious():
    risk, reasons = _risk(call(_getattr(DETECT, "forward"), s(MARKER_CMD)))
    assert risk == "malicious"
    assert any("is called" in r for r in reasons)


def test_called_result_through_obj_and_newobj_is_malicious():
    assert _risk(b"(" + _getattr(OD, "keys") + b"o")[0] == "malicious"
    assert _risk(_getattr(OD, "keys") + tup() + b"\x81")[0] == "malicious"


@pytest.mark.parametrize("name", ["__class__", "__globals__", "__subclasses__", "__reduce_ex__"])
def test_dunder_name_is_malicious(name):
    risk, reasons = _risk(_getattr(OD, name))
    assert risk == "malicious"
    assert any("dunder" in r for r in reasons)


@pytest.mark.parametrize("name", ["system", "popen", "eval", "exec", "load", "open"])
def test_sink_name_is_malicious(name):
    risk, reasons = _risk(_getattr(OD, name))
    assert risk == "malicious"
    assert any("sink attribute" in r for r in reasons)


@pytest.mark.parametrize("target", [g("os", "path"), g("posix", "environ"), g("builtins", "object"),
                                    g("subprocess", "Popen")])
def test_sink_object_is_malicious(target, tmp_path):
    body = _getattr(target, "join")
    assert _risk(body)[0] == "malicious"
    assert _scan(tmp_path, body).verdict is Verdict.MALICIOUS


def test_payload_through_getattr_is_malicious(tmp_path):
    # getattr(posix, "system")("echo MARKER"), with the module as a value
    body = call(_getattr(g("posix", "environ"), "system"), s(MARKER_CMD))
    assert _scan(tmp_path, body).verdict is Verdict.MALICIOUS


# --- everything else is RISKY, never overridable ------------------------------------------

def _risky_only(tmp_path, body: bytes) -> list[str]:
    risk, reasons = _risk(body)
    assert risk == "suspicious", reasons
    result = _scan(tmp_path, body)
    assert result.verdict is Verdict.SUSPICIOUS
    assert not result.unverifiable_only, result.findings
    return reasons


def test_uncalled_method_outside_allowlist_is_risky(tmp_path):
    # the Ultralytics form, getattr(Detect, "forward"), with a class outside the allowlist
    reasons = _risky_only(tmp_path, _getattr(DETECT, "forward"))
    assert any("not built from allowlisted classes" in r for r in reasons)


def test_private_name_is_risky(tmp_path):
    reasons = _risky_only(tmp_path, _getattr(OD, "_private"))
    assert any("private attribute" in r for r in reasons)


def test_non_constant_name_is_risky(tmp_path):
    reasons = _risky_only(tmp_path, call(g("builtins", "getattr"), OD, OD))
    assert any("not a constant string" in r for r in reasons)


def test_wrong_arity_and_default_are_risky(tmp_path):
    _risky_only(tmp_path, call(g("builtins", "getattr"), OD, s("keys"), s("default")))


def test_getattr_passed_as_value_is_risky(tmp_path):
    reasons = _risky_only(tmp_path, call(g("collections", "OrderedDict"), tup(tup(s("k"), g("builtins", "getattr")))))
    assert any("passed as a value" in r for r in reasons)


def test_getattr_chain_is_risky_or_worse():
    risk, _ = _risk(_getattr(_getattr(OD, "keys"), "mapping"))
    assert risk in ("suspicious", "malicious")


# --- Ultralytics checkpoints after the 2026-10-19 source review -------------------------------

SEGMENT = g("ultralytics.nn.modules.head", "Segment")
DETECT_OK = g("ultralytics.nn.modules.head", "Detect")
NEWOBJ, BUILD = b"\x81", b"b"


def _module(cls: bytes, state: bytes = b"}") -> bytes:
    """How torch.save writes an nn.Module: NEWOBJ () + BUILD."""
    return cls + b")" + NEWOBJ + state + BUILD


def test_old_segment_head_with_stored_detect_forward_is_clean():
    # ultralytics 8.0.x: Segment.__init__ stores self.detect = Detect.forward
    state = b"}(" + s("detect") + _getattr(DETECT_OK, "forward") + b"u"
    risk, reasons = _risk(_module(SEGMENT, state))
    assert risk == "clean", reasons


def test_fused_bound_method_of_allowlisted_module_is_clean():
    conv = _module(g("ultralytics.nn.modules.conv", "Conv"))
    risk, reasons = _risk(b"}(" + s("forward") + _getattr(conv, "forward_fuse") + b"u")
    assert risk == "clean", reasons


def test_stored_detect_forward_called_is_still_malicious():
    assert _risk(call(_getattr(DETECT_OK, "forward"), s(MARKER_CMD)))[0] == "malicious"


def test_allowlisted_module_called_directly_is_still_flagged():
    risk, reasons = _risk(call(g("torch.nn.modules.activation", "SiLU"), s(MARKER_CMD)))
    assert risk == "suspicious"
    assert any("is called" in r for r in reasons)


def test_unreviewed_neighbours_stay_out():
    from safeloadai.static import allowlists

    for pair in [("xgboost.core", "Booster"), ("ultralytics.utils", "IterableSimpleNamespace"),
                 ("torch.nn.modules.rnn", "LSTM"), ("torch.nn.modules.lazy", "LazyModuleMixin"),
                 ("ultralytics.nn.modules.block", "BNContrastiveHead"), ("torch.nn.modules.linear", "LazyLinear")]:
        assert pair not in allowlists.PICKLE_GLOBALS, pair


# --- using a getattr result is calling it or passing it to any call (owner, 2026-10-19) ----

def test_result_passed_as_defaultdict_factory_is_not_clean():
    risk, reasons = _risk(call(g("collections", "defaultdict"), _getattr(OD, "keys")))
    assert risk == "malicious"
    assert any("passed as an argument to collections.defaultdict" in r for r in reasons)


def test_result_passed_to_numpy_ctor_helper_is_not_clean():
    body = call(g("numpy.random._pickle", "__generator_ctor"), s("PCG64"), _getattr(OD, "keys"))
    assert _risk(body)[0] == "malicious"


def test_result_nested_in_a_call_argument_is_not_clean():
    body = call(g("collections", "OrderedDict"), b"]" + b"(" + tup(s("cb"), _getattr(OD, "keys")) + b"e")
    assert _risk(body)[0] == "malicious"


def test_getattr_chain_passes_a_result_to_getattr():
    assert _risk(_getattr(_getattr(OD, "keys"), "mapping"))[0] == "malicious"


def test_allowlisted_class_is_allowed_only_as_getattrs_first_argument():
    # as the attribute name slot it is a value passed to a call
    body = call(g("builtins", "getattr"), OD, g("collections", "defaultdict"))
    assert _risk(body)[0] != "clean"
    assert _risk(call(g("collections", "OrderedDict"), tup(tup(s("k"), g("collections", "defaultdict")))))[0] \
        != "clean"


def test_result_stored_in_build_state_is_clean():
    state = b"}(" + s("detect") + _getattr(DETECT_OK, "forward") + b"u"
    assert _risk(_module(SEGMENT, state))[0] == "clean"
