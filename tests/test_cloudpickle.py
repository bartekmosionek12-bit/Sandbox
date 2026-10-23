"""cloudpickle and dill helpers met on the 0.8.0 held-out sets (owner's decision of
2026-10-23). Each case is rebuilt here as a synthetic pickle, opcode by opcode; nothing
is unpickled on the host.

* A function cloudpickle pickles with its bytecode takes the same path as a dill function
  and a Keras Lambda: RISKY ("file carries executable Python code"), MALICIOUS only with
  evidence of a sink (sink names in the code, or a sink call when it is emulated). The
  class cloudpickle rebuilds it in (``builtins.type``, ``staticmethod``) is no sink.
* dill's ``_create_array(f, args, state)`` with numpy's reconstructor rebuilds an array;
  any other ``f`` is a call of that argument.
* dill's ``__builtin__.__main__`` (the loading program's globals) is no sink.
"""
from __future__ import annotations

import pytest
from corpus.build_corpus import LAMBDAS, MARKER_CMD, STOP, call, g, s, tup
from test_dill import CODE, DILL, P4, _scan, _value, code_fields, dill_function

from safeloadai import Verdict
from safeloadai.static.pickle_static import parse_pickle

CP = "cloudpickle.cloudpickle"
RECONSTRUCT = g("numpy._core.multiarray", "_reconstruct")


def cp_code(fields: list) -> bytes:
    return call(call(g(CP, "_builtin_type"), s("CodeType")), *[_value(f) for f in fields])


def cp_function(fields: list, name: str = "scale") -> bytes:
    globs = b"}" + s("__name__") + s("__main__") + b"s"
    return call(g(CP, "_make_function"), cp_code(fields), globs, b"N", b"N", b"N")


def cp_class(method: bytes) -> bytes:
    """_class_setstate(_make_skeleton_class(type, "Model", (object,), {}, id, None),
    ({"predict": staticmethod(<function>)}, {})): how cloudpickle writes a class."""
    skeleton = call(g(CP, "_make_skeleton_class"), g("builtins", "type"), s("Model"),
                    tup(g("builtins", "object")), b"}", s("0123abcd"), b"N")
    state = b"}" + s("predict") + call(g("builtins", "staticmethod"), method) + b"s"
    return P4 + call(g(CP, "_class_setstate"), skeleton, tup(state, b"}")) + STOP


@pytest.fixture(scope="module")
def compiled():
    return code_fields({
        "benign": LAMBDAS["b_lambda_scale.keras"][2],
        "os_system": LAMBDAS["k_lambda_os_system.keras"][2],
    })


# --- cloudpickle ---------------------------------------------------------------------

def test_cloudpickle_function_without_sinks_is_risky(compiled, tmp_path):
    data = P4 + cp_function(compiled["benign"]) + STOP
    report = parse_pickle(data)
    assert report["static_risk"] == "suspicious", report["reasons"]
    assert any(CODE in r for r in report["reasons"])
    assert any("pickle written by cloudpickle" in r for r in report["reasons"])
    assert report["dill_code"] and report["dill_code"][0]["path"].startswith("cloudpickle code@")
    result = _scan(tmp_path, data)
    assert result.verdict is Verdict.SUSPICIOUS and not result.unverifiable_only, result.findings
    layer = next(la for la in result.layers if la.name == "emulation[dill code]")
    assert layer.ran and layer.verdict is not Verdict.MALICIOUS, layer.reasons
    assert not any("other Python version" in r for r in layer.reasons), layer.reasons


def test_cloudpickle_function_with_os_system_is_malicious(compiled, tmp_path):
    data = P4 + cp_function(compiled["os_system"]) + STOP
    report = parse_pickle(data)
    assert report["static_risk"] == "malicious"
    assert any("cloudpickle code object" in r and "system" in r for r in report["code_malicious"])
    result = _scan(tmp_path, data)
    assert result.verdict is Verdict.MALICIOUS
    layer = next(la for la in result.layers if la.name == "emulation[dill code]")
    assert layer.verdict is Verdict.MALICIOUS, layer.reasons


def test_cloudpickle_class_with_type_and_staticmethod_is_risky(compiled, tmp_path):
    # The shape of the held-out-2 false positive: a class rebuilt with builtins.type, a
    # staticmethod in its dict, a function with its bytecode and no sink.
    result = _scan(tmp_path, cp_class(cp_function(compiled["benign"])))
    assert result.verdict is Verdict.SUSPICIOUS and not result.unverifiable_only, result.findings
    assert not any("known sink" in r for r in result.reasons), result.reasons
    assert not any("code_exec" in r for r in result.reasons), result.reasons


def test_cloudpickle_class_with_a_sink_in_a_method_is_malicious(compiled, tmp_path):
    assert _scan(tmp_path, cp_class(cp_function(compiled["os_system"]))).verdict is Verdict.MALICIOUS


def test_builtin_type_outside_the_reviewed_names_is_named():
    data = P4 + call(call(g(CP, "_builtin_type"), s("new_class")), s("X")) + STOP
    report = parse_pickle(data)
    assert report["static_risk"] == "suspicious"
    assert any("looks up 'new_class' of the types module by name" in r for r in report["reasons"])


@pytest.mark.parametrize("module,flagged", [("numpy", False), ("os", True)])
def test_subimport_is_judged_by_the_module_name(module, flagged, tmp_path):
    data = P4 + call(g(CP, "subimport"), s(module)) + STOP
    report = parse_pickle(data)
    assert report["static_risk"] == "suspicious"
    assert any("subimport at" in r and f"imports {module}" in r for r in report["reasons"]) is flagged
    assert _scan(tmp_path, data).verdict is Verdict.SUSPICIOUS


def test_cloudpickle_helpers_used_on_a_sink_stay_malicious(tmp_path):
    data = P4 + call(g(CP, "_make_function"), call(g("posix", "system"), s(MARKER_CMD)), b"}", b"N", b"N",
                     b"N") + STOP
    assert parse_pickle(data)["static_risk"] == "malicious"
    assert _scan(tmp_path, data).verdict is Verdict.MALICIOUS


# --- built-ins a class is rebuilt with -----------------------------------------------

@pytest.mark.parametrize("name", ["type", "staticmethod", "classmethod", "property"])
def test_class_builders_are_risky_not_sinks(name):
    report = parse_pickle(P4 + call(g("builtins", name), s("x")) + STOP)
    assert report["static_risk"] == "suspicious", report["reasons"]
    assert not report["suspicious_imports"]
    assert not report["unverifiable"], report["unverifiable"]


@pytest.mark.parametrize("name", ["eval", "exec", "setattr", "__import__", "open"])
def test_other_builtins_stay_sinks(name):
    assert parse_pickle(P4 + call(g("builtins", name), s(MARKER_CMD)) + STOP)["static_risk"] == "malicious"


def test_dill_function_with_main_globals_is_risky(compiled, tmp_path):
    # How dill writes the globals of a function defined in __main__ (held-out file).
    fn = dill_function(compiled["benign"])[len(P4):-len(STOP)]
    globs = b"}" + s("__name__") + s("__main__") + b"s"
    data = P4 + fn.replace(globs, g("__builtin__", "__main__")) + STOP
    assert g("__builtin__", "__main__") in data
    result = _scan(tmp_path, data)
    assert result.verdict is Verdict.SUSPICIOUS, result.reasons
    assert not any("known sink" in r for r in result.reasons)


# --- dill._create_array --------------------------------------------------------------

def _array(f: bytes) -> bytes:
    args = tup(g("numpy", "ndarray"), tup(b"K\x00"), b"C\x01b")
    state = tup(b"K\x01", tup(b"K\x03"), call(g("numpy", "dtype"), s("i8")), b"\x89", b"C\x00")
    return P4 + call(g(DILL, "_create_array"), f, args, state, b"N") + STOP


def test_dill_array_with_numpy_reconstructor_is_not_code(tmp_path):
    report = parse_pickle(_array(RECONSTRUCT))
    assert report["static_risk"] == "suspicious"
    assert not report["suspicious_imports"]
    assert not any("calls its first argument" in r for r in report["reasons"])
    result = _scan(tmp_path, _array(RECONSTRUCT))
    assert result.verdict is Verdict.SUSPICIOUS, result.reasons
    assert not any("code_exec" in r or "known sink" in r for r in result.reasons), result.reasons


def test_dill_array_calling_a_sink_is_malicious(tmp_path):
    data = _array(g("posix", "system"))
    assert parse_pickle(data)["static_risk"] == "malicious"
    assert _scan(tmp_path, data).verdict is Verdict.MALICIOUS


def test_dill_array_calling_something_else_is_named(tmp_path):
    report = parse_pickle(_array(g("collections", "Counter")))
    assert report["static_risk"] == "suspicious"
    assert any("_create_array at" in r and "calls its first argument" in r for r in report["reasons"])
