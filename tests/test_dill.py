"""dill pickles (owner's decision of 2026-10-19: a function dill pickles with its bytecode is
treated like a Keras Lambda).

dill writes a function as ``_create_function(_create_code(<fields>), globals, name, ...)``
(dill 0.3.8 and 0.4.1, evaluation/results/source-review-2-20261019.md). The code fields
are judged statically (sink names among co_names and string constants: MALICIOUS) and
the function is rebuilt and called on fakes inside the WASI sandbox. Without sinks the
file is RISKY ("file carries executable Python code").

Code fields are produced inside the WASI guest, pickles are assembled opcode by opcode,
and nothing is unpickled on the host.
"""
from __future__ import annotations

import json
import struct

import pytest
from corpus.build_corpus import LAMBDAS, MARKER_CMD, STOP, call, g, s

from safeloadai import Verdict, scan
from safeloadai.static.pickle_static import parse_pickle

P4 = b"\x80\x04"
DILL = "dill._dill"
CODE = "file carries executable Python code"

_FIELDS = """
import base64, json
def enc(v):
    if isinstance(v, bytes):
        return {"b": base64.b64encode(v).decode()}
    if isinstance(v, tuple):
        return {"t": [enc(x) for x in v]}
    if isinstance(v, frozenset):
        return {"fs": [enc(x) for x in v]}
    if hasattr(v, "co_code"):
        return {"code": fields(v)}
    return v
def fields(c):
    return [enc(x) for x in (c.co_argcount, c.co_posonlyargcount, c.co_kwonlyargcount, c.co_nlocals,
            c.co_stacksize, c.co_flags, c.co_code, c.co_consts, c.co_names, c.co_varnames, c.co_filename,
            c.co_name, c.co_qualname, c.co_firstlineno, c.co_linetable, c.co_exceptiontable,
            c.co_freevars, c.co_cellvars)]
out = {}
"""


def code_fields(sources: dict[str, str]) -> dict[str, list]:
    """CodeType fields of each lambda, compiled inside the WASI guest (tagged JSON)."""
    from safeloadai.sandbox import run_guest

    lines = [_FIELDS] + [f"out[{k!r}] = fields(({src}).__code__)" for k, src in sources.items()]
    lines.append("print(json.dumps(out))")
    run = run_guest({"kind": "python", "code": "\n".join(lines)}, {})
    assert run.completed, run.problems
    return json.loads(run.guest_stdout.strip().splitlines()[-1])


def _value(v) -> bytes:
    """Opcodes for one tagged-JSON value."""
    if v is None:
        return b"N"
    if isinstance(v, bool):
        return b"\x88" if v else b"\x89"
    if isinstance(v, int):
        return b"J" + struct.pack("<i", v)
    if isinstance(v, float):
        return b"G" + struct.pack(">d", v)
    if isinstance(v, str):
        return s(v)
    if "b" in v:
        import base64

        raw = base64.b64decode(v["b"])
        return b"B" + struct.pack("<I", len(raw)) + raw
    if "t" in v:
        return b"(" + b"".join(_value(x) for x in v["t"]) + b"t"
    if "code" in v:
        return _code(v["code"])
    raise ValueError(v)


def _code(fields: list) -> bytes:
    # dill writes the co_lnotab first (bytes), then the 18 fields of Python 3.11+
    return call(g(DILL, "_create_code"), b"C\x00", *[_value(f) for f in fields])


def dill_function(fields: list, name: str = "<lambda>") -> bytes:
    globs = b"}" + s("__name__") + s("__main__") + b"s"
    return P4 + call(g(DILL, "_create_function"), _code(fields), globs, s(name), b"N", b"N") + STOP


def _scan(tmp_path, data: bytes, name: str = "fn.pkl"):
    path = tmp_path / name
    path.write_bytes(data)
    return scan(str(path))


@pytest.fixture(scope="module")
def compiled():
    return code_fields({
        "benign": LAMBDAS["b_lambda_scale.keras"][2],
        "os_system": LAMBDAS["k_lambda_os_system.keras"][2],
        "nested": "lambda x: (lambda y: y + 1)(x)",
    })


def test_dill_function_without_sinks_is_risky(compiled, tmp_path):
    data = dill_function(compiled["benign"])
    report = parse_pickle(data)
    assert report["static_risk"] == "suspicious", report["reasons"]
    assert any(CODE in r for r in report["reasons"])
    assert report["dill_code"] and report["dill_code"][0]["code_fields"]
    result = _scan(tmp_path, data)
    assert result.verdict is Verdict.SUSPICIOUS and not result.unverifiable_only, result.findings
    layer = next(la for la in result.layers if la.name == "emulation[dill code]")
    assert layer.ran and layer.verdict is not Verdict.MALICIOUS, layer.reasons
    assert not layer.reasons, layer.reasons  # rebuilt and called without any finding


def test_dill_function_with_os_system_is_malicious(compiled, tmp_path):
    data = dill_function(compiled["os_system"])
    report = parse_pickle(data)
    assert report["static_risk"] == "malicious"
    assert any("names the sink(s)" in r and "system" in r for r in report["reasons"])
    result = _scan(tmp_path, data)
    assert result.verdict is Verdict.MALICIOUS
    layer = next(la for la in result.layers if la.name == "emulation[dill code]")
    assert layer.verdict is Verdict.MALICIOUS, layer.reasons


def test_nested_code_object_is_rebuilt(compiled, tmp_path):
    result = _scan(tmp_path, dill_function(compiled["nested"]))
    assert result.verdict is Verdict.SUSPICIOUS
    layer = next(la for la in result.layers if la.name == "emulation[dill code]")
    assert not any("cannot rebuild" in r for r in layer.reasons), layer.reasons


def test_sink_name_in_nested_code_is_malicious(compiled):
    nested = json.loads(json.dumps(compiled["benign"]))
    outer = json.loads(json.dumps(compiled["nested"]))
    nested[8] = {"t": ["system"]}  # co_names of the inner code object
    outer[7] = {"t": [{"code": nested}] + outer[7]["t"][1:]}
    assert parse_pickle(dill_function(outer))["static_risk"] == "malicious"


def test_code_from_another_python_version_is_not_run(compiled, tmp_path):
    fields = compiled["benign"][:-2]  # a 16-field layout
    result = _scan(tmp_path, dill_function(fields))
    assert result.verdict is Verdict.SUSPICIOUS
    layer = next(la for la in result.layers if la.name == "emulation[dill code]")
    assert any("cannot rebuild dill code object" in r for r in layer.reasons), layer.reasons


def test_field_that_is_not_data_is_risky_and_not_emulated(compiled):
    fields = list(compiled["benign"])
    body = call(g(DILL, "_create_code"), b"C\x00", *[_value(f) for f in fields[:7]],
                call(g("collections", "OrderedDict")), *[_value(f) for f in fields[8:]])
    report = parse_pickle(P4 + body + STOP)
    assert report["static_risk"] == "suspicious"
    assert report["dill_code"][0]["code_fields"] is None
    assert any("not plain data" in r for r in report["reasons"])


# --- dill without code ------------------------------------------------------------------

def test_set_through_load_type_is_risky_not_malicious(tmp_path):
    # how dill writes a set inside a torch module (YOLO-World): _load_type('set')([])
    body = b"}(" + s("hooks") + call(call(g(DILL, "_load_type"), s("set")), b"]") + b"u"
    result = _scan(tmp_path, P4 + body + STOP)
    assert result.verdict is Verdict.SUSPICIOUS and not result.unverifiable_only, result.findings
    assert any("pickle written by dill" in r for r in result.reasons)
    assert not any(la.name.endswith("dill code]") for la in result.layers)


@pytest.mark.parametrize("helper,arg", [("_import_module", "os"), ("_eval_repr", "print(1)"),
                                        ("_create_type", "x"), ("_get_attr", "eval"), ("_unmarshal", "x")])
def test_dangerous_dill_helpers_stay_malicious(helper, arg, tmp_path):
    data = P4 + call(g(DILL, helper), s(arg)) + STOP
    assert parse_pickle(data)["static_risk"] == "malicious"
    assert _scan(tmp_path, data).verdict is Verdict.MALICIOUS


def test_dill_dill_module_name_is_the_same_module():
    assert parse_pickle(P4 + call(g("dill.dill", "_import_module"), s(MARKER_CMD)) + STOP)["static_risk"] \
        == "malicious"
