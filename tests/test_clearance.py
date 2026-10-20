"""0.7.0 Parts 1 and 2: globals that are only referenced, and source-derived state-only
classes (static/clearance.py). Every way a cleared global could still run code while
loading must stay flagged."""
from __future__ import annotations

import pytest

from safeloadai import Verdict, scan
from safeloadai.behaviour import classify
from safeloadai.sandbox.host import GuestRun
from safeloadai.static import clearance, upstream
from safeloadai.static.pickle_static import parse_pickle

P4, STOP = b"\x80\x04", b"."


def s(text: str) -> bytes:
    raw = text.encode()
    return b"\x8c" + bytes([len(raw)]) + raw


def g(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


def run(body: bytes) -> dict:
    return parse_pickle(P4 + body + STOP)


def cleared(report: dict) -> dict[str, str]:
    return {c["item"]: c["mechanism"] for c in report["cleared"]}


FUNC = ("sklearn.metrics._ranking", "average_precision_score")  # a def in an inert sklearn module
REF = g(*FUNC)
FUNC_NAME = ".".join(FUNC)


def test_pinned_data_has_the_reference_names():
    assert upstream.inert_definition(*FUNC)
    assert not upstream.inert_definition(FUNC[0], "average_precision_score.__wrapped__")
    assert upstream.distributions()["scikit-learn"]["version"]


# --- Part 1: referenced vs used --------------------------------------------------------

def test_referenced_only_global_is_clean():
    report = run(b"}" + s("scorer") + REF + b"s")
    assert report["static_risk"] == "clean", report["reasons"]
    assert cleared(report) == {FUNC_NAME: "referenced"}


def test_referenced_in_a_list_and_tuple_is_clean():
    report = run(b"]" + REF + REF + b"\x86a")
    assert report["static_risk"] == "clean", report["reasons"]


@pytest.mark.parametrize("body", [
    REF + b")R",  # called
    b"}" + s("f") + REF + b"\x94s" + s("g") + b"h\x00)Rs",  # referenced, then called through the memo
    g("collections", "defaultdict") + REF + b"\x85R",  # handed to a factory slot
    g("functools", "partial") + REF + b"\x85R",  # handed to partial
    g("builtins", "list") + b"]" + REF + b"a\x85R",  # inside an argument of another call
    REF + b"}b",  # BUILD target
    REF + b")\x81",  # NEWOBJ
    b"}" + REF + s("v") + b"s",  # dict key: hashed
    b"(" + REF + b"\x91",  # frozenset member: hashed
    b"\x8f(" + REF + b"\x90",  # set member: hashed
    g("collections", "OrderedDict") + b")R" + REF + s("v") + b"s",  # key of an OrderedDict
    g("mod_unknown", "Box") + b")\x81" + REF + b"a",  # appended into an unknown object
    g("mod_unknown", "Box") + b")\x81}" + s("f") + REF + b"sb",  # in the BUILD state of an unknown class
    REF + b"Q",  # persistent id
], ids=["called", "memo-call", "defaultdict", "partial", "nested-arg", "build-target", "newobj", "dict-key",
        "frozenset", "set", "ordereddict-key", "append-unknown", "unknown-build-state", "persid"])
def test_used_global_keeps_its_finding(body):
    report = run(body)
    assert report["static_risk"] != "clean", report["reasons"]
    assert FUNC_NAME not in cleared(report)
    assert any(FUNC_NAME in r for r in report["reasons"]), report["reasons"]


def test_getattr_result_used_marks_the_target():
    getattr_call = g("builtins", "getattr") + REF + s("x") + b"\x86R"
    report = run(getattr_call + b")R")
    assert report["static_risk"] == "malicious", report["reasons"]
    assert FUNC_NAME not in cleared(report)


def test_value_of_an_allowlisted_container_stays_referenced():
    report = run(g("collections", "OrderedDict") + b")R" + s("k") + REF + b"s")
    assert report["static_risk"] == "clean", report["reasons"]


@pytest.mark.parametrize("pair", [
    ("antigravity", "geohash"),  # import side effect
    ("this", "s"),
    ("webbrowser", "open"),  # a sink
    ("sklaern.metrics._ranking", "average_precision_score"),  # look-alike package name
    ("sklearn_metrics._ranking", "average_precision_score"),
    ("sklearn.metrics._ranking", "average_precision_score.__globals__"),  # dotted qualname
    ("sklearn.metrics._scorer", "_passthrough_scorer"),  # not in the pinned version
    ("transformers.models.bert.modeling_bert", "BertModel"),  # import chain not inert (lazy module)
    ("mod_unknown", "anything"),  # unknown package
])
def test_referenced_only_but_not_eligible_stays_flagged(pair):
    report = run(b"}" + s("f") + g(*pair) + b"s")
    assert report["static_risk"] != "clean", report["reasons"]
    assert ".".join(pair) not in cleared(report)


def test_walk_error_clears_nothing():
    report = parse_pickle(P4 + b"}" + s("f") + REF + b"s" + b"\xff")
    assert report["error"]
    assert not report["cleared"]


def test_emulation_flags_a_call_to_a_referenced_pair():
    run_ = GuestRun(status="ok", completed=True, events=[
        {"kind": "import", "module": FUNC[0], "name": FUNC[1], "resolved": "stub"},
        {"kind": "call", "target": FUNC_NAME, "args": []},
    ])
    layer = classify(run_, framework=False, referenced=frozenset({FUNC}))
    assert layer.verdict is Verdict.SUSPICIOUS
    assert [f["category"] for f in layer.findings] == ["RISKY"]
    import_only = GuestRun(status="ok", completed=True, events=run_.events[:1])
    assert classify(import_only, framework=False, referenced=frozenset({FUNC})).verdict is Verdict.CLEAN


# --- Part 2: pinned state-only policies ---------------------------------------------------

CLS = ("sklearn.ensemble._voting", "VotingRegressor")
CLS_NAME = ".".join(CLS)


def test_policy_class_rebuilt_from_dict_state_is_clean():
    assert upstream.state_only(CLS)
    report = run(g(*CLS) + b")\x81}" + s("n_jobs") + b"Ns" + b"b")
    assert report["static_risk"] == "clean", report["reasons"]
    assert cleared(report)[CLS_NAME] == "policy"


@pytest.mark.parametrize("body", [
    g(*CLS) + b")R",  # REDUCE: runs __init__
    g(*CLS) + s("x") + b"\x85\x81",  # NEWOBJ with arguments
    g(*CLS) + b")\x81N}" + s("n") + b"Ns\x86b",  # (None, slotstate): setattr per item
    g(*CLS) + b")\x81]b",  # a non-dict state goes to __setstate__ differently
    g(*CLS) + b")\x81}b)R",  # the instance is called
    g("functools", "partial") + g(*CLS) + b"\x85R",  # the class handed to a call
    b"c" + CLS[0].encode() + b"\n" + CLS[1].encode() + b"\n(X\x01\x00\x00\x00xt\x81",  # GLOBAL opcode, NEWOBJ args
])
def test_policy_class_used_otherwise_is_flagged(body):
    report = run(body)
    assert report["static_risk"] != "clean", report["reasons"]


@pytest.mark.parametrize("pair", [
    ("sklearn.preprocessing._function_transformer", "FunctionTransformer"),  # owner decision A1
    ("sklearn.compose._target", "TransformedTargetRegressor"),
    ("xgboost.core", "Booster"),  # decision A4
    ("torch.nn.modules.rnn", "LSTM"),  # RNNBase.__setstate__ is not reviewed
])
def test_excluded_or_unreviewed_classes_are_not_policies(pair):
    assert upstream.state_only(pair) is None
    report = run(g(*pair) + b")\x81}b")
    assert report["static_risk"] != "clean"


def test_reviewed_hooks_are_pinned_by_source_hash():
    from safeloadai.static import sources

    index = sources.SourceIndex(lambda m: {
        "lib": ("class Base:\n    def __setstate__(self, state):\n        self.__dict__.update(state)\n"
                "class Child(Base):\n    pass\n", False)}.get(m), reviewed_hooks={})
    assert not index.state_only("lib", "Child").state_only
    text = "def __setstate__(self, state):\n        self.__dict__.update(state)"
    reviewed = {("lib", "Base", "__setstate__"): (sources.source_sha256(text), "test")}
    index = sources.SourceIndex(lambda m: {
        "lib": ("class Base:\n    def __setstate__(self, state):\n        self.__dict__.update(state)\n"
                "class Child(Base):\n    pass\n", False)}.get(m), reviewed_hooks=reviewed)
    assert index.state_only("lib", "Child").state_only


@pytest.mark.wasi
def test_scan_of_a_referenced_only_global_is_clean(tmp_path):
    path = tmp_path / "scorer.pkl"
    path.write_bytes(P4 + b"}" + s("scorer") + REF + b"s" + STOP)
    report = scan(path)
    assert report.verdict is Verdict.CLEAN, report.reasons


@pytest.mark.wasi
def test_scan_of_a_called_referenced_global_is_not_clean(tmp_path):
    path = tmp_path / "scorer.pkl"
    path.write_bytes(P4 + REF + b")R" + STOP)
    assert scan(path).verdict is not Verdict.CLEAN


def test_referenced_ok_rules():
    assert clearance.referenced_ok(*FUNC)
    assert not clearance.referenced_ok("builtins", "getattr")
    assert not clearance.referenced_ok("antigravity", "geohash")


@pytest.mark.wasi
def test_safe_load_resolves_cleared_pairs(tmp_path):
    pytest.importorskip("sklearn")
    from safeloadai import safe_load

    path = tmp_path / "model.pkl"
    path.write_bytes(P4 + b"}(" + s("scorer") + REF + s("model") + g(*CLS) + b")\x81}" + s("n_jobs") + b"Nsb"
                     + b"u" + STOP)
    loaded = safe_load(path)
    assert loaded["scorer"].__name__ == FUNC[1]
    assert type(loaded["model"]).__name__ == CLS[1] and loaded["model"].n_jobs is None
