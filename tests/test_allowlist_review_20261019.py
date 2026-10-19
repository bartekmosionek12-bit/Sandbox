"""Allowlist growth from the 2026-10-19 review (evaluation/results/allowlist-review-20261019.md):
every pair added here passes only with an argument check, and each check has a marker
test that must stay flagged.

Benign objects are only pickled (dumped) here, never loaded. Malicious variants are
assembled opcode by opcode and only ever scanned.
"""
from __future__ import annotations

import pickle
from collections import defaultdict

import pytest
from corpus.build_corpus import MARKER_CMD, P2, P4, STOP, call, g, s, sg, tup

from safeloadai import Verdict, scan
from safeloadai.static import allowlists
from safeloadai.static.pickle_static import parse_pickle

TA = ("transformers.training_args", "TrainingArguments")
STRATEGY = ("transformers.trainer_utils", "IntervalStrategy")
NEW_INDEX = ("pandas.core.indexes.base", "_new_Index")
INDEX = ("pandas.core.indexes.base", "Index")
DD = ("collections", "defaultdict")
EMPTY_DICT, NEWOBJ, BUILD, SETITEM = b"}", b"\x81", b"b", b"s"


def _risk(data: bytes) -> tuple[str, list[str]]:
    report = parse_pickle(data)
    return report["static_risk"], report["reasons"]


def _state(*pairs: bytes) -> bytes:
    """An EMPTY_DICT filled with key/value pairs (each item is key bytes + value bytes)."""
    return EMPTY_DICT + (b"(" + b"".join(pairs) + b"u" if pairs else b"")


def _training_args(state: bytes) -> bytes:
    return P2 + g(*TA) + b")" + NEWOBJ + state + BUILD + STOP


def test_every_new_pair_is_argument_checked():
    for pair in allowlists.ARGUMENT_CHECKED:
        assert pair in allowlists.PICKLE_GLOBALS, pair
    # never a module grant, never the risky neighbours the review left out
    for pair in [("transformers.training_args", "default_logdir"), ("accelerate.state", "PartialState"),
                 ("xgboost.core", "Booster"), ("keras.layers", "TFSMLayer"),
                 ("sklearn.preprocessing._function_transformer", "FunctionTransformer"),
                 ("pandas.core.indexes.base", "ensure_index")]:
        assert pair not in allowlists.PICKLE_GLOBALS, pair


# --- the forms the libraries write are clean ----------------------------------------------

def test_training_args_rebuilt_from_state_is_clean():
    state = _state(s("output_dir") + s("out"), s("learning_rate") + b"G?\x1a6\xe2\xeb\x1cC-",
                   s("eval_strategy") + call(g(*STRATEGY), s("steps")),
                   s("optim") + call(g("transformers.training_args", "OptimizerNames"), s("adamw_torch")),
                   s("lr_scheduler_type") + call(g("transformers.trainer_utils", "SchedulerType"), s("linear")),
                   s("hub_strategy") + call(g("transformers.trainer_utils", "HubStrategy"), s("every_save")))
    risk, reasons = _risk(_training_args(state))
    assert risk == "clean", reasons
    risk, reasons = _risk(P4 + sg(*TA) + b")" + NEWOBJ + _state() + BUILD + STOP)
    assert risk == "clean", reasons


@pytest.mark.parametrize("proto", [2, 4, 5])
def test_library_pickles_are_clean(proto):
    pytest.importorskip("sklearn")
    from scipy.sparse import csr_matrix
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.ensemble import RandomForestRegressor
    from sklearn.impute import SimpleImputer
    from sklearn.linear_model import Lasso
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.svm import LinearSVC

    np = pytest.importorskip("numpy")
    x = np.array([[0.0, 1.0], [1.0, 0.0], [1.0, 1.0], [0.0, 0.0]] * 3)
    y = np.array([0, 1, 1, 0] * 3)
    models = [csr_matrix(np.eye(3)), SimpleImputer().fit(x), Lasso().fit(x, y), MultinomialNB().fit(x, y),
              RandomForestRegressor(n_estimators=2, random_state=0).fit(x, y),
              CalibratedClassifierCV(LinearSVC(), cv=2).fit(x, y),
              defaultdict(list, {"a": [1, 2]}), defaultdict(None, {"b": 1}),
              defaultdict(__import__("collections").OrderedDict)]
    from argparse import Namespace

    from sklearn.impute import MissingIndicator
    from sklearn.linear_model import LogisticRegressionCV
    from sklearn.model_selection import StratifiedKFold
    from sklearn.preprocessing import MinMaxScaler, OrdinalEncoder
    from sklearn.tree import ExtraTreeRegressor
    models += [MissingIndicator().fit(x), LogisticRegressionCV(cv=2).fit(x, y), StratifiedKFold(2),
               MinMaxScaler().fit(x), OrdinalEncoder().fit(x), ExtraTreeRegressor(random_state=0).fit(x, y),
               Namespace(lr=0.1, out="o")]
    for model in models:
        risk, reasons = _risk(pickle.dumps(model, protocol=proto))
        assert risk == "clean", (type(model).__name__, reasons)


def test_pandas_index_pickle_is_clean():
    pd = pytest.importorskip("pandas")
    risk, reasons = _risk(pickle.dumps(pd.Index(["a", "b"], name="cols"), protocol=4))
    assert risk == "clean", reasons


RANGE = ("pandas.core.indexes.range", "RangeIndex")


@pytest.mark.parametrize("data", [
    P2 + call(g(*NEW_INDEX), g(*INDEX), _state(s("data") + b"N", s("name") + s("cols"))) + STOP,
])
def test_pandas_new_index_as_pandas_writes_it_is_clean(data):
    risk, reasons = _risk(data)
    assert risk == "clean", reasons


# --- every other use stays flagged ----------------------------------------------------------

@pytest.mark.parametrize("data", [
    # state-only classes called: the constructor would run
    P2 + call(g(*TA), s(MARKER_CMD)) + STOP,
    P2 + g(*TA) + tup(s("out")) + NEWOBJ + STOP,
    P2 + b"(" + g(*TA) + s("out") + b"o" + STOP,
    b"(S'out'\nitransformers.training_args\nTrainingArguments\n.",
    P2 + call(g("scipy.sparse._csr", "csr_matrix"), tup(b"K\x01", b"K\x01")) + STOP,
    P2 + call(g("sklearn.impute._base", "SimpleImputer"), b"N") + STOP,
    # BUILD on the class object itself (sets class attributes)
    P2 + g(*TA) + _state(s("__init__") + b"N") + BUILD + STOP,
    # passed around as a value
    P2 + call(g("collections", "OrderedDict"), b"]" + g(*TA) + b"a") + STOP,
    # enum: functional API (two arguments), a callable argument, NEWOBJ
    P2 + call(g(*STRATEGY), s("A"), s("B C")) + STOP,
    P2 + call(g("transformers.trainer_utils", "SaveStrategy"), s("A"), s("B C")) + STOP,
    P2 + call(g("argparse", "Namespace"), b"N") + STOP,
    P2 + call(g(*STRATEGY), g("collections", "OrderedDict")) + STOP,
    P2 + g(*STRATEGY) + tup(s("steps")) + NEWOBJ + STOP,
    # _new_Index calls its first argument: only pandas' own Index with a data/name dict
    P2 + call(g(*NEW_INDEX), g("collections", "OrderedDict"), _state(s("data") + b"N")) + STOP,
    P2 + call(g(*NEW_INDEX), g(*INDEX), _state(s("data") + b"N", s("tupleize_cols") + b"\x88")) + STOP,
    P2 + call(g(*NEW_INDEX), g(*INDEX), b"]") + STOP,
    P2 + call(g(*NEW_INDEX), s("pandas"), _state()) + STOP,
    P2 + call(g(*NEW_INDEX), g(*RANGE), _state(s("data") + b"N")) + STOP,
    # RangeIndex is not reviewed (seen only in held-out files)
    P2 + call(g(*NEW_INDEX), g(*RANGE), _state(s("name") + b"N", s("start") + b"K\x00")) + STOP,
    # defaultdict: no factory or one imported global; the global itself is checked
    P2 + call(g(*DD), g(*TA)) + STOP,  # a state-only class passed as a value
    P2 + call(g(*DD), g("safeloadai_marker_pkg", "factory")) + STOP,  # not on the allowlist
    P2 + call(g(*DD), call(g("collections", "OrderedDict"))) + STOP,  # not a global
    P2 + call(g(*DD), b"N", b"N") + STOP,
])
def test_misuse_of_argument_checked_pairs_stays_flagged(data):
    risk, reasons = _risk(data)
    assert risk != "clean", reasons


@pytest.mark.parametrize("data", [
    P2 + call(g(*NEW_INDEX), g("posix", "system"), _state(s("data") + s(MARKER_CMD))) + STOP,
    P2 + call(g(*DD), g("posix", "system")) + STOP,
    _training_args(_state(s("x") + call(g("posix", "system"), s(MARKER_CMD)))),
])
def test_a_sink_reached_through_a_checked_pair_is_malicious(data):
    risk, reasons = _risk(data)
    assert risk == "malicious", reasons


@pytest.mark.wasi
def test_called_training_args_is_not_clean_end_to_end(tmp_path):
    path = tmp_path / "training_args.bin"
    path.write_bytes(P2 + call(g(*TA), s(MARKER_CMD)) + STOP)
    assert scan(path).verdict is not Verdict.CLEAN


# --- Keras ------------------------------------------------------------------------------------

def _keras_node(class_name: str, config: dict, module: str | None = "keras.layers") -> dict:
    node = {"class_name": class_name, "config": config}
    if module is not None:
        node["module"] = module
    return node


def _keras_findings(*nodes: dict) -> list:
    from safeloadai.static.keras_static import _empty_report, walk_config

    report = _empty_report("m.keras")
    walk_config({"class_name": "Sequential", "module": "keras", "config": {"layers": list(nodes)}}, report)
    return report["unknown_imports"] + report["suspicious_imports"] + report["flagged_opcodes"]


@pytest.mark.parametrize("node", [
    _keras_node("RandomRotation", {"factor": 0.1, "fill_mode": "reflect", "interpolation": "bilinear", "seed": 1}),
    _keras_node("RandomTranslation", {"height_factor": 0.1, "width_factor": 0.1}),
    _keras_node("RandomZoom", {"height_factor": 0.2}),
    _keras_node("RandomFlip", {"mode": "horizontal"}, module=None),
    _keras_node("RandomContrast", {"factor": 0.2}, module=None),
    _keras_node("OrthogonalInitializer", {"gain": 1.0, "seed": None}, module="keras.initializers"),
    _keras_node("CategoricalFocalCrossentropy", {"alpha": 0.25, "gamma": 2.0}, module="keras.losses"),
    _keras_node("R2Score", {"class_aggregation": "uniform_average"}, module="keras.metrics"),
    _keras_node("Subtract", {"name": "subtract"}, module="keras.src.ops.numpy"),
    _keras_node("TrueDivide", {"name": "true_divide"}, module="keras.src.ops.numpy"),
])
def test_reviewed_keras_classes_are_known(node):
    assert not _keras_findings(node)


@pytest.mark.parametrize("node", [
    # a nested object inside an accepted layer's config is still checked
    _keras_node("RandomRotation", {"factor": 0.1, "fill_value": {"class_name": "function", "module": "posix",
                                                                   "config": "system"}}),
    _keras_node("RandomZoom", {"height_factor": {"class_name": "Lambda", "module": "keras.layers",
                                                 "config": {"function": "x"}}}),
    # left out by the review: loads a SavedModel from a path
    _keras_node("TFSMLayer", {"filepath": "/tmp/safeloadai_marker"}),
    # an accepted name from another module is not accepted
    _keras_node("RandomRotation", {}, module="safeloadai_marker_pkg"),
    _keras_node("Subtract", {}, module="keras.src.ops.core"),
])
def test_keras_neighbours_stay_flagged(node):
    assert _keras_findings(node)


# --- value walk shared by all calls of a stream ---------------------------------------------

def test_large_state_walked_once_is_clean():
    vocab = b"}(" + b"".join(s(f"w{i}") + b"J" + i.to_bytes(4, "little") for i in range(150_000)) + b"u"
    memo = b"q\x01"
    obj = g("sklearn.feature_extraction.text", "TfidfVectorizer") + b")" + NEWOBJ
    data = P2 + b"(" + obj + _state(s("vocabulary_") + vocab + memo) + BUILD \
        + b"".join(obj + _state(s("vocabulary_") + b"h\x01") + BUILD for _ in range(20)) + b"l" + STOP
    risk, reasons = _risk(data)
    assert risk == "clean", reasons[:3]


def test_exempt_argument_tuple_reused_as_a_value_is_flagged():
    # _new_Index's (cls, d) tuple is memoised, then passed as a value: the class inside it
    # must be found there even though the first call exempted that position.
    args = tup(g(*INDEX), _state(s("data") + b"N")) + b"q\x02"
    data = P2 + g(*NEW_INDEX) + args + b"R0" + call(g("collections", "OrderedDict"), b"]h\x02a") + STOP
    risk, reasons = _risk(data)
    assert risk != "clean", reasons


def test_builtins_object_as_a_value_is_clean_and_a_sink_next_to_it_is_not():
    selector = (g("sklearn.compose._column_transformer", "make_column_selector") + b")" + NEWOBJ
                + _state(s("dtype_exclude") + g("builtins", "object"), s("dtype_include") + g("numpy", "number"))
                + BUILD)
    risk, reasons = _risk(P2 + selector + STOP)
    assert risk == "clean", reasons
    risk, _ = _risk(P2 + call(g("builtins", "getattr"), g("builtins", "object"), s("__subclasses__")) + STOP)
    assert risk == "malicious"


def test_xgboost_booster_is_unverifiable_with_its_own_explanation(tmp_path):
    from safeloadai import pipeline

    data = P2 + g("xgboost.core", "Booster") + b")" + NEWOBJ + _state(s("handle") + b"C\x03abc") + BUILD + STOP
    assert ("xgboost.core", "Booster") not in allowlists.PICKLE_GLOBALS
    path = tmp_path / "booster.pkl"
    path.write_bytes(data)
    report = pipeline.scan(str(path))
    assert report.verdict is Verdict.SUSPICIOUS and report.unverifiable_only, report.findings
    assert report.unverifiable_items == ["xgboost.core.Booster"]
    explanation = next(f["explanation"] for f in report.findings if f["category"] == "UNVERIFIABLE")
    assert "native" in explanation and "save_model" in explanation


# --- zero-arg call rule (owner, 2026-10-19): IterableSimpleNamespace -------------------------

NS = ("ultralytics.utils", "IterableSimpleNamespace")
EMPTY_TUPLE, REDUCE = b")", b"R"


def _ns(state: bytes = b"}") -> bytes:
    """How pickle writes a SimpleNamespace subclass: REDUCE cls() + BUILD(dict)."""
    return g(*NS) + EMPTY_TUPLE + REDUCE + state + BUILD


def test_zero_arg_namespace_rebuilt_from_dict_is_clean():
    risk, reasons = _risk(P2 + _ns(_state(s("epochs") + b"Kd", s("model") + s("yolov8n.pt"))) + STOP)
    assert risk == "clean", reasons
    old = P2 + g("ultralytics.yolo.utils", "IterableSimpleNamespace") + EMPTY_TUPLE + REDUCE + b"}" + BUILD + STOP
    assert _risk(old)[0] == "clean"


def test_zero_arg_class_with_arguments_is_flagged():
    risk, reasons = _risk(P2 + call(g(*NS), s("x")) + STOP)
    assert risk == "suspicious" and any("only as a call with no arguments" in r for r in reasons)


def test_zero_arg_call_on_an_unreviewed_class_is_flagged():
    risk, reasons = _risk(P2 + g("types", "SimpleNamespace") + EMPTY_TUPLE + REDUCE + b"}" + BUILD + STOP)
    assert risk != "clean"
    risk, reasons = _risk(P2 + g("ultralytics.utils", "SimpleClass") + EMPTY_TUPLE + REDUCE + STOP)
    assert risk != "clean"


def test_zero_arg_result_called_is_flagged():
    risk, reasons = _risk(P2 + call(g(*NS) + EMPTY_TUPLE + REDUCE, s(MARKER_CMD)) + STOP)
    assert risk != "clean" and any("is called" in r for r in reasons)


def test_zero_arg_result_passed_to_another_call_is_flagged():
    risk, reasons = _risk(P2 + call(g("collections", "OrderedDict"), _ns()) + STOP)
    assert risk != "clean" and any("is passed to a call" in r for r in reasons)


def test_zero_arg_slotstate_build_is_flagged():
    slot = b"(" + b"N" + _state(s("x") + b"K\x01") + b"t"  # (None, {"x": 1})
    risk, reasons = _risk(P2 + g(*NS) + EMPTY_TUPLE + REDUCE + slot + BUILD + STOP)
    assert risk != "clean" and any("BUILD state" in r for r in reasons)


def test_state_only_slotstate_build_is_flagged():
    slot = b"(" + b"N" + _state(s("x") + b"K\x01") + b"t"
    risk, reasons = _risk(P2 + g(*TA) + b")" + NEWOBJ + slot + BUILD + STOP)
    assert risk != "clean" and any("BUILD state" in r for r in reasons)


def test_state_only_instance_called_is_flagged():
    risk, reasons = _risk(P2 + call(g(*TA) + b")" + NEWOBJ, s(MARKER_CMD)) + STOP)
    assert risk != "clean" and any("is called" in r for r in reasons)
