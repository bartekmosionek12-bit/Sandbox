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
              defaultdict(list, {"a": [1, 2]}), defaultdict(None, {"b": 1})]
    for model in models:
        risk, reasons = _risk(pickle.dumps(model, protocol=proto))
        assert risk == "clean", (type(model).__name__, reasons)


def test_pandas_index_pickle_is_clean():
    pd = pytest.importorskip("pandas")
    risk, reasons = _risk(pickle.dumps(pd.Index(["a", "b"], name="cols"), protocol=4))
    assert risk == "clean", reasons


def test_pandas_new_index_as_pandas_writes_it_is_clean():
    data = P2 + call(g(*NEW_INDEX), g(*INDEX), _state(s("data") + b"N", s("name") + s("cols"))) + STOP
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
    P2 + call(g(*STRATEGY), g("collections", "OrderedDict")) + STOP,
    P2 + g(*STRATEGY) + tup(s("steps")) + NEWOBJ + STOP,
    # _new_Index calls its first argument: only pandas' own Index with a data/name dict
    P2 + call(g(*NEW_INDEX), g("collections", "OrderedDict"), _state(s("data") + b"N")) + STOP,
    P2 + call(g(*NEW_INDEX), g(*INDEX), _state(s("data") + b"N", s("tupleize_cols") + b"\x88")) + STOP,
    P2 + call(g(*NEW_INDEX), g(*INDEX), b"]") + STOP,
    P2 + call(g(*NEW_INDEX), s("pandas"), _state()) + STOP,
    # defaultdict: only a builtin type (or nothing) as the factory
    P2 + call(g(*DD), g("numpy", "float64")) + STOP,
    P2 + call(g(*DD), g(*TA)) + STOP,
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
