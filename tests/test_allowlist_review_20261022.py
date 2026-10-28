"""Allowlist growth from the Phase 5 tune review (evaluation/results/source-review-3-20261022.md):
pandas DataFrame and Series as pandas 1.4 to 3.1 pickle them, dabl's estimators and
scikit-learn's _ThresholdScorer with its score function. Every entry passes only in the
form its library writes, and each one has a marker test that must stay flagged.

Nothing here is loaded: every stream is assembled opcode by opcode and only scanned.
"""
from __future__ import annotations

import struct

import pytest
from corpus.build_corpus import MARKER_CMD, P4, STOP, call, g, s, tup

from safeloadai import Verdict, scan
from safeloadai.static import allowlists
from safeloadai.static.pickle_static import parse_pickle

DF = ("pandas.core.frame", "DataFrame")
SERIES = ("pandas.core.series", "Series")
BM = ("pandas.core.internals.managers", "BlockManager")
SBM = ("pandas.core.internals.managers", "SingleBlockManager")
UNPICKLE_BLOCK = ("pandas._libs.internals", "_unpickle_block")
CAT = ("pandas.core.dtypes.dtypes", "CategoricalDtype")
NEW_INDEX = ("pandas.core.indexes.base", "_new_Index")
INDEX = ("pandas.core.indexes.base", "Index")
SCORER = ("sklearn.metrics._scorer", "_ThresholdScorer")
APS = ("sklearn.metrics._ranking", "average_precision_score")
SIMPLE = ("dabl.models", "SimpleClassifier")
EASY = ("dabl.preprocessing", "EasyPreprocessor")
SYSTEM = ("posix", "system")
EMPTY_DICT, EMPTY_LIST, NEWOBJ, BUILD = b"}", b"]", b"\x81", b"b"
TRUE, FALSE, NONE = b"\x88", b"\x89", b"N"


def _risk(data: bytes) -> tuple[str, list[str]]:
    report = parse_pickle(data)
    return report["static_risk"], report["reasons"]


def _int(n: int) -> bytes:
    return b"K" + bytes([n])


def _bytes(raw: bytes) -> bytes:
    return b"C" + bytes([len(raw)]) + raw


def _state(*pairs: bytes) -> bytes:
    return EMPTY_DICT + (b"(" + b"".join(pairs) + b"u" if pairs else b"")


def _list(*items: bytes) -> bytes:
    return EMPTY_LIST + (b"(" + b"".join(items) + b"e" if items else b"")


def _array() -> bytes:
    """numpy's own form: _reconstruct(ndarray, (0,), b"b") + BUILD (1, shape, dtype, False, data)."""
    dtype = call(g("numpy", "dtype"), s("f8"), FALSE, TRUE) + tup(
        _int(3), s("<"), NONE, NONE, NONE, b"J" + struct.pack("<i", -1), b"J" + struct.pack("<i", -1), _int(0)) + BUILD
    head = call(g("numpy._core.multiarray", "_reconstruct"), g("numpy", "ndarray"), tup(_int(0)), _bytes(b"b"))
    return head + tup(_int(1), tup(_int(2)), dtype, FALSE, _bytes(b"\x00" * 16)) + BUILD


def _index() -> bytes:
    return call(g(*NEW_INDEX), g(*INDEX), _state(s("data") + _array(), s("name") + NONE))


def _slice(stop: int = 2) -> bytes:
    return call(g("builtins", "slice"), _int(0), _int(stop), _int(1))


def _block(values: bytes | None = None, locs: bytes | None = None, ndim: bytes = _int(2)) -> bytes:
    return call(g(*UNPICKLE_BLOCK), values or _array(), locs or _slice(), ndim)


def _manager(blocks: bytes | None = None, axes: bytes | None = None) -> bytes:
    return call(g(*BM), blocks or tup(_block()), axes or _list(_index(), _index()))


def _flags(*extra: bytes) -> bytes:
    return _state(s("allows_duplicate_labels") + TRUE, *extra)


def _frame(mgr: bytes | None = None, *extra: bytes, flags: bytes | None = None) -> bytes:
    state = _state(s("_mgr") + (mgr or _manager()), s("_typ") + s("dataframe"), s("_metadata") + _list(),
                   s("attrs") + EMPTY_DICT, s("_flags") + (flags or _flags()), *extra)
    return g(*DF) + b")" + NEWOBJ + state + BUILD


def _manager_state(values: bytes | None = None) -> bytes:
    first = _state(s("axes") + _list(_index()),
                   s("blocks") + _list(_state(s("values") + (values or _array()), s("mgr_locs") + _slice())))
    return tup(_list(_index()), _list(_array()), _list(_index()), _state(s("0.14.1") + first))


def _single_manager(state: bytes | None = None) -> bytes:
    return g(*SBM) + b")" + NEWOBJ + (state or _manager_state()) + BUILD


def _series(name: bytes = s("col"), mgr: bytes | None = None) -> bytes:
    state = _state(s("_mgr") + (mgr or _single_manager()), s("_typ") + s("series"), s("_metadata") + _list(s("name")),
                   s("attrs") + EMPTY_DICT, s("_flags") + _flags(), s("name") + name)
    return g(*SERIES) + b")" + NEWOBJ + state + BUILD


def _categorical(categories: bytes | None = None, ordered: bytes = FALSE) -> bytes:
    return g(*CAT) + b")" + NEWOBJ + _state(s("categories") + (categories or _index()), s("ordered") + ordered) + BUILD


def _scorer(func: bytes | None = None, *extra: bytes) -> bytes:
    state = _state(s("_kwargs") + _state(s("pos_label") + s("yes")), s("_score_func") + (func or g(*APS)),
                   s("_sign") + _int(1), *extra)
    return g(*SCORER) + b")" + NEWOBJ + state + BUILD


def _estimator(pair: tuple[str, str], *items: bytes) -> bytes:
    return g(*pair) + b")" + NEWOBJ + _state(*items) + BUILD


def _dabl_pickle() -> bytes:
    """The shape of the dabl clf.pkl files on the tune split, reduced to one of each object."""
    pre = _estimator(EASY, s("types") + _frame(), s("dtypes_") + _series(), s("verbose") + _int(0))
    clf = _estimator(SIMPLE, s("preprocessor_") + pre, s("scoring_") + _scorer(),
                     s("log_") + _list(_series(name=NONE)), s("cats") + _categorical())
    return P4 + clf + STOP


def test_reviewed_pairs_are_argument_checked_exactly():
    for pair in (DF, SERIES, BM, SBM, UNPICKLE_BLOCK, CAT, SCORER, APS, SIMPLE, EASY,
                 ("dabl.models", "SimpleRegressor")):
        assert pair in allowlists.ARGUMENT_CHECKED and pair in allowlists.PICKLE_GLOBALS, pair
    # exact pairs only: neighbours the review did not cover stay out
    # (RangeIndex was reviewed later, in 0.10.0: tests/test_allowlist_review_0_10_0.py)
    for pair in [("pandas.core.arrays.categorical", "Categorical"),
                 ("pandas.io.pickle", "read_pickle"), ("sklearn.metrics._scorer", "_PredictScorer"),
                 ("sklearn.metrics._ranking", "roc_auc_score"), ("dabl.models", "AnyClassifier"),
                 ("_loss", "CyHalfBinomialLoss"), ("pandas.core.internals.blocks", "new_block")]:
        assert pair not in allowlists.PICKLE_GLOBALS, pair


# --- the forms the libraries write are clean ----------------------------------------------

@pytest.mark.parametrize("data", [
    P4 + _frame() + STOP,
    P4 + _series() + STOP,
    P4 + _series(name=tup(s("a"), _int(1))) + STOP,
    P4 + _categorical() + STOP,
    P4 + _categorical(categories=NONE, ordered=NONE) + STOP,
    P4 + _scorer() + STOP,
    P4 + _manager() + STOP,
    P4 + _block(locs=_int(0), ndim=_int(1)) + STOP,
    _dabl_pickle(),
])
def test_library_forms_are_clean(data):
    risk, reasons = _risk(data)
    assert risk == "clean", reasons


# --- every other use stays flagged: a marker abusing each entry -------------------------------

@pytest.mark.parametrize("data", [
    # the classes called: their constructors would run on file-chosen arguments
    P4 + call(g(*DF), s(MARKER_CMD)) + STOP,
    P4 + call(g(*SERIES), s(MARKER_CMD)) + STOP,
    P4 + call(g(*SBM), s(MARKER_CMD)) + STOP,
    P4 + call(g(*CAT), s(MARKER_CMD)) + STOP,
    P4 + call(g(*SCORER), g(*APS), _int(1), EMPTY_DICT) + STOP,
    P4 + call(g(*SIMPLE), s(MARKER_CMD)) + STOP,
    P4 + call(g(*EASY), s(MARKER_CMD)) + STOP,
    # the score function called, or handed to something that may call it
    P4 + call(g(*APS), s(MARKER_CMD), s(MARKER_CMD)) + STOP,
    P4 + call(g("collections", "defaultdict"), g(*APS)) + STOP,
    P4 + _estimator(SIMPLE, s("scoring_") + g(*APS)) + STOP,
    # a rebuilt instance called (its __call__ would run)
    P4 + call(g(*SCORER) + b")" + NEWOBJ, s(MARKER_CMD)) + STOP,
    # NDFrame.__setstate__ sets every key with object.__setattr__: only pandas' own keys
    P4 + _frame(None, s("index") + s(MARKER_CMD)) + STOP,
    P4 + _frame(None, s("_item_cache") + EMPTY_DICT) + STOP,
    P4 + _frame(flags=_flags(s("x") + s(MARKER_CMD))) + STOP,  # Flags(self, **_flags)
    P4 + _frame(mgr=_single_manager()) + STOP,  # a DataFrame holds a BlockManager
    P4 + _frame(mgr=_estimator(EASY)) + STOP,
    P4 + _series(mgr=_manager()) + STOP,
    P4 + _series(name=_frame()) + STOP,
    P4 + g(*DF) + b")" + NEWOBJ + tup(_manager()) + BUILD + STOP,  # not a dict state
    # managers and blocks only in pandas' form
    P4 + _single_manager(_state(s("0.14.1") + EMPTY_DICT)) + STOP,
    P4 + _single_manager(tup(_list(), _list(), _list(), _state(s("0.14.1") + _state(s("axes") + _list())))) + STOP,
    P4 + _single_manager(_manager_state(values=_estimator(EASY))) + STOP,
    P4 + _manager(blocks=tup(_estimator(EASY))) + STOP,
    P4 + _manager(blocks=_list(_block())) + STOP,
    P4 + _manager(axes=_list(_index())) + STOP,
    P4 + _manager(axes=tup(_index(), _index())) + STOP,
    P4 + _block(values=s(MARKER_CMD)) + STOP,
    P4 + _block(values=_frame()) + STOP,
    P4 + _block(locs=s(MARKER_CMD)) + STOP,
    P4 + _block(ndim=_int(3)) + STOP,
    P4 + call(g(*UNPICKLE_BLOCK), _array(), _slice()) + STOP,
    # CategoricalDtype and the scorer with states their libraries never write
    P4 + _categorical(categories=s(MARKER_CMD)) + STOP,
    P4 + _categorical(ordered=s(MARKER_CMD)) + STOP,
    P4 + g(*CAT) + b")" + NEWOBJ + _state(s("_categories") + _index()) + BUILD + STOP,
    P4 + _scorer(g("sklearn.metrics._ranking", "roc_auc_score")) + STOP,
    P4 + _scorer(None, s("_response_method") + s("predict")) + STOP,
    P4 + g(*SCORER) + b")" + NEWOBJ + _state(s("_score_func") + g(*APS), s("_sign") + s(MARKER_CMD)) + BUILD + STOP,
    P4 + g(*SCORER) + b")" + NEWOBJ + _state(s("_score_func") + g(*APS), s("_kwargs") + _state(
        s("k") + _frame())) + BUILD + STOP,
    # a slot state makes pickle call setattr per item
    P4 + g(*EASY) + b")" + NEWOBJ + tup(NONE, _state(s("x") + s(MARKER_CMD))) + BUILD + STOP,
])
def test_misuse_of_reviewed_pairs_stays_flagged(data):
    risk, reasons = _risk(data)
    assert risk != "clean", reasons


@pytest.mark.parametrize("data", [
    P4 + _frame(None, s("attrs") + _state(s("x") + call(g(*SYSTEM), s(MARKER_CMD)))) + STOP,
    P4 + _frame(mgr=call(g(*SYSTEM), s(MARKER_CMD))) + STOP,
    P4 + _series(name=call(g(*SYSTEM), s(MARKER_CMD))) + STOP,
    P4 + _single_manager(_manager_state(values=call(g(*SYSTEM), s(MARKER_CMD)))) + STOP,
    P4 + _block(values=call(g(*SYSTEM), s(MARKER_CMD))) + STOP,
    P4 + _manager(blocks=tup(call(g(*SYSTEM), s(MARKER_CMD)))) + STOP,
    P4 + _categorical(categories=call(g(*SYSTEM), s(MARKER_CMD))) + STOP,
    P4 + _scorer(g(*SYSTEM)) + STOP,
    P4 + _scorer(g("builtins", "eval")) + STOP,
    P4 + _estimator(SIMPLE, s("est_") + call(g(*SYSTEM), s(MARKER_CMD))) + STOP,
])
def test_a_sink_reached_through_a_reviewed_pair_is_malicious(data):
    risk, reasons = _risk(data)
    assert risk == "malicious", reasons


def test_marker_scorer_is_not_clean_end_to_end(tmp_path):
    path = tmp_path / "clf.pkl"
    path.write_bytes(P4 + _estimator(SIMPLE, s("scoring_") + _scorer(g(*SYSTEM))) + STOP)
    assert scan(str(path)).verdict is Verdict.MALICIOUS


@pytest.mark.wasi
def test_emulation_flags_a_called_score_function(tmp_path):
    """The score function is on the allowlist only to be stored: the guest reports a call."""
    path = tmp_path / "model.pkl"
    stored = g("sklearn.linear_model._logistic", "LogisticRegression") + b")" + NEWOBJ + _state(
        s("__setstate__") + g(*APS)) + BUILD + s("argument") + BUILD
    path.write_bytes(P4 + stored + STOP)
    report = scan(str(path))
    assert any(r.startswith("[emulation]") and "average_precision_score" in r for r in report.reasons), report.reasons
