"""0.11.0 tune review (evaluation/results/source-review-0.11.0.md): Keras 3 operations and data
markers in functional graphs, TextVectorization and RandomBrightness, an HDF5 model named
``.keras`` (DECISIONS.md N6) and scikit-learn's Cython SGD losses. Each accepted form has a
neighbour that stays flagged.

Nothing here is loaded: pickles are assembled opcode by opcode, Keras configs are dicts and
the HDF5 files are the committed fixtures.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from corpus.build_corpus import MARKER_CMD, _h5_with_userblock, call, g, s

from safeloadai import Verdict, scan
from safeloadai.static import allowlists, analyze_bytes
from safeloadai.static.keras_static import _empty_report, walk_config
from safeloadai.static.pickle_static import parse_pickle

H5 = Path(__file__).with_name("fixtures") / "h5"
P2, STOP = b"\x80\x02", b"."


def _findings(*layers: dict) -> list:
    report = _empty_report("m.keras")
    walk_config({"class_name": "Functional", "module": "keras.src.models.functional",
                 "config": {"layers": list(layers)}}, report)
    return report["unknown_imports"] + report["suspicious_imports"] + report["flagged_opcodes"] + report["reasons"]


def _op(module: str, name: str, config: dict | None = None, args: list | None = None) -> dict:
    return {"module": module, "class_name": name, "config": config or {"name": name.lower()},
            "registered_name": None, "name": name.lower(),
            "inbound_nodes": [{"args": args or [], "kwargs": {}}]}


def _layer(name: str, config: dict) -> dict:
    return {"module": "keras.layers", "class_name": name, "config": config, "registered_name": None}


ELLIPSIS = {"class_name": "__ellipsis__", "config": {}}


def _slice(start, stop, step=None) -> dict:
    return {"class_name": "__slice__", "config": {"start": start, "stop": stop, "step": step}}


def _tensor(value, dtype="float32") -> dict:
    return {"class_name": "__tensor__", "config": {"value": value, "dtype": dtype}}


REVIEWED_OPS = [("keras.src.ops.numpy", n) for n in ("NotEqual", "LogicalOr", "Any", "Concatenate", "Stack",
                                                     "GetItem")] + [
    ("keras.src.ops.core", "Cast"), ("keras.src.ops.nn", "LeakyRelu"), ("keras.src.ops.nn", "Gelu")]


@pytest.mark.parametrize("pair", REVIEWED_OPS)
def test_reviewed_keras_operations_are_known(pair):
    assert pair in allowlists.KERAS_CLASS_PAIRS
    assert not _findings(_op(*pair))


@pytest.mark.parametrize("pair", [("keras.src.ops.numpy", "Vectorize"),  # takes a Python function
                                  ("keras.src.ops.core", "Map"),  # calls a function
                                  ("keras.src.ops.numpy", "GetItemX"),
                                  ("safeloadai_marker_pkg.ops", "GetItem")])
def test_other_operations_stay_flagged(pair):
    assert _findings(_op(*pair))


def test_operation_config_is_still_walked():
    sink = {"class_name": "function", "module": "posix", "config": "system"}
    assert _findings(_op("keras.src.ops.core", "Cast", {"dtype": sink}))


@pytest.mark.parametrize("args", [
    [{"class_name": "__keras_tensor__", "config": {"shape": [None, 3], "dtype": "float32",
                                                   "keras_history": ["x", 0, 0]}}, [ELLIPSIS, 0]],
    [None, [_slice(0, 4), _slice(None, None, 2)]],
    [None, _tensor([[1.0, 2.0], [3.0, 4.0]])],
    [None, _tensor(3, "int64")],
    [None, _tensor([True, False], "bool")],
])
def test_data_markers_as_keras_writes_them_are_accepted(args):
    assert not _findings(_op("keras.src.ops.numpy", "GetItem", args=args))


@pytest.mark.parametrize("marker", [
    {"class_name": "__ellipsis__", "config": {"x": 1}},
    {"class_name": "__ellipsis__", "config": {}, "module": "builtins"},
    _slice("a", 2),
    _slice(True, 2),
    {"class_name": "__slice__", "config": {"start": 0, "stop": 1, "step": None, "extra": 0}},
    _tensor(["a", "b"], "string"),
    _tensor([1.0], "object"),
    _tensor([1.0], {"dtype": "float32"}),  # unhashable: refused, never a crash
    _tensor([{"class_name": "function", "module": "posix", "config": "system"}]),
    {"class_name": "__tensor__", "config": {"value": [1.0], "dtype": "float32", "x": 0}},
    {"class_name": "__numpy__", "config": {"value": [1.0], "dtype": "float32"}},  # not reviewed
    {"class_name": "__lambda__", "config": {"value": "AAAA"}},
])
def test_other_marker_forms_stay_flagged(marker):
    assert _findings(_op("keras.src.ops.numpy", "GetItem", args=[None, marker]))


def test_a_sink_inside_a_marker_is_malicious():
    report = _empty_report("m.keras")
    sink = {"class_name": "function", "module": "posix", "config": "system"}
    walk_config({"class_name": "Functional", "module": "keras.src.models.functional",
                 "config": {"layers": [_op("keras.src.ops.numpy", "GetItem", args=[None, _slice(0, sink)])]}},
                report)
    assert report["suspicious_imports"]


TV_OK = {"name": "tv", "max_tokens": 20000, "standardize": "lower_and_strip_punctuation", "split": "whitespace",
         "ngrams": None, "output_mode": "int", "output_sequence_length": 200, "pad_to_max_tokens": False,
         "sparse": False, "ragged": False, "vocabulary": ["", "[UNK]", "the"], "idf_weights": None,
         "encoding": "utf-8", "vocabulary_size": 3}


@pytest.mark.parametrize("config", [TV_OK, dict(TV_OK, vocabulary=None, standardize=None, split="character")])
def test_text_vectorization_with_inline_vocabulary_is_known(config):
    assert not _findings(_layer("TextVectorization", config))


@pytest.mark.parametrize("change", [
    {"vocabulary": "/etc/hostname"},  # a file path the layer reads (unchecked before keras 3.9)
    {"vocabulary": "gs://bucket/vocab.txt"},
    {"standardize": {"class_name": "function", "module": "mypkg", "config": "clean"}},
    {"split": "regex"},
    {"idf_weights": "/tmp/w.npy"},
    {"encoding": "latin-1"},
])
def test_text_vectorization_otherwise_stays_flagged(change):
    assert _findings(_layer("TextVectorization", dict(TV_OK, **change)))


def test_random_brightness_and_cosine_restarts_are_known():
    assert not _findings(_layer("RandomBrightness", {"factor": 0.2, "value_range": [0, 255], "seed": None}))
    schedule = {"module": "keras.optimizers.schedules", "class_name": "CosineDecayRestarts", "registered_name": None,
                "config": {"initial_learning_rate": 0.001, "first_decay_steps": 1000, "t_mul": 2.0, "m_mul": 1.0,
                           "alpha": 0.0, "name": "SGDRDecay"}}
    assert not _findings(schedule)


# --- an HDF5 model named .keras (N6) ---------------------------------------------------

@pytest.mark.wasi
def test_hdf5_model_named_keras_is_judged_as_hdf5(tmp_path):
    path = tmp_path / "model.keras"
    path.write_bytes((H5 / "k2_sequential.h5").read_bytes())
    report = scan(path)
    assert report.verdict is Verdict.CLEAN, report.reasons
    static = analyze_bytes(path.read_bytes(), "model.keras")
    assert any("tf.keras reads a .keras file that is not a ZIP archive as HDF5" in n for n in static["notes"])


@pytest.mark.wasi
@pytest.mark.parametrize("fixture, verdict", [("k2_lambda_marker.h5", Verdict.MALICIOUS),
                                              ("k2_custom_objects.h5", Verdict.SUSPICIOUS)])
def test_hdf5_named_keras_keeps_every_hdf5_finding(tmp_path, fixture, verdict):
    path = tmp_path / "model.keras"
    path.write_bytes((H5 / fixture).read_bytes())
    assert scan(path).verdict is verdict


@pytest.mark.wasi
def test_hdf5_named_keras_with_a_second_reading_keeps_the_mismatch(tmp_path):
    # a user block holding a pickle: h5py reads the superblock at 512, pickle.load the payload
    path = tmp_path / "model.keras"
    path.write_bytes(_h5_with_userblock(P2 + call(g("posix", "system"), s(MARKER_CMD)) + STOP))
    report = scan(path)
    assert report.verdict is Verdict.MALICIOUS
    benign = tmp_path / "benign.keras"
    benign.write_bytes(_h5_with_userblock(P2 + b"}" + STOP))
    report = scan(benign)
    assert report.verdict is not Verdict.CLEAN
    assert any("does not match its content" in r for r in report.reasons)


@pytest.mark.wasi
def test_other_extension_mismatches_stay_reasons(tmp_path):
    path = tmp_path / "model.pkl"
    path.write_bytes((H5 / "k2_sequential.h5").read_bytes())
    report = scan(path)
    assert report.verdict is not Verdict.CLEAN
    assert any("does not match its content" in r for r in report.reasons)


# --- scikit-learn's Cython SGD losses --------------------------------------------------

SGD = "sklearn.linear_model._sgd_fast"


@pytest.mark.parametrize("name, args", [("Log", b")"), ("ModifiedHuber", b")"), ("SquaredLoss", b")"),
                                        ("SquaredHinge", b"G?\xf0\x00\x00\x00\x00\x00\x00\x85"),
                                        ("Huber", b"G?\xf0\x00\x00\x00\x00\x00\x00\x85"),
                                        ("EpsilonInsensitive", b"G?\xb9\x99\x99\x99\x99\x99\x9a\x85"),
                                        ("SquaredEpsilonInsensitive", b"G?\xb9\x99\x99\x99\x99\x99\x9a\x85")])
def test_sgd_losses_as_their_reduce_writes_them_are_clean(name, args):
    assert (SGD, name) in allowlists.PICKLE_GLOBALS
    report = parse_pickle(P2 + g(SGD, name) + args + b"R" + STOP)
    assert report["static_risk"] == "clean", report["reasons"]


def test_a_sink_as_an_sgd_loss_argument_is_malicious():
    payload = P2 + g(SGD, "Huber") + call(g("posix", "system"), s(MARKER_CMD)) + b"\x85R" + STOP
    assert parse_pickle(payload)["static_risk"] == "malicious"


@pytest.mark.parametrize("name", ["LossFunction", "plain_sgd", "_plain_sgd", "Hinge2"])
def test_other_sgd_fast_names_stay_flagged(name):
    assert parse_pickle(P2 + g(SGD, name) + b")R" + STOP)["static_risk"] != "clean"


# --- pandas 3 names and MultiIndex (pandas 1.4.4, 2.2.3 and 3.0.6 indexes/base.py, multi.py) --

from corpus.build_corpus import P4, tup  # noqa: E402
from test_allowlist_review_20261022 import (  # noqa: E402
    BM,
    NEW_INDEX,
    NONE,
    _array,
    _block,
    _index,
    _int,
    _list,
    _state,
)

PD_INDEX = ("pandas", "Index")
MULTI = [("pandas", "MultiIndex"), ("pandas.core.indexes.multi", "MultiIndex")]


def _pd_index() -> bytes:
    return call(g(*NEW_INDEX), g(*PD_INDEX), _state(s("data") + _array(), s("name") + NONE))


def _multi(pair, levels=None, codes=None, sortorder=NONE, names=None, extra=b"") -> bytes:
    d = _state(s("levels") + (levels or _list(_index(), _pd_index())),
               s("codes") + (codes or _list(_array(), _array())), s("sortorder") + sortorder,
               s("names") + (names or _list(s("a"), NONE)), extra)
    return call(g(*NEW_INDEX), g(*pair), d)


@pytest.mark.parametrize("data", [_pd_index()] + [_multi(p) for p in MULTI] + [_multi(MULTI[0], sortorder=_int(0))])
def test_pandas_index_forms_are_clean(data):
    report = parse_pickle(P4 + data + STOP)
    assert report["static_risk"] == "clean", report["reasons"]


def test_an_empty_frame_manager_is_clean():
    report = parse_pickle(P4 + call(g(*BM), tup(), _list(_index(), _index())) + STOP)
    assert report["static_risk"] == "clean", report["reasons"]


SINK = call(g("posix", "system"), s(MARKER_CMD))


@pytest.mark.parametrize("data", [
    _multi(MULTI[0], levels=_list(_array())),  # levels that are not Index objects
    _multi(MULTI[0], codes=_list(_array())),  # fewer codes than levels
    _multi(MULTI[0], sortorder=s("x")),  # int(sortorder) of anything else
    _multi(MULTI[0], names=_list(_list())),
    _multi(MULTI[0], extra=s("dtype") + s("object")),
    _multi(MULTI[0], levels=b"N"),
    call(g(*NEW_INDEX), g(*PD_INDEX), _state(s("data") + _array(), s("name") + NONE, s("copy") + b"\x88")),
    call(g(*PD_INDEX), _array()),  # the class called directly
    call(g(*MULTI[0]), _list(_index()), _list(_array())),
    call(g(*BM), tup(_block()), _list(_index())),  # one axis
])
def test_other_pandas_index_forms_stay_flagged(data):
    assert parse_pickle(P4 + data + STOP)["static_risk"] != "clean"


def test_a_sink_inside_a_multi_index_is_malicious():
    assert parse_pickle(P4 + _multi(MULTI[0], names=_list(SINK)) + STOP)["static_risk"] == "malicious"
