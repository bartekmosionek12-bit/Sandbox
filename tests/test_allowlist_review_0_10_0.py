"""Allowlist growth from the 0.10.0 tune review (evaluation/results/source-review-0.10.0.md):
state-only classes of scikit-learn, LightGBM's wrappers and the training-argument dataclasses
of public fine-tuning libraries. Each passes only as NEWOBJ () + BUILD with a dict state;
calling it, giving NEWOBJ arguments or hiding a sink in the state stays flagged.

Nothing here is loaded: every stream is assembled opcode by opcode and only scanned.
"""
from __future__ import annotations

import pytest
from corpus.build_corpus import MARKER_CMD, call, g, s

from safeloadai import Verdict, scan
from safeloadai.static import allowlists
from safeloadai.static.pickle_static import parse_pickle

REVIEWED = [
    ("sklearn.ensemble._hist_gradient_boosting.gradient_boosting", "HistGradientBoostingRegressor"),
    ("sklearn.compose._column_transformer", "_RemainderColsList"),
    ("sklearn.utils._bunch", "Bunch"),
    ("llamafactory.hparams.training_args", "TrainingArguments"),
    ("FlagEmbedding.baai_general_embedding.finetune.arguments", "RetrieverTrainingArguments"),
    ("FlagEmbedding.finetune.embedder.encoder_only.m3.arguments", "EncoderOnlyEmbedderM3TrainingArguments"),
    ("swift.trainers.rlhf_arguments", "GRPOConfig"),
    ("axolotl.core.trainer_builder", "AxolotlTrainingArguments"),
    ("axolotl.core.training_args", "AxolotlTrainingArguments"),
    ("lightgbm.sklearn", "LGBMClassifier"),
    ("lightgbm.sklearn", "LGBMRegressor"),
]
P2, STOP, NEWOBJ, BUILD = b"\x80\x02", b".", b"\x81", b"b"
SYSTEM = ("posix", "system")


def _state(*pairs: bytes) -> bytes:
    return b"}(" + b"".join(pairs) + b"u"


def _rebuilt(pair, state: bytes | None = None, args: bytes = b")") -> bytes:
    return P2 + g(*pair) + args + NEWOBJ + (state or _state(s("output_dir") + s("out"), s("seed") + b"K\x2a")) \
        + BUILD + STOP


@pytest.mark.parametrize("pair", REVIEWED)
def test_reviewed_classes_are_state_only(pair):
    assert pair in allowlists.STATE_ONLY_CLASSES
    report = parse_pickle(_rebuilt(pair))
    assert report["static_risk"] == "clean", report["reasons"]


@pytest.mark.parametrize("pair", REVIEWED)
def test_calling_a_reviewed_class_stays_flagged(pair):
    assert parse_pickle(P2 + call(g(*pair), s("x")) + STOP)["static_risk"] != "clean"


@pytest.mark.parametrize("pair", REVIEWED)
def test_newobj_with_arguments_stays_flagged(pair):
    assert parse_pickle(_rebuilt(pair, args=b"(" + s("x") + b"t"))["static_risk"] != "clean"


@pytest.mark.parametrize("pair", REVIEWED)
def test_a_sink_in_the_state_is_malicious(pair):
    state = _state(s("output_dir") + call(g(*SYSTEM), s(MARKER_CMD)))
    assert parse_pickle(_rebuilt(pair, state))["static_risk"] == "malicious"


@pytest.mark.wasi
def test_a_sink_in_reviewed_training_arguments_is_malicious_end_to_end(tmp_path):
    path = tmp_path / "training_args.bin"
    state = _state(s("output_dir") + call(g(*SYSTEM), s(MARKER_CMD)))
    path.write_bytes(_rebuilt(("llamafactory.hparams.training_args", "TrainingArguments"), state))
    assert scan(str(path)).verdict is Verdict.MALICIOUS


@pytest.mark.parametrize("pair", [("axolotl.utils.dict", "DictDefault"),  # addict NEWOBJ with items: not reviewed
                                  ("axolotl.utils.trainer", "AxolotlTrainingArguments"),  # no source on PyPI
                                  ("sklearn.preprocessing._function_transformer", "FunctionTransformer")])  # A1
def test_near_misses_are_not_on_the_list(pair):
    assert pair not in allowlists.STATE_ONLY_CLASSES and pair not in allowlists.PICKLE_GLOBALS
    assert parse_pickle(_rebuilt(pair))["static_risk"] == "suspicious"


NEW_INDEX = ("pandas.core.indexes.base", "_new_Index")
RANGE_INDEXES = [("pandas.core.indexes.range", "RangeIndex"), ("pandas", "RangeIndex")]


def _range(cls, *items: bytes) -> bytes:
    return P2 + call(g(*NEW_INDEX), g(*cls), _state(*items)) + STOP


INTS = (s("name") + b"N", s("start") + b"K\x00", s("stop") + b"K\x0a", s("step") + b"K\x01")


@pytest.mark.parametrize("cls", RANGE_INDEXES)
def test_range_index_as_pandas_writes_it_is_clean(cls):
    report = parse_pickle(_range(cls, *INTS))
    assert report["static_risk"] == "clean", report["reasons"]


@pytest.mark.parametrize("cls", RANGE_INDEXES)
@pytest.mark.parametrize("items", [
    INTS[:3],  # step missing
    (INTS[0], s("start") + s("0"), INTS[2], INTS[3]),  # start is not an int
    (INTS[0], s("start") + b"\x88", INTS[2], INTS[3]),  # bool is not an int here
    INTS + (s("data") + b"N",),  # a key RangeIndex never writes
    (INTS[0], s("start") + call(g(*SYSTEM), s(MARKER_CMD)), INTS[2], INTS[3]),
])
def test_range_index_misuse_stays_flagged(cls, items):
    assert parse_pickle(_range(cls, *items))["static_risk"] != "clean"


@pytest.mark.parametrize("cls", RANGE_INDEXES)
def test_a_sink_in_a_range_index_is_malicious(cls):
    items = (INTS[0], s("start") + call(g(*SYSTEM), s(MARKER_CMD)), INTS[2], INTS[3])
    assert parse_pickle(_range(cls, *items))["static_risk"] == "malicious"


def _keras_findings(node: dict) -> list:
    from safeloadai.static.keras_static import _empty_report, walk_config
    report = _empty_report("m.keras")
    walk_config({"class_name": "Sequential", "module": "keras",
                 "config": {"layers": [], "metrics": [node]}}, report)
    return report["unknown_imports"] + report["suspicious_imports"] + report["flagged_opcodes"]


def _metric(name: str, config: dict, module: str = "keras.metrics") -> dict:
    return {"class_name": name, "module": module, "config": config, "registered_name": None}


@pytest.mark.parametrize("node", [
    _metric("TopKCategoricalAccuracy", {"name": "top_k_categorical_accuracy", "dtype": "float32", "k": 5}),
    _metric("SparseTopKCategoricalAccuracy", {"name": "top5", "dtype": "float32", "k": 5, "from_sorted_ids": True}),
])
def test_keras_top_k_metrics_are_known(node):
    assert not _keras_findings(node)


@pytest.mark.parametrize("node", [
    _metric("TopKCategoricalAccuracy", {"k": {"class_name": "function", "module": "posix", "config": "system"}}),
    _metric("SparseTopKCategoricalAccuracy", {"k": 5}, module="safeloadai_marker_pkg"),
    _metric("TopKCategoricalAccuracyX", {"k": 5}),
])
def test_keras_top_k_neighbours_stay_flagged(node):
    assert _keras_findings(node)
