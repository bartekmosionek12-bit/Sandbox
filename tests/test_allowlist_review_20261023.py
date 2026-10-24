"""0.9.0 tune / tune-2 review (evaluation/results/source-review-4-20261023.md): trl configs,
sentence-transformers training arguments and samplers, the DeepSpeed configs a training_args.bin
holds, three reviewed hooks (IsotonicRegression, AAttn, DeepSpeedPlugin) and five enums.
Every entry passes only in the form its library writes; each has a test that must stay flagged.

Nothing here is loaded: every stream is assembled opcode by opcode and only scanned.
"""
from __future__ import annotations

import pytest
from corpus.build_corpus import MARKER_CMD, call, g, s

from safeloadai.static import allowlists, upstream
from safeloadai.static.lookalike import GENUINE
from safeloadai.static.pickle_static import parse_pickle
from safeloadai.static.sources import REVIEWED_HOOKS

P2, STOP = b"\x80\x02", b"."
EMPTY_TUPLE, EMPTY_DICT, NEWOBJ, BUILD = b")", b"}", b"\x81", b"b"

POLICIES = [
    ("trl.trainer.sft_config", "SFTConfig"),
    ("trl.trainer.dpo_config", "DPOConfig"),
    ("sentence_transformers.sentence_transformer.training_args", "SentenceTransformerTrainingArguments"),
    ("sentence_transformers.base.sampler", "NoDuplicatesBatchSampler"),
    ("transformers.integrations.deepspeed", "HfTrainerDeepSpeedConfig"),
    ("transformers.integrations.deepspeed", "HfDeepSpeedConfig"),
    ("accelerate.utils.dataclasses", "DeepSpeedPlugin"),
    ("sklearn.isotonic", "IsotonicRegression"),
    ("ultralytics.nn.modules.block", "AAttn"),
]
ENUMS = [
    ("sentence_transformers.base.sampler", "BatchSamplers"),
    ("sentence_transformers.base.sampler", "MultiDatasetBatchSamplers"),
    ("sentence_transformers.training_args", "BatchSamplers"),
    ("sentence_transformers.training_args", "MultiDatasetBatchSamplers"),
    ("trl.trainer.dpo_config", "FDivergenceType"),
]
PAYLOAD = call(g("posix", "system"), s(MARKER_CMD))


def _risk(data: bytes) -> tuple[str, list[str]]:
    report = parse_pickle(data)
    return report["static_risk"], report["reasons"]


def _rebuilt(pair, value: bytes = b"K\x05") -> bytes:
    return P2 + g(*pair) + EMPTY_TUPLE + NEWOBJ + EMPTY_DICT + b"(" + s("x") + value + b"u" + BUILD + STOP


@pytest.mark.parametrize("pair", POLICIES)
def test_policy_rebuilt_from_state_is_clean(pair):
    assert upstream.state_only(pair), pair
    risk, reasons = _risk(_rebuilt(pair))
    assert risk == "clean", reasons


@pytest.mark.parametrize("pair", POLICIES)
def test_policy_called_is_refused(pair):
    assert _risk(P2 + call(g(*pair), s(MARKER_CMD)) + STOP)[0] != "clean"
    assert _risk(P2 + g(*pair) + b"(" + s(MARKER_CMD) + b"t" + NEWOBJ + STOP)[0] != "clean"


@pytest.mark.parametrize("pair", POLICIES)
def test_policy_does_not_rescue_a_payload_in_its_state(pair):
    assert _risk(_rebuilt(pair, PAYLOAD))[0] == "malicious"


@pytest.mark.parametrize("pair", ENUMS)
def test_enum_member_lookup_is_clean(pair):
    assert pair in allowlists.ENUM_CLASSES
    risk, reasons = _risk(P2 + call(g(*pair), s("no_duplicates")) + STOP)
    assert risk == "clean", reasons


@pytest.mark.parametrize("pair", ENUMS)
def test_enum_used_otherwise_is_refused(pair):
    assert _risk(P2 + call(g(*pair), s("a"), s("b")) + STOP)[0] != "clean"
    assert _risk(P2 + call(g(*pair), PAYLOAD) + STOP)[0] == "malicious"
    assert _risk(_rebuilt(pair))[0] != "clean"


def test_reviewed_hooks_are_pinned_to_their_source():
    for key in [("sklearn.isotonic", "IsotonicRegression", "__setstate__"),
                ("ultralytics.nn.modules.block", "AAttn", "__setstate__"),
                ("accelerate.utils.dataclasses", "DeepSpeedPlugin", "selected.setter")]:
        digest, note = REVIEWED_HOOKS[key]
        assert len(digest) == 64 and note


def test_neighbours_stay_out():
    for pair in [("trl.trainer.sft_trainer", "SFTTrainer"), ("trl.trainer", "SFTConfig"),
                 ("sentence_transformers", "SentenceTransformer"), ("transformers.integrations", "HfDeepSpeedConfig"),
                 ("sklearn.isotonic", "isotonic_regression"), ("lightgbm.basic", "Booster")]:
        assert not upstream.state_only(pair) and pair not in allowlists.PICKLE_GLOBALS, pair


def test_sentence_transformers_is_no_lookalike_but_imitations_are():
    from safeloadai.static.lookalike import imitates

    assert "sentence_transformers" in GENUINE
    assert imitates("sentence_transformers") is None
    assert imitates("transformers_evil") is not None
