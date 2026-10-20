"""0.7.0 Part 3: profiles for well-known files. A profile only accepts its globals inside
the structure its producer writes; a file with the name but not the shape is RISKY, and
nothing a profile does lowers other evidence."""
from __future__ import annotations

import io
import zipfile

import pytest

from safeloadai import profiles
from safeloadai.pipeline import scan
from safeloadai.report import Verdict
from safeloadai.static import analyze_file
from safeloadai.static.pickle_static import parse_pickle

P2, STOP = b"\x80\x02", b"."


def g(module: str, name: str) -> bytes:
    return b"c" + module.encode() + b"\n" + name.encode() + b"\n"


def u(text: str) -> bytes:
    raw = text.encode()
    return b"X" + len(raw).to_bytes(4, "little") + raw


def d(*items: bytes) -> bytes:
    return b"}(" + b"".join(items) + b"u"


def inst(pair, state: bytes) -> bytes:
    return g(*pair) + b")\x81" + state + b"b"


PS = ("accelerate.state", "PartialState")
AC = ("transformers.trainer_pt_utils", "AcceleratorConfig")
ARGS = ("transformers.training_args", "TrainingArguments")
DEVICE = g("torch", "device") + u("cpu") + b"\x85R"
DIST = g("accelerate.utils.dataclasses", "DistributedType") + u("NO") + b"\x85R"
PARTIAL = inst(PS, d(u("device"), DEVICE, u("distributed_type"), DIST, u("_cpu"), b"\x89"))
CONFIG = inst(AC, d(u("split_batches"), b"\x89", u("even_batches"), b"\x88"))
SINK = g("posix", "system") + u("echo MARKER") + b"\x85R"


def training_args(*extra: bytes, partial: bytes = PARTIAL, root=ARGS) -> bytes:
    return P2 + inst(root, d(u("output_dir"), u("out"), u("distributed_state"), partial,
                             u("accelerator_config"), CONFIG, *extra)) + STOP


def static(data: bytes, name: str = "training_args.bin") -> dict:
    return parse_pickle(data, name, torch=True, file_format="torch")


def cleared(report: dict) -> dict:
    return {c["item"]: c["mechanism"] for c in report["cleared"]}


def profile_reasons(report: dict) -> list[str]:
    return [r for r in report["reasons"] if "profile" in r]


# --- transformers Trainer: training_args.bin ------------------------------------------

def test_training_args_matches_and_is_clean():
    report = static(training_args())
    assert report["static_risk"] == "clean", report["reasons"]
    assert report["profile"] == "transformers-training-args"
    assert cleared(report) == {"accelerate.state.PartialState": "profile",
                               "transformers.trainer_pt_utils.AcceleratorConfig": "profile"}


def test_the_same_stream_under_another_name_gets_nothing():
    report = static(training_args(), "args.bin")
    assert report["profile"] is None and not cleared(report)
    assert "import outside the allowlist: accelerate.state.PartialState" in report["reasons"]


def test_name_match_is_exact_and_case_sensitive():
    for name in ("Training_Args.bin", "training_args.bin.pt", "my_training_args.bin"):
        assert static(training_args(), name)["profile"] is None, name


def test_a_sink_stays_malicious():
    report = static(training_args(u("report_to"), SINK))
    assert report["static_risk"] == "malicious"


def test_an_unknown_root_subclass_stays_unverifiable():
    report = static(training_args(root=("trl.trainer.sft_config", "SFTConfig")))
    assert report["profile"] == "transformers-training-args"
    assert "import outside the allowlist: trl.trainer.sft_config.SFTConfig" in report["reasons"]
    assert set(report["unverifiable"]) == {"import outside the allowlist: trl.trainer.sft_config.SFTConfig"}


def test_an_unknown_global_elsewhere_is_not_lowered():
    report = static(training_args(u("callback"), g("evil.mod", "Thing")))
    assert report["profile"] == "transformers-training-args"
    assert "import outside the allowlist: evil.mod.Thing" in report["reasons"]


@pytest.mark.parametrize("data, why", [
    # PartialState at a key the profile does not allow
    (P2 + inst(ARGS, d(u("other"), PARTIAL)) + STOP, "outside its allowed position"),
    # a second instance nested one level deeper
    (training_args(u("nested"), b"]" + PARTIAL + b"a"), "outside its allowed position"),
    # the same (memoised) instance at its position and once more elsewhere
    (training_args(u("again"), b"h\x07", partial=PARTIAL + b"q\x07"), "more than once"),
    # rebuilt by REDUCE with an argument instead of NEWOBJ ()
    (training_args(partial=g(*PS) + u("x") + b"\x85R"), "not rebuilt from a dict state"),
    # BUILD with a (state, slotstate) tuple
    (training_args(partial=g(*PS) + b")\x81" + b"N" + d(u("k"), u("v")) + b"\x86b"), "not rebuilt from a dict state"),
    # the class itself stored as a value
    (training_args(partial=g(*PS)), "appears as a value"),
    # the root is a plain dict, not a TrainingArguments instance
    (P2 + d(u("distributed_state"), PARTIAL) + STOP, "the root is not an object"),
])
def test_structure_mismatch_is_risky_and_nothing_is_accepted(data, why):
    report = static(data)
    assert report["profile"] is None
    # (a class stored as a value may still be cleared as referenced-only by Part 1)
    assert "profile" not in cleared(report).values()
    reasons = profile_reasons(report)
    assert reasons and why in reasons[0], report["reasons"]
    assert report["static_risk"] == "suspicious"
    assert reasons[0] not in report["unverifiable"]  # RISKY: no item-by-item override


def test_a_referenced_instance_later_passed_to_a_call_is_risky():
    # PartialState memoised at its position, then fetched and passed to torch.device(...),
    # whose result is discarded (POP), so the instance appears once in the tree
    partial = PARTIAL + b"q\x07"
    data = training_args(u("x"), u("y") + g("torch", "device") + b"h\x07\x85R0", partial=partial)
    reasons = profile_reasons(static(data))
    assert reasons and "passed to a call" in reasons[0]


def test_a_second_build_on_the_instance_is_risky():
    partial = PARTIAL + d(u("device"), u("cuda")) + b"b"
    reasons = profile_reasons(static(training_args(partial=partial)))
    assert reasons and "exactly one BUILD" in reasons[0]


def test_setitem_into_the_instance_is_risky():
    partial = PARTIAL + u("k") + u("v") + b"s"
    reasons = profile_reasons(static(training_args(partial=partial)))
    assert reasons and "receives setitem" in reasons[0]


def test_an_extra_construction_outside_the_tree_is_risky():
    data = P2 + g(*PS) + b")\x81" + b"0" + training_args()[2:]  # PartialState() built and POPped first
    reasons = profile_reasons(static(data))
    assert reasons and "constructed outside its allowed position" in reasons[0]


# --- Trainer state files -----------------------------------------------------------------

def test_optimizer_scheduler_and_rng_state_shapes():
    optimizer = P2 + d(u("state"), b"}", u("param_groups"), b"]") + STOP
    assert static(optimizer, "optimizer.pt")["profile"] == "transformers-optimizer"
    scheduler = P2 + d(u("last_epoch"), b"K\x05", u("base_lrs"), b"]") + STOP
    assert static(scheduler, "scheduler.pt")["profile"] == "transformers-scheduler"
    rng = P2 + d(u("python"), b")", u("numpy"), b")", u("cpu"), b"N", u("cuda"), b"N") + STOP
    assert static(rng, "rng_state_3.pth")["profile"] == "transformers-rng-state"
    for data, name in ((optimizer, "optimizer.pt"), (scheduler, "scheduler.pt"), (rng, "rng_state.pth")):
        assert static(data, name)["static_risk"] == "clean"


@pytest.mark.parametrize("name, data", [
    ("optimizer.pt", P2 + d(u("state"), b"}", u("param_groups"), b"]", u("payload"), b"N") + STOP),
    ("scheduler.pt", P2 + b"]" + STOP),
    ("rng_state.pth", P2 + d(u("python"), b")", u("numpy"), b")", u("cpu"), b"N", u("extra"), b"N") + STOP),
])
def test_trainer_state_file_with_the_wrong_shape_is_risky(name, data):
    report = static(data, name)
    assert report["profile"] is None and profile_reasons(report)
    assert report["static_risk"] == "suspicious"


# --- Ultralytics -------------------------------------------------------------------------

DETECT = ("ultralytics.nn.tasks", "DetectionModel")
MODEL = inst(DETECT, d(u("yaml"), b"}", u("training"), b"\x89"))


def ultra(*items: bytes) -> bytes:
    return P2 + d(u("epoch"), b"J\xff\xff\xff\xff", u("model"), MODEL, u("ema"), b"N",
                  u("date"), u("2026-01-01"), u("version"), u("8.4.182"), *items) + STOP


def test_ultralytics_checkpoint_matches():
    report = static(ultra(), "best.pt")
    assert report["profile"] == "ultralytics-checkpoint" and report["static_risk"] == "clean", report["reasons"]


def test_ultralytics_extra_payload_key_is_risky():
    report = static(ultra(u("payload"), u("echo")), "best.pt")
    reasons = profile_reasons(report)
    assert reasons and "'payload'" in reasons[0] and report["static_risk"] == "suspicious"


def test_ultralytics_model_outside_model_and_ema_is_risky():
    report = static(ultra(u("train_args"), b"]" + MODEL + b"a"), "best.pt")
    reasons = profile_reasons(report)
    assert reasons and "outside its allowed position" in reasons[0]


def test_ultralytics_payload_stays_malicious():
    assert static(ultra(u("train_args"), SINK), "best.pt")["static_risk"] == "malicious"


def test_training_args_with_only_weights_only_globals_is_not_engaged():
    # a plain dict of arguments saved under the name: torch's weights-only loader accepts
    # every import, so the profile has nothing to allow and judges nothing
    data = P2 + g("collections", "OrderedDict") + b")R" + d(u("output_dir"), u("out")) + b"b" + STOP
    report = static(data)
    assert report["profile"] is None and not profile_reasons(report)


def test_training_args_dict_holding_partial_state_is_still_risky():
    report = static(P2 + d(u("distributed_state"), PARTIAL) + STOP)
    assert report["profile"] is None
    assert profile_reasons(report) and report["static_risk"] == "suspicious"


def test_a_generic_name_without_the_producer_signature_is_not_engaged():
    data = P2 + d(u("weights"), b"]", u("payload"), u("x")) + STOP
    report = static(data, "best.pt")
    assert report["profile"] is None and not profile_reasons(report)


def test_registry_profiles_are_reviewed_data():
    names = [p.name for p in profiles.registry.PROFILES]
    assert len(names) == len(set(names))
    for p in profiles.registry.PROFILES:
        assert p.patterns and p.producer and p.source
        for pair in p.clears:
            assert p.is_placed(pair)


# --- through the archive reader and the pipeline --------------------------------------------

def torch_zip(data_pkl: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", data_pkl)
        zf.writestr("archive/version", b"3\n")
    return buf.getvalue()


def test_profile_is_looked_up_by_the_archive_name(tmp_path):
    path = tmp_path / "training_args.bin"
    path.write_bytes(torch_zip(training_args()))
    report = analyze_file(path)
    assert report["profile"] == "transformers-training-args" and report["static_risk"] == "clean"
    other = tmp_path / "data.pkl.bin"
    other.write_bytes(torch_zip(training_args()))
    assert analyze_file(other)["profile"] is None


def test_pipeline_records_the_profile_mechanism(tmp_path, fake_emulation):
    path = tmp_path / "training_args.bin"
    path.write_bytes(torch_zip(training_args()))
    report = scan(path)
    assert report.verdict is Verdict.CLEAN, report.reasons
    assert {c["mechanism"] for c in report.cleared} == {"profile"}


@pytest.mark.wasi
def test_wasi_scan_of_training_args_is_clean(tmp_path):
    path = tmp_path / "training_args.bin"
    path.write_bytes(torch_zip(training_args()))
    report = scan(path)
    assert report.verdict is Verdict.CLEAN, report.reasons


@pytest.mark.wasi
def test_wasi_scan_of_a_mismatched_training_args_is_risky(tmp_path):
    path = tmp_path / "training_args.bin"
    path.write_bytes(torch_zip(P2 + inst(ARGS, d(u("other"), PARTIAL)) + STOP))
    report = scan(path)
    assert report.verdict is Verdict.SUSPICIOUS and report.category == "RISKY", report.reasons
