"""Monotone verdict: no layer can lower another (judge escalate-only, evidence always counts)."""
import pytest
from conftest import sandbox_report

from safeloadai import behaviour, verdict
from safeloadai.report import LayerResult, Verdict, combine
from safeloadai.sandbox.host import GuestRun

CLEAN_PARSER = {"static_risk": "clean"}
JUDGE_SAFE = {"available": True, "verdict": "safe", "injection_attempt_detected": False}
NO_JUDGE = {"available": False, "verdict": "unknown"}
EXEC_EVENT = [{"type": "os_system", "detail": "echo MARKER"}]


def test_combine_is_the_worst_layer():
    layers = [LayerResult("a", Verdict.CLEAN), LayerResult("b", Verdict.SUSPICIOUS), LayerResult("c", Verdict.CLEAN)]
    assert combine(layers)[0] is Verdict.SUSPICIOUS


def test_judge_cannot_clear_observed_execution():
    assert verdict.final_verdict(CLEAN_PARSER, JUDGE_SAFE, sandbox_report(events=EXEC_EVENT))[0] is Verdict.MALICIOUS


def test_without_judge_sandbox_events_still_count():
    assert verdict.final_verdict(CLEAN_PARSER, NO_JUDGE, sandbox_report(events=EXEC_EVENT))[0] is Verdict.MALICIOUS


@pytest.mark.parametrize("judge_verdict", ["safe", "suspicious", "malicious", "unknown"])
@pytest.mark.parametrize("static", ["clean", "suspicious", "malicious"])
def test_judge_never_lowers(static, judge_verdict):
    without, _ = verdict.final_verdict({"static_risk": static}, None, None)
    with_judge, _ = verdict.final_verdict({"static_risk": static}, dict(JUDGE_SAFE, verdict=judge_verdict), None)
    assert with_judge.rank >= without.rank


def test_injection_attempt_raises_verdict():
    judge = dict(JUDGE_SAFE, injection_attempt_detected=True)
    assert verdict.final_verdict(CLEAN_PARSER, judge, None)[0] is Verdict.SUSPICIOUS


def test_judge_can_escalate():
    assert verdict.final_verdict(CLEAN_PARSER, dict(JUDGE_SAFE, verdict="malicious"), None)[0] is Verdict.MALICIOUS


@pytest.mark.parametrize("overrides", [
    {"detonated": False, "skipped_reason": "no Docker"},
    {"timed_out": True},
    {"load_succeeded": False, "error": "ModuleNotFoundError"},
])
def test_incomplete_deep_detonation_is_suspicious(overrides):
    assert verdict.final_verdict(CLEAN_PARSER, None, sandbox_report(**overrides))[0] is Verdict.SUSPICIOUS


def test_unknown_static_risk_is_suspicious():
    assert verdict.final_verdict({"static_risk": "unknown"})[0] is Verdict.SUSPICIOUS


def test_lambda_only_static_defers_to_emulation():
    report = {"file_format": "keras", "static_risk": "suspicious", "error": None,
              "lambdas": [{"path": "layers[1]", "has_code": True, "sink_tokens": []}],
              "flagged_opcodes": [{"name": "Lambda"}], "suspicious_imports": [], "unknown_imports": [],
              "reasons": ["layers[1]: Lambda layer with marshalled bytecode"]}
    assert verdict.static_layer(report, defer_lambdas=True).verdict is Verdict.CLEAN
    assert verdict.static_layer(report).verdict is Verdict.SUSPICIOUS
    report["unknown_imports"] = [{"module": "x", "symbol": "y"}]
    assert verdict.static_layer(report, defer_lambdas=True).verdict is Verdict.SUSPICIOUS


# --- behaviour classification of emulation records -----------------------------

def _run(*events, **kw):
    base = {"status": "ok", "completed": True}
    base.update(kw)
    return GuestRun(events=[{"kind": "start", "seq": 0}, *events], **base)


def _call(target, *args):
    return {"kind": "call", "target": target, "args": list(args), "kwargs": {}}


def test_tampered_channel_is_malicious():
    assert behaviour.classify(_run(tampered=True)).verdict is Verdict.MALICIOUS


@pytest.mark.parametrize("status", ["timeout", "fuel_exhausted", "exit", "trap"])
def test_incomplete_emulation_is_suspicious(status):
    assert behaviour.classify(_run(status=status, completed=False)).verdict is Verdict.SUSPICIOUS


def test_unavailable_emulation_is_suspicious():
    layer = behaviour.classify(GuestRun(status="unavailable", problems=["no runtime"]))
    assert layer.verdict is Verdict.SUSPICIOUS and not layer.ran


def test_any_anomaly_is_suspicious():
    assert behaviour.classify(_run({"kind": "anomaly", "what": "marshal error"})).verdict is Verdict.SUSPICIOUS


@pytest.mark.parametrize("target", ["posix.system", "os.popen().read", "subprocess.Popen", "socket.socket",
                                    "builtins.exec", "tf.io.write_file", "tf.py_function", "ctypes.CDLL",
                                    "importlib.import_module", "shutil.rmtree"])
def test_sinks_are_malicious(target):
    assert behaviour.classify(_run(_call(target))).verdict is Verdict.MALICIOUS


def test_open_for_write_is_malicious_and_read_is_suspicious():
    assert behaviour.classify(_run(_call("builtins.open", "'/tmp/safeloadai_marker'", "'w'"))).verdict \
        is Verdict.MALICIOUS
    assert behaviour.classify(_run(_call("builtins.open", "'/etc/hostname'", "'r'"))).verdict is Verdict.SUSPICIOUS


@pytest.mark.parametrize("target", ["os.environ.get", "builtins.getattr", "mystery.helper", "sys.modules"])
def test_probes_and_unexpected_calls_are_suspicious(target):
    assert behaviour.classify(_run(_call(target))).verdict is Verdict.SUSPICIOUS


def test_framework_and_allowlisted_calls_are_clean():
    run = _run(_call("tf.nn.relu"), _call("Tensor.reshape"),
               _call("numpy.core.multiarray._reconstruct"),
               _call("numpy.core.multiarray._reconstruct().__setstate__"))
    assert behaviour.classify(run).verdict is Verdict.CLEAN


def test_import_outside_allowlist_is_suspicious():
    event = {"kind": "import", "module": "evilpkg", "name": "Thing", "resolved": "fake"}
    assert behaviour.classify(_run(event)).verdict is Verdict.SUSPICIOUS
    allowed = behaviour.classify(_run(event), extra_allowed=frozenset({("evilpkg", "Thing")}))
    assert allowed.verdict is Verdict.CLEAN
