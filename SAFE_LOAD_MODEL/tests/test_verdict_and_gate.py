from conftest import sandbox_report
from sandbox_rce import api, pipeline

CLEAN_PARSER = {"static_risk": "clean"}
JUDGE_SAFE = {"available": True, "verdict": "safe", "injection_attempt_detected": False}
NO_JUDGE = {"available": False, "verdict": "unknown"}
EXEC_EVENT = [{"type": "os_system", "detail": "touch /tmp/pwned"}]


def test_judge_cannot_clear_observed_execution():
    verdict, source = pipeline.final_verdict(
        CLEAN_PARSER, JUDGE_SAFE, sandbox_report(events=EXEC_EVENT)
    )
    assert verdict == "malicious"
    assert "twarde przesłanki" in source


def test_without_judge_sandbox_events_still_count():
    # Dawniej: brak klucza API = werdykt tylko z parsera, a log detonacji
    # był ignorowany. Ładunek, którego parser nie rozpoznał, przechodził.
    verdict, _ = pipeline.final_verdict(CLEAN_PARSER, NO_JUDGE, sandbox_report(events=EXEC_EVENT))
    assert verdict == "malicious"


def test_judge_cannot_clear_static_malicious():
    verdict, _ = pipeline.final_verdict({"static_risk": "malicious"}, JUDGE_SAFE, sandbox_report())
    assert verdict == "suspicious"


def test_injection_attempt_raises_verdict():
    judge = dict(JUDGE_SAFE, injection_attempt_detected=True)
    verdict, _ = pipeline.final_verdict(CLEAN_PARSER, judge, sandbox_report())
    assert verdict == "suspicious"


def test_judge_can_still_escalate():
    judge = dict(JUDGE_SAFE, verdict="malicious")
    assert pipeline.final_verdict(CLEAN_PARSER, judge, sandbox_report())[0] == "malicious"


def _report(**sandbox):
    return {"final_verdict": "safe", "verdict_source": "x", "sandbox": sandbox_report(**sandbox)}


def test_gate_allows_full_clean_scan():
    assert api.gate_decision(_report())["code"] == api.OK


def test_gate_blocks_timeout():
    decision = api.gate_decision(_report(timed_out=True, load_succeeded=None))
    assert not decision["allowed"] and decision["code"] == api.DETONATION_TIMEOUT


def test_gate_blocks_failed_load_in_sandbox():
    decision = api.gate_decision(_report(load_succeeded=False, error="ModuleNotFoundError: sklearn"))
    assert not decision["allowed"] and decision["code"] == api.LOAD_FAILED_IN_SANDBOX


def test_gate_blocks_missing_detonation():
    decision = api.gate_decision(_report(detonated=False, skipped_reason="Brak Dockera."))
    assert not decision["allowed"] and decision["code"] == api.NO_DETONATION


def test_gate_explicit_opt_out_is_marked():
    decision = api.gate_decision(_report(detonated=False), require_detonation=False)
    assert decision["allowed"] and decision["code"] == api.OK_STATIC_ONLY


def test_gate_blocks_unknown_verdict():
    report = _report()
    report["final_verdict"] = "unknown"
    assert api.gate_decision(report)["code"] == api.BLOCKED_VERDICT
