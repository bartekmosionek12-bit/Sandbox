import json
import pickle

from corpus.build_corpus import MARKER_CMD, P2, STOP, call, g, s

from safeloadai.__main__ import main
from safeloadai.pipeline import scan
from safeloadai.report import Verdict
from safeloadai.sarif import RULES, to_sarif


def _write(path, data):
    path.write_bytes(data)
    return str(path)


def _evil(tmp_path, name="evil.pkl"):
    return _write(tmp_path / name, P2 + call(g("posix", "system"), s(MARKER_CMD)) + STOP)


def _unverifiable(tmp_path):
    return _write(tmp_path / "custom.pkl", P2 + g("safeloadai_marker_pkg", "Thing") + b")\x81" + STOP)


def test_one_result_per_blocked_file(tmp_path, fake_emulation):
    clean = _write(tmp_path / "ok.pkl", pickle.dumps({"a": 1}))
    log = to_sarif([scan(clean), scan(_evil(tmp_path))], base=str(tmp_path))
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == list(RULES)
    (result,) = run["results"]
    assert result["ruleId"] == "safeloadai/malicious" and result["level"] == "error"
    assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == result["ruleId"]
    location = result["locations"][0]["physicalLocation"]["artifactLocation"]
    assert location == {"uri": "evil.pkl", "uriBaseId": "%SRCROOT%"}
    assert "MALICIOUS" in result["message"]["text"] and result["properties"]["verdict"] == "MALICIOUS"
    assert run["invocations"][0]["executionSuccessful"] is True


def test_error_is_a_result_not_a_pass(tmp_path):
    log = to_sarif([scan(str(tmp_path / "missing.pkl"))], base=str(tmp_path))
    run = log["runs"][0]
    (result,) = run["results"]
    assert result["ruleId"] == "safeloadai/error" and result["level"] == "error"
    assert result["properties"]["errorCode"] == "E101"
    assert run["invocations"][0]["executionSuccessful"] is False


def test_accepted_override_is_suppressed_not_dropped(tmp_path, fake_emulation):
    path = _unverifiable(tmp_path)
    report = scan(path)
    assert report.verdict is Verdict.SUSPICIOUS and report.unverifiable_only
    (result,) = to_sarif([report], base=str(tmp_path))["runs"][0]["results"]
    assert result["ruleId"] == "safeloadai/unverifiable" and "suppressions" not in result
    out = tmp_path / "out.sarif"
    args = ["scan", "-q", "--no-input", path, "--sarif", str(out)]
    for item in report.unverifiable_items:
        args += ["--accept-unverified", item]
    assert main(args) == 0
    (result,) = json.loads(out.read_text())["runs"][0]["results"]
    assert result["suppressions"][0]["kind"] == "external"
    assert result["properties"]["verdict"] == "SUSPICIOUS"


def test_file_outside_base_gets_a_file_uri(tmp_path, fake_emulation):
    inner = tmp_path / "repo"
    inner.mkdir()
    (result,) = to_sarif([scan(_evil(tmp_path))], base=str(inner))["runs"][0]["results"]
    location = result["locations"][0]["physicalLocation"]["artifactLocation"]
    assert location["uri"].startswith("file://") and "uriBaseId" not in location


def test_cli_sarif_keeps_the_exit_code(tmp_path, fake_emulation):
    out = tmp_path / "scan.sarif"
    assert main(["scan", "-q", _evil(tmp_path), "--sarif", str(out)]) == 1
    assert json.loads(out.read_text())["runs"][0]["results"][0]["ruleId"] == "safeloadai/malicious"
    fake_emulation.verdict = Verdict.SUSPICIOUS
    clean = _write(tmp_path / "ok.pkl", pickle.dumps([1, 2]))
    assert main(["scan", "-q", clean, "--sarif", str(out)]) == 3
    (result,) = json.loads(out.read_text())["runs"][0]["results"]
    assert result["ruleId"] == "safeloadai/suspicious" and result["level"] == "warning"
