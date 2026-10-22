"""Update monitoring: workflows are pinned and read-only, the drift and runtime checks
report without trusting anything (no network: only the parsing and reporting parts)."""
from __future__ import annotations

import importlib.util
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))


def _tool(name: str):
    spec = importlib.util.spec_from_file_location(f"_tool_{name}", ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_action_is_pinned_by_commit_sha():
    assert WORKFLOWS
    for path in WORKFLOWS:
        for line in path.read_text(encoding="utf-8").splitlines():
            match = re.search(r"uses:\s*(\S+)", line)
            if match:
                assert re.fullmatch(r"[\w.-]+/[\w.-]+(/[\w.-]+)*@[0-9a-f]{40}", match.group(1)), (path.name, line)
                assert re.search(r"# v\d+\.\d+\.\d+$", line), (path.name, line)


def test_publish_uses_trusted_publishing_with_attestations():
    text = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
    assert text.count("attestations: true") == 2  # PEP 740, both packages
    assert text.count("environment: ${{ inputs.target }}") == 2  # the "pypi" environment's reviewer gates uploads
    assert "password:" not in text and "PYPI_API_TOKEN" not in text  # OIDC only, no stored token
    assert "github.ref != 'refs/heads/main'" in text


def test_scorecard_is_read_only_apart_from_its_results():
    text = (ROOT / ".github" / "workflows" / "scorecard.yml").read_text(encoding="utf-8")
    assert "permissions: read-all" in text and "persist-credentials: false" in text
    assert re.findall(r"^\s+(\S+): write", text, re.M) == ["security-events", "id-token"]


def test_monitoring_workflows_cannot_change_the_repository():
    for name in ("upstream-drift.yml", "runtime-watch.yml"):
        text = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
        assert "workflow_dispatch:" in text and "schedule:" in text
        assert re.findall(r"^\s+(contents|issues|pull-requests):\s*(\w+)", text, re.M) == [
            ("contents", "read"), ("contents", "read"), ("issues", "write")]
        assert "git push" not in text and "pulls.create" not in text and "allowlists.py" not in text


def test_dependabot_covers_pip_and_actions_weekly():
    text = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    assert re.findall(r"package-ecosystem:\s*(\S+)", text) == ["pip", "github-actions"]
    assert text.count("interval: weekly") == 2


def test_drift_report_lists_names_versions_and_diff():
    drift = _tool("drift_check")
    results = [{"file": "a.pkl", "verdict": "CLEAN", "names": [], "reasons": []},
               {"file": "b.pkl", "verdict": "SUSPICIOUS", "names": ["sklearn.new.Thing"],
                "reasons": ["[static] SUSPICIOUS: import outside the allowlist: sklearn.new.Thing"]}]
    versions = drift.versions("numpy==9.0.0\nscikit-learn==2.0.0\nrequests==1.0\n")
    assert versions == {"numpy": "9.0.0", "scikit-learn": "2.0.0"}
    text, found = drift.build_report(results, versions)
    assert found and "`sklearn.new.Thing` | b.pkl" in text and "| scikit-learn | 2.0.0 |" in text
    assert "-b.pkl: CLEAN" in text and "+b.pkl: SUSPICIOUS" in text and "Nothing was added" in text
    assert drift.build_report(results[:1], versions)[1] is False


def test_runtime_watch_compares_with_the_pins():
    watch = _tool("runtime_watch")
    from safeloadai.sandbox.runtime import PINNED

    version, date, tag = watch.pinned_runtime()
    assert tag.replace("/", "%2F").replace("+", "%2B") in PINNED.source_url
    assert ".".join(map(str, version)) == PINNED.python_version
    assert watch.newer_runtimes([tag, "python/3.11.4+20230714-11be424", "php/8.2.6+20230714-11be424"],
                                (version, date)) == []
    newer = ["python/3.12.0+20250101-0123abc", "python/3.13.1+20240101-0123abc"]
    assert watch.newer_runtimes(newer + [tag], (version, date)) == newer[::-1]
    upper = watch.pinned_wasmtime_upper()
    assert watch.newer_wasmtime([f"{upper - 1}.0.0", f"{upper}.0.0rc1", f"{upper}.0.1"], upper) == [f"{upper}.0.1"]
    text, found = watch.report(newer, [])
    assert found and "docs/UPDATING_RUNTIME.md" in text


def test_updating_runtime_procedure_is_documented():
    text = (ROOT / "docs" / "UPDATING_RUNTIME.md").read_text(encoding="utf-8")
    for step in ("sha256", "safeloadai-runtime", "pytest", "run_eval.py", "version"):
        assert step in text, step
    assert os.path.exists(ROOT / "packages" / "safeloadai-runtime" / "fetch_runtime.py")
