"""Deep-mode plumbing.

No process is started here: the jail subprocess is replaced.
"""
from __future__ import annotations

import os
import sys

from safeloadai import deep, pipeline, verdict
from safeloadai.report import LayerResult, Verdict

# --- deep mode -------------------------------------------------------------------

def test_deep_without_backend_is_a_tool_error(monkeypatch, tmp_path):
    monkeypatch.setattr(deep, "choose_backend", lambda requested=None: None)
    path = tmp_path / "m.pkl"
    path.write_bytes(b"\x80\x04}\x94.")
    layer = verdict.docker_layer(deep.run_deep(str(path), "pickle"))
    assert [e["code"] for e in layer.errors] == ["E310"] and not layer.ran


def test_unknown_requested_backend_is_refused():
    assert deep.choose_backend("chroot") is None


def test_bwrap_command_isolates_network_and_home(tmp_path):
    cmd = deep.bwrap_command(str(tmp_path), "detonate.py")
    assert "--unshare-all" in cmd and "--cap-drop" in cmd and "--clearenv" in cmd
    bound = {cmd[i + 1] for i, a in enumerate(cmd) if a == "--ro-bind"}
    home = os.path.realpath(os.path.expanduser("~"))
    assert home not in bound or home in (os.path.realpath(sys.prefix), os.path.realpath(sys.base_prefix))
    assert ["--tmpfs", "/tmp"] == cmd[cmd.index("--tmpfs"):cmd.index("--tmpfs") + 2]


def test_jail_output_union_and_forged_result():
    out = ('@@EVENT@@ {"type": "os_system", "detail": "echo MARKER"}\n'
           '@@RESULT@@ {"load_succeeded": true, "events": []}\n'
           '@@RESULT@@ {"load_succeeded": true, "events": []}\n')
    report = deep.finish_report(deep.docker_sandbox._empty_report("m", ""), out, "", 0, False)
    assert report["tampered"] and report["events"]
    assert verdict.docker_layer(report).verdict is Verdict.MALICIOUS


def test_deep_layer_only_adds(monkeypatch, tmp_path, fake_emulation):
    clean_deep = dict(deep.docker_sandbox._empty_report("m", ""), detonated=True, load_succeeded=True,
                      skipped_reason=None)
    monkeypatch.setattr(deep, "run_deep", lambda path, fmt, backend=None: clean_deep)
    fake_emulation.verdict = Verdict.SUSPICIOUS
    path = tmp_path / "m.pkl"
    path.write_bytes(b"\x80\x04}\x94.")
    report = pipeline.scan(str(path), deep=True)
    assert report.layer("deep").verdict is Verdict.CLEAN and report.verdict is Verdict.SUSPICIOUS
    assert isinstance(report.layer("deep"), LayerResult)
