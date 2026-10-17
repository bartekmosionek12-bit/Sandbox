import subprocess

from sandbox_rce import sandbox


class Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def test_stale_image_is_rebuilt(monkeypatch):
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        if cmd[:3] == ["docker", "image", "inspect"]:
            return Proc(stdout="stary-odcisk\n")
        return Proc()

    monkeypatch.setattr(sandbox, "docker_status", lambda: (True, "Docker test"))
    monkeypatch.setattr(sandbox.subprocess, "run", run)
    sandbox.ensure_image(profile="pickle")
    build = [c for c in calls if c[:2] == ["docker", "build"]]
    assert build and f"{sandbox.IMAGE_LABEL}={sandbox.image_fingerprint('pickle')}" in build[0]


def test_current_image_is_not_rebuilt(monkeypatch):
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        return Proc(stdout=sandbox.image_fingerprint("keras") + "\n")

    monkeypatch.setattr(sandbox, "docker_status", lambda: (True, "Docker test"))
    monkeypatch.setattr(sandbox.subprocess, "run", run)
    sandbox.ensure_image(profile="keras")
    assert not [c for c in calls if c[:2] == ["docker", "build"]]


def test_timeout_kills_container_and_is_flagged(monkeypatch, tmp_path):
    sample = tmp_path / "m.pkl"
    sample.write_bytes(b"\x80\x04N.")
    killed = []

    def run(cmd, **kw):
        if cmd[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"), output="", stderr="")
        if cmd[:2] == ["docker", "kill"]:
            killed.append(cmd[2])
        return Proc()

    monkeypatch.setattr(sandbox, "docker_status", lambda: (True, "Docker test"))
    monkeypatch.setattr(sandbox, "ensure_image", lambda **kw: None)
    monkeypatch.setattr(sandbox.subprocess, "run", run)
    report = sandbox.detonate_in_docker(str(sample), timeout_s=1)
    assert report["timed_out"] is True
    assert killed and killed[0].startswith("safeloadai-")
