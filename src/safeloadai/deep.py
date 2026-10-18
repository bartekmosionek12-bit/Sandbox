"""Optional deep mode: really load the file inside an OS-level sandbox and watch it.

Unlike the WASI emulation layer, deep mode runs the real framework (pickle, Keras)
on the real kernel, so the isolation is only as good as the backend:

* ``docker``: the hardened container from ``docker_sandbox`` (no network, read-only
  root, no capabilities, resource limits).
* ``bwrap``: bubblewrap with every namespace unshared (no network), read-only
  system directories, the user's home hidden, a private /tmp, rlimits.
* ``nsjail``: equivalent nsjail flags (UNVERIFIED: written without nsjail at hand).

The detoner prints EVENT and RESULT lines on stdout; the payload shares that
stdout, so the host takes the union of all EVENT lines and treats a second RESULT
line as tampering (see ``docker_sandbox._parse_detoner_output``). Deep mode can
only add findings: if it cannot run, the scan is SUSPICIOUS, never CLEAN.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile

from . import docker_sandbox

try:
    import resource
except ImportError:  # Windows: no rlimits; the jail backends (bwrap, nsjail) are Linux-only anyway
    resource = None

BACKENDS = ("docker", "bwrap", "nsjail")
DETONERS = {"pickle": "detonate.py", "keras": "detonate_keras.py"}
TIMEOUT_S = {"pickle": 60, "keras": 180}
MEMORY_BYTES = 2 * 1024 * 1024 * 1024
SAMPLE = "sample"
_HERE = os.path.dirname(os.path.abspath(__file__))


def available_backends() -> list[str]:
    found = []
    if docker_sandbox.docker_status()[0]:
        found.append("docker")
    found.extend(name for name in ("bwrap", "nsjail") if shutil.which(name))
    return found


def choose_backend(requested: str | None = None) -> str | None:
    requested = requested or os.environ.get("SAFELOADAI_DEEP_BACKEND") or None
    if requested:
        return requested if requested in BACKENDS else None
    found = available_backends()
    return found[0] if found else None


def _ro_system_dirs() -> list[str]:
    dirs = ["/usr", "/bin", "/lib", "/lib64", "/etc", sys.base_prefix, sys.prefix]
    seen, out = set(), []
    for d in dirs:
        real = os.path.realpath(d)
        if os.path.isdir(real) and real not in seen:
            seen.add(real)
            out.append(real)
    return out


def bwrap_command(staging: str, detoner: str) -> list[str]:
    cmd = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
           "--clearenv", "--setenv", "HOME", "/tmp", "--setenv", "PATH", "/usr/bin:/bin"]
    for d in _ro_system_dirs():
        cmd += ["--ro-bind", d, d]
    cmd += ["--ro-bind", staging, "/target", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
            "--chdir", "/tmp", "--", sys.executable, "-I", f"/target/{detoner}", f"/target/{SAMPLE}"]
    return cmd


def nsjail_command(staging: str, detoner: str, timeout_s: int) -> list[str]:
    cmd = ["nsjail", "--mode", "o", "--quiet", "--time_limit", str(timeout_s),
           "--rlimit_as", str(MEMORY_BYTES // (1024 * 1024)), "--rlimit_nproc", "64", "--rlimit_fsize", "16",
           "--env", "HOME=/tmp", "--cwd", "/tmp", "-T", "/tmp"]
    for d in _ro_system_dirs():
        cmd += ["-R", d]
    cmd += ["-R", f"{staging}:/target", "--", sys.executable, "-I", f"/target/{detoner}", f"/target/{SAMPLE}"]
    return cmd


def _limits() -> None:  # runs in the child before exec
    if resource is None:
        raise OSError("rlimits are not available on this platform")
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _jail_report(path: str, file_format: str, backend: str) -> dict:
    report = docker_sandbox._empty_report(os.path.basename(path), "")
    report.update(skipped_reason=None, detonation_backend=backend)
    timeout_s = TIMEOUT_S[file_format]
    with tempfile.TemporaryDirectory(prefix="safeloadai-deep-") as staging:
        detoner = DETONERS[file_format]
        shutil.copyfile(os.path.join(_HERE, detoner), os.path.join(staging, detoner))
        shutil.copyfile(path, os.path.join(staging, SAMPLE))
        os.chmod(staging, 0o555)
        cmd = (bwrap_command(staging, detoner) if backend == "bwrap"
               else nsjail_command(staging, detoner, timeout_s))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,  # noqa: S603
                                encoding="utf-8", errors="replace", start_new_session=True, preexec_fn=_limits)
        try:
            stdout, stderr = proc.communicate(timeout=timeout_s)
            timed_out = False
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            stdout, stderr = proc.communicate()
            timed_out = True
        finally:
            os.chmod(staging, 0o755)
    return finish_report(report, stdout, stderr, proc.returncode, timed_out)


def finish_report(report: dict, stdout: str, stderr: str, returncode: int | None, timed_out: bool) -> dict:
    events, result, result_lines = docker_sandbox._parse_detoner_output(stdout or "")
    report["events"] = docker_sandbox._union_events(events, (result or {}).get("events") or [])
    report["tampered"] = result_lines > 1
    if report["tampered"]:
        report["tamper_reason"] = f"{result_lines} RESULT lines on stdout; the payload forged at least one"
    report["detonated"] = result is not None or bool(events) or timed_out
    report["timed_out"] = timed_out
    if result:
        report.update(load_succeeded=result.get("load_succeeded"), duration_ms=result.get("duration_ms"),
                      error=result.get("error"))
    if timed_out:
        report["error"] = "deep detonation killed at the time limit"
    elif not report["detonated"]:
        report["skipped_reason"] = f"jail exited with code {returncode} without a result"
        report["error"] = (stderr or "").strip()[-1000:] or None
    report["raw_log"] = (stderr or "")[-4000:]
    return report


def run_deep(path: str, file_format: str, backend: str | None = None) -> dict:
    """Deep detonation report (docker_sandbox report format) for ``path``."""
    name = os.path.basename(path)
    if file_format not in DETONERS:
        return docker_sandbox._empty_report(name, f"no deep detoner for format {file_format!r}")
    chosen = choose_backend(backend)
    if chosen is None:
        return docker_sandbox._empty_report(
            name, "no deep backend available (Docker, bubblewrap or nsjail), or an unknown one was requested")
    if chosen == "docker":
        return docker_sandbox.detonate_in_docker(path, profile=file_format)
    return _jail_report(path, file_format, chosen)
