"""Host side of the sandbox: prepare the read-only directory, start the runner
subprocess, enforce the wall-clock limit, and validate the evidence channel.

Evidence integrity rules (owner decision, DECISIONS.md):

* Only records that arrive through the host-implemented evidence channel count.
  Guest stdout and stderr are kept for debugging and never interpreted.
* Every record must carry this scan's random nonce. A record with a wrong or
  missing nonce, or one that is not valid JSON, is a write to the channel that did
  not come from the recorder: ``tampered = True`` (the verdict layer maps that to
  MALICIOUS).
* Sequence numbers must be 0, 1, 2, ... with no gaps or repeats, and the last
  record must be ``done``. Anything else is an incomplete run.
* The guest must return from ``_start``. A guest that calls ``proc_exit`` (even with
  status 0) did not run to the end of the bootstrap, whatever records it wrote: the
  run is incomplete (status ``exit``). This is observed by the runner, outside the
  guest, so guest code cannot forge it (0.8.0, docs/EVIDENCE_CHANNEL.md).

What this cannot prevent: the payload shares the guest interpreter with the
recorder, so it can find the nonce and append well-formed records of its own. It
cannot remove records already received by the host, so it can add noise but
cannot turn a recorded alarm into a clean log.
"""
from __future__ import annotations

import base64
import hmac
import json
import os
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import runtime

GUEST_SOURCE = Path(__file__).with_name("guest")
# Stdlib-only modules the host and the guest share (format layouts, readers).
SHARED_SOURCE = Path(__file__).resolve().parent.parent / "shared"
SHARED_MODULES = ("joblib_layout.py", "hdf5_meta.py")
RUNNER_ARGV = [sys.executable, "-I", "-m", "safeloadai.sandbox.runner"]
RECORD_MAGIC = b"SLAI1 "


@dataclass(frozen=True)
class Limits:
    memory_bytes: int = 512 * 1024 * 1024
    fuel: int = 20_000_000_000
    wall_seconds: float = 30.0
    max_records: int = 10_000
    max_record_bytes: int = 64 * 1024
    max_stdio_bytes: int = 64 * 1024


@dataclass
class GuestRun:
    """Outcome of one sandbox run. ``events`` are validated records only."""

    status: str  # ok | exit | trap | fuel_exhausted | timeout | runner_error | unavailable
    completed: bool = False
    tampered: bool = False
    events: list[dict] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    guest_stdout: str = ""
    guest_stderr: str = ""
    exit_code: int | None = None
    trap: str | None = None
    timings_ms: dict = field(default_factory=dict)
    runtime: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _make_readonly(root: Path) -> None:
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            os.chmod(os.path.join(dirpath, name), stat.S_IRUSR)
        os.chmod(dirpath, stat.S_IRUSR | stat.S_IXUSR)


def _make_writable(root: Path) -> None:
    for dirpath, _dirnames, filenames in os.walk(root):
        os.chmod(dirpath, stat.S_IRWXU)
        for name in filenames:  # Windows cannot delete read-only files
            os.chmod(os.path.join(dirpath, name), stat.S_IRUSR | stat.S_IWUSR)


def validate_records(raw_records: list[bytes], nonce: str) -> tuple[list[dict], list[str], bool, bool]:
    """Check nonce, framing and sequence. Returns (events, problems, tampered, completed)."""
    events: list[dict] = []
    problems: list[str] = []
    tampered = False
    expected_prefix = RECORD_MAGIC + nonce.encode("ascii") + b" "
    for index, raw in enumerate(raw_records):
        head = raw[: len(expected_prefix)]
        if not hmac.compare_digest(head, expected_prefix):
            tampered = True
            problems.append(f"record {index}: write to the evidence channel without this scan's nonce")
            continue
        try:
            record = json.loads(raw[len(expected_prefix):].decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            tampered = True
            problems.append(f"record {index}: malformed record on the evidence channel")
            continue
        if not isinstance(record, dict) or not isinstance(record.get("kind"), str):
            tampered = True
            problems.append(f"record {index}: record without a kind")
            continue
        events.append(record)

    for position, record in enumerate(events):
        if record.get("seq") != position:
            problems.append(f"evidence sequence broken at position {position} (seq={record.get('seq')!r})")
            break
    completed = bool(events) and events[-1].get("kind") == "done" and not any(
        "sequence broken" in p for p in problems
    )
    if events and sum(1 for e in events if e.get("kind") == "done") > 1:
        problems.append("more than one done record")
        completed = False
    if not completed:
        problems.append("guest did not finish cleanly (no final done record)")
    return events, problems, tampered, completed


def run_guest(task: dict, artefacts: dict[str, bytes], limits: Limits | None = None) -> GuestRun:
    """Run ``task`` in a fresh sandbox with ``artefacts`` under ``/in/artefacts``.

    A missing runtime gives ``status="unavailable"`` (callers fail closed); a runtime
    that does not match the pinned hash raises RuntimeIntegrityError.
    """
    limits = limits or Limits()
    try:
        wasm = runtime.locate()
    except runtime.RuntimeUnavailable as exc:
        return GuestRun(status="unavailable", problems=[str(exc)])

    nonce = secrets.token_hex(16)
    workdir = Path(tempfile.mkdtemp(prefix="safeloadai-wasi-"))
    try:
        inbox = workdir / "in"
        guest_dir = inbox / ".guest"
        shutil.copytree(GUEST_SOURCE, guest_dir, ignore=shutil.ignore_patterns("__pycache__"))
        for module in SHARED_MODULES:
            shutil.copyfile(SHARED_SOURCE / module, guest_dir / module)
        (guest_dir / "task.json").write_text(json.dumps(task), encoding="utf-8")
        art_dir = inbox / "artefacts"
        art_dir.mkdir()
        for name, data in artefacts.items():
            target = art_dir / name
            if target.resolve().parent != art_dir.resolve():
                raise ValueError(f"artefact name escapes the directory: {name!r}")
            target.write_bytes(data)
        _make_readonly(inbox)

        cache = runtime.compiled_cache_dir().path
        job = {
            "wasm_path": str(wasm),
            "wasm_sha256": runtime.PINNED.sha256,
            "compiled_cache_dir": str(cache) if cache else None,
            "workdir": str(inbox),
            "argv": ["python", "-I", "-S", "/in/.guest/bootstrap.py"],
            "env": {"SAFELOADAI_NONCE": nonce},
            "memory_bytes": limits.memory_bytes,
            "fuel": limits.fuel,
            "max_records": limits.max_records,
            "max_record_bytes": limits.max_record_bytes,
            "max_stdio_bytes": limits.max_stdio_bytes,
        }
        started = time.perf_counter()
        proc = subprocess.Popen(  # noqa: S603 - fixed argv, our own module
            RUNNER_ARGV,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            out, err = proc.communicate(json.dumps(job).encode(), timeout=limits.wall_seconds)
        except subprocess.TimeoutExpired:
            _kill(proc)
            proc.communicate()
            return GuestRun(
                status="timeout",
                problems=[f"wall-clock limit of {limits.wall_seconds}s reached; runner killed"],
                timings_ms={"total": round((time.perf_counter() - started) * 1000, 1)},
                runtime=_runtime_info(wasm),
            )
        elapsed = round((time.perf_counter() - started) * 1000, 1)
    finally:
        _make_writable(workdir)
        shutil.rmtree(workdir, ignore_errors=True)

    try:
        result = json.loads(out.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return GuestRun(status="runner_error", problems=[
            f"runner produced no result (exit {proc.returncode}): {err.decode('utf-8', 'replace')[-500:]}"
        ], runtime=_runtime_info(wasm))
    if result.get("status") == "integrity_error":
        raise runtime.RuntimeIntegrityError(str(result.get("error")))
    if result.get("status") == "runner_error":
        return GuestRun(status="runner_error", problems=[result.get("error", "runner error")],
                        runtime=_runtime_info(wasm))

    raw = [base64.b64decode(r) for r in result.get("records", [])]
    events, problems, tampered, completed = validate_records(raw, nonce)
    flags = result.get("flags", {})
    if flags.get("records_dropped"):
        problems.append(f"{flags['records_dropped']} evidence records dropped (limit {limits.max_records})")
        completed = False
    if flags.get("records_truncated"):
        problems.append(f"{flags['records_truncated']} evidence records over {limits.max_record_bytes} bytes")
        completed = False
    status = result.get("status", "runner_error")
    if status != "ok":
        detail = result.get("trap") or (f"proc_exit({result.get('exit_code')}) called inside the guest"
                                         if status == "exit" else "")
        problems.append(f"guest ended with status {status}" + (f": {detail}" if detail else ""))
        completed = False
    timings = dict(result.get("timings_ms", {}), total=elapsed)
    info = _runtime_info(wasm)
    info.update(module_source=result.get("module_source"), fuel_budget=result.get("fuel_budget"),
                fuel_left=result.get("fuel_left"))
    return GuestRun(
        status=status,
        completed=completed,
        tampered=tampered,
        events=events,
        problems=problems,
        guest_stdout=result.get("guest_stdout", ""),
        guest_stderr=result.get("guest_stderr", ""),
        exit_code=result.get("exit_code"),
        trap=result.get("trap"),
        timings_ms=timings,
        runtime=info,
    )


def _kill(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, AttributeError):
        proc.kill()


def _runtime_info(wasm: Path) -> dict:
    from importlib.metadata import PackageNotFoundError, version

    try:
        wasmtime_version = version("wasmtime")
    except PackageNotFoundError:
        wasmtime_version = None
    return {"name": runtime.PINNED.name, "sha256": runtime.PINNED.sha256,
            "path": str(wasm), "wasmtime": wasmtime_version}
