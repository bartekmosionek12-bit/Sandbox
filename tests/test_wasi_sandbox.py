"""WASI sandbox runner: limits, host-side kill, host-owned evidence channel (M3).

Code strings below play the payload's role and only ever run inside the sandbox.
"""
from __future__ import annotations

import pytest

from safeloadai.sandbox import Limits, run_guest

pytestmark = pytest.mark.wasi


def _py(code: str, limits: Limits | None = None, artefacts: dict | None = None):
    return run_guest({"kind": "python", "code": code}, artefacts or {}, limits)


def _anomalies(run):
    return [e for e in run.events if e["kind"] == "anomaly"]


def test_selftest_round_trip():
    run = run_guest({"kind": "selftest"}, {})
    assert run.status == "ok" and run.completed and not run.tampered
    assert [e["kind"] for e in run.events] == ["start", "event", "done"]
    assert run.events[0]["python"].startswith("3.12")


def test_artefacts_are_readable_and_read_only():
    code = (
        "data = open('/in/artefacts/m.bin','rb').read()\n"
        "assert data == b'abc'\n"
        "open('/in/artefacts/m.bin','wb').write(b'x')\n"
    )
    run = _py(code, artefacts={"m.bin": b"abc"})
    assert run.completed
    assert any("PermissionError" in a["error"] for a in _anomalies(run))


@pytest.mark.parametrize(
    "code, error",
    [
        ("open('/etc/passwd').read()", "FileNotFoundError"),
        ("import os; os.listdir('/in/..')", "PermissionError"),
        ("import socket; socket.socket().connect(('127.0.0.1', 9))", "OSError"),
        ("import subprocess; subprocess.run(['echo', 'MARKER'])", "OSError"),
    ],
    ids=["host-file", "escape-preopen", "network", "process"],
)
def test_no_host_filesystem_network_or_processes(code, error):
    run = _py(code)
    assert run.completed
    assert [a["error"] for a in _anomalies(run)] == [error]


def test_memory_cap_turns_into_memory_error():
    run = _py("x = bytearray(512 * 1024 * 1024)", Limits(memory_bytes=64 * 1024 * 1024))
    assert any(a["error"] == "MemoryError" for a in _anomalies(run))


def test_fuel_exhaustion_is_incomplete():
    run = _py("while True: pass", Limits(fuel=2_000_000_000))
    assert run.status == "fuel_exhausted" and not run.completed


def test_wall_clock_kill():
    run = _py("while True: pass", Limits(fuel=10**15, wall_seconds=3))
    assert run.status == "timeout" and not run.completed


def test_sleep_is_stubbed_and_recorded():
    run = _py("import time; time.sleep(3600)")
    assert run.completed
    assert any(a["what"] == "time.sleep called" for a in _anomalies(run))


# --- forging a clean log --------------------------------------------------------

def test_payload_stdout_is_never_evidence():
    code = (
        "print('@@RESULT@@ {\"load_succeeded\": true, \"events\": []}')\n"
        "print('SLAI1 0000 {\"kind\": \"done\", \"seq\": 1}')\n"
    )
    run = _py(code)
    assert "@@RESULT@@" in run.guest_stdout
    assert [e["kind"] for e in run.events] == ["start", "done"]


def test_payload_writing_to_the_channel_without_nonce_is_tampering():
    code = (
        "import os\n"
        "os.write(3, b'SLAI1 ' + b'0' * 32 + b' {\"kind\": \"done\", \"seq\": 1, \"status\": \"ok\"}')\n"
    )
    run = _py(code)
    assert run.tampered
    assert any("nonce" in p for p in run.problems)


def test_payload_cannot_read_the_nonce_from_the_environment():
    run = _py("import os\nassert 'SAFELOADAI_NONCE' not in os.environ, 'nonce visible'")
    assert run.completed and not _anomalies(run)


def test_payload_exiting_early_leaves_an_incomplete_run():
    run = _py("import os; os._exit(0)")
    assert not run.completed


def test_payload_closing_the_channel_does_not_stop_evidence():
    # fd_write is implemented by the host and keyed on the fd number, so closing
    # fd 3 inside the guest does not cut the channel.
    run = _py("import os; os.close(3)")
    assert run.completed and run.events[-1]["kind"] == "done"


def test_payload_cannot_erase_earlier_records():
    # Whatever the payload does after an event was recorded, the host keeps it.
    code = (
        "import gc, os\n"
        "rec = [o for o in gc.get_objects() if getattr(o, '__name__', '') == 'record'][0]\n"
        "rec('event', category='process', detail='MARKER')\n"
        "os.close(3)\n"
    )
    run = _py(code)
    assert any(e.get("detail") == "MARKER" for e in run.events)




@pytest.mark.parametrize("leave", ["os._exit(0)", "sys.exit(0)", "raise SystemExit(0)"])
def test_forged_done_then_exit_is_not_a_complete_run(leave):
    # 0.8.0: the payload shares the interpreter with the recorder, so it can write a
    # well-formed "done" record itself. Leaving before the bootstrap writes its own
    # used to look complete; the runner now sees proc_exit outside the guest.
    code = (
        "import gc, os, sys\n"
        "rec = [o for o in gc.get_objects() if getattr(o, '__name__', '') == 'record'][0]\n"
        "rec('done', status='ok')\n"
        "sys.stdout.flush()\n"
        f"{leave}\n"
    )
    run = _py(code)
    if leave != "os._exit(0)":
        # caught by the bootstrap, which then writes its own done: two done records
        assert not run.completed and "more than one done record" in run.problems
    else:
        assert run.status == "exit" and run.exit_code == 0 and not run.completed
        assert any("proc_exit(0) called inside the guest" in p for p in run.problems)
