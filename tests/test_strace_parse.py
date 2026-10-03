"""Testy parsera wyjścia strace.

Sam przebieg ze strace wymaga Dockera i ``--cap-add=SYS_PTRACE``, więc tutaj
testujemy to, co da się przetestować bez kontenera: zamianę surowych linii
strace na zdarzenia kontraktu. Linie poniżej są w formacie, jaki daje
``strace -f`` — z przedrostkiem pidu w obu wariantach, z wywołaniami
przerwanymi i z liniami sygnałów.
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sandbox_rce.strace_parse import parse_strace  # noqa: E402


def _types(events):
    return [e["type"] for e in events]


def test_execve_of_payload_is_captured():
    text = (
        '1234  execve("/bin/sh", ["sh", "-c", "touch /tmp/pwned"], 0x7ffd1234) = 0\n'
    )
    events = parse_strace(text)
    assert _types(events) == ["syscall_exec"]
    assert "/bin/sh" in events[0]["detail"]


def test_blocked_connect_reveals_address_and_port():
    """To jest najcenniejsza linia w całym logu: payload ujawnia adres i port
    swojego C2, a pakiet nigdzie nie idzie."""
    text = (
        "1234  connect(3, {sa_family=AF_INET, sin_port=htons(4444), "
        'sin_addr=inet_addr("192.0.2.1")}, 16) = -1 ENETUNREACH '
        "(Network is unreachable)\n"
    )
    events = parse_strace(text)
    assert len(events) == 1
    assert events[0]["type"] == "syscall_network"
    assert "192.0.2.1:4444" in events[0]["detail"]
    assert events[0]["blocked"] is True
    assert "ENETUNREACH" in events[0]["detail"]


def test_successful_connect_is_not_marked_blocked():
    text = (
        "1234  connect(3, {sa_family=AF_INET, sin_port=htons(80), "
        'sin_addr=inet_addr("10.0.0.5")}, 16) = 0\n'
    )
    events = parse_strace(text)
    assert events[0]["blocked"] is False


def test_pid_prefix_in_both_formats():
    text = (
        '[pid  4321] openat(AT_FDCWD, "/tmp/exfil", O_WRONLY|O_CREAT, 0666) = 3\n'
        '5555  openat(AT_FDCWD, "/tmp/drugi", O_WRONLY|O_CREAT, 0666) = 4\n'
    )
    events = parse_strace(text)
    assert _types(events) == ["syscall_file_write", "syscall_file_write"]
    assert "/tmp/exfil" in events[0]["detail"]
    assert "/tmp/drugi" in events[1]["detail"]


def test_read_only_open_is_not_a_write():
    text = '1234  openat(AT_FDCWD, "/tmp/cokolwiek", O_RDONLY) = 3\n'
    assert parse_strace(text) == []


def test_interpreter_noise_is_filtered():
    """Start Pythona to tysiące linii importów. Zasypanie sędziego szumem to
    ten sam błąd, który popełniliśmy raz na exec() z maszynerii importów."""
    text = (
        '1234  openat(AT_FDCWD, "/usr/local/lib/python3.11/os.py", O_RDONLY) = 3\n'
        '1234  openat(AT_FDCWD, "/usr/local/lib/python3.11/__pycache__/x.pyc", '
        "O_WRONLY|O_CREAT, 0666) = 4\n"
        '1234  openat(AT_FDCWD, "/proc/self/status", O_RDONLY) = 5\n'
        '1234  openat(AT_FDCWD, "/tmp/pwned", O_WRONLY|O_CREAT, 0666) = 6\n'
    )
    events = parse_strace(text)
    assert len(events) == 1, f"szum przeszedł do logu: {events}"
    assert "/tmp/pwned" in events[0]["detail"]


def test_unfinished_and_resumed_lines_are_not_counted_twice():
    text = (
        "1234  connect(3, {sa_family=AF_INET, sin_port=htons(4444), "
        'sin_addr=inet_addr("192.0.2.1")}, 16 <unfinished ...>\n'
        "1234  <... connect resumed>) = -1 ENETUNREACH (Network is unreachable)\n"
    )
    assert parse_strace(text) == []


def test_signal_lines_are_ignored():
    text = (
        "1234  --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED} ---\n"
        "1234  +++ exited with 0 +++\n"
    )
    assert parse_strace(text) == []


def test_ptrace_attempt_is_flagged():
    """Payload próbujący ptrace to próba wyjścia z obserwacji — warto widzieć."""
    text = "1234  ptrace(PTRACE_ATTACH, 1, NULL, NULL) = -1 EPERM (Operation not permitted)\n"
    events = parse_strace(text)
    assert _types(events) == ["syscall_other"]
    assert events[0]["blocked"] is True


def test_limit_truncates_and_says_so():
    """Payload w pętli wygenerowałby setki tysięcy linii i rozsadziłby
    zarówno dashboard, jak i prompt sędziego."""
    line = '1234  openat(AT_FDCWD, "/tmp/plik", O_WRONLY|O_CREAT, 0666) = 3\n'
    events = parse_strace(line * 50, limit=10)
    assert len(events) == 11
    assert "ucięty" in events[-1]["detail"]


def test_garbage_input_does_not_crash():
    assert parse_strace("") == []
    assert parse_strace("zupelnie nie strace\n\n???\n") == []


def test_unix_socket_target_is_named():
    text = (
        "1234  connect(3, {sa_family=AF_UNIX, "
        'sun_path="/var/run/docker.sock"}, 110) = -1 ENOENT (No such file)\n'
    )
    events = parse_strace(text)
    assert "unix:/var/run/docker.sock" in events[0]["detail"]
