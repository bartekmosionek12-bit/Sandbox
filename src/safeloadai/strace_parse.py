"""Parser wyjścia ``strace`` — trzecie, nieobchodzalne źródło dowodów.

Dlaczego to w ogóle istnieje. Log z warstwy 2 powstaje przez monkey-patche
w Pythonie, czyli **wewnątrz** procesu, który detonujemy. Payload, który
zamiast ``os.system`` zawoła syscall wprost przez ``ctypes``, albo wczyta
świeży moduł obok ``sys.modules``, ominie te haki. Nadal nic nie zrobi poza
kontenerem, ale **nie pojawi się w logu** — a pusty log wygląda jak dowód
niewinności. To jest najgorsza możliwa awaria tego narzędzia.

``strace`` patrzy na proces z zewnątrz, przez ``ptrace``, i widzi każdy
syscall niezależnie od tego, jak payload go wywołał. Z wnętrza kontenera
nie da się tego wyłączyć.

Cena jest realna i trzeba ją mówić wprost: tryb śledzenia wymaga
``--cap-add=SYS_PTRACE``, czyli oddaje jedno uprawnienie, które domyślny
przebieg zabiera przez ``--cap-drop=ALL``. Dlatego to **osobny, opcjonalny
przebieg**, a nie domyślny: najpierw maksymalna izolacja, a śledzenie
wtedy, gdy świadomie wybieramy widoczność ponad szczelność.

Ten moduł jest czystym parserem tekstu, bez Dockera, więc daje się
przetestować normalnymi testami jednostkowymi.
"""

from __future__ import annotations

import re

# Linia strace z -f ma przedrostek z pidem w jednej z dwóch form:
#   "1234  connect(...)"  albo  "[pid  1234] connect(...)"
_PID_PREFIX = re.compile(r"^(?:\[pid\s+(\d+)\]|(\d+))\s+")

# Nazwa syscalla i jego argumenty w nawiasie, do pierwszego " = " na końcu.
_CALL = re.compile(r"^(?P<name>[a-z_][a-z0-9_]*)\((?P<args>.*)\)\s+=\s+(?P<result>.+)$")

# connect() pokazuje adres w rozwiniętej strukturze sockaddr.
_INET = re.compile(
    r"sin_port=htons\((?P<port>\d+)\).*?sin_addr=inet_addr\(\"(?P<addr>[^\"]+)\"\)"
)
_INET6 = re.compile(
    r"sin6_port=htons\((?P<port>\d+)\).*?inet_pton\([^,]+,\s*\"(?P<addr>[^\"]+)\""
)
_UNIX = re.compile(r"sun_path=\"(?P<path>[^\"]+)\"")

# Pierwszy argument będący literałem tekstowym — ścieżka dla open/exec.
_FIRST_STRING = re.compile(r"\"((?:[^\"\\]|\\.)*)\"")

# Flagi otwarcia pliku oznaczające zapis.
_WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC")

# Syscalle, które nas interesują, i typ zdarzenia w kontrakcie sandboksa.
# Celowo WĄSKA lista: pełny strace na starcie Pythona to tysiące linii
# importów, a zasypanie sędziego szumem to ten sam błąd, który popełniliśmy
# raz na exec() wołanym przez maszynerię importów.
_INTERESTING = {
    "execve": "syscall_exec",
    "execveat": "syscall_exec",
    "connect": "syscall_network",
    "sendto": "syscall_network",
    "sendmsg": "syscall_network",
    "ptrace": "syscall_other",
    "chmod": "syscall_other",
    "fchmodat": "syscall_other",
    "unlink": "syscall_other",
    "unlinkat": "syscall_other",
    "open": "syscall_file_write",
    "openat": "syscall_file_write",
    "creat": "syscall_file_write",
}

# Ścieżki, których zapis/otwarcie jest własnym ruchem Pythona, nie payloadu.
_NOISE_PREFIXES = (
    "/usr/lib/python",
    "/usr/local/lib/python",
    "/opt/detonate",
    "/proc/",
    "/sys/",
    "/dev/urandom",
    "/dev/null",
    "/etc/ld.so",
    "/etc/localtime",
)


def _strip_pid(line: str) -> str:
    return _PID_PREFIX.sub("", line, count=1)


def _target_of(name: str, args: str) -> str:
    """Czytelny opis celu syscalla — to jest treść, którą czyta człowiek."""
    if name in ("connect", "sendto", "sendmsg"):
        match = _INET.search(args) or _INET6.search(args)
        if match:
            return f"{match.group('addr')}:{match.group('port')}"
        unix = _UNIX.search(args)
        if unix:
            return f"unix:{unix.group('path')}"
        return "adres nierozpoznany"
    first = _FIRST_STRING.search(args)
    return first.group(1) if first else args[:120]


def _is_write(name: str, args: str) -> bool:
    if name == "creat":
        return True
    return any(flag in args for flag in _WRITE_FLAGS)


def _is_noise(name: str, target: str, args: str) -> bool:
    """Odfiltrowuje własny ruch interpretera, nie zachowanie payloadu."""
    if name in ("open", "openat", "creat"):
        if not _is_write(name, args):
            return True
        if target.startswith(_NOISE_PREFIXES):
            return True
    if name in ("execve", "execveat") and target in ("/usr/local/bin/python", "python"):
        return True
    return False


def parse_strace(text: str, limit: int = 200) -> list[dict]:
    """Zamienia wyjście ``strace -f`` w listę zdarzeń kontraktu sandboksa.

    ``limit`` ucina listę, bo payload w pętli mógłby wygenerować setki tysięcy
    linii i rozsadzić zarówno dashboard, jak i prompt sędziego.
    """
    events: list[dict] = []
    for raw in text.splitlines():
        line = _strip_pid(raw.strip())
        if not line or line.startswith(("---", "+++")):
            continue  # sygnały i komunikaty o zakończeniu procesu
        if "<unfinished" in line or "resumed>" in line:
            # Wywołanie przerwane przez przełączenie wątku: jego dokończenie
            # przyjdzie w osobnej linii, więc liczylibyśmy je podwójnie.
            continue

        match = _CALL.match(line)
        if match is None:
            continue

        name = match.group("name")
        event_type = _INTERESTING.get(name)
        if event_type is None:
            continue

        args = match.group("args")
        result = match.group("result").strip()
        target = _target_of(name, args)
        if _is_noise(name, target, args):
            continue

        failed = result.startswith("-1")
        detail = f"{name}({target})"
        if failed:
            # Dla sieci to jest najcenniejsza linia w całym logu: payload
            # ujawnił adres i port, a pakiet nigdzie nie poszedł.
            detail = f"{detail} → {result}"

        events.append(
            {
                "type": event_type,
                "detail": detail,
                "blocked": True if failed else (False if event_type == "syscall_network" else None),
            }
        )
        if len(events) >= limit:
            events.append(
                {
                    "type": "syscall_other",
                    "detail": f"log syscalli ucięty po {limit} zdarzeniach",
                    "blocked": None,
                }
            )
            break
    return events


if __name__ == "__main__":
    import json
    import sys

    print(json.dumps(parse_strace(sys.stdin.read()), indent=2, ensure_ascii=False))
