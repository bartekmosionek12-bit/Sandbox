"""Detoner — uruchamiany WEWNĄTRZ kontenera, nigdy na hoście.

Instaluje monkey-patche na funkcjach, przez które przechodzi realne
wykonanie kodu z pickle'a, a potem wywołuje prawdziwe ``pickle.load()``.
Każda przechwycona próba jest logowana, a następnie **przepuszczana do
oryginalnej funkcji** — to jest faktyczna detonacja, nie symulacja.
Izolację zapewnia kontener (``--network=none``, ``--read-only``,
``--cap-drop=ALL``), nie te patche.

Zdarzenia lecą na stdout jako linie ``@@EVENT@@ {json}``, a końcowe
podsumowanie jako ``@@RESULT@@ {json}``. Host parsuje te linie; reszta
stdout/stderr jest surowym logiem do pokazania na dashboardzie.

UWAGA na szczegół, który decyduje o skuteczności: ``os.system`` to w
istocie ``posix.system``, a pickle importuje ``posix.system`` wprost.
Patchowanie samego ``os`` nie przechwyciłoby takiego payloadu, dlatego
patchujemy atrybut na module ``posix`` (i ``nt`` na Windows) również.
"""

from __future__ import annotations

import builtins
import json
import os
import pickle
import sys
import time
import traceback

EVENT_PREFIX = "@@EVENT@@"
RESULT_PREFIX = "@@RESULT@@"

_events: list[dict] = []


def _emit(event_type: str, detail: str, blocked: bool | None = None) -> None:
    event = {"type": event_type, "detail": detail, "blocked": blocked}
    _events.append(event)
    sys.stdout.write(f"{EVENT_PREFIX} {json.dumps(event, ensure_ascii=False)}\n")
    sys.stdout.flush()


def _truncate(value: object, limit: int = 400) -> str:
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "…(obcięte)"


def _install_patches() -> None:
    # --- wykonanie polecenia powłoki -------------------------------------
    import posix

    real_system = os.system

    def traced_system(command):  # noqa: ANN001, ANN202
        _emit("os_system", _truncate(command))
        return real_system(command)

    for mod_name in ("os", "posix", "nt"):
        mod = sys.modules.get(mod_name)
        if mod is not None and hasattr(mod, "system"):
            try:
                mod.system = traced_system
            except Exception:  # noqa: BLE001 — moduł może być tylko do odczytu
                pass

    real_popen = os.popen

    def traced_popen(command, *args, **kwargs):  # noqa: ANN001, ANN202
        _emit("os_system", f"os.popen: {_truncate(command)}")
        return real_popen(command, *args, **kwargs)

    os.popen = traced_popen

    for exec_name in ("execv", "execve", "execvp", "spawnv", "spawnl", "spawnve"):
        real_exec = getattr(os, exec_name, None)
        if real_exec is None:
            continue

        def make(name, fn):  # noqa: ANN001, ANN202
            def traced(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
                _emit("subprocess", f"os.{name}: {_truncate(args)}")
                return fn(*args, **kwargs)

            return traced

        try:
            setattr(os, exec_name, make(exec_name, real_exec))
        except Exception:  # noqa: BLE001
            pass

    # --- subprocess -------------------------------------------------------
    try:
        import subprocess

        real_popen_cls = subprocess.Popen

        class TracedPopen(real_popen_cls):  # type: ignore[misc, valid-type]
            def __init__(self, args, *a, **kw):  # noqa: ANN001, ANN002, ANN003
                _emit("subprocess", f"subprocess.Popen: {_truncate(args)}")
                super().__init__(args, *a, **kw)

        subprocess.Popen = TracedPopen  # type: ignore[misc]

        for fn_name in ("run", "call", "check_call", "check_output", "getoutput"):
            real_fn = getattr(subprocess, fn_name, None)
            if real_fn is None:
                continue

            def make_sp(name, fn):  # noqa: ANN001, ANN202
                def traced(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
                    detail = _truncate(args[0]) if args else _truncate(kwargs)
                    _emit("subprocess", f"subprocess.{name}: {detail}")
                    return fn(*args, **kwargs)

                return traced

            setattr(subprocess, fn_name, make_sp(fn_name, real_fn))
    except Exception:  # noqa: BLE001
        pass

    # --- sieć -------------------------------------------------------------
    try:
        import socket

        real_connect = socket.socket.connect

        def traced_connect(self, address, *a, **kw):  # noqa: ANN001, ANN002, ANN003
            try:
                result = real_connect(self, address, *a, **kw)
            except Exception as exc:  # noqa: BLE001
                _emit("network", f"connect {_truncate(address)} → {exc}", blocked=True)
                raise
            _emit("network", f"connect {_truncate(address)}", blocked=False)
            return result

        socket.socket.connect = traced_connect  # type: ignore[assignment]

        real_create = socket.create_connection

        def traced_create(address, *a, **kw):  # noqa: ANN001, ANN002, ANN003
            try:
                result = real_create(address, *a, **kw)
            except Exception as exc:  # noqa: BLE001
                _emit(
                    "network",
                    f"socket.create_connection {_truncate(address)} → {exc}",
                    blocked=True,
                )
                raise
            _emit(
                "network",
                f"socket.create_connection {_truncate(address)}",
                blocked=False,
            )
            return result

        socket.create_connection = traced_create  # type: ignore[assignment]

        real_getaddrinfo = socket.getaddrinfo

        def traced_getaddrinfo(host, port, *a, **kw):  # noqa: ANN001, ANN002, ANN003
            _emit("network", f"DNS lookup: {_truncate(host)}:{port}")
            return real_getaddrinfo(host, port, *a, **kw)

        socket.getaddrinfo = traced_getaddrinfo  # type: ignore[assignment]
    except Exception:  # noqa: BLE001
        pass

    # --- zapis plików -----------------------------------------------------
    real_open = builtins.open

    def traced_open(file, mode="r", *a, **kw):  # noqa: ANN001, ANN002, ANN003
        if any(flag in str(mode) for flag in ("w", "a", "x", "+")):
            _emit("file_write", f"open({_truncate(file)}, mode={mode!r})")
        return real_open(file, mode, *a, **kw)

    builtins.open = traced_open  # type: ignore[assignment]

    # --- dynamiczne wykonanie kodu ---------------------------------------
    real_eval, real_exec = builtins.eval, builtins.exec

    # Logujemy tylko wykonanie kodu podanego jako ŹRÓDŁO (str/bytes) — czyli
    # to, co faktycznie mógł dostarczyć payload. Maszyneria importów Pythona
    # woła exec() na gotowych obiektach code przy każdym imporcie; wrzucanie
    # tego do logu zaśmiecałoby dowody i myliło sędziego.
    def traced_eval(expr, *a, **kw):  # noqa: ANN001, ANN002, ANN003
        if isinstance(expr, (str, bytes)):
            _emit("code_exec", f"eval: {_truncate(expr)}")
        return real_eval(expr, *a, **kw)

    def traced_exec(code, *a, **kw):  # noqa: ANN001, ANN002, ANN003
        if isinstance(code, (str, bytes)):
            _emit("code_exec", f"exec: {_truncate(code)}")
        return real_exec(code, *a, **kw)

    builtins.eval = traced_eval  # type: ignore[assignment]
    builtins.exec = traced_exec  # type: ignore[assignment]

    real_import = builtins.__import__

    def traced_import(name, *a, **kw):  # noqa: ANN001, ANN002, ANN003
        if name in ("os", "posix", "subprocess", "socket", "shutil", "ctypes", "pty"):
            _emit("other", f"import {name}")
        return real_import(name, *a, **kw)

    builtins.__import__ = traced_import  # type: ignore[assignment]


def detonate(target: str) -> dict:
    _install_patches()

    started = time.monotonic()
    load_succeeded = False
    error = None

    print(f"[detoner] deserializacja {target}", flush=True)
    try:
        with open(target, "rb") as fh:
            pickle.load(fh)
        load_succeeded = True
        print("[detoner] pickle.load() zakończony bez wyjątku", flush=True)
    except Exception as exc:  # noqa: BLE001 — payload może rzucić czymkolwiek
        error = f"{type(exc).__name__}: {exc}"
        print(f"[detoner] pickle.load() rzucił wyjątek: {error}", flush=True)
        traceback.print_exc()

    duration_ms = int((time.monotonic() - started) * 1000)

    result = {
        "load_succeeded": load_succeeded,
        "duration_ms": duration_ms,
        "error": error,
        "events": _events,
    }
    sys.stdout.write(f"{RESULT_PREFIX} {json.dumps(result, ensure_ascii=False)}\n")
    sys.stdout.flush()
    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: detonate.py <plik.pkl>", file=sys.stderr)
        raise SystemExit(2)
    detonate(sys.argv[1])
