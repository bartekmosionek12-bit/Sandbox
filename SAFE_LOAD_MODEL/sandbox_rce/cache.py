"""Cache wyników skanu po skrócie pliku.

Detonacja ``.keras`` trwa około minuty, bo w kontenerze startuje TensorFlow.
W CI ten sam model bywa sprawdzany przy każdym przebiegu, więc wynik
zapisujemy pod kluczem złożonym ze skrótu SHA-256 pliku i odcisku silnika
(kod biblioteki, pliki obrazu, model sędziego, runtime kontenera). Zmiana
któregokolwiek z nich daje nowy klucz, czyli skan od nowa.

Cache jest WYŁĄCZONY domyślnie. Włącza go parametr ``cache_dir`` albo
zmienna środowiskowa ``SAFELOADAI_CACHE_DIR``.

Granica, którą trzeba znać: kto może pisać do katalogu cache, ten może
wpisać plikowi werdykt "safe". Katalog musi być zapisywalny wyłącznie dla
użytkownika (albo zadania CI), który uruchamia skan.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile

CACHE_ENV = "SAFELOADAI_CACHE_DIR"
CACHE_FORMAT = 1

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_PACKAGE_DIR)


def resolve_dir(cache_dir: str | os.PathLike | None) -> str | None:
    value = os.fspath(cache_dir) if cache_dir is not None else os.environ.get(CACHE_ENV)
    return os.path.expanduser(value) if value else None


def engine_fingerprint() -> str:
    """Odcisk wszystkiego, co wpływa na werdykt, poza samym plikiem."""
    digest = hashlib.sha256()
    for directory, names in (
        (_PACKAGE_DIR, sorted(n for n in os.listdir(_PACKAGE_DIR) if n.endswith(".py"))),
        (os.path.join(_ROOT, "docker"), None),
    ):
        if names is None:
            try:
                names = sorted(os.listdir(directory))
            except OSError:
                names = []
        for name in names:
            full = os.path.join(directory, name)
            if not os.path.isfile(full):
                continue
            digest.update(name.encode())
            with open(full, "rb") as fh:
                digest.update(fh.read())
    from sandbox_rce import judge  # noqa: PLC0415 — unikamy cyklu importów

    digest.update(judge.DEFAULT_MODEL.encode())
    digest.update((os.environ.get("SANDBOX_RUNTIME") or "").encode())
    # Bez klucza werdykt pochodzi z heurystyki. Wynik z heurystyki nie może
    # zostać podany jako wynik sędziego, kiedy klucz się pojawi.
    digest.update(b"judge" if os.environ.get("ANTHROPIC_API_KEY") else b"nojudge")
    return digest.hexdigest()[:16]


def _entry_path(cache_dir: str, sha256: str, fingerprint: str) -> str:
    return os.path.join(cache_dir, f"{sha256}-{fingerprint}.json")


def load(cache_dir: str, sha256: str) -> dict | None:
    fingerprint = engine_fingerprint()
    path = _entry_path(cache_dir, sha256, fingerprint)
    try:
        with open(path, encoding="utf-8") as fh:
            entry = json.load(fh)
    except (OSError, ValueError):
        return None
    if entry.get("format") != CACHE_FORMAT or entry.get("sha256") != sha256:
        return None
    report = entry.get("report")
    if not isinstance(report, dict):
        return None
    report["cache"] = {"hit": True, "file": path, "engine": fingerprint}
    return report


def is_cacheable(report: dict) -> bool:
    """Zapisujemy tylko pełne skany.

    Bez detonacji, po przekroczeniu limitu czasu albo gdy sędzia miał być,
    a się nie odezwał (błąd API), wynik jest stanem chwilowym, nie wynikiem.
    """
    sandbox = report.get("sandbox") or {}
    judge = report.get("judge") or {}
    if not sandbox.get("detonated") or sandbox.get("timed_out"):
        return False
    if os.environ.get("ANTHROPIC_API_KEY") and not judge.get("available"):
        return False
    return True


def store(cache_dir: str, sha256: str, report: dict) -> None:
    if not is_cacheable(report):
        return
    os.makedirs(cache_dir, mode=0o700, exist_ok=True)
    path = _entry_path(cache_dir, sha256, engine_fingerprint())
    clean = {k: v for k, v in report.items() if k != "cache"}
    entry = {"format": CACHE_FORMAT, "sha256": sha256, "report": clean}
    # Zapis atomowy: przerwany zapis nie zostawi uciętego JSON-a.
    fd, tmp = tempfile.mkstemp(dir=cache_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(entry, fh, ensure_ascii=False)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
