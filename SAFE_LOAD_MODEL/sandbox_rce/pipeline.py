"""Spina warstwy w jeden przebieg: parser → sandbox → sędzia.

Zwraca jeden obiekt z kontraktami w środku. Dashboard konsumuje wyłącznie
to; nie wie nic o pickle'u ani o Dockerze. Obsługiwane formaty: .pkl i
.keras — oba z realną detonacją w kontenerze.
"""

from __future__ import annotations

import hashlib
import os
from typing import Callable

from sandbox_rce import cache as cache_mod
from sandbox_rce import judge as judge_mod
from sandbox_rce import parser as parser_mod
from sandbox_rce import parser_keras as parser_keras_mod
from sandbox_rce import sandbox as sandbox_mod

# Rozszerzenia obsługiwane przez poszczególne parsery statyczne.
PICKLE_EXTENSIONS = {".pkl", ".pickle"}
KERAS_EXTENSIONS = {".keras"}

KERAS_DETONATION_DISABLED = (
    "Detonacja .keras wyłączona przez wywołującego — werdykt z analizy "
    "statycznej konfiguracji modelu."
)

# Kolejność ważności werdyktów — do wyznaczenia wyniku końcowego.
_SEVERITY = {"malicious": 3, "suspicious": 2, "safe": 1, "clean": 1, "unknown": 0}

# Zdarzenia z detonacji, które same w sobie są dowodem wykonania kodu: zwykły
# model przy wczytaniu nie uruchamia procesów i nie łączy się z siecią.
# Celowo NIE ma tu "file_write", "code_exec" ani "other" — te potrafi
# wygenerować sam framework (Keras/TF), więc oceniamy je w kontekście.
HARD_EVENT_TYPES = {"os_system", "subprocess", "network"}


def hard_evidence(parser_report: dict, sandbox_report: dict, judge_report: dict) -> list[str]:
    """Przesłanki, których żadna warstwa nie może "przegłosować".

    Sędzia LLM czyta treść kontrolowaną przez atakującego, więc jego
    werdykt "safe" nie może zbić dowodu, który zebrały warstwy niezależne od
    modelu językowego. Zwraca listę opisów (pusta = brak twardych przesłanek).
    """
    found: list[str] = []
    hard_events = [
        e for e in sandbox_report.get("events") or []
        if e.get("type") in HARD_EVENT_TYPES
    ]
    if hard_events:
        kinds = sorted({e.get("type") for e in hard_events})
        found.append(
            f"detonacja zarejestrowała {len(hard_events)} zdarzeń typu "
            f"{', '.join(kinds)}"
        )
    if parser_report.get("static_risk") == "malicious":
        found.append("parser statyczny ocenił plik jako malicious")
    if judge_report.get("injection_attempt_detected"):
        found.append("sędzia wykrył w danych próbę sterowania oceną")
    return found


def final_verdict(
    parser_report: dict,
    judge_report: dict,
    sandbox_report: dict | None = None,
) -> tuple[str, str]:
    """Werdykt końcowy + skąd się wziął.

    Sędzia decyduje, jeśli jest dostępny — ale tylko w górę od twardych
    przesłanek, nigdy w dół. Bez sędziego spadamy na heurystykę statyczną
    i mówimy o tym otwarcie, a log z detonacji i tak jest brany pod uwagę.

    Poprzednia wersja przy braku sędziego patrzyła wyłącznie na parser:
    plik, którego parser nie rozpoznał, a który w kontenerze uruchomił
    os.system, dostawał "safe" i był wczytywany na hoście.
    """
    sandbox_report = sandbox_report or {}
    evidence = hard_evidence(parser_report, sandbox_report, judge_report)
    executed = any(
        e.get("type") in HARD_EVENT_TYPES for e in sandbox_report.get("events") or []
    )

    if judge_report.get("available"):
        verdict, source = judge_report.get("verdict", "unknown"), "sędzia LLM"
    else:
        static = parser_report.get("static_risk", "unknown")
        verdict = {"clean": "safe"}.get(static, static)
        source = "heurystyka statyczna (sędzia niedostępny)"

    floor = "malicious" if executed else ("suspicious" if evidence else None)
    if floor and _SEVERITY.get(verdict, 0) < _SEVERITY[floor]:
        verdict = floor
        source += " — podniesione przez twarde przesłanki: " + "; ".join(evidence)
    return verdict, source


def file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analyze(
    path: str,
    detonate: bool = True,
    progress: Callable[[str], None] | None = None,
    cache_dir: str | os.PathLike | None = None,
) -> dict:
    """Pełny przebieg: parser → detonacja → sędzia → werdykt końcowy.

    ``cache_dir`` (albo zmienna ``SAFELOADAI_CACHE_DIR``) włącza cache po
    skrócie pliku — patrz ``sandbox_rce/cache.py``.
    """
    def step(message: str) -> None:
        if progress:
            progress(message)

    path = os.fspath(path)
    extension = os.path.splitext(path)[1].lower()
    is_keras = extension in KERAS_EXTENSIONS
    sha256 = file_sha256(path)

    directory = cache_mod.resolve_dir(cache_dir) if detonate else None
    if directory:
        cached = cache_mod.load(directory, sha256)
        if cached is not None:
            step("Wynik z cache (ten sam plik, ta sama wersja silnika)")
            cached["file_name"] = os.path.basename(path)
            return cached

    step("Analiza statyczna pliku")
    parser_report = (
        parser_keras_mod.parse_file(path) if is_keras else parser_mod.parse_file(path)
    )

    if not detonate:
        reason = (
            KERAS_DETONATION_DISABLED
            if is_keras
            else "Detonacja wyłączona przez wywołującego."
        )
        sandbox_report = sandbox_mod._empty_report(os.path.basename(path), reason)
    elif is_keras:
        step("Detonacja w izolowanym kontenerze (keras)")
        sandbox_report = sandbox_mod.detonate_in_docker(path, profile="keras")
    else:
        step("Detonacja w izolowanym kontenerze")
        sandbox_report = sandbox_mod.detonate_in_docker(path, profile="pickle")

    step("Ocena przez sędziego LLM")
    judge_report = judge_mod.judge(parser_report, sandbox_report)

    verdict, source = final_verdict(parser_report, judge_report, sandbox_report)

    report = {
        "file_name": os.path.basename(path),
        "sha256": sha256,
        "parser": parser_report,
        "sandbox": sandbox_report,
        "judge": judge_report,
        "final_verdict": verdict,
        "verdict_source": source,
        "cache": {"hit": False},
    }
    if directory:
        cache_mod.store(directory, sha256, report)
    return report


if __name__ == "__main__":
    import json
    import sys

    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    no_detonate = "--no-detonate" in sys.argv

    if len(args) != 1:
        print(
            "usage: python -m sandbox_rce.pipeline [--no-detonate] <plik.pkl|.keras>",
            file=sys.stderr,
        )
        raise SystemExit(2)

    result = analyze(
        args[0],
        detonate=not no_detonate,
        progress=lambda m: print(f"[*] {m}", file=sys.stderr),
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
