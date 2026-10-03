"""Spina warstwy w jeden przebieg: parser → sandbox → sędzia.

Zwraca jeden obiekt z kontraktami w środku. Dashboard konsumuje wyłącznie
to; nie wie nic o pickle'u ani o Dockerze. Obsługiwane formaty: .pkl i
.keras — oba z realną detonacją w kontenerze.
"""

from __future__ import annotations

import os
from typing import Callable

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


def final_verdict(parser_report: dict, judge_report: dict) -> tuple[str, str]:
    """Werdykt końcowy + skąd się wziął.

    Sędzia decyduje, jeśli jest dostępny. Bez sędziego spadamy na heurystykę
    statyczną i mówimy o tym otwarcie — zamiast udawać, że mamy werdykt AI.
    """
    if judge_report.get("available"):
        return judge_report.get("verdict", "unknown"), "sędzia LLM"

    static = parser_report.get("static_risk", "unknown")
    mapped = {"clean": "safe"}.get(static, static)
    return mapped, "heurystyka statyczna (sędzia niedostępny)"


def analyze(
    path: str,
    detonate: bool = True,
    progress: Callable[[str], None] | None = None,
) -> dict:
    def step(message: str) -> None:
        if progress:
            progress(message)

    extension = os.path.splitext(path)[1].lower()
    is_keras = extension in KERAS_EXTENSIONS

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

    verdict, source = final_verdict(parser_report, judge_report)

    return {
        "file_name": os.path.basename(path),
        "parser": parser_report,
        "sandbox": sandbox_report,
        "judge": judge_report,
        "final_verdict": verdict,
        "verdict_source": source,
    }


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
