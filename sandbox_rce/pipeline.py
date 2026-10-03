"""Spina trzy warstwy w jeden przebieg: parser → sandbox → sędzia.

Zwraca jeden obiekt z trzema kontraktami w środku. Dashboard konsumuje
wyłącznie to; nie wie nic o pickle'u ani o Dockerze.
"""

from __future__ import annotations

import os
from typing import Callable

from sandbox_rce import judge as judge_mod
from sandbox_rce import parser as parser_mod
from sandbox_rce import parser_keras as parser_keras_mod
from sandbox_rce import sandbox as sandbox_mod
from sandbox_rce import stego as stego_mod

# Rozszerzenia obsługiwane przez poszczególne parsery statyczne.
PICKLE_EXTENSIONS = {".pkl", ".pickle"}
KERAS_EXTENSIONS = {".keras"}
# Pliki z samymi wagami — nie ma w nich kodu do detonacji, liczy się dla nich
# wyłącznie warstwa LSB (tensor steganography).
WEIGHT_EXTENSIONS = {".npy", ".npz"}

KERAS_DETONATION_DISABLED = (
    "Detonacja .keras wyłączona przez wywołującego — werdykt z analizy "
    "statycznej konfiguracji modelu."
)

# Kolejność ważności werdyktów — do wyznaczenia wyniku końcowego.
_SEVERITY = {"malicious": 3, "suspicious": 2, "safe": 1, "clean": 1, "unknown": 0}


def _has_trigger(parser_report: dict) -> bool:
    """Czy w pliku jest wyzwalacz wykonania kodu (REDUCE / Lambda / custom)?

    Decyduje o tym, czy anomalia LSB to tylko ``suspicious``, czy już pełny
    łańcuch ``malicious``.
    """
    if parser_report.get("flagged_opcodes") or parser_report.get("suspicious_imports"):
        return True
    return parser_report.get("static_risk") in ("malicious", "suspicious")


def _weights_only_report(path: str) -> dict:
    """Minimalny raport parsera dla pliku z samymi wagami (.npy/.npz).

    Zgodny kształtem z kontraktem parsera, żeby dashboard i sędzia nie musiały
    wiedzieć, że to inny format. Taki plik nie zawiera kodu — cały sygnał
    niesie warstwa LSB.
    """
    return {
        "schema_version": "1.0",
        "file_name": os.path.basename(path),
        "file_format": "weights",
        "opcodes": [],
        "flagged_opcodes": [],
        "suspicious_imports": [],
        "raw_disasm": "",
        "static_risk": "clean",
        "notes": [
            "Plik z samymi wagami (tablice liczb) — brak opcode'ów i kodu. "
            "Analiza skupia się na warstwie LSB (tensor steganography)."
        ],
        "error": None,
    }


def final_verdict(
    parser_report: dict, judge_report: dict, stego_report: dict | None = None
) -> tuple[str, str]:
    """Werdykt końcowy + skąd się wziął.

    Sędzia decyduje o warstwie kodu, jeśli jest dostępny; bez niego spadamy na
    heurystykę statyczną i mówimy o tym otwarcie. Niezależnie od tego warstwa
    LSB może **podnieść** werdykt: sama anomalia do ``suspicious``, a anomalia
    z wyzwalaczem do ``malicious``.
    """
    if judge_report.get("available"):
        verdict, source = judge_report.get("verdict", "unknown"), "sędzia LLM"
    else:
        static = parser_report.get("static_risk", "unknown")
        verdict = {"clean": "safe"}.get(static, static)
        source = "heurystyka statyczna (sędzia niedostępny)"

    stego_risk = (stego_report or {}).get("stego_risk", "clean")
    if _SEVERITY.get(stego_risk, 0) > _SEVERITY.get(verdict, 0):
        verdict = stego_risk
        label = "LSB + wyzwalacz" if stego_risk == "malicious" else "anomalia LSB"
        source = f"tensor steganography ({label})"
    return verdict, source


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
    is_weights_only = extension in WEIGHT_EXTENSIONS

    step("Analiza statyczna pliku")
    if is_keras:
        parser_report = parser_keras_mod.parse_file(path)
    elif is_weights_only:
        parser_report = _weights_only_report(path)
    else:
        parser_report = parser_mod.parse_file(path)

    if is_weights_only:
        sandbox_report = sandbox_mod._empty_report(
            os.path.basename(path),
            "Plik zawiera wyłącznie dane (wagi) — nie ma czego detonować. "
            "Sygnał niesie analiza LSB poniżej.",
        )
    elif not detonate:
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

    # Warstwa LSB (tensor steganography) — statyczna i bezpieczna, czyta tylko
    # dane. Wyzwalacz bierzemy z parsera: anomalia LSB + wyzwalacz = malicious.
    step("Analiza LSB wag (tensor steganography)")
    trigger_present = _has_trigger(parser_report)
    stego_report = stego_mod.analyze_file(path, trigger_present=trigger_present)

    step("Ocena przez sędziego LLM")
    judge_report = judge_mod.judge(parser_report, sandbox_report)

    verdict, source = final_verdict(parser_report, judge_report, stego_report)

    return {
        "file_name": os.path.basename(path),
        "parser": parser_report,
        "sandbox": sandbox_report,
        "stego": stego_report,
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
            "usage: python -m sandbox_rce.pipeline [--no-detonate] <plik.pkl>",
            file=sys.stderr,
        )
        raise SystemExit(2)

    result = analyze(
        args[0],
        detonate=not no_detonate,
        progress=lambda m: print(f"[*] {m}", file=sys.stderr),
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
