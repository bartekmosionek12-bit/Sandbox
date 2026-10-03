"""Warstwa 1 — parser statyczny plików pickle.

Rozkłada plik na opcody przez ``pickletools.genops`` (bezpieczne: NIE
wykonuje pickle'a, tylko czyta strumień bajtów), flaguje opcody dające
wykonanie dowolnego kodu (GLOBAL/STACK_GLOBAL/REDUCE/INST/OBJ/NEWOBJ)
i dopasowuje importy do listy niebezpiecznych modułów i symboli.

Output to kontrakt zgodny ze ``schemas/parser.schema.json``.
"""

from __future__ import annotations

import io
import pickletools
from typing import Any

SCHEMA_VERSION = "1.0"

# Opcody, które umożliwiają zbudowanie i wywołanie dowolnego obiektu.
# To jest rdzeń wektora RCE w pickle.
DANGEROUS_OPCODES = {
    "GLOBAL": "importuje dowolny obiekt po nazwie (module.attr)",
    "STACK_GLOBAL": "importuje dowolny obiekt po nazwie (wariant protokołu 4)",
    "REDUCE": "wywołuje callable ze stosu — faktyczne wykonanie kodu",
    "INST": "tworzy instancję dowolnej klasy (stary protokół)",
    "OBJ": "tworzy instancję dowolnej klasy ze stosu",
    "NEWOBJ": "tworzy obiekt przez __new__ dowolnej klasy",
    "NEWOBJ_EX": "jak NEWOBJ, z dodatkowymi argumentami",
    "BUILD": "wywołuje __setstate__ / aktualizuje stan obiektu",
}

# Moduły, których pojawienie się w GLOBAL jest silnym sygnałem złośliwości.
DANGEROUS_MODULES = {
    "os",
    "posix",
    "nt",
    "subprocess",
    "sys",
    "socket",
    "shutil",
    "builtins",
    "__builtin__",
    "importlib",
    "pty",
    "commands",
    "pickle",
    "runpy",
    "code",
    "ctypes",
}

# Opcody wrzucające literał stringowy na stos. Potrzebne, by odtworzyć
# argumenty STACK_GLOBAL, który sam nie ma argumentu.
STRING_PUSH_OPCODES = {
    "SHORT_BINUNICODE",
    "BINUNICODE",
    "BINUNICODE8",
    "UNICODE",
    "SHORT_BINSTRING",
    "BINSTRING",
    "STRING",
    "BINBYTES",
    "SHORT_BINBYTES",
}

# Konkretne symbole (callable), które same w sobie oznaczają wykonanie kodu.
DANGEROUS_SYMBOLS = {
    "system",
    "popen",
    "spawn",
    "spawnl",
    "spawnv",
    "exec",
    "execv",
    "execve",
    "execfile",
    "eval",
    "compile",
    "Popen",
    "call",
    "check_call",
    "check_output",
    "run",
    "getoutput",
    "getstatusoutput",
    "__import__",
    "load",
    "loads",
    "fromfile",
    "connect",
}


def _format_arg(arg: Any) -> str | None:
    if arg is None:
        return None
    if isinstance(arg, (tuple, list)):
        return " ".join(str(a) for a in arg)
    return str(arg)


def parse_pickle(data: bytes, file_name: str = "<memory>") -> dict:
    """Analizuje bajty pickle i zwraca kontrakt parsera (dict)."""

    report: dict = {
        "schema_version": SCHEMA_VERSION,
        "file_name": file_name,
        "file_format": "pickle",
        "opcodes": [],
        "flagged_opcodes": [],
        "suspicious_imports": [],
        "raw_disasm": "",
        "static_risk": "clean",
        "notes": [],
        "error": None,
    }

    # Surowy disasm do pokazania na dashboardzie. pickletools.dis NIE wykonuje
    # pickle'a — czyta tylko strumień opcode'ów.
    disasm_buf = io.StringIO()
    try:
        pickletools.dis(io.BytesIO(data), annotate=1, out=disasm_buf)
        report["raw_disasm"] = disasm_buf.getvalue()
    except Exception as exc:  # noqa: BLE001 — chcemy pokazać każdy błąd parsowania
        report["raw_disasm"] = disasm_buf.getvalue()
        report["notes"].append(f"pickletools.dis przerwany: {exc}")

    # Właściwy przebieg po opcodach.
    #
    # Uwaga na różnicę między protokołami:
    #   * GLOBAL (proto <= 3) ma argument "moduł\nsymbol".
    #   * STACK_GLOBAL (proto 4) NIE ma argumentu — moduł i symbol są
    #     wcześniej wrzucone na stos jako dwa osobne stringi. Dlatego
    #     śledzimy ostatnie literały stringowe, żeby odtworzyć import.
    try:
        string_stack: list[tuple[str, int]] = []
        for opcode, arg, pos in pickletools.genops(io.BytesIO(data)):
            name = opcode.name
            arg_str = _format_arg(arg)
            entry = {"name": name, "arg": arg_str, "pos": pos}
            report["opcodes"].append(entry)

            if name in DANGEROUS_OPCODES:
                flagged = dict(entry)
                flagged["reason"] = DANGEROUS_OPCODES[name]
                report["flagged_opcodes"].append(flagged)

            if name in STRING_PUSH_OPCODES and arg_str is not None:
                string_stack.append((arg_str, pos))
                continue

            module = symbol = None
            if name == "GLOBAL" and arg_str:
                # pickletools zwraca argument GLOBAL jako "moduł symbol".
                parts = arg_str.replace("\n", " ").split()
                if len(parts) >= 2:
                    module, symbol = parts[0], parts[1]
            elif name == "STACK_GLOBAL" and len(string_stack) >= 2:
                module = string_stack[-2][0]
                symbol = string_stack[-1][0]

            if module is not None and symbol is not None:
                if module in DANGEROUS_MODULES or symbol in DANGEROUS_SYMBOLS:
                    report["suspicious_imports"].append(
                        {"module": module, "symbol": symbol, "pos": pos}
                    )
    except Exception as exc:  # noqa: BLE001
        report["error"] = f"Błąd podczas analizy opcode'ów: {exc}"
        report["notes"].append(
            "Plik może być celowo zniekształcony, by utrudnić analizę statyczną."
        )

    report["static_risk"] = _score(report)
    return report


def _score(report: dict) -> str:
    """Heurystyka statyczna. Celowo ostrożna — ostateczny werdykt wydaje sędzia."""
    has_reduce = any(o["name"] == "REDUCE" for o in report["flagged_opcodes"])
    has_global = any(
        o["name"] in ("GLOBAL", "STACK_GLOBAL") for o in report["flagged_opcodes"]
    )
    suspicious = report["suspicious_imports"]

    # REDUCE + import niebezpiecznego symbolu = klasyczny łańcuch RCE.
    if has_reduce and suspicious:
        return "malicious"
    # Sam niebezpieczny import, albo REDUCE bez jasnego celu — podejrzane.
    if suspicious or (has_reduce and has_global):
        return "suspicious"
    return "clean"


def parse_file(path: str) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()
    import os

    return parse_pickle(data, file_name=os.path.basename(path))


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        print("usage: python -m sandbox_rce.parser <plik.pkl>", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(parse_file(sys.argv[1]), indent=2, ensure_ascii=False))
