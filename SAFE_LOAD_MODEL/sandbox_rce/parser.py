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
    # Moduły z callable'ami, które uruchamiają kod albo proces, choć nazwa
    # tego nie zdradza (znane obejścia skanerów opartych na liście):
    # pydoc.pipepager, timeit.timeit, cProfile.run, pdb.run, webbrowser.open...
    "_posixsubprocess",
    "multiprocessing",
    "asyncio",
    "pydoc",
    "pdb",
    "bdb",
    "timeit",
    "cProfile",
    "profile",
    "trace",
    "webbrowser",
    "marshal",
    "pip",
    "ensurepip",
    "venv",
    "zipimport",
    "_pyrepl",
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
    "getattr",
    "pipepager",
    "pipe_pager",
    "timeit",
    "runctx",
    "runcode",
    "run_path",
    "run_module",
    "import_module",
}

# Opcody zapisujące i odczytujące pamięć podręczną (memo) pickle'a. Bez ich
# śledzenia STACK_GLOBAL da się oszukać: moduł i symbol trafiają do memo,
# na stos wraca coś innego, a potem BINGET wyjmuje je tuż przed importem.
# Parser patrzący tylko na "dwa ostatnie stringi" widział wtedy niewinną parę.
_PUT_OPCODES = {"PUT", "BINPUT", "LONG_BINPUT"}
_GET_OPCODES = {"GET", "BINGET", "LONG_BINGET"}
_MARK = object()

# Typy wbudowane, które zwykły pickle w protokole 0–2 importuje z
# ``builtins``/``__builtin__``, żeby odtworzyć set, bytearray czy complex.
# Bez tego wyjątku moduł ``builtins`` na liście zrobiłby z każdego starego
# pickle'a ze zbiorem "malicious", a taki werdykt jest u nas nie do obniżenia.
SAFE_BUILTINS = {
    "set", "frozenset", "bytearray", "bytes", "complex", "slice", "range",
    "object", "list", "dict", "tuple", "int", "float", "str", "bool",
}

# Importy, którymi zwykłe modele numpy / scikit-learn odtwarzają swoje
# obiekty. Gdy plik importuje WYŁĄCZNIE z tej listy, REDUCE nie jest sam
# w sobie podejrzany. Bez tego heurystyka dawała "suspicious" 42 na 45
# łagodnych plikach z korpusu (tools/eval_static.py), czyli bez sędziego
# bramka odrzucała praktycznie każdy prawdziwy model.
#
# To lista dozwolonych, więc jej granica jest jawna: klasa z sklearn/numpy/
# scipy jest przepuszczana po kształcie nazwy (wielka litera), a nie po
# sprawdzeniu, że jej konstruktor nie ma efektów ubocznych. Kontrolą tego
# jest detonacja, nie parser.
KNOWN_SAFE_IMPORTS = {
    ("numpy", "dtype"),
    ("numpy", "ndarray"),
    ("numpy.core.multiarray", "_reconstruct"),
    ("numpy.core.multiarray", "scalar"),
    ("numpy._core.multiarray", "_reconstruct"),
    ("numpy._core.multiarray", "scalar"),
    ("numpy.core.numeric", "_frombuffer"),
    ("numpy._core.numeric", "_frombuffer"),
    ("_codecs", "encode"),
    ("copyreg", "_reconstructor"),
    ("copy_reg", "_reconstructor"),
    ("collections", "OrderedDict"),
    ("collections", "defaultdict"),
}
KNOWN_SAFE_ROOTS = {"numpy", "sklearn", "scipy"}


def _is_known_safe_import(module: str, symbol: str) -> bool:
    if (module, symbol) in KNOWN_SAFE_IMPORTS:
        return True
    root = module.split(".", 1)[0]
    if root in ("builtins", "__builtin__") and symbol in SAFE_BUILTINS:
        return True
    if root in KNOWN_SAFE_ROOTS and "." not in symbol:
        # Klasy, pomocnicze funkcje Cythona do odtwarzania obiektów
        # (__pyx_unpickle_*, newObj) i konstruktory generatorów numpy.
        return (
            symbol[:1].isupper()
            or symbol.startswith("__pyx_unpickle_")
            or symbol == "newObj"
            or (module == "numpy.random._pickle" and symbol.endswith("_ctor"))
        )
    return False


# Opcody, które WYWOŁUJĄ zaimportowany obiekt. REDUCE to najczęstszy, ale
# INST i OBJ robią dokładnie to samo (klasa albo dowolny callable z argumentami),
# więc heurystyka licząca tylko REDUCE dawała "clean" ładunkowi zbudowanemu
# na OBJ.
CALL_OPCODES = {"REDUCE", "INST", "OBJ"}


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
        # Wszystkie importy (także te nieflagowane) — do oceny listą dozwolonych.
        "imports": [],
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
    #   * STACK_GLOBAL (proto 4) NIE ma argumentu — moduł i symbol leżą
    #     wcześniej na stosie jako dwa osobne stringi. Żeby je odtworzyć,
    #     symulujemy stos maszyny pickle (bez wykonywania czegokolwiek):
    #     efekt każdego opcode'u bierzemy z opisu w pickletools, a wartości
    #     śledzimy tylko dla stringów i memo. Wcześniejsza wersja brała "dwa
    #     ostatnie wrzucone stringi", co dało się obejść przez MEMOIZE/BINGET.
    try:
        stack: list = []
        memo: dict = {}
        for opcode, arg, pos in pickletools.genops(io.BytesIO(data)):
            name = opcode.name
            arg_str = _format_arg(arg)
            entry = {"name": name, "arg": arg_str, "pos": pos}
            report["opcodes"].append(entry)

            if name in DANGEROUS_OPCODES:
                flagged = dict(entry)
                flagged["reason"] = DANGEROUS_OPCODES[name]
                report["flagged_opcodes"].append(flagged)

            module = symbol = None
            if name in STRING_PUSH_OPCODES:
                stack.append(arg_str)
            elif name == "MEMOIZE":
                memo[len(memo)] = stack[-1] if stack else None
            elif name in _PUT_OPCODES:
                memo[arg] = stack[-1] if stack else None
            elif name in _GET_OPCODES:
                stack.append(memo.get(arg))
            elif name == "STACK_GLOBAL":
                symbol = stack.pop() if stack else None
                module = stack.pop() if stack else None
                stack.append(None)
                if not (isinstance(module, str) and isinstance(symbol, str)):
                    report["notes"].append(
                        f"STACK_GLOBAL na pozycji {pos}: nie udało się odtworzyć "
                        "nazwy importu ze stosu — import nieznany."
                    )
                    module = symbol = None
            else:
                if name in ("GLOBAL", "INST") and arg_str:
                    # pickletools zwraca argument GLOBAL i INST jako "moduł symbol".
                    parts = arg_str.replace("\n", " ").split()
                    if len(parts) >= 2:
                        module, symbol = parts[0], parts[1]
                _apply_stack_effect(opcode, stack)

            if name == "STACK_GLOBAL" and module is None:
                report["imports"].append({"module": None, "symbol": None, "pos": pos})
            if module is not None and symbol is not None:
                report["imports"].append({"module": module, "symbol": symbol, "pos": pos})
                if _is_dangerous_import(module, symbol):
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


def _is_dangerous_import(module: str, symbol: str) -> bool:
    """Moduł lub symbol z listy — także w formie z kropkami.

    ``os.path`` ma korzeń ``os``, a symbol ``Popen.__init__`` czy
    ``sys.modules`` kończy się nazwą, którą warto zobaczyć w raporcie.
    """
    root = module.split(".", 1)[0]
    if root in ("builtins", "__builtin__") and symbol in SAFE_BUILTINS:
        return False
    leaf = symbol.rsplit(".", 1)[-1]
    head = symbol.split(".", 1)[0]
    return (
        module in DANGEROUS_MODULES
        or root in DANGEROUS_MODULES
        or symbol in DANGEROUS_SYMBOLS
        or leaf in DANGEROUS_SYMBOLS
        or head in DANGEROUS_SYMBOLS
    )


def _apply_stack_effect(opcode, stack: list) -> None:
    """Zdejmuje i dokłada elementy stosu według opisu opcode'u w pickletools.

    Wartości nas nie interesują (poza stringami, obsłużonymi wyżej), więc
    wynik każdej operacji to ``None``. Pusty stos nie przerywa analizy:
    zniekształcony plik i tak dostanie notatkę i ostrożny wynik.
    """
    before = opcode.stack_before
    if pickletools.markobject in before:
        while stack:
            if stack.pop() is _MARK:
                break
        for _ in range(before.index(pickletools.markobject)):
            if stack:
                stack.pop()
    else:
        for _ in before:
            if stack:
                stack.pop()
    for item in opcode.stack_after:
        stack.append(_MARK if item is pickletools.markobject else None)


def _score(report: dict) -> str:
    """Heurystyka statyczna. Celowo ostrożna — ostateczny werdykt wydaje sędzia."""
    has_reduce = any(o["name"] in CALL_OPCODES for o in report["flagged_opcodes"])
    has_global = any(
        o["name"] in ("GLOBAL", "STACK_GLOBAL") for o in report["flagged_opcodes"]
    )
    suspicious = report["suspicious_imports"]

    # REDUCE + import niebezpiecznego symbolu = klasyczny łańcuch RCE.
    if has_reduce and suspicious:
        return "malicious"
    # Pliku, którego parser nie umiał przeczytać do końca, nie wolno uznać za
    # czysty: to, czego nie przeczytaliśmy, mogło być ładunkiem. Wcześniej
    # dowolny nie-pickle (np. plik tekstowy) wychodził jako "clean".
    if report.get("error"):
        return "suspicious"
    if suspicious:
        return "suspicious"
    # Wywołanie obiektu spoza listy dozwolonych — cel nieznany, podejrzane.
    if has_reduce and has_global:
        imports = report.get("imports") or []
        if imports and all(
            i["module"] is not None and _is_known_safe_import(i["module"], i["symbol"])
            for i in imports
        ):
            report["notes"].append(
                "Wszystkie importy pochodzą z listy znanych konstruktorów "
                "numpy/scikit-learn — REDUCE uznany za odtwarzanie obiektów."
            )
            return "clean"
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
