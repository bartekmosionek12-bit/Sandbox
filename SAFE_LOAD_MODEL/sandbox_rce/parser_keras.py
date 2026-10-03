"""Warstwa 1 dla plików ``.keras`` — parser statyczny.

``.keras`` to archiwum ZIP zawierające m.in. ``config.json`` z opisem
architektury modelu. Wektor wykonania kodu jest tu inny niż w pickle, ale
równie realny:

* **Lambda layer** — warstwa przechowuje zserializowaną funkcję Pythona
  (zmarshallowany obiekt code w base64, pole ``function``). Przy
  ``load_model(safe_mode=False)`` ta funkcja jest odtwarzana i wykonywana.
* **custom_objects / registered_name** — model odwołuje się po nazwie do
  klasy spoza Kerasa, którą ładujący musi dostarczyć; to ścieżka do
  wykonania cudzego kodu w procesie ładującym.

Parser **nie uruchamia Kerasa** — czyta wyłącznie JSON z archiwum, tak jak
pickle'owy czyta opcody bez deserializacji.

Output to ten sam kontrakt co ``parser.py`` (``schemas/parser.schema.json``),
dzięki czemu dashboard i sędzia nie muszą wiedzieć, jaki to format.
"""

from __future__ import annotations

import json
import os
import zipfile

SCHEMA_VERSION = "1.0"

CONFIG_CANDIDATES = ("config.json", "model.json")
METADATA_NAME = "metadata.json"

# Konstrukcje w config.json dające wykonanie kodu przy ładowaniu modelu.
DANGEROUS_CLASSES = {
    "Lambda": "warstwa Lambda przechowuje zserializowaną funkcję Pythona, "
              "wykonywaną przy load_model(safe_mode=False)",
    "TFOpLambda": "wariant Lambda opakowujący operację TF",
    "SlicingOpLambda": "wariant Lambda dla operacji slicingu",
}

# Moduły, których obecność w polu "module" oznacza kod spoza Kerasa.
SAFE_MODULE_PREFIXES = ("keras", "tensorflow", "tf", "builtins.")

# Wbudowane kontenery Kerasa, którym Keras sam wpisuje registered_name.
KERAS_CONTAINER_CLASSES = {"Functional", "Sequential", "Model"}


def _empty_report(file_name: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "file_name": file_name,
        "file_format": "keras",
        "opcodes": [],
        "flagged_opcodes": [],
        "suspicious_imports": [],
        "raw_disasm": "",
        "static_risk": "clean",
        "notes": [],
        "error": None,
    }


def _walk(node, path: str, report: dict) -> None:
    """Rekurencyjnie przechodzi config.json i flaguje niebezpieczne konstrukcje."""
    if isinstance(node, list):
        for index, item in enumerate(node):
            _walk(item, f"{path}[{index}]", report)
        return

    if not isinstance(node, dict):
        return

    class_name = node.get("class_name")
    if isinstance(class_name, str):
        # Każda warstwa trafia do "opcodes" jako inwentarz architektury.
        report["opcodes"].append({"name": class_name, "arg": path, "pos": 0})

        if class_name in DANGEROUS_CLASSES:
            entry = {
                "name": class_name,
                "arg": path,
                "pos": 0,
                "reason": DANGEROUS_CLASSES[class_name],
            }
            report["flagged_opcodes"].append(entry)

            # Lambda z faktycznym bytecode'em to najmocniejsza przesłanka.
            config = node.get("config")
            if isinstance(config, dict):
                function = config.get("function")
                if _carries_code(function):
                    report["suspicious_imports"].append(
                        {
                            "module": "keras.layers.Lambda",
                            "symbol": "function (zserializowany bytecode)",
                            "pos": None,
                        }
                    )
                    report["notes"].append(
                        f"{path}: warstwa Lambda niesie zserializowany kod Pythona."
                    )

    # registered_name wskazuje obiekt spoza standardowego Kerasa — ale TYLKO
    # wtedy, gdy faktycznie jest custom. Keras wpisuje tu również własne
    # kontenery ("Functional", "Sequential") razem z modułem keras.*, więc
    # flagowanie każdego registered_name dawało "suspicious" na każdym
    # normalnym modelu funkcyjnym. Patrz _is_custom_registration.
    registered = node.get("registered_name")
    if isinstance(registered, str) and registered:
        if _is_custom_registration(registered, node.get("module")):
            report["suspicious_imports"].append(
                {"module": registered, "symbol": "registered_name", "pos": None}
            )
            report["notes"].append(
                f"{path}: odwołanie do custom object '{registered}' — ładujący musi "
                "dostarczyć tę klasę, co jest ścieżką do wykonania cudzego kodu."
            )

    module = node.get("module")
    if isinstance(module, str) and module:
        if not module.startswith(SAFE_MODULE_PREFIXES):
            report["suspicious_imports"].append(
                {"module": module, "symbol": "module", "pos": None}
            )
            report["notes"].append(f"{path}: moduł spoza Kerasa — '{module}'.")

    for key, value in node.items():
        _walk(value, f"{path}.{key}" if path else str(key), report)


def _is_custom_registration(registered: str, module) -> bool:
    """Czy ``registered_name`` wskazuje obiekt spoza Kerasa?

    Rozstrzyga to jeden sprawdzony na żywo szczegół formatu: obiekt zapisany
    przez ``@keras.saving.register_keras_serializable(package=...)`` dostaje
    ``registered_name`` w formie ``pakiet>Klasa`` (i zwykle ``module: null``),
    a wbudowany kontener Kerasa dostaje samą nazwę klasy razem z modułem
    ``keras.*``. Bez tego rozróżnienia każdy zwyczajny model funkcyjny
    wychodził jako „suspicious", bo Keras wpisuje mu ``registered_name:
    "Functional"``.
    """
    if ">" in registered:
        return True
    if isinstance(module, str) and module:
        return not module.startswith(SAFE_MODULE_PREFIXES)
    # Brak modułu przy nazwie bez separatora — nie ma po czym poznać, że to
    # Keras, więc traktujemy jako custom (fail closed).
    return registered not in KERAS_CONTAINER_CLASSES


def _carries_code(function) -> bool:
    """Czy pole 'function' niesie zserializowany kod, a nie samą nazwę?"""
    if isinstance(function, dict):
        config = function.get("config")
        if isinstance(config, dict) and config.get("code"):
            return True
        if function.get("class_name") in ("__lambda__", "function"):
            return True
    # Starsze zapisy trzymały tu listę [code, defaults, closure].
    return isinstance(function, list) and bool(function)


def parse_keras(data: bytes, file_name: str = "<memory>") -> dict:
    report = _empty_report(file_name)

    import io

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        report["error"] = f"Plik nie jest poprawnym archiwum .keras (ZIP): {exc}"
        report["static_risk"] = "suspicious"
        report["notes"].append(
            "Plik .keras musi być archiwum ZIP. Uszkodzony lub podrobiony "
            "nagłówek sam w sobie jest podejrzany."
        )
        return report

    with archive:
        names = archive.namelist()
        report["notes"].append(f"Zawartość archiwum: {', '.join(names[:20])}")

        config_name = next((n for n in CONFIG_CANDIDATES if n in names), None)
        if config_name is None:
            report["error"] = (
                "Archiwum nie zawiera config.json — nie ma czego analizować."
            )
            report["static_risk"] = "suspicious"
            return report

        try:
            raw = archive.read(config_name).decode("utf-8", errors="replace")
            config = json.loads(raw)
        except Exception as exc:  # noqa: BLE001
            report["error"] = f"Nie udało się odczytać {config_name}: {exc}"
            report["static_risk"] = "suspicious"
            return report

        report["raw_disasm"] = json.dumps(config, indent=2, ensure_ascii=False)
        _walk(config, "", report)

    report["static_risk"] = _score(report)
    return report


def _score(report: dict) -> str:
    has_lambda = any(
        o["name"] in DANGEROUS_CLASSES for o in report["flagged_opcodes"]
    )
    carries_code = any(
        i["symbol"].startswith("function") for i in report["suspicious_imports"]
    )
    other_suspicious = bool(report["suspicious_imports"])

    # Lambda z osadzonym bytecode'em to odpowiednik REDUCE + niebezpieczny import.
    if has_lambda and carries_code:
        return "malicious"
    if has_lambda or other_suspicious:
        return "suspicious"
    return "clean"


def parse_file(path: str) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()
    return parse_keras(data, file_name=os.path.basename(path))


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("usage: python -m sandbox_rce.parser_keras <model.keras>", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(parse_file(sys.argv[1]), indent=2, ensure_ascii=False))
