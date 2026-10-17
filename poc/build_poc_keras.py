"""Generator fixture'ów ``.keras`` — drugi format, ten sam schemat ataku.

``.keras`` to archiwum ZIP z ``config.json``. Budujemy je ręcznie, bez
instalowania Kerasa ani TensorFlow: do testu parsera statycznego liczy się
struktura JSON-a, a nie to, czy model da się wytrenować.

Plik złośliwy niesie **warstwę Lambda ze zserializowaną funkcją Pythona**
(zmarshallowany obiekt code w base64) — dokładnie tak, jak robi to Keras.
Przy ``load_model(safe_mode=False)`` taka funkcja zostaje odtworzona
i wykonana. Efekt jest nieszkodliwy i widoczny: ``touch /tmp/pwned_keras``.

Dwa szczegóły, bez których fixture wygląda na złośliwy w parserze, ale
w detonacji daje pusty log (czyli fałszywy dowód niewinności):

* obiekt code musi przyjmować **jeden argument**, bo Keras woła funkcję
  warstwy jako ``fn(inputs)``;
* ``model.weights.h5`` musi być **poprawnym** plikiem HDF5, a model nie może
  mieć warstw z wagami (Dense), bo pustego magazynu wag Keras nie przyjmie.
  Dlatego fixture'y składają się z warstw bez zmiennych.
"""

from __future__ import annotations

import base64
import json
import marshal
import os
import platform
import zipfile

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")

MARKER = "/tmp/pwned_keras"

# Pusty, ale POPRAWNY plik HDF5 (800 B, wygenerowany przez h5py). Trzymamy go
# jako stałą, żeby generator fixture'ów nie wymagał h5py na maszynie, na
# której się go odpala.
EMPTY_HDF5_B64 = (
    "iUhERg0KGgoAAAAAAAgIAAQAEAAAAAAAAAAAAAAAAAD//////////yADAAAAAAAA//////////8A"
    "AAAAAAAAAGAAAAAAAAAAAQAAAAAAAACIAAAAAAAAAKgCAAAAAAAAAQABAAEAAAAYAAAAAAAAABEA"
    "EAAAAAAAiAAAAAAAAACoAgAAAAAAAFRSRUUAAAAA/////////////////////wAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIRUFQ"
    "AAAAAFgAAAAAAAAACAAAAAAAAADIAgAAAAAAAAAAAAAAAAAAAQAAAAAAAABQAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAA="
)


def _serialized_payload() -> str:
    """Zwraca base64 ze zmarshallowanego obiektu code — tak jak Keras.

    Keras serializuje funkcję warstwy Lambda przez ``marshal.dumps`` na
    obiekcie code i koduje wynik base64. Odtworzenie tego kodu przy
    ładowaniu modelu jest właśnie wektorem RCE.
    """
    # Keras woła funkcję warstwy jako fn(inputs), więc obiekt code MUSI
    # przyjmować jeden argument. Pierwsza wersja marshalowała wyrażenie
    # bez argumentów i Keras wywalał się na "takes 0 positional arguments"
    # PRZED wykonaniem ciała — plik jawnie złośliwy dawał pusty log
    # zdarzeń, czyli wyglądał na czysty. Jest na to test regresyjny.
    source = f"lambda x: (__import__('os').system('touch {MARKER}'), x)[1]"
    fn = eval(compile(source, "<lambda>", "eval"))  # noqa: S307 — nasz własny literał
    return base64.b64encode(marshal.dumps(fn.__code__)).decode("ascii")


def _malicious_config() -> dict:
    return {
        "module": "keras",
        "class_name": "Sequential",
        "config": {
            "name": "sequential",
            "layers": [
                {
                    "module": "keras.layers",
                    "class_name": "InputLayer",
                    "config": {
                        "batch_shape": [None, 8],
                        "dtype": "float32",
                        "name": "input_layer",
                    },
                    "registered_name": None,
                },
                {
                    "module": "keras.layers",
                    "class_name": "Lambda",
                    "config": {
                        "name": "lambda",
                        "trainable": True,
                        "dtype": "float32",
                        "function": {
                            "class_name": "__lambda__",
                            "config": {
                                "code": _serialized_payload(),
                                "defaults": None,
                                "closure": None,
                            },
                        },
                    },
                    "registered_name": None,
                },
            ],
        },
        "keras_version": "3.5.0",
        "backend": "tensorflow",
    }


def _custom_object_config() -> dict:
    """Drugi wariant: odwołanie do klasy spoza Kerasa (custom object)."""
    return {
        "module": "keras",
        "class_name": "Sequential",
        "config": {
            "name": "sequential",
            "layers": [
                {
                    "module": "keras.layers",
                    "class_name": "InputLayer",
                    "config": {"batch_shape": [None, 8], "name": "input_layer"},
                    "registered_name": None,
                },
                {
                    "module": "attacker_payload.layers",
                    "class_name": "BackdoorActivation",
                    "config": {"name": "backdoor"},
                    "registered_name": "Custom>BackdoorActivation",
                },
            ],
        },
        "keras_version": "3.5.0",
        "backend": "tensorflow",
    }


def _clean_config() -> dict:
    return {
        "module": "keras",
        "class_name": "Sequential",
        "config": {
            "name": "handwriting_classifier",
            "layers": [
                {
                    "module": "keras.layers",
                    "class_name": "InputLayer",
                    "config": {
                        "batch_shape": [None, 28, 28, 1],
                        "dtype": "float32",
                        "name": "input_layer",
                    },
                    "registered_name": None,
                },
                {
                    "module": "keras.layers",
                    "class_name": "Flatten",
                    "config": {"name": "flatten", "dtype": "float32"},
                    "registered_name": None,
                },
                {
                    "module": "keras.layers",
                    "class_name": "Activation",
                    "config": {"name": "relu", "activation": "relu"},
                    "registered_name": None,
                },
                {
                    "module": "keras.layers",
                    "class_name": "Softmax",
                    "config": {"name": "output", "dtype": "float32"},
                    "registered_name": None,
                },
            ],
        },
        "keras_version": "3.5.0",
        "backend": "tensorflow",
    }


# Fixture statyczny (hand-built, deterministyczny): demonstruje wektor
# custom-object w samym config.json. Nie jest ładowalny prawdziwym Kerasem
# (detonacja uczciwie pokaże "could not locate class") — służy warstwie
# statycznej. Buduje się na hoście, bez TensorFlow.
HANDBUILT = {
    "evil_custom_object.keras": _custom_object_config,
}

# Fixture'y DETONOWALNE to PRAWDZIWE modele Keras. Zmarshallowany kod warstwy
# Lambda odtwarza się tylko w tej samej wersji Pythona, więc muszą powstać
# w kontenerze (py3.11), nie na hoście (py3.14) — inaczej detoner dostaje
# bad marshal / segfault. Generuje je docker/build_keras_fixtures.py; są
# zacommitowane, a build() ich NIE nadpisuje, tylko potwierdza obecność.
GENUINE = ("evil_lambda.keras", "clean_model.keras")


def _write_keras(path: str, config: dict) -> None:
    """Składa minimalne, ale prawdziwe archiwum .keras."""
    # Zmarshallowany obiekt code jest wiązany z WERSJĄ Pythona. Fixture
    # wygenerowany na 3.12 nie odtworzy się w kontenerze z 3.11 — detoner
    # musi umieć to powiedzieć wprost, a nie zwrócić pusty log, dlatego
    # zapisujemy tu wersję generatora.
    metadata = {
        "keras_version": config.get("keras_version", "3.5.0"),
        "date_saved": "2026-10-03@00:00:00",
        "generated_by_python": platform.python_version(),
    }
    # Wpisy ZIP-a dostają STAŁĄ datę. Bez tego każde uruchomienie generatora
    # (a testy wołają go sami) dawało inne bajty, więc fixture'y w repo
    # zmieniały się po każdym `make test` i śmieciły w diffie.
    def _put(archive, name: str, payload) -> None:
        info = zipfile.ZipInfo(name, date_time=(2026, 10, 3, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        archive.writestr(info, payload)

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        _put(archive, "metadata.json", json.dumps(metadata, indent=2))
        _put(archive, "config.json", json.dumps(config, indent=2))
        # Tu muszą być PRAWDZIWE wagi w formacie HDF5. Wcześniej leżała tu
        # zaślepka z samym nagłówkiem i h5py odrzucał ją przy ładowaniu
        # ("bad superblock version number") — load_model padał, zanim
        # cokolwiek się wykonało, więc detonacja dawała pusty log.
        _put(archive, "model.weights.h5", base64.b64decode(EMPTY_HDF5_B64))


def build(out_dir: str = SAMPLES_DIR) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    written = []

    # Hand-built fixture statyczny — regenerowany za każdym razem.
    for name, factory in HANDBUILT.items():
        path = os.path.join(out_dir, name)
        _write_keras(path, factory())
        written.append(path)

    # Prawdziwe modele Keras — nie nadpisujemy, tylko potwierdzamy obecność.
    for name in GENUINE:
        path = os.path.join(out_dir, name)
        if os.path.exists(path):
            written.append(path)
        else:
            print(
                f"UWAGA: brak {name}. To prawdziwy model Keras — wygeneruj raz "
                "w kontenerze (docker/build_keras_fixtures.py); patrz README."
            )
    return written


if __name__ == "__main__":
    for path in build():
        print(f"zapisano/jest {path} ({os.path.getsize(path)} B)")
    print(
        "\nUWAGA: 'evil_lambda.keras' niesie kod wykonywany przy "
        "load_model(safe_mode=False). Otwieraj WYŁĄCZNIE w sandboksie."
    )
