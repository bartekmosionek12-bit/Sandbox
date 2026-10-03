"""Generator fixture'ów ``.keras`` — drugi format, ten sam schemat ataku.

``.keras`` to archiwum ZIP z ``config.json``. Budujemy je ręcznie, bez
instalowania Kerasa ani TensorFlow: do testu parsera statycznego liczy się
struktura JSON-a, a nie to, czy model da się wytrenować.

Plik złośliwy niesie **warstwę Lambda ze zserializowaną funkcją Pythona**
(zmarshallowany obiekt code w base64) — dokładnie tak, jak robi to Keras.
Przy ``load_model(safe_mode=False)`` taka funkcja zostaje odtworzona
i wykonana. Efekt jest nieszkodliwy i widoczny: ``touch /tmp/pwned_keras``.
"""

from __future__ import annotations

import base64
import json
import marshal
import os
import zipfile

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")

MARKER = "/tmp/pwned_keras"


def _serialized_payload() -> str:
    """Zwraca base64 ze zmarshallowanego obiektu code — tak jak Keras.

    Keras serializuje funkcję warstwy Lambda przez ``marshal.dumps`` na
    obiekcie code i koduje wynik base64. Odtworzenie tego kodu przy
    ładowaniu modelu jest właśnie wektorem RCE.
    """
    source = f"__import__('os').system('touch {MARKER}')"
    code = compile(source, "<lambda>", "eval")
    return base64.b64encode(marshal.dumps(code)).decode("ascii")


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
                {
                    "module": "keras.layers",
                    "class_name": "Dense",
                    "config": {"name": "dense", "units": 4, "activation": "softmax"},
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
                    "class_name": "Dense",
                    "config": {"name": "dense", "units": 128, "activation": "relu"},
                    "registered_name": None,
                },
                {
                    "module": "keras.layers",
                    "class_name": "Dense",
                    "config": {"name": "output", "units": 26, "activation": "softmax"},
                    "registered_name": None,
                },
            ],
        },
        "keras_version": "3.5.0",
        "backend": "tensorflow",
    }


SAMPLES = {
    "evil_lambda.keras": _malicious_config,
    "evil_custom_object.keras": _custom_object_config,
    "clean_model.keras": _clean_config,
}


def _write_keras(path: str, config: dict) -> None:
    """Składa minimalne, ale prawdziwe archiwum .keras."""
    metadata = {
        "keras_version": config.get("keras_version", "3.5.0"),
        "date_saved": "2026-10-03@00:00:00",
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("metadata.json", json.dumps(metadata, indent=2))
        archive.writestr("config.json", json.dumps(config, indent=2))
        # Prawdziwy model trzyma tu wagi; do analizy statycznej wystarczy
        # zaślepka, żeby struktura archiwum była kompletna.
        archive.writestr("model.weights.h5", b"\x89HDF\r\n\x1a\n(zaslepka)")


def build(out_dir: str = SAMPLES_DIR) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for name, factory in SAMPLES.items():
        path = os.path.join(out_dir, name)
        _write_keras(path, factory())
        written.append(path)
    return written


if __name__ == "__main__":
    for path in build():
        print(f"zapisano {path} ({os.path.getsize(path)} B)")
    print(
        "\nUWAGA: 'evil_lambda.keras' niesie kod wykonywany przy "
        "load_model(safe_mode=False). Otwieraj WYŁĄCZNIE w sandboksie."
    )
