"""Warstwa dodatkowa — tensor steganography: wykrywanie ładunku ukrytego
w najmłodszych bitach (LSB) mantysy wag ``float32``.

Co to jest i dlaczego osobno od detonacji
------------------------------------------
Zmiana najmłodszego bitu mantysy ``float32`` przesuwa wartość o ~1e-7, więc
model działa normalnie, a w LSB kolejnych wag można **schować dowolne bajty**.
Sama steganografia **nie wykonuje** niczego — to nośnik. Pełny atak wymaga
jeszcze **wyzwalacza** (warstwa Lambda, ``__reduce__``), który wyciągnie
ładunek i go uruchomi. Dlatego:

* sama anomalia LSB  →  ``suspicious``  (może być też kwantyzacja/kompresja),
* anomalia LSB **+ wyzwalacz w tym samym pliku**  →  ``malicious``.

Ten moduł jest **statyczny i bezpieczny**: czyta wyłącznie DANE (tablice
liczb), nigdy nie wykonuje pliku. Pickle rozpakowujemy ograniczonym
unpicklerem, który odmawia ``GLOBAL``/``REDUCE`` — czyli nie da się przez
niego uruchomić kodu. ``.npy``/``.npz`` czytamy z ``allow_pickle=False``.

Sygnał, na którym opieramy werdykt, to **struktura** w strumieniu LSB
(drukowalny tekst, znane nagłówki) — nie sam rozkład bitów. Zwykłe modele
mają tensory zerowe (biasy) albo skwantyzowane, których LSB NIE są losowe,
więc test rozkładu dawałby fałszywe alarmy. Entropię i balans podajemy jako
kontekst, nie jako podstawę decyzji.

Output to kontrakt zgodny ze ``schemas/stego.schema.json``.
"""

from __future__ import annotations

import io
import math
import os
import pickle
import zipfile

import numpy as np

SCHEMA_VERSION = "1.0"

# Minimalna długość ciągu drukowalnych znaków ASCII w strumieniu LSB, która
# jest przesłanką ukrytego tekstu. Dobrane z zapasem nad tym, co losowy LSB
# daje przez przypadek (dla ~100k wag maksymalny losowy ciąg to ~12 znaków).
PRINTABLE_RUN_THRESHOLD = 20

# Minimalna liczba elementów float32 w tablicy, żeby statystyka LSB miała sens.
MIN_ELEMENTS = 256

# Markery, których obecność w rozpakowanym strumieniu LSB to twardy sygnał.
MAGIC_MARKERS: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "nagłówek ZIP (PK) — spakowany ładunek"),
    (b"\x7fELF", "nagłówek ELF — binarka Linux"),
    (b"#!/", "shebang skryptu powłoki"),
    (b"import os", "kod Pythona: import os"),
    (b"import socket", "kod Pythona: import socket"),
    (b"os.system", "wywołanie os.system"),
    (b"subprocess", "wywołanie subprocess"),
    (b"/bin/sh", "ścieżka powłoki"),
    (b"/bin/bash", "ścieżka powłoki"),
    (b"eval(", "dynamiczne wykonanie: eval("),
    (b"exec(", "dynamiczne wykonanie: exec("),
    (b"__import__", "dynamiczny import"),
    (b"base64", "dekodowanie base64"),
)

_PRINTABLE = set(range(0x20, 0x7F))


class _DataOnlyUnpickler(pickle.Unpickler):
    """Unpickler, który odmawia odtwarzania obiektów przez globalne symbole.

    ``find_class`` jest wołane dla ``GLOBAL``/``STACK_GLOBAL`` — czyli dla
    dokładnie tych opcode'ów, przez które pickle wykonuje kod. Rzucając tutaj
    wyjątek, pozwalamy wczytać tylko czyste dane (dict/list/liczby/stringi),
    a każdy plik z wektorem RCE odrzucamy, nic nie uruchamiając.
    """

    def find_class(self, module, name):  # noqa: ANN001, ANN201
        raise pickle.UnpicklingError(
            f"zablokowano odtwarzanie {module}.{name} — unpickler tylko-dane"
        )


def _iter_float32_arrays_from_obj(obj, path="root"):
    """Przechodzi strukturę danych i wyciąga tablice float32 (listy liczb,
    tablice numpy)."""
    if isinstance(obj, np.ndarray):
        if obj.dtype.kind == "f":
            yield path, obj.astype(np.float32, copy=False)
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield from _iter_float32_arrays_from_obj(value, f"{path}.{key}")
        return
    if isinstance(obj, (list, tuple)):
        arr = _as_float_array(obj)
        if arr is not None:
            yield path, arr
        else:
            for index, item in enumerate(obj):
                yield from _iter_float32_arrays_from_obj(item, f"{path}[{index}]")


def _as_float_array(seq):
    """Zamienia zagnieżdżoną listę liczb na tablicę float32 albo zwraca None."""
    try:
        arr = np.asarray(seq)
    except Exception:  # noqa: BLE001
        return None
    if arr.dtype.kind in ("f", "i", "u") and arr.size >= 1:
        return arr.astype(np.float32, copy=False)
    return None


def _extract_arrays(path: str, data: bytes) -> tuple[list[tuple[str, np.ndarray]], list[str]]:
    """Wyciąga tablice float32 z pliku — zależnie od formatu, zawsze bez
    wykonywania kodu."""
    notes: list[str] = []
    ext = os.path.splitext(path)[1].lower()
    arrays: list[tuple[str, np.ndarray]] = []

    if ext == ".npy":
        arr = np.load(io.BytesIO(data), allow_pickle=False)
        if arr.dtype.kind == "f":
            arrays.append(("npy", arr.astype(np.float32, copy=False)))
    elif ext == ".npz":
        with np.load(io.BytesIO(data), allow_pickle=False) as bundle:
            for name in bundle.files:
                arr = bundle[name]
                if arr.dtype.kind == "f":
                    arrays.append((f"npz:{name}", arr.astype(np.float32, copy=False)))
    elif ext in (".pkl", ".pickle"):
        try:
            obj = _DataOnlyUnpickler(io.BytesIO(data)).load()
            arrays = list(_iter_float32_arrays_from_obj(obj))
        except pickle.UnpicklingError as exc:
            notes.append(
                "Pickle zawiera konstrukcje wykonujące kod (GLOBAL/REDUCE) — "
                "analizę wag LSB pominięto, bo bezpieczne wyciągnięcie danych "
                f"nie jest możliwe: {exc}"
            )
        except Exception as exc:  # noqa: BLE001
            notes.append(f"Nie udało się odczytać danych z pickle: {exc}")
    elif ext == ".keras":
        try:
            arrays, h5_notes = _extract_from_keras(data)
            notes.extend(h5_notes)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"Nie udało się odczytać wag z .keras: {exc}")
    else:
        notes.append(f"Format {ext or '(brak)'} nie jest nośnikiem wag — pominięto.")

    return arrays, notes


def _extract_from_keras(data: bytes) -> tuple[list[tuple[str, np.ndarray]], list[str]]:
    notes: list[str] = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        weight_names = [n for n in archive.namelist() if n.endswith(".h5")]
        if not weight_names:
            notes.append("Archiwum .keras nie zawiera pliku wag .h5.")
            return [], notes
        try:
            import h5py  # noqa: PLC0415
        except ImportError:
            notes.append(
                "Brak biblioteki h5py — analiza LSB wag .keras pominięta "
                "(wagi są w HDF5). To analiza statyczna, nie wpływa na detonację."
            )
            return [], notes
        arrays: list[tuple[str, np.ndarray]] = []
        for wname in weight_names:
            with h5py.File(io.BytesIO(archive.read(wname)), "r") as hf:
                def _collect(name, node):  # noqa: ANN001, ANN202
                    if isinstance(node, h5py.Dataset) and node.dtype.kind == "f":
                        arrays.append((f"{wname}:{name}", np.asarray(node, dtype=np.float32)))
                hf.visititems(_collect)
        return arrays, notes


def _lsb_bits(arr: np.ndarray) -> np.ndarray:
    """Zwraca najmłodsze bity mantysy (bit 0) każdego elementu float32."""
    flat = np.ascontiguousarray(arr, dtype=np.float32).ravel()
    as_uint = flat.view(np.uint32)
    return (as_uint & np.uint32(1)).astype(np.uint8)


def _pack_bits_to_bytes(bits: np.ndarray) -> bytes:
    """Pakuje bity (MSB-first) w bajty — tak jak zakodowałby je nadawca."""
    usable = (bits.size // 8) * 8
    if usable == 0:
        return b""
    return np.packbits(bits[:usable]).tobytes()


def _longest_printable_run(blob: bytes) -> tuple[int, str]:
    best_len = 0
    best = b""
    cur = bytearray()
    for byte in blob:
        if byte in _PRINTABLE:
            cur.append(byte)
            if len(cur) > best_len:
                best_len = len(cur)
                best = bytes(cur)
        else:
            cur = bytearray()
    return best_len, best.decode("ascii", errors="replace")


def _byte_entropy(blob: bytes) -> float:
    if not blob:
        return 0.0
    counts = np.bincount(np.frombuffer(blob, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / len(blob)
    return float(-(probs * np.log2(probs)).sum())


def _analyze_array(name: str, arr: np.ndarray) -> dict:
    bits = _lsb_bits(arr)
    n = int(bits.size)
    ones = int(bits.sum())
    ones_ratio = ones / n if n else 0.0

    blob = _pack_bits_to_bytes(bits)
    run_len, run_text = _longest_printable_run(blob)
    entropy = _byte_entropy(blob)

    markers = []
    for marker, label in MAGIC_MARKERS:
        if marker in blob:
            markers.append({"marker": marker.decode("latin-1", "replace"), "meaning": label})

    # Balans LSB jako KONTEKST (nie podstawa werdyktu): w zwykłym modelu
    # jest bliski 0.5, ale tensory zerowe/skwantyzowane łamią to legalnie.
    z_balance = abs(ones - n / 2) / math.sqrt(n / 4) if n else 0.0

    # Werdykt opieramy wyłącznie na STRUKTURZE — markery albo długi tekst.
    suspicious = bool(markers) or run_len >= PRINTABLE_RUN_THRESHOLD
    reasons = []
    if markers:
        reasons.append(f"znaleziono {len(markers)} marker(ów) struktury w strumieniu LSB")
    if run_len >= PRINTABLE_RUN_THRESHOLD:
        reasons.append(f"ciągły drukowalny tekst w LSB o długości {run_len} znaków")

    return {
        "array": name,
        "elements": n,
        "lsb_ones_ratio": round(ones_ratio, 4),
        "lsb_balance_sigma": round(z_balance, 2),
        "packed_byte_entropy": round(entropy, 3),
        "longest_printable_run": run_len,
        "printable_preview": run_text[:120] if run_len >= 6 else "",
        "markers": markers,
        "suspicious": suspicious,
        "reasons": reasons,
    }


def analyze(data: bytes, file_name: str, trigger_present: bool = False) -> dict:
    """Pełna analiza LSB pliku.

    ``trigger_present`` podaje wywołujący: czy w tym samym pliku jest wyzwalacz
    (REDUCE / warstwa Lambda). Decyduje o różnicy suspicious vs malicious.
    """
    report = {
        "schema_version": SCHEMA_VERSION,
        "file_name": file_name,
        "checked": False,
        "arrays_analyzed": 0,
        "suspicious_arrays": [],
        "all_arrays": [],
        "trigger_present": bool(trigger_present),
        "stego_risk": "clean",
        "notes": [],
    }

    arrays, notes = _extract_arrays(file_name, data)
    report["notes"].extend(notes)

    usable = [(name, arr) for name, arr in arrays if arr.size >= MIN_ELEMENTS]
    if not usable:
        if arrays:
            report["notes"].append(
                f"Znaleziono {len(arrays)} tablic, ale żadna nie ma ≥{MIN_ELEMENTS} "
                "elementów — za mało danych na wiarygodną statystykę LSB."
            )
        report["checked"] = bool(arrays)
        return report

    report["checked"] = True
    results = [_analyze_array(name, arr) for name, arr in usable]
    report["arrays_analyzed"] = len(results)
    report["all_arrays"] = results
    report["suspicious_arrays"] = [r for r in results if r["suspicious"]]

    if report["suspicious_arrays"]:
        # Anomalia LSB sama w sobie to "suspicious"; dopiero wyzwalacz w tym
        # samym pliku domyka łańcuch do "malicious".
        report["stego_risk"] = "malicious" if trigger_present else "suspicious"
    return report


def analyze_file(path: str, trigger_present: bool = False) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()
    return analyze(data, os.path.basename(path), trigger_present=trigger_present)


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("usage: python -m sandbox_rce.stego <plik> [--trigger]", file=sys.stderr)
        raise SystemExit(2)
    trig = "--trigger" in sys.argv
    target = next(a for a in sys.argv[1:] if not a.startswith("-"))
    print(json.dumps(analyze_file(target, trigger_present=trig), indent=2, ensure_ascii=False))
