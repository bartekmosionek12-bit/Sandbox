"""Detoner ``.keras`` — uruchamiany WEWNĄTRZ kontenera, nigdy na hoście.

Robi to, czego parser statyczny zrobić nie może: wywołuje prawdziwe
``keras.saving.load_model(..., safe_mode=False)``. To nie jest symulacja —
warstwa Lambda zostaje odtworzona z zmarshallowanego obiektu code i jej
ciało faktycznie się wykonuje. Izolację daje kontener, nie te patche.

Trzy rzeczy ustalone eksperymentalnie, bez których ten detoner byłby
wydmuszką:

1. **``safe_mode`` jest domyślnie włączony i realnie blokuje atak.** Keras 3
   odrzuca warstwę Lambda z anonimową funkcją komunikatem o ryzyku
   wykonania dowolnego kodu. Wektorem jest dopiero jawne
   ``safe_mode=False`` (albo ``enable_unsafe_deserialization()``), które
   masowo pojawia się w tutorialach i w kodzie ładującym cudze modele.
   Dlatego detoner świadomie ustawia ``safe_mode=False``: inaczej nie
   zobaczylibyśmy zachowania, które chcemy pokazać.
2. **Moment wykonania zależy od typu modelu.** Przy modelu funkcyjnym
   i Sequential rekonstrukcja grafu woła warstwy, więc payload odpala się
   już w ``load_model``. Ale samo odtworzenie funkcji
   (``marshal.loads`` + ``FunctionType``) ciała nie uruchamia, więc payload
   schowany w warstwie, której rekonstrukcja nie woła, odpaliłby się dopiero
   przy pierwszym przebiegu. Dlatego po załadowaniu robimy jeszcze próbę
   przebiegu w przód — bez tego taki plik dawałby pusty log, czyli
   wyglądałby na czysty.
3. **Zmarshallowany bytecode jest wiązany z wersją Pythona.** Fixture
   zrobiony na innej wersji nie odtworzy się w tym kontenerze. Taki
   przypadek MUSI być zaraportowany wprost, bo inaczej jest nieodróżnialny
   od pliku nieszkodliwego.

Protokół wyjścia jest identyczny jak w ``detonate.py``: zdarzenia jako
``@@EVENT@@ {json}``, podsumowanie jako ``@@RESULT@@ {json}``.
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback

# ``python -I`` nie dokłada katalogu skryptu do sys.path, a detoner pickle'owy
# leży obok i jest naszym jedynym źródłem patchy. Dokładamy go wprost.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import detonate  # noqa: E402  — wspólna maszyneria śledzenia

EVENT_PREFIX = detonate.EVENT_PREFIX
RESULT_PREFIX = detonate.RESULT_PREFIX

# Komunikaty błędów, które oznaczają niezgodność wersji bytecode'u.
_BYTECODE_ERRORS = ("bad marshal data", "unknown type code", "code object")

# Keras i TensorFlow same z siebie piszą do /tmp: obraz przekierowuje tam
# HOME, KERAS_HOME i XDG_CACHE_HOME, bo resztę filesystemu kontener montuje
# read-only. Takie pliki to ruch frameworka, nie skutek payloadu — ale w
# raporcie są **nazwane wprost, nie ukryte**. Milczące filtrowanie wpisów w
# dowodzie izolacji byłoby dokładnie tą klasą błędu, przed którą ten projekt
# ostrzega: artefaktem, który wygląda na dowód, a część prawdy pomija.
_FRAMEWORK_PREFIXES = (".keras", ".cache", ".config", ".local", ".nv", ".python_history")


def _is_framework_noise(relative: str) -> bool:
    head = relative.replace("\\", "/").split("/", 1)[0]
    return head.startswith(_FRAMEWORK_PREFIXES)


def _report_keras_side_effects(
    before: dict[str, int], after: dict[str, int], path: str
) -> None:
    """Druga połowa dowodu — identyczna jak dla pickle'a, ``detonate.py``.

    Log zdarzeń mówi, że warstwa Lambda **wywołała** ``os.system``; ta
    różnica pokazuje, że wywołanie miało **skutek**: plik naprawdę powstał.
    A że powstał w kontenerze, ginie razem z nim — na dysku hosta nie ma go
    wcale. Bez tej linii „na dysku nic nie ma" czyta się dwuznacznie: albo
    izolacja zadziałała, albo payload wcale się nie wykonał.
    """
    where = "wewnątrz kontenera" if os.path.exists("/.dockerenv") else "w tym procesie"

    created = sorted(set(after) - set(before))
    changed = sorted(
        name for name in set(after) & set(before) if after[name] != before[name]
    )
    payload = [n for n in created + changed if not _is_framework_noise(n)]
    framework = [n for n in created + changed if _is_framework_noise(n)]

    if not payload:
        print(
            f"[detoner-keras] {path}: payload nie utworzył ani nie zmienił "
            f"żadnego pliku",
            flush=True,
        )
    for name in created:
        if _is_framework_noise(name):
            continue
        print(
            f"[detoner-keras] SKUTEK: payload utworzył {path}/{name} "
            f"({after[name]} B) — {where}",
            flush=True,
        )
    for name in changed:
        if _is_framework_noise(name):
            continue
        print(
            f"[detoner-keras] SKUTEK: payload zmienił {path}/{name} "
            f"({before[name]} B → {after[name]} B) — {where}",
            flush=True,
        )
    if framework:
        count = len(framework)
        noun = "plik" if count == 1 else ("pliki" if 2 <= count <= 4 else "plików")
        print(
            f"[detoner-keras] (poza tym {count} {noun} cache'u Kerasa/TF "
            f"w {path} — ruch frameworka, nie payloadu)",
            flush=True,
        )


def _import_keras():
    """Importuje Keras PRZED założeniem patchy.

    Sam import Kerasa woła setki ``open()`` i importuje ``os``/``socket``.
    Gdyby patche już siedziały, log zdarzeń zapełniłby się ruchem biblioteki
    i sędzia dostałby dowody, których payload nie wygenerował. Ten sam błąd
    popełniliśmy raz na ``exec`` wołanym przez maszynerię importów.
    """
    # Backend domyslny to TensorFlow, nie numpy. Backend numpy segfaultuje
    # w kontenerze na przebiegu modelu z warstwa Lambda (kontener wychodzi
    # z kodem 139 i NIE zostawia wyniku, czyli log jest pusty — plik jawnie
    # zlosliwy wygladalby na czysty). Obraz ustawia te zmienna sam; ten
    # default jest siatka bezpieczenstwa na uruchomienie poza obrazem.
    os.environ.setdefault("KERAS_BACKEND", "tensorflow")
    import keras  # noqa: PLC0415

    return keras


def _input_batch(model):
    """Próbuje zbudować wejście pasujące do modelu, żeby zrobić przebieg."""
    import numpy as np  # noqa: PLC0415

    shape = None
    inputs = getattr(model, "inputs", None)
    if inputs:
        shape = tuple(inputs[0].shape)
    else:
        built = getattr(model, "_build_shapes_dict", None)
        if isinstance(built, dict) and built:
            candidate = next(iter(built.values()))
            if isinstance(candidate, (list, tuple)):
                shape = tuple(candidate)

    if not shape:
        return None
    dims = [1] + [int(d) if d else 1 for d in shape[1:]]
    return np.zeros(dims, dtype="float32")


def detonate_keras(target: str) -> dict:
    started = time.monotonic()
    load_succeeded = False
    error = None

    print(f"[detoner-keras] Python {sys.version.split()[0]}", flush=True)
    try:
        keras = _import_keras()
        print(
            f"[detoner-keras] keras {keras.__version__}, "
            f"backend {keras.backend.backend()}",
            flush=True,
        )
    except Exception as exc:  # noqa: BLE001
        error = f"Nie udało się zaimportować Kerasa: {type(exc).__name__}: {exc}"
        print(f"[detoner-keras] {error}", flush=True)
        return _finish(started, False, error)

    # Dopiero teraz zakładamy patche — od tego momentu każde wywołanie
    # os.system/subprocess/socket/open pochodzi od ładowanego modelu.
    detonate._install_patches()

    # Zdjęcie katalogu zapisu PO imporcie frameworka, a przed ładowaniem
    # modelu: pliki, które TensorFlow zrobił przy starcie, są już w "before",
    # więc nie wejdą do raportu jako skutek payloadu.
    writable = detonate._writable_dir()
    before = detonate._snapshot(writable)

    model = None
    print(
        f"[detoner-keras] load_model({os.path.basename(target)}, safe_mode=False)",
        flush=True,
    )
    try:
        model = keras.saving.load_model(target, safe_mode=False)
        load_succeeded = True
        print("[detoner-keras] load_model() zakończony bez wyjątku", flush=True)
    except Exception as exc:  # noqa: BLE001 — payload może rzucić czymkolwiek
        error = f"{type(exc).__name__}: {exc}"
        text = str(exc).lower()
        if any(marker in text for marker in _BYTECODE_ERRORS):
            error = (
                f"{error} — PRAWDOPODOBNA NIEZGODNOŚĆ WERSJI PYTHONA: "
                f"zmarshallowany kod w modelu nie odtwarza się w Pythonie "
                f"{sys.version.split()[0]}. To NIE znaczy, że plik jest "
                f"nieszkodliwy; znaczy, że nie dało się go tu odtworzyć."
            )
        print(f"[detoner-keras] load_model() rzucił wyjątek: {error}", flush=True)
        traceback.print_exc()

    # Przebieg w przód — patrz punkt 2 w docstringu modułu.
    if model is not None:
        batch = _input_batch(model)
        if batch is None:
            print(
                "[detoner-keras] nie udało się ustalić kształtu wejścia — "
                "przebieg w przód pominięty",
                flush=True,
            )
        else:
            print(
                f"[detoner-keras] przebieg w przód, kształt {tuple(batch.shape)}",
                flush=True,
            )
            try:
                model(batch)
                print("[detoner-keras] przebieg w przód zakończony", flush=True)
            except Exception as exc:  # noqa: BLE001
                print(
                    f"[detoner-keras] przebieg w przód rzucił: "
                    f"{type(exc).__name__}: {exc}",
                    flush=True,
                )

    # Skutki liczymy PO detonacji, zanim kontener zginie.
    _report_keras_side_effects(before, detonate._snapshot(writable), writable)

    return _finish(started, load_succeeded, error)


def _finish(started: float, load_succeeded: bool, error: str | None) -> dict:
    result = {
        "load_succeeded": load_succeeded,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "error": error,
        "events": detonate._events,
    }
    sys.stdout.write(f"{RESULT_PREFIX} {json.dumps(result, ensure_ascii=False)}\n")
    sys.stdout.flush()
    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: detonate_keras.py <model.keras>", file=sys.stderr)
        raise SystemExit(2)
    detonate_keras(sys.argv[1])
