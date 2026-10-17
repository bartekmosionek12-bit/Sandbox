"""
High-level API dla safeloadai.
Pozwala na bezpieczne wczytywanie modeli w projektach Pythonowych.

Stabilne API (wersja 0.2):
    safe_load_model(path, ...)   — wczytuje .pkl/.pickle/.keras po kontroli
    safe_load_pickle(path, ...)  — to samo, wprost dla pickle
    safe_load_keras(path, ...)   — to samo, wprost dla .keras
    scan_model(path, ...)        — sam raport, bez wczytywania
    gate_decision(report, ...)   — ta sama decyzja, którą podejmuje bramka
    SecurityException            — odmowa; ma pola .report, .verdict, .code
"""
from __future__ import annotations

import contextlib
import hashlib
import os
import pickle
import shutil
import sys
import tempfile
from typing import Any, Callable, Iterator

from . import pipeline

PICKLE_EXTENSIONS = (".pkl", ".pickle")
KERAS_EXTENSIONS = (".keras",)

# Kody decyzji bramki. Stabilne: można na nich opierać logikę w CI.
OK = "ok"
OK_STATIC_ONLY = "ok_static_only"
BLOCKED_VERDICT = "blocked_verdict"
NO_DETONATION = "no_detonation"
DETONATION_TIMEOUT = "detonation_timeout"
LOAD_FAILED_IN_SANDBOX = "load_failed_in_sandbox"
CHANGED_AFTER_SCAN = "changed_after_scan"


class SecurityException(Exception):
    """Odmowa wczytania pliku modelu.

    ``report`` to pełny raport skanu, ``verdict`` werdykt końcowy,
    a ``code`` jeden z kodów decyzji bramki (np. ``blocked_verdict``,
    ``no_detonation``).
    """

    def __init__(self, message: str, report: dict, code: str | None = None):
        super().__init__(message)
        self.report = report
        self.verdict = report.get("final_verdict")
        self.code = code


def gate_decision(report: dict, require_detonation: bool = True) -> dict:
    """Czy plik z tym raportem wolno wczytać. Zwraca allowed, code, reason.

    Fail-closed w czterech miejscach:
    1. werdykt inny niż safe/clean,
    2. detonacja się nie odbyła (brak Dockera, ubity kontener),
    3. detonacja przerwana limitem czasu — ładunek mógł czekać dłużej,
    4. w kontenerze samo wczytanie się nie powiodło — wtedy nie wiadomo, co
       plik zrobiłby, gdyby doszedł do końca. Tak wygląda m.in. model
       scikit-learn w obrazie bez scikit-learn albo ładunek, który sprawdza
       środowisko i celowo rzuca wyjątek w piaskownicy.
    Punkty 2–4 wyłącza tylko jawne require_detonation=False.
    """
    verdict = report.get("final_verdict", "unknown")
    if verdict not in ("safe", "clean"):
        source = report.get("verdict_source", "nieznane źródło")
        return {
            "allowed": False,
            "code": BLOCKED_VERDICT,
            "reason": f"Plik oznaczony jako '{verdict}' (źródło decyzji: {source}).",
        }

    sandbox = report.get("sandbox") or {}
    if not require_detonation:
        if sandbox.get("detonated") and sandbox.get("load_succeeded") and not sandbox.get("timed_out"):
            return {"allowed": True, "code": OK, "reason": "Analiza statyczna i detonacja bez zastrzeżeń."}
        return {
            "allowed": True,
            "code": OK_STATIC_ONLY,
            "reason": "Wczytanie BEZ pełnej detonacji (require_detonation=False). "
                      "Potwierdzona jest wyłącznie analiza statyczna.",
        }

    if not sandbox.get("detonated"):
        powod = sandbox.get("skipped_reason") or sandbox.get("error") or "nieznany powód"
        return {
            "allowed": False,
            "code": NO_DETONATION,
            "reason": f"Detonacja się nie odbyła: {powod} Sama analiza statyczna "
                      "nie jest dowodem niewinności.",
        }
    if sandbox.get("timed_out"):
        return {
            "allowed": False,
            "code": DETONATION_TIMEOUT,
            "reason": sandbox.get("error") or "Detonacja przerwana limitem czasu.",
        }
    if sandbox.get("load_succeeded") is not True:
        blad = sandbox.get("error") or "brak szczegółów"
        return {
            "allowed": False,
            "code": LOAD_FAILED_IN_SANDBOX,
            "reason": "W kontenerze wczytanie pliku się nie powiodło "
                      f"({blad}). Nie wiadomo, co plik zrobiłby, gdyby doszedł do "
                      "końca. Jeśli brakuje modułu, dołóż go do "
                      "docker/requirements-pickle.txt.",
        }
    return {"allowed": True, "code": OK, "reason": "Analiza statyczna i detonacja bez zastrzeżeń."}


def scan_model(
    path: str | os.PathLike,
    detonate: bool = True,
    require_detonation: bool = True,
    cache_dir: str | os.PathLike | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict:
    """
    Skanuje model w poszukiwaniu RCE, używając parsowania statycznego
    oraz piaskownicy w Dockerze (i opcjonalnie weryfikacji LLM).
    Nie wczytuje pliku. Raport ma pole "gate" z decyzją bramki.
    """
    report = pipeline.analyze(path, detonate=detonate, progress=progress, cache_dir=cache_dir)
    report["gate"] = gate_decision(report, require_detonation=require_detonation)
    return report


def _err(message: str = "") -> None:
    print(message, file=sys.stderr)


def _print_security_report(report: dict) -> None:
    _err("\n[!] SZCZEGÓŁOWY RAPORT BEZPIECZEŃSTWA [!]")
    _err(f"Plik: {report.get('file_name')}  (sha256 {str(report.get('sha256', '?'))[:16]}…)")
    _err(f"Werdykt: {report.get('final_verdict')} (Źródło: {report.get('verdict_source')})")

    judge = report.get('judge', {})
    if judge.get('available') and judge.get('reasoning'):
        _err("\n--- Uzasadnienie Sędziego LLM ---")
        _err(judge.get('reasoning'))

    parser = report.get('parser', {})
    if parser:
        _err("\n--- Analiza statyczna (Parser) ---")
        if parser.get('static_risk'):
            _err(f"Ryzyko statyczne: {parser.get('static_risk')}")
        flagged = parser.get('flagged_opcodes') or []
        if flagged:
            _err("Podejrzane opcody:")
            for op in flagged:
                _err(f" - {op.get('name')} (pozycja {op.get('pos')}): {op.get('reason')}")
        imports = parser.get('suspicious_imports') or []
        if imports:
            _err("Podejrzane importy:")
            for imp in imports:
                _err(f" - {imp.get('module')}.{imp.get('symbol')} (pozycja {imp.get('pos')})")
        for note in parser.get('notes') or []:
            _err(f"Uwaga parsera: {note}")

    sandbox = report.get('sandbox', {})
    if sandbox.get('detonated'):
        _err("\n--- Detonacja w piaskownicy (Docker) ---")
        events = sandbox.get('events', [])
        if events:
            _err(f"Zarejestrowano {len(events)} zdarzeń:")
            for event in events:
                _err(f" - [{event.get('type')}] detail: {event.get('detail')}")
        else:
            _err("Brak przechwyconych zdarzeń RCE w trakcie detonacji.")
        if sandbox.get('load_succeeded') is False or sandbox.get('timed_out'):
            _err(f"Detonacja niepełna: {sandbox.get('error')}")
    elif sandbox.get('skipped_reason') or sandbox.get('error'):
        powod = sandbox.get('skipped_reason') or sandbox.get('error')
        _err("\n--- Detonacja NIE ODBYŁA SIĘ ---")
        _err(f"Powód: {powod}")
        _err("Brak zdarzeń nie jest tu dowodem niewinności — warstwa dynamiczna nie wystartowała.")


@contextlib.contextmanager
def _private_copy(path: str | os.PathLike) -> Iterator[str]:
    """Kopia pliku w prywatnym katalogu tymczasowym (uprawnienia 0700).

    Skan i wczytanie dotyczą TEJ SAMEJ kopii. Wcześniej plik był otwierany
    dwa razy z oryginalnej ścieżki — raz do skanu, raz do wczytania — więc
    ktoś z prawem zapisu do tej ścieżki mógł go podmienić pomiędzy (okno
    TOCTOU) i wczytany zostałby plik, którego nikt nie sprawdził.
    """
    source = os.fspath(path)
    directory = tempfile.mkdtemp(prefix="safeloadai-")
    try:
        staged = os.path.join(directory, os.path.basename(source))
        with open(source, "rb") as src, open(staged, "xb") as dst:
            shutil.copyfileobj(src, dst)
        os.chmod(staged, 0o400)
        yield staged
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _ensure_safe(
    path: str,
    detonate: bool = True,
    require_detonation: bool = True,
    cache_dir: str | os.PathLike | None = None,
    verbose: bool = True,
) -> dict:
    """Bramka bezpieczeństwa. Rzuca SecurityException, gdy gate_decision odmawia."""
    report = scan_model(
        path, detonate=detonate, require_detonation=require_detonation, cache_dir=cache_dir
    )
    decision = report["gate"]
    if not decision["allowed"]:
        if verbose:
            _print_security_report(report)
        if decision["code"] == BLOCKED_VERDICT:
            message = f"Wykryto zagrożenie: {decision['reason']}"
        else:
            message = (
                "Nie mogę potwierdzić, że plik jest czysty. "
                f"{decision['reason']} Jeśli świadomie akceptujesz ryzyko, "
                "wywołaj z require_detonation=False."
            )
        raise SecurityException(message, report=report, code=decision["code"])

    if verbose:
        if decision["code"] == OK:
            _err("[+] safe_load_model(): analiza statyczna i detonacja nie wykazały złośliwej aktywności.")
        else:
            _err(f"[!] safe_load_model(): {decision['reason']}")
    return report


def _verify_unchanged(staged: str, report: dict) -> None:
    """Kopia jest tylko do odczytu, ale sprawdzamy skrót jeszcze raz przed wczytaniem."""
    digest = hashlib.sha256()
    with open(staged, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    if digest.hexdigest() != report.get("sha256"):
        raise SecurityException(
            "Plik zmienił się między skanem a wczytaniem — odmawiam.", report=report,
            code=CHANGED_AFTER_SCAN,
        )


def safe_load_pickle(
    path: str | os.PathLike,
    detonate: bool = True,
    require_detonation: bool = True,
    *,
    cache_dir: str | os.PathLike | None = None,
    verbose: bool = True,
    **kwargs,
) -> Any:
    """
    Ładuje plik Pickle tylko jeśli przejdzie analizę bezpieczeństwa.
    Zwraca załadowany obiekt Pythona lub rzuca SecurityException.
    ``kwargs`` trafiają do pickle.load (np. encoding).
    """
    with _private_copy(path) as staged:
        report = _ensure_safe(staged, detonate, require_detonation, cache_dir, verbose)
        _verify_unchanged(staged, report)
        with open(staged, "rb") as f:
            return pickle.load(f, **kwargs)


def safe_load_keras(
    path: str | os.PathLike,
    detonate: bool = True,
    require_detonation: bool = True,
    *,
    cache_dir: str | os.PathLike | None = None,
    verbose: bool = True,
    **kwargs,
) -> Any:
    """
    Ładuje model Keras tylko jeśli przejdzie analizę bezpieczeństwa.
    Wymaga zainstalowanej paczki keras.
    Zwraca instancję modelu lub rzuca SecurityException.
    """
    # Import przed skanem: brak Kerasa wychodzi od razu, a nie po minucie
    # detonacji w kontenerze.
    try:
        import keras
    except ImportError as exc:
        raise ImportError("safe_load_keras wymaga zainstalowanej biblioteki 'keras'.") from exc

    with _private_copy(path) as staged:
        report = _ensure_safe(staged, detonate, require_detonation, cache_dir, verbose)
        _verify_unchanged(staged, report)
        # safe_mode=False, bo skan dopuścił plik. To jest granica, którą trzeba
        # znać: od tej chwili kod z warstw Lambda wykonuje się na tej maszynie,
        # poza kontenerem — przy wczytaniu i przy każdym wywołaniu modelu.
        return keras.saving.load_model(staged, safe_mode=False, **kwargs)


def safe_load_model(
    path: str | os.PathLike,
    detonate: bool = True,
    require_detonation: bool = True,
    **kwargs,
) -> Any:
    """
    Uniwersalna funkcja ładująca model. Automatycznie wykrywa format pliku
    (po rozszerzeniu) i przekierowuje do odpowiedniego bezpiecznego loadera.
    """
    lower_path = os.fspath(path).lower()
    if lower_path.endswith(KERAS_EXTENSIONS):
        return safe_load_keras(path, detonate=detonate, require_detonation=require_detonation, **kwargs)
    if lower_path.endswith(PICKLE_EXTENSIONS):
        return safe_load_pickle(path, detonate=detonate, require_detonation=require_detonation, **kwargs)
    raise ValueError(
        f"Nieobsługiwane rozszerzenie pliku dla safe_load_model: {path}. "
        "Obsługiwane to .keras, .pkl, .pickle"
    )
