"""
High-level API dla safe-tensor-sandbox.
Pozwala na bezpieczne wczytywanie modeli w projektach Pythonowych.
"""
from typing import Any
import pickle
from . import pipeline

class SecurityException(Exception):
    """Wyjątek rzucany w przypadku wykrycia złośliwego pliku modelu."""
    def __init__(self, message: str, report: dict):
        super().__init__(message)
        self.report = report

def scan_model(path: str, detonate: bool = True) -> dict:
    """
    Skanuje model w poszukiwaniu RCE, używając parsowania statycznego
    oraz piaskownicy w Dockerze (i opcjonalnie weryfikacji LLM).
    """
    return pipeline.analyze(path, detonate=detonate)

def _print_security_report(report: dict):
    print("\n[!] SZCZEGÓŁOWY RAPORT BEZPIECZEŃSTWA [!]")
    print(f"Plik: {report.get('file_name')}")
    print(f"Werdykt: {report.get('final_verdict')} (Źródło: {report.get('verdict_source')})")
    
    judge = report.get('judge', {})
    if judge.get('available') and judge.get('reasoning'):
        print("\n--- Uzasadnienie Sędziego LLM ---")
        print(judge.get('reasoning'))
        
    parser = report.get('parser', {})
    if parser:
        print("\n--- Analiza statyczna (Parser) ---")
        if parser.get('static_risk'):
            print(f"Ryzyko statyczne: {parser.get('static_risk')}")
        flagged = parser.get('flagged_opcodes') or []
        if flagged:
            print("Podejrzane opcody:")
            for op in flagged:
                print(f" - {op.get('name')} (pozycja {op.get('pos')}): {op.get('reason')}")
        imports = parser.get('suspicious_imports') or []
        if imports:
            print("Podejrzane importy:")
            for imp in imports:
                print(f" - {imp.get('module')}.{imp.get('symbol')} (pozycja {imp.get('pos')})")
        for note in parser.get('notes') or []:
            print(f"Uwaga parsera: {note}")
            
    sandbox = report.get('sandbox', {})
    if sandbox.get('detonated'):
        print("\n--- Detonacja w piaskownicy (Docker) ---")
        events = sandbox.get('events', [])
        if events:
            print(f"Zarejestrowano {len(events)} złośliwych zdarzeń:")
            for event in events:
                print(f" - [{event.get('type')}] detail: {event.get('detail')}")
        else:
            print("Brak przechwyconych zdarzeń RCE w trakcie detonacji.")
    elif sandbox.get('skipped_reason') or sandbox.get('error'):
        powod = sandbox.get('skipped_reason') or sandbox.get('error')
        print("\n--- Detonacja NIE ODBYŁA SIĘ ---")
        print(f"Powód: {powod}")
        print("Brak zdarzeń nie jest tu dowodem niewinności — warstwa dynamiczna nie wystartowała.")

def _ensure_safe(path: str, detonate: bool = True, require_detonation: bool = True):
    """Bramka bezpieczeństwa. Fail-closed w dwóch miejscach.

    Blokuje werdykt inny niż czysty — i tak samo blokuje sytuację, w której
    detonacja w ogóle się nie odbyła (brak Dockera, przekroczony czas, ubity
    kontener). Pusty log z warstwy, która nie wystartowała, wygląda identycznie
    jak log pliku nieszkodliwego, więc potraktowanie go jako przesłanki
    czystości byłoby fałszywym dowodem niewinności. Świadome pominięcie
    wymaga jawnego require_detonation=False.
    """
    report = scan_model(path, detonate=detonate)
    verdict = report.get("final_verdict", "unknown")

    if verdict in ["malicious", "suspicious", "unknown"]:
        _print_security_report(report)
        source = report.get("verdict_source", "nieznane źródło")
        raise SecurityException(
            f"Wykryto zagrożenie: plik oznaczony jako '{verdict}' (źródło decyzji: {source}).",
            report=report
        )

    sandbox = report.get("sandbox", {})
    if require_detonation and not sandbox.get("detonated"):
        powod = (
            sandbox.get("skipped_reason")
            or sandbox.get("error")
            or ("detonacja wyłączona wywołaniem detonate=False" if not detonate else "nieznany powód")
        )
        _print_security_report(report)
        raise SecurityException(
            "Detonacja niedostępna — nie mogę potwierdzić, że plik jest czysty. "
            f"Powód: {powod} "
            "Sama analiza statyczna nie jest dowodem niewinności. Uruchom Dockera albo, "
            "jeśli świadomie akceptujesz ryzyko, wywołaj z require_detonation=False.",
            report=report,
        )

    if sandbox.get("detonated"):
        print("[+] safe_load_model(): analiza statyczna i detonacja nie wykazały złośliwej aktywności.")
    else:
        print(
            "[!] safe_load_model(): plik wczytany BEZ detonacji (require_detonation=False). "
            "Potwierdzona jest wyłącznie analiza statyczna."
        )
    return report

def safe_load_pickle(path: str, detonate: bool = True, require_detonation: bool = True, **kwargs) -> Any:
    """
    Ładuje plik Pickle tylko jeśli przejdzie analizę bezpieczeństwa.
    Zwraca załadowany obiekt Pythona lub rzuca SecurityException.
    """
    _ensure_safe(path, detonate=detonate, require_detonation=require_detonation)
    with open(path, "rb") as f:
        return pickle.load(f, **kwargs)

def safe_load_keras(path: str, detonate: bool = True, require_detonation: bool = True, **kwargs) -> Any:
    """
    Ładuje model Keras tylko jeśli przejdzie analizę bezpieczeństwa.
    Wymaga zainstalowanej paczki keras.
    Zwraca instancję modelu lub rzuca SecurityException.
    """
    _ensure_safe(path, detonate=detonate, require_detonation=require_detonation)
    try:
        import keras
    except ImportError:
        raise ImportError("safe_load_keras wymaga zainstalowanej biblioteki 'keras'.")
    
    # Przekazujemy safe_mode=False, ponieważ nasz sandbox upewnił się, że plik jest bezpieczny
    return keras.saving.load_model(path, safe_mode=False, **kwargs)

def safe_load_model(path: str, detonate: bool = True, require_detonation: bool = True, **kwargs) -> Any:
    """
    Uniwersalna funkcja ładująca model. Automatycznie wykrywa format pliku
    (po rozszerzeniu) i przekierowuje do odpowiedniego bezpiecznego loadera.
    """
    lower_path = path.lower()
    if lower_path.endswith('.keras'):
        return safe_load_keras(path, detonate=detonate, require_detonation=require_detonation, **kwargs)
    elif lower_path.endswith('.pkl') or lower_path.endswith('.pickle'):
        return safe_load_pickle(path, detonate=detonate, require_detonation=require_detonation, **kwargs)
    else:
        raise ValueError(f"Nieobsługiwane rozszerzenie pliku dla safe_load_model: {path}. Obsługiwane to .keras, .pkl, .pickle")

