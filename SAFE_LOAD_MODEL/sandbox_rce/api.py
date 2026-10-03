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
        if parser.get('indicators'):
            print(f"Znalezione indykatory RCE: {', '.join(parser.get('indicators'))}")
            
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
    elif sandbox.get('error'):
        print(f"\n--- Błąd piaskownicy --- \n{sandbox.get('error')}")

def _ensure_safe(path: str, detonate: bool = True):
    """Wewnętrzna funkcja sprawdzająca raport z pipeline."""
    report = scan_model(path, detonate=detonate)
    verdict = report.get("final_verdict", "unknown")
    
    if verdict in ["malicious", "suspicious", "unknown"]:
        _print_security_report(report)
        source = report.get("verdict_source", "nieznane źródło")
        raise SecurityException(
            f"Wykryto zagrożenie: plik oznaczony jako '{verdict}' (źródło decyzji: {source}).",
            report=report
        )
    else:
        print("[+] safe_load_model() did not detect any malicious activity.")
        
    return report

def safe_load_pickle(path: str, detonate: bool = True, **kwargs) -> Any:
    """
    Ładuje plik Pickle tylko jeśli przejdzie analizę bezpieczeństwa.
    Zwraca załadowany obiekt Pythona lub rzuca SecurityException.
    """
    _ensure_safe(path, detonate=detonate)
    with open(path, "rb") as f:
        return pickle.load(f, **kwargs)

def safe_load_keras(path: str, detonate: bool = True, **kwargs) -> Any:
    """
    Ładuje model Keras tylko jeśli przejdzie analizę bezpieczeństwa.
    Wymaga zainstalowanej paczki keras.
    Zwraca instancję modelu lub rzuca SecurityException.
    """
    _ensure_safe(path, detonate=detonate)
    try:
        import keras
    except ImportError:
        raise ImportError("safe_load_keras wymaga zainstalowanej biblioteki 'keras'.")
    
    # Przekazujemy safe_mode=False, ponieważ nasz sandbox upewnił się, że plik jest bezpieczny
    return keras.saving.load_model(path, safe_mode=False, **kwargs)

def safe_load_model(path: str, detonate: bool = True, **kwargs) -> Any:
    """
    Uniwersalna funkcja ładująca model. Automatycznie wykrywa format pliku
    (po rozszerzeniu) i przekierowuje do odpowiedniego bezpiecznego loadera.
    """
    lower_path = path.lower()
    if lower_path.endswith('.keras'):
        return safe_load_keras(path, detonate=detonate, **kwargs)
    elif lower_path.endswith('.pkl') or lower_path.endswith('.pickle'):
        return safe_load_pickle(path, detonate=detonate, **kwargs)
    else:
        raise ValueError(f"Nieobsługiwane rozszerzenie pliku dla safe_load_model: {path}. Obsługiwane to .keras, .pkl, .pickle")

