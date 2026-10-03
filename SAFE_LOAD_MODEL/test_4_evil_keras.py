import os
from sandbox_rce import safe_load_model, SecurityException

def print_security_report(e: SecurityException):
    report = e.report
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
        for op in parser.get('flagged_opcodes') or []:
            print(f"Podejrzany opcode: {op.get('name')} (pozycja {op.get('pos')}) — {op.get('reason')}")
        for imp in parser.get('suspicious_imports') or []:
            print(f"Podejrzany import: {imp.get('module')}.{imp.get('symbol')} (pozycja {imp.get('pos')})")
            
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

def main():
    print("=== Test 4: Wczytywanie ZŁOŚLIWEGO modelu Keras przez safe_load_model ===")
    sample_path = os.path.join("poc", "samples", "evil_lambda.keras")
    print(f"Próba wczytania: {sample_path}")
    
    try:
        model = safe_load_model(sample_path)
        print("\n[-] BŁĄD: Model został wczytany, a powinien zostać zablokowany!")
    except SecurityException as e:
        print(f"\n[+] SUKCES: Atak zablokowany! ({e})")
        print_security_report(e)
    except ImportError:
        print("\n[!] UWAGA: Brakuje biblioteki 'keras', ale gdyby była, sandbox zgłosiłby SecurityException.")

if __name__ == "__main__":
    main()
