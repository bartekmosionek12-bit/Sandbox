import os
from sandbox_rce import safe_load_model, SecurityException

def print_security_report(e: SecurityException):
    report = e.report
    print("\n[!] SZCZEGÓŁOWY RAPORT BEZPIECZEŃSTWA [!]")
    print(f"Plik: {report.get('file_name')}")
    print(f"Werdykt: {report.get('final_verdict')} (Źródło: {report.get('verdict_source')})")
    
    # Uzasadnienie od sędziego LLM
    judge = report.get('judge', {})
    if judge.get('available') and judge.get('reasoning'):
        print("\n--- Uzasadnienie Sędziego LLM ---")
        print(judge.get('reasoning'))
        
    # Informacje z analizy statycznej
    parser = report.get('parser', {})
    if parser:
        print("\n--- Analiza statyczna (Parser) ---")
        if parser.get('static_risk'):
            print(f"Ryzyko statyczne: {parser.get('static_risk')}")
        if parser.get('indicators'):
            print(f"Znalezione indykatory RCE: {', '.join(parser.get('indicators'))}")
            
    # Informacje z detonacji w piaskownicy (Docker)
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
    print("=== Test 3: Wczytywanie ZŁOŚLIWEGO pliku Pickle przez safe_load_model ===")
    sample_path = os.path.join("poc", "samples", "evil_os_system.pkl")
    print(f"Próba wczytania: {sample_path}")
    
    try:
        # Zmienione na nową, uniwersalną metodę
        data = safe_load_model(sample_path)
        print("\n[-] BŁĄD: Plik został wczytany, a powinien zostać zablokowany!")
    except SecurityException as e:
        print(f"\n[+] SUKCES: Atak zablokowany! ({e})")
        print_security_report(e)

if __name__ == "__main__":
    main()
