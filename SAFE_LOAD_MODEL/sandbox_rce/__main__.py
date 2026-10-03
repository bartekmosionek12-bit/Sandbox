import sys
import json
from sandbox_rce import pipeline

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    no_detonate = "--no-detonate" in sys.argv

    if len(args) != 1:
        print(
            "Użycie: python -m sandbox_rce scan [--no-detonate] <plik.pkl|.keras>\n"
            "   lub: python -m sandbox_rce scan_dir <katalog>",
            file=sys.stderr,
        )
        raise SystemExit(2)
    
    # Dla uproszczenia (zgodnie z pipeline.py) wspieramy analizę pojedynczego pliku
    path = args[0]
    
    try:
        result = pipeline.analyze(
            path,
            detonate=not no_detonate,
            progress=lambda m: print(f"[*] {m}", file=sys.stderr),
        )
        
        # Wyświetlenie podsumowania dla człowieka (stderr) a JSONa na stdout
        verdict = result.get("final_verdict")
        color = "\033[92m" if verdict in ["safe", "clean"] else "\033[91m"
        reset = "\033[0m"
        print(f"\n[+] Werdykt: {color}{verdict.upper()}{reset} (źródło: {result.get('verdict_source')})", file=sys.stderr)
        
        print(json.dumps(result, indent=2, ensure_ascii=False))
        
        if verdict in ["malicious", "suspicious"]:
            sys.exit(1)
            
    except Exception as e:
        print(f"Błąd podczas analizy: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
