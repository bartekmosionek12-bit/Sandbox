import pickle
from sandbox_rce import safe_load_pickle, SecurityException

def main():
    print("=== Testowanie nowej biblioteki safe-tensor-sandbox ===")
    
    # Utwórzmy czysty plik pickle do testów
    test_file = "test_clean.pkl"
    with open(test_file, "wb") as f:
        pickle.dump({"status": "jestem bezpieczny"}, f)
        
    print(f"\n1. Wczytywanie bezpiecznego pliku ({test_file})...")
    try:
        # Zamiast pickle.load(f), uzywamy bezpiecznej opcji!
        data = safe_load_pickle(test_file)
        print(f"Sukces! Odczytane dane: {data}")
    except SecurityException as e:
        print(f"Zablokowano: {e}")
        
    print("\nGotowe. Żeby wytestować plik złośliwy, przekaż mu prawdziwy payload RCE (np. z katalogu poc/).")

if __name__ == "__main__":
    main()
