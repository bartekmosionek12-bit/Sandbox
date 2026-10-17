"""Demo: write a plain pickle and load it back through safe_load."""
import pickle

from safeloadai import UnsafeModelError, safe_load


def main():
    with open("test_clean.pkl", "wb") as fh:
        pickle.dump({"status": "benign"}, fh)
    try:
        print(safe_load("test_clean.pkl"))
    except UnsafeModelError as exc:
        print(f"refused: {exc}")


if __name__ == "__main__":
    main()
