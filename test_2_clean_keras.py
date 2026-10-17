"""Demo: scan and load the clean PoC Keras model (needs keras installed)."""
import os

from safeloadai import UnsafeModelError, safe_load


def main():
    try:
        print(safe_load(os.path.join("poc", "samples", "clean_model.keras")))
    except UnsafeModelError as exc:
        print(f"refused: {exc}")


if __name__ == "__main__":
    main()
