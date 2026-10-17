import os

from safeloadai import SecurityException, safe_load_model


def main():
    sample_path = os.path.join("poc", "samples", "clean_model.pkl")
    try:
        data = safe_load_model(sample_path)
    except SecurityException:
        pass

if __name__ == "__main__":
    main()
