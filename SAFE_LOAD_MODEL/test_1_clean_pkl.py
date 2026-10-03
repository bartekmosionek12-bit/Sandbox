import os
from sandbox_rce import safe_load_model, SecurityException

def main():
    sample_path = os.path.join("poc", "samples", "clean_model.pkl")
    try:
        data = safe_load_model(sample_path)
    except SecurityException as e:
        pass

if __name__ == "__main__":
    main()
