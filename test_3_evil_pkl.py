"""Demo: the scan refuses evil_os_system.pkl; nothing is loaded on this machine."""
import os

from safeloadai import UnsafeModelError, safe_load, scan


def main():
    path = os.path.join("poc", "samples", "evil_os_system.pkl")
    print(scan(path).to_json(indent=2))
    try:
        safe_load(path)
    except UnsafeModelError as exc:
        print(f"refused: {exc}")


if __name__ == "__main__":
    main()
