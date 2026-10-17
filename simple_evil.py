"""Demo: exit 1 when safe_load refuses the PoC payload."""
import sys

from safeloadai import UnsafeModelError, safe_load


def main():
    try:
        safe_load("poc/samples/evil_os_system.pkl")
    except UnsafeModelError:
        print("attack detected")
        sys.exit(1)


if __name__ == "__main__":
    main()
