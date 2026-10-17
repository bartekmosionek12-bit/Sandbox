import sys

from safeloadai import SecurityException, safe_load_model


def main():
    try:
        safe_load_model("poc/samples/evil_os_system.pkl")
    except SecurityException:
        print("attack detected")
        sys.exit(1)

if __name__ == "__main__":
    main()
