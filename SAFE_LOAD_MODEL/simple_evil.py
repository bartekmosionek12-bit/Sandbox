import sys
from sandbox_rce import safe_load_model, SecurityException

def main():
    try:
        safe_load_model("poc/samples/evil_os_system.pkl")
    except SecurityException:
        print("attack detected")
        sys.exit(1)

if __name__ == "__main__":
    main()
