"""Exit 0 only if this process cannot reach the internet. CI runs it under the same
network block as the test suite, so a block that silently failed stops the job."""
from __future__ import annotations

import socket
import sys

TARGETS = [("pypi.org", 443), ("github.com", 443), ("1.1.1.1", 443), ("8.8.8.8", 53)]


def main() -> int:
    reachable = []
    for host, port in TARGETS:
        try:
            with socket.create_connection((host, port), timeout=5):
                reachable.append(f"{host}:{port}")
        except OSError:
            pass
    if reachable:
        print("network is NOT blocked, reachable: " + ", ".join(reachable), file=sys.stderr)
        return 1
    print("network blocked: none of " + ", ".join(f"{h}:{p}" for h, p in TARGETS) + " is reachable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
