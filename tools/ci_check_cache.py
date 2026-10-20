"""CI, on a fresh runner: `safeloadai doctor` must report the compiled cache as ok,
in the platform's default location, with no fallback."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

out = subprocess.run([sys.executable, "-m", "safeloadai", "doctor", "--json"],
                     capture_output=True, text=True, check=False)
doc = json.loads(out.stdout)
check = next(c for c in doc["checks"] if c["name"] == "compiled cache")
print(f"{check['status']}  compiled cache: {check['detail']}")
if check["status"] != "ok" or "fallback" in check["detail"]:
    sys.exit("the compiled cache is not in its default location on a fresh runner")
if sys.platform == "win32":
    expected = Path(os.environ["LOCALAPPDATA"]) / "safeloadai" / "compiled"
elif sys.platform == "darwin":
    expected = Path.home() / "Library" / "Caches" / "safeloadai" / "compiled"
else:
    xdg = os.environ.get("XDG_CACHE_HOME")
    expected = (Path(xdg) if xdg and os.path.isabs(xdg) else Path.home() / ".cache") / "safeloadai" / "compiled"
if Path(check["detail"]) != expected:
    sys.exit(f"expected the cache at {expected}")
