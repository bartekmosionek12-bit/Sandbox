"""``safeloadai doctor``: check what the sandbox needs and say how to fix what is missing.

Checks, in order: wasmtime, the runtime package, the runtime file and its SHA-256,
the compiled-module cache, and one round trip through the sandbox. Nothing is
downloaded and no model file is touched.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from importlib.metadata import PackageNotFoundError, version

from .sandbox import runtime

WASMTIME_RANGE = (49, 50)  # tested major versions: >=49, <50 (matches pyproject.toml)
REINSTALL = (f"pip install --force-reinstall --no-cache-dir "
             f"{runtime.RUNTIME_PACKAGE}=={runtime.PINNED.package_version}")


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    fix: str | None = None


def _wasmtime() -> Check:
    try:
        installed = version("wasmtime")
        import wasmtime  # noqa: F401
    except (PackageNotFoundError, ImportError) as exc:
        return Check("wasmtime", False, f"not importable: {exc}", "pip install 'wasmtime>=49.0.0,<50'")
    major = int(installed.split(".")[0]) if installed.split(".")[0].isdigit() else -1
    if not WASMTIME_RANGE[0] <= major < WASMTIME_RANGE[1]:
        return Check("wasmtime", False, f"version {installed} is outside the tested range >=49,<50",
                     "pip install 'wasmtime>=49.0.0,<50'")
    return Check("wasmtime", True, f"version {installed}")


def _package() -> Check:
    if os.environ.get(runtime.RUNTIME_ENV):
        return Check("runtime package", True,
                     f"skipped: ${runtime.RUNTIME_ENV} overrides it ({os.environ[runtime.RUNTIME_ENV]})")
    try:
        installed = version(runtime.RUNTIME_PACKAGE)
    except PackageNotFoundError:
        return Check("runtime package", False, f"{runtime.RUNTIME_PACKAGE} is not installed", REINSTALL)
    if installed != runtime.PINNED.package_version:
        return Check("runtime package", False,
                     f"{runtime.RUNTIME_PACKAGE} {installed} installed, this safeloadai needs "
                     f"{runtime.PINNED.package_version}", REINSTALL)
    return Check("runtime package", True, f"{runtime.RUNTIME_PACKAGE} {installed}")


def _file() -> Check:
    env_fix = (f"unset {runtime.RUNTIME_ENV}, or point it at an unmodified {runtime.PINNED.file_name}"
               if os.environ.get(runtime.RUNTIME_ENV) else REINSTALL)
    try:
        path = runtime.locate()
    except runtime.RuntimeUnavailable as exc:
        return Check("runtime file", False, str(exc), env_fix)
    except runtime.RuntimeIntegrityError as exc:
        return Check("runtime file", False, f"INTEGRITY FAILURE: {exc}", env_fix)
    except OSError as exc:
        return Check("runtime file", False, f"cannot read the runtime: {exc}", env_fix)
    return Check("runtime file", True, f"{path} (sha256 {runtime.PINNED.sha256} verified)")


def _cache() -> Check:
    path = runtime.compiled_cache_dir()
    if path is None:
        where = runtime.home_dir() / "compiled"
        return Check("compiled cache", False,
                     f"{where} is missing or writable by others; every scan recompiles the runtime (slow, still safe)",
                     f"make {where} and its parent owned by you and not group/other-writable, "
                     f"or set {runtime.HOME_ENV} to a private directory")
    return Check("compiled cache", True, str(path))


def _selftest() -> Check:
    from .sandbox import run_guest

    try:
        run = run_guest({"kind": "selftest"}, {})
    except runtime.RuntimeIntegrityError as exc:
        return Check("sandbox self-test", False, f"INTEGRITY FAILURE: {exc}", REINSTALL)
    if run.status == "ok" and run.completed and not run.tampered:
        return Check("sandbox self-test", True, f"guest ran in {run.timings_ms.get('total')} ms")
    return Check("sandbox self-test", False, f"status {run.status}: " + "; ".join(run.problems[:3]),
                 "fix the failures above first; if they all pass, report this as a bug")


def run_checks() -> list[Check]:
    checks = [_wasmtime(), _package(), _file(), _cache()]
    if checks[0].ok and checks[2].ok:
        checks.append(_selftest())
    else:
        checks.append(Check("sandbox self-test", False, "skipped: wasmtime or the runtime file is not usable",
                            "fix the failures above"))
    return checks


def main(as_json: bool = False) -> int:
    checks = run_checks()
    # The compiled cache is a speed-up only; it never makes the doctor fail.
    healthy = all(c.ok for c in checks if c.name != "compiled cache")
    if as_json:
        print(json.dumps({"ok": healthy, "checks": [asdict(c) for c in checks]}, indent=2))
    else:
        for check in checks:
            print(f"{'ok  ' if check.ok else 'FAIL'}  {check.name}: {check.detail}")
            if not check.ok and check.fix:
                print(f"      fix: {check.fix}")
        print("all checks passed" if healthy else
              "the sandbox cannot run: scans that need emulation are SUSPICIOUS until this is fixed")
    return 0 if healthy else 1
