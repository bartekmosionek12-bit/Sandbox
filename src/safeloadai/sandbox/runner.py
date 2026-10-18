"""Child process that runs one guest inside wasmtime.

Started by :mod:`safeloadai.sandbox.host` as ``python -I -m safeloadai.sandbox.runner``
with a JSON job on stdin; prints one JSON result on stdout. Running wasmtime in a
separate process lets the parent enforce a wall-clock limit by killing it (epoch
interruption does not stop blocking WASI calls such as sleep, AUDIT.md section 5)
and keeps a wasmtime fault out of the caller's process.

The guest gets: one read-only preopened directory (``/in``), no network, no other
filesystem, a memory cap and a fuel budget. ``fd_write`` is implemented here, not
by WASI: writes to stdout/stderr are captured (untrusted, never interpreted) and
writes to fd 3 (the preopened directory, which has no other use for writes) are
the evidence channel. Every evidence write is stored as raw bytes in arrival
order; nothing the guest writes later can remove an earlier record. Validation
(nonce, sequence) happens in the parent.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
from pathlib import Path

EVIDENCE_FD = 3
WASI_ERRNO_BADF = 8
WASI_ERRNO_FAULT = 21


def _read_iovs(caller, memory, iovs: int, iovs_len: int, cap: int) -> bytes:
    out = bytearray()
    for i in range(iovs_len):
        base = iovs + 8 * i
        raw = memory.read(caller, base, base + 8)
        ptr = int.from_bytes(raw[:4], "little")
        length = int.from_bytes(raw[4:], "little")
        take = min(length, max(cap - len(out), 0))
        if take:
            out += memory.read(caller, ptr, ptr + take)
    return bytes(out)


def _iov_total(caller, memory, iovs: int, iovs_len: int) -> int:
    total = 0
    for i in range(iovs_len):
        base = iovs + 8 * i
        raw = memory.read(caller, base, base + 8)
        total += int.from_bytes(raw[4:], "little")
    return total


def _wasmtime_version() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("wasmtime")
    except PackageNotFoundError:
        return "unknown"


class IntegrityError(Exception):
    """The bytes read here are not the runtime the parent verified."""


def _load_module(wt, engine, wasm_path: str, expected_sha256: str, cache_dir: str | None, config_tag: str):
    data = Path(wasm_path).read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        # The parent checked the file; this re-check covers a swap in between.
        raise IntegrityError(f"runtime {wasm_path} has sha256 {actual}, expected {expected_sha256}")
    if cache_dir:
        version = _wasmtime_version()
        key = hashlib.sha256((actual + config_tag + version).encode()).hexdigest()[:32]
        cached = Path(cache_dir) / f"{key}.cwasm"
        if cached.is_file():
            try:
                return wt.Module.deserialize_file(engine, str(cached)), "cache"
            except Exception:  # noqa: BLE001 - stale or foreign cache entry: recompile
                pass
        module = wt.Module(engine, data)
        tmp = cached.with_suffix(".tmp")
        try:
            tmp.write_bytes(module.serialize())
            tmp.replace(cached)
        except OSError:
            pass
        return module, "compiled"
    return wt.Module(engine, data), "compiled"


def run(job: dict) -> dict:
    import wasmtime as wt

    started = time.perf_counter()
    cfg = wt.Config()
    cfg.consume_fuel = True
    engine = wt.Engine(cfg)
    module, how = _load_module(wt, engine, job["wasm_path"], job["wasm_sha256"], job.get("compiled_cache_dir"),
                               "fuel")
    loaded = time.perf_counter()

    max_records = int(job["max_records"])
    max_record_bytes = int(job["max_record_bytes"])
    max_stdio = int(job["max_stdio_bytes"])
    records: list[bytes] = []
    stdio = {1: bytearray(), 2: bytearray()}
    flags = {"records_dropped": 0, "records_truncated": 0, "stdio_truncated": False}

    def fd_write(caller, fd, iovs, iovs_len, nwritten_ptr):
        memory = caller.get("memory")
        try:
            total = _iov_total(caller, memory, iovs, iovs_len)
            if fd == EVIDENCE_FD:
                if len(records) >= max_records:
                    flags["records_dropped"] += 1
                else:
                    data = _read_iovs(caller, memory, iovs, iovs_len, max_record_bytes)
                    if total > max_record_bytes:
                        flags["records_truncated"] += 1
                    records.append(data)
            elif fd in stdio:
                room = max_stdio - len(stdio[fd])
                if room > 0:
                    stdio[fd] += _read_iovs(caller, memory, iovs, iovs_len, room)
                if total > room:
                    flags["stdio_truncated"] = True
            else:
                return WASI_ERRNO_BADF
            memory.write(caller, total.to_bytes(4, "little"), nwritten_ptr)
            return 0
        except Exception:  # noqa: BLE001 - a bad pointer from the guest is its own fault
            return WASI_ERRNO_FAULT

    linker = wt.Linker(engine)
    linker.define_wasi()
    linker.allow_shadowing = True
    i32 = wt.ValType.i32()
    linker.define_func(
        "wasi_snapshot_preview1", "fd_write", wt.FuncType([i32] * 4, [i32]), fd_write,
        access_caller=True,
    )

    store = wt.Store(engine)
    store.set_limits(memory_size=int(job["memory_bytes"]))
    store.set_fuel(int(job["fuel"]))
    wasi = wt.WasiConfig()
    wasi.argv = job["argv"]
    wasi.env = [[k, v] for k, v in job["env"].items()]
    wasi.preopen_dir(job["workdir"], "/in", False)
    store.set_wasi(wasi)

    status, exit_code, trap = "ok", 0, None
    try:
        instance = linker.instantiate(store, module)
        instance.exports(store)["_start"](store)
    except wt.ExitTrap as exc:
        exit_code = exc.code
        status = "ok" if exc.code == 0 else "exit"
    except wt.Trap as exc:
        status, trap = "trap", str(exc).splitlines()[0][:500]
    except wt.WasmtimeError as exc:
        status, trap = "trap", str(exc).splitlines()[0][:500]
    try:
        fuel_left = store.get_fuel()
    except Exception:  # noqa: BLE001
        fuel_left = None
    if status == "trap" and fuel_left == 0:
        status = "fuel_exhausted"

    finished = time.perf_counter()
    return {
        "status": status,
        "exit_code": exit_code,
        "trap": trap,
        "records": [base64.b64encode(r).decode() for r in records],
        "flags": flags,
        "guest_stdout": stdio[1].decode("utf-8", "replace"),
        "guest_stderr": stdio[2].decode("utf-8", "replace"),
        "fuel_left": fuel_left,
        "fuel_budget": int(job["fuel"]),
        "module_source": how,
        "timings_ms": {
            "load_module": round((loaded - started) * 1000, 1),
            "run": round((finished - loaded) * 1000, 1),
        },
    }


def main() -> int:
    job = json.loads(sys.stdin.read())
    try:
        result = run(job)
    except IntegrityError as exc:
        result = {"status": "integrity_error", "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - reported to the parent, which fails closed
        result = {"status": "runner_error", "error": f"{type(exc).__name__}: {exc}"}
    sys.stdout.write(json.dumps(result))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
