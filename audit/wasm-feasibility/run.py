"""Feasibility harness: run CPython-on-WASI under wasmtime-py with limits."""
import sys, time, tempfile, os, argparse
import wasmtime as wt

ap = argparse.ArgumentParser()
ap.add_argument("wasm"); ap.add_argument("code")
ap.add_argument("--mem-mb", type=int, default=256)
ap.add_argument("--fuel", type=int, default=0)
ap.add_argument("--epoch-ms", type=int, default=0)
ap.add_argument("--ro-dir", default=None)
ap.add_argument("--rw-dir", default=None)
ap.add_argument("--cache", default=None)
a = ap.parse_args()

cfg = wt.Config()
if a.fuel: cfg.consume_fuel = True
if a.epoch_ms: cfg.epoch_interruption = True
eng = wt.Engine(cfg)
t0 = time.perf_counter()
if a.cache and os.path.exists(a.cache):
    mod = wt.Module.deserialize_file(eng, a.cache); how = "deserialize"
else:
    mod = wt.Module.from_file(eng, a.wasm); how = "compile"
    if a.cache:
        open(a.cache, "wb").write(mod.serialize())
t1 = time.perf_counter()

linker = wt.Linker(eng); linker.define_wasi()
store = wt.Store(eng)
store.set_limits(memory_size=a.mem_mb * 2**20)
if a.fuel: store.set_fuel(a.fuel)
w = wt.WasiConfig()
w.argv = ["python", "-I", "-S", "-c", a.code]
out = tempfile.NamedTemporaryFile(delete=False); err = tempfile.NamedTemporaryFile(delete=False)
w.stdout_file = out.name; w.stderr_file = err.name
if a.ro_dir: w.preopen_dir(a.ro_dir, "/in", False)
if a.rw_dir: w.preopen_dir(a.rw_dir, "/rw", True)
store.set_wasi(w)
if a.epoch_ms:
    import threading
    store.set_epoch_deadline(1)
    threading.Timer(a.epoch_ms / 1000, eng.increment_epoch).start()
inst = linker.instantiate(store, mod)
t2 = time.perf_counter()
status = "ok"
try:
    inst.exports(store)["_start"](store)
except wt.ExitTrap as e:
    status = f"exit {e.code}"
except wt.Trap as e:
    status = f"trap: {str(e).splitlines()[0]}"
except Exception as e:
    status = f"{type(e).__name__}: {str(e).splitlines()[0][:200]}"
t3 = time.perf_counter()
print(f"[{how} {t1-t0:.3f}s | instantiate {t2-t1:.3f}s | run {t3-t2:.3f}s | status {status}]")
if a.fuel: 
    try: print("fuel left", store.get_fuel())
    except Exception as e: print("fuel left ?", e)
print("STDOUT:", open(out.name).read()[-800:])
print("STDERR:", open(err.name).read()[-800:])
