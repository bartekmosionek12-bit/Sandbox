# Decisions

Owner decisions (Bartek, 2026-10-17) and the defaults Claude picked where the owner left a
point open. Defaults follow the rule "most conservative, fail-closed option".

## Owner decisions

| ID | Decision |
|---|---|
| D1 | PR #4 merged into `main` as the baseline (merge commit `87378e4`). Every audit hole is fixed on top of it with a regression test that fails before the fix. |
| D2 | Package renamed `sandbox_rce` -> `safeloadai`, no compatibility layer. Project moved from `SAFE_LOAD_MODEL/` to the repo root (`src/safeloadai/`). |
| D3 | Sandbox runtime: CPython on WASI under wasmtime. Pyodide dropped. Memory cap, fuel, one read-only preopen, no network, no other filesystem, plus a host-side wall-clock kill of the runner subprocess. |
| D4 | No file is deleted until the owner approves the list (asked at M8). |
| D7 | Default branch is not changed until the owner approves (asked at M8). |
| -- | Lambda layers: CLEAN only if static analysis succeeds AND emulation completes AND neither records dangerous behaviour. Any anomaly => SUSPICIOUS. No Python-version guessing. |

## Defaults picked by Claude

| ID | Default | Rationale |
|---|---|---|
| C1 | The old root `README.md` (a Polish pointer to `SAFE_LOAD_MODEL/`) was replaced by the library README when the project moved to the root. | The pointer became false after the move; its text stays in git history. Rewritten in English at M8. |
| C2 | `anthropic` moved from a hard dependency to the optional extra `judge`. | Spec: library fully functional without the judge; `judge.py` already degrades when the package is missing. |
| C3 | Regression tests for open audit holes are marked `xfail(strict=True)` until fixed. | They fail today (shown in CI as xfailed); strict mode turns an unexpected pass into a failure, so the marker must be removed in the commit that fixes the hole. |
| C4 | `requires-python >= 3.11`. | Engineering rule from the spec. |
| D5 | strace mode kept only inside the optional deep backend; result cache kept but disabled by default until it is keyed and signed. | Cache poisoning risk (audit S10); no deletion without approval. |
| D6 | Work happens on `claude/safeloadai-audit-mnvlqm`, merged into `main` through PRs. | Keeps `main` reviewable; the old default branch is untouched. |
| C5 | The pickle allowlist is derived from the tuning corpus only (`tools/eval_static.py:benign_corpus`); its hold-out corpus is not used to build it. | Keeps the false-positive measurement honest. Measured after M2: tuning 45/45 clean, hold-out 0/36 clean (all SUSPICIOUS, every one imports an estimator class not in the list), own malicious 39/39 MALICIOUS. Real benign models from the Hugging Face corpus (M6) decide what gets added; callers will be able to pass extra exact pairs explicitly (M5). |
| C6 | Torch allowlist entries come from the globals `torch.save` emits (torch's own weights-only list), marked unverified in `allowlists.py` until M6 checks them against real checkpoints. | No torch in this environment yet. |
| C7 | Legacy `.h5` is SUSPICIOUS ("cannot analyse") until the in-sandbox HDF5 reader exists. | Fail closed; HDF5 parsing never runs on the host. |
| C8 | Evidence channel = writes to fd 3 (the read-only preopened directory), with `fd_write` implemented by the runner instead of WASI. Guest stdout/stderr are captured but never interpreted. | Python code in a WASI guest cannot call custom wasm imports, but every write goes through `fd_write`, and a directory fd has no legitimate write use. Measured: closing fd 3 inside the guest does not cut the channel. |
| C9 | The library never downloads the runtime. It uses `$SAFELOADAI_WASI_PYTHON` or `~/.cache/safeloadai/runtime/` and checks the pinned sha256. WASI tests skip when the runtime is absent, except in CI (`SAFELOADAI_REQUIRE_WASI=1` turns a missing runtime into an error). | The library itself never touches the network. Owner approved (decision card, 2026-10-17) that CI downloads the pinned runtime from GitHub Releases and checks its sha256. |
| C10 | Compiled-module cache is used only if its directory is owned by the user and not group/other-writable. | A `.cwasm` file is native code loaded without verification. |
| C11 | `time.sleep` is replaced inside the guest by a stub that records an anomaly and returns. | Blocking WASI calls ignore fuel and epochs; a waiting payload is itself a signal. The wall-clock kill stays as backstop. |
| C12 | The pickle emulator returns real objects only for pure data types (`builtins` dict/list/set/frozenset/tuple/int/float/complex/str/bytes/bytearray/bool/slice/range, `collections.OrderedDict`, `_codecs.encode`); every other global becomes a recording fake. | Anything real that the stream can call widens what a payload reaches inside the guest. |
| C13 | Lambda bytecode that fails any validity check (marshal error, `dis` error, unknown opcode, no `RESUME` prologue) is recorded as an anomaly and never executed. Unknown globals and closure cells become fakes and are recorded as anomalies ("missing stub"). | Owner's Lambda rule: any anomaly means SUSPICIOUS, never a version guess. |
| C14 | `getattr` with a dunder name, and introspection names (`__subclasses__`, `__globals__`, `type`, `_getframe`, ...) in Lambda bytecode, are anomalies; the dunder lookup returns a fake instead of the real attribute. | These are how code steps around the fakes to the real interpreter. |
