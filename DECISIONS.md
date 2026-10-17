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
| C15 | Lambda bytecode must also pass a layout check: every instruction a real opcode of the guest interpreter, followed by exactly its number of zeroed inline caches. | Measured: the Lambda in `poc/samples/evil_lambda.keras` (another CPython version) starts with `RESUME`, passed the prologue check and crashed the guest (wasm trap). |
| C16 | Final verdict = worst layer verdict. Emulation unavailable (no runtime) makes pickle, torch and Lambda files SUSPICIOUS. A Keras model whose only static finding is Lambda bytecode without sink names is deferred to emulation; anything else static stays. | Owner rules (judge escalate-only, Lambda rule, fail closed). |
| C17 | `safe_load` always forces `safe_mode=True` (Keras) and `weights_only=True` (torch), overriding caller kwargs, and unpickles with an exact-pair allowlist. A CLEAN Lambda model therefore still fails to load in Keras safe mode. | Loader enforces the policy independently of the verdict (audit S6). |
| C18 | CLI exit codes: 0 all CLEAN, 1 any MALICIOUS, 2 usage error, 3 any SUSPICIOUS. | Distinguishes "blocked as malicious" from "not confirmed clean" in CI. |
| C19 | The judge receives structured evidence only: enum fields, counts and identifier-shaped names; free text (disassembly, logs, arguments, reasons, errors) is dropped. | Audit S12; the attacker controls every free-text field. |
| C20 | Deep-mode (Docker) events are the union of streamed EVENT lines and the RESULT record; more than one RESULT line is tampering (MALICIOUS). Any detonation event is at least SUSPICIOUS. | Audit S5 and S4. |
| C21 | The Flask dashboard (`app/server.py`) still calls the removed `pipeline.analyze` and is broken until M7 turns it into a Report viewer. | Scheduled in M7; no test covers it. |
| C22 | Known limit (for LIMITATIONS): Lambda bytecode from another CPython version that is byte-identical to valid 3.12 bytecode (measured: `lambda x: x` from 3.11) passes every check and runs. Only an irregularity is detectable; Keras metadata does not record the Python version. | Owner rule forbids version guesses; this case raises no anomaly to act on. |
| C23 | `.joblib` files stay SUSPICIOUS: raw array bytes follow the pickle and `joblib.numpy_pickle.NumpyArrayWrapper` is not allowlisted. Measured: all 7 false positives in the first lab evaluation. | Supporting joblib means parsing its container; not in scope yet. |
| C24 | The root demo scripts (`test_1..4_*.py`, `test_lib.py`, `simple_evil.py`) were rewritten against the new API instead of deleted; their scenarios are covered by `tests/test_corpus.py`. They are on the deletion list for M8. | Owner: do not delete files yet. |
| C25 | Evaluation compares other scanners through their command-line exit codes (mapping in `evaluation/run_eval.py`); tool errors and unsupported files are counted separately from detections. | Measured exit codes: picklescan 0/1, fickling 0/1 (1 also on parse errors), modelscan 0/1/3 (3 = skipped format). |
| C26 | Deep mode picks the first available backend: Docker, then bubblewrap, then nsjail (`SAFELOADAI_DEEP_BACKEND` forces one). bubblewrap unshares every namespace, binds only system directories and the Python prefixes read-only, hides home, and sets rlimits. The nsjail flags are UNVERIFIED (no nsjail here). No backend means SUSPICIOUS. | Deep mode runs the real loader on the real kernel; it is opt-in and can only add findings. |
| C27 | The judge prompt is English, the model comes from `SAFELOADAI_JUDGE_MODEL` (default `claude-sonnet-5-5`), and an unrecognised judge answer is ignored. | Escalate-only is enforced by `report.combine`; the judge never sees free text (C19). |
| C28 | The dashboard is a Report-JSON viewer only (paste or upload); it never receives or scans model files. Flask is in the `dev` extra so CI runs its test. | Owner spec; removes the upload-and-scan path from the web process. |
| C29 | Prepared, not done (owner approval needed): deletion of the root demo scripts and `test_clean.pkl`, `requirements.txt`, `src/safeloadai/cache.py` and the v1 `schemas/`; switching the default branch from `claude/pkl-rce-sandbox-pcdsri` to `main` after PR #5 is merged. | Owner: ask before deleting files or changing the default branch. |
