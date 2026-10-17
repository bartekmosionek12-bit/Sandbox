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
