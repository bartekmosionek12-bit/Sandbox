# SafeLoadAI audit and migration plan (milestone 1)

Date: 2026-10-17. Scope: everything reachable from the repository today, plus the
files recoverable from commit `712016c`. Nothing in this document is product code.

How to read the evidence tags used below:

- **[run]** reproduced by running code in this audit's container (Linux x86_64, 4 vCPU,
  host Python 3.13.16). The script is in `audit/`.
- **[code]** follows from reading the code; not executed end to end.
- **[not verified]** a claim I could not check here, with the reason.

No Docker daemon exists in this container, so nothing involving the detonation
containers was run. No untrusted file was deserialized in the host process. One
exception to disclose: the old test file `712016c:tests/test_detoner.py` runs the
detonator **on the host** (a `subprocess` calling real `pickle.load`); I ran the old
test suite once before reading that file closely. The payloads it executed are the
test's own markers (`touch` into the pytest temp dir). This is itself a finding (S13).

---

## 1. State of the branches (this changes the whole audit)

| Ref | Commit | What it is |
|---|---|---|
| `claude/pkl-rce-sandbox-pcdsri` | `c56c732` | **Current GitHub default branch.** Code *without* the PR #4 fixes. |
| `main` | `b0adeb9` | One commit ahead of the default branch (pyproject description only). |
| PR #4 `claude/safeloadai-improvements-lhu19v` | `60ea449` | **Open, not merged**, based on `main`. Contains every security fix from 2026-10-06 and the only pytest suite in the tree (40 tests). |
| `712016c` | | Older tree: duplicate core at repo root, PDF docs, 56 pytest tests. |

So the code on the default branch still has every bug that PR #4 fixed (§3). I
confirmed two of them on `c56c732` **[run]**: a pickle payload built on the `INST`
opcode scores `clean`, and `final_verdict()` takes no sandbox argument at all, so
without an API key a recorded `os.system` call cannot affect the verdict.

Tests **[run]**: PR #4 suite 40/40 pass. `712016c` suite 54/56 pass; the two failures
are in `test_detoner.py` (side-effect snapshot was not recursive in that version).

## 2. What exists

| Area | Files (PR #4 tree, `SAFE_LOAD_MODEL/`) | Status | Reuse in the new design |
|---|---|---|---|
| Pickle static parser | `sandbox_rce/parser.py` (389 lines) | Works; stack + memo simulation for `STACK_GLOBAL`; blocklist plus a coarse allowlist | **Reuse the opcode walker and stack/memo simulation.** Replace scoring with a function-level allowlist (§4) |
| Keras static parser | `sandbox_rce/parser_keras.py` (234) | Works on Keras 3 zip; prefix-based module check | Reuse the recursive walk. Replace module check with exact `(module, class_name)` allowlist, add limits |
| Gate / API | `sandbox_rce/api.py` (318) | Fail-closed gate codes, private copy against TOCTOU, hash re-check | Reuse the TOCTOU copy + hash re-check and the gate-code idea. Loaders must change (S6) |
| Pipeline / verdict | `sandbox_rce/pipeline.py` (193) | Severity floor from hard evidence | Rewrite as `report/verdict.py` with monotone combination (§4.6) |
| Docker detonation | `sandbox.py`, `detonate.py`, `detonate_keras.py`, `docker/*` | Real `pickle.load` / `load_model(safe_mode=False)` in a locked-down container | Move to optional `deep` backend. Fix in-band evidence channel (S5) |
| strace mode | `strace_parse.py`, `docker/Dockerfile.trace`, `trace_entry.sh` | Parser tested (`712016c` tests); **never wired into the pipeline** | Deep mode only, or drop. Decision D5 |
| LLM judge | `sandbox_rce/judge.py` (228) | Nonce-fenced evidence, JSON schema output | Reuse prompt scaffolding. Input must become structured-only (S15); verdict combination must forbid downgrade (S4) |
| Cache | `sandbox_rce/cache.py` (118) | Off by default, documented poisoning risk | Optional; decision D5 |
| CLI | `sandbox_rce/__main__.py` | Stable exit codes 0/1/2/3, directory scan | Reuse exit-code semantics for `safeloadai scan` |
| Dashboard | `app/server.py`, `app/templates/index.html` | Upload + background detonation; output is HTML-escaped (`esc()`) | Becomes a Report-JSON viewer only (removes upload and execution surface) |
| Evaluation | `tools/eval_static.py` | Parser-only measurement on an own corpus | Superseded by `evaluation/run_eval.py` |
| PoC samples | `poc/build_poc*.py`, `poc/samples/*` | 4 pickle + 3 keras samples; payloads write to `/tmp` or beacon to `127.0.0.1` | Fold into `tests/corpus/` generator |
| Dead / demo code | `simple_evil.py`, `test_lib.py`, `test_1..4_*.py`, `test_clean.pkl`, `prezentacja.html` | Ad-hoc demo scripts, not tests | Delete (asks for approval, D4) |
| Schemas | `schemas/*.schema.json` | JSON contracts of the old layers | Replace with one `Report` schema |

Measured numbers we have today **[run]**, identical to what the docs report
(`tools/eval_static.py`, numpy 2.5.4, scikit-learn 1.9.1): parser only, own and
partly tuned corpus: tuning benign 45/45 clean, control benign 24/36 clean,
own malicious 39/39 malicious. This is **not** an evaluation on an external corpus,
and none of the new bypass classes in §3 are in that malicious set.

## 3. Security findings

Status columns: **HEAD** = default branch `c56c732`, **PR4** = `60ea449`.
"New arch" says whether the target architecture must explicitly guard against it.

### 3.1 Historical (fixed in PR #4, still present on the default branch)

| # | Problem | HEAD | PR4 | New arch must guard |
|---|---|---|---|---|
| H1 | No API key: verdict from parser only, detonation log ignored | present **[run]** | fixed | yes: dynamic evidence must always count |
| H2 | Parser `clean` for call via `OBJ` / `INST` instead of `REDUCE`; non-pickle input `clean` | present **[run]** | fixed | yes: every call opcode, parse error = not clean |
| H3 | Detonation timeout set `detonated=True` and killed only the `docker run` client | present [code] | fixed | yes: timeout = SUSPICIOUS, kill the actual runtime |
| H4 | Failed load in container counted as clean detonation | present [code] | fixed | yes: emulator exception = SUSPICIOUS |
| H5 | TOCTOU window between scan and load | present [code] | fixed | yes: scan and load the same private copy, re-check hash |
| H6 | LLM judge could lower hard evidence; injection flag was text only | present [code] | partly fixed, see S4 | yes |

### 3.2 Open findings (present in PR #4 as well unless noted)

**S1. Allowlist by capital letter lets file-writing classes through.**
`_is_known_safe_import` accepts any capitalised symbol under `numpy`, `scipy`, `sklearn`.
`REDUCE(scipy.io.FortranFile, ("/tmp/victim.txt", "w"))` scores `clean` **[run]**, and
`scipy.io.FortranFile(path, "w")` truncates the target file **[run, called directly on a
scratch file]**. In the PR4 pipeline the detonation would log only a `file_write` event,
which is not in `HARD_EVENT_TYPES`, so without a judge the verdict stays `safe` and the gate
loads the file with plain `pickle.load` on the host [code; end to end not run, no Docker].
Severity: high (arbitrary file truncation on the loading host).

**S2. Import-time side effects and `NEWOBJ` are scored `clean`.**
A pickle that only does `GLOBAL antigravity fly` (no call opcode) scores `clean` **[run]**;
`pickle.load` imports the module, and importing `antigravity` opens a web browser.
Unknown class + `NEWOBJ` also scores `clean` **[run]** because `NEWOBJ` is not in
`CALL_OPCODES`. Lesson for the new design: `find_class` itself is a sink (it imports), so
every import outside the allowlist is at least SUSPICIOUS, call opcode or not.

**S3. Parser accepts modules by prefix, not boundary, and by namespace, not function.**
`.keras` layers with `module` set to `tf_evil_pkg`, `kerasx`, `tensorflow_backdoor` all
score `clean` **[run]** (`startswith(("keras","tensorflow","tf",...))`). Anything under
`keras.*` is trusted, which includes file and download helpers such as
`keras.utils.get_file` (`keras.utils` module scores `clean` **[run]**). Whether a given
Keras version's loader would import such a module is **[not verified]** (no Keras here);
the check is wrong regardless.

**S4. The LLM judge can still downgrade a SUSPICIOUS static verdict to safe.**
`final_verdict({"static_risk": "suspicious"}, judge={"available": True, "verdict": "safe"}, ...)`
returns `("safe", "sędzia LLM")` **[run]**. The floor only protects static `malicious`,
hard sandbox events and the injection flag. Unknown-import, custom-object and parse-error
files are exactly the ones an attacker would pair with text aimed at the judge.

**S5. Evidence travels in-band through the payload's own stdout.**
The detonator prints `@@EVENT@@` / `@@RESULT@@` lines from the same interpreter the payload
runs in, and the host takes the *last* `@@RESULT@@` and uses its `events` list.
Feeding `@@EVENT@@ os_system ...` followed by a forged `@@RESULT@@ {"load_succeeded": true, "events": []}`
yields an empty event list **[run, parser of the output only]**. A payload that prints the
forged line and calls `os._exit(0)` erases its own evidence [code]. This matters for the new
design: fake modules inside the WASM guest also share the interpreter with the payload, so
**the recorder can always be tampered with**. Design consequence in §4.1.

**S6. The loaders trust the scan completely.**
`safe_load_pickle` uses unrestricted `pickle.load`; `safe_load_keras` uses
`safe_mode=False` [code]. Any scanner miss (S1, S2) becomes host code execution. The new
`safe_load` must enforce the same allowlist at load time (restricted `Unpickler`,
`torch.load(weights_only=True)`, `keras ... safe_mode=True`), as the spec already asks.

**S7. No size or zip-bomb limits; recursion escapes.**
A 199 KB `.keras` archive with a 200 MB `config.json` member drives `parse_keras` to a
437 MB Python heap peak (tracemalloc) **[run]**. A config nested about 700 levels deep
raises `RecursionError` out of `parse_keras` **[run]** (480 levels was fine). No check on
member names (`../`), duplicate names, member count or compression ratio.

**S8. PyTorch formats are not supported.** `safe_load_model("x.pt")` raises `ValueError`;
`pipeline.analyze` routes a torch zip to the pickle parser, which fails closed as
`suspicious` **[run]**. Legacy (non-zip) torch files are several pickles in a row; a walker
that stops at the first `STOP` would miss the rest. The new parser must walk all of them.

**S9. Monkey-patch coverage gaps in the Docker detonator.** `os.execv` is patched but
`posix.execv` is not; `socket.socket.connect` but not `_socket.socket` [code]. The container
is the real boundary, so this is evidence quality, not escape. Relevant to the fake-module
list in the new design: stubs must be installed by name in `find_class`, not by patching.

**S10. Cache poisoning.** Whoever can write the cache dir can mark a file `safe`. It is
documented and off by default [code]. Keep only if signed or drop (D5).

**S11. Deep mode only works from a source checkout.** `docker/` is not in the wheel
(`packages.find include = ["sandbox_rce*"]`), so `pip install` users get `no_detonation`
forever [code].

**S12. Judge sees raw attacker strings.** `raw_disasm` and `raw_log` go into the prompt,
fenced with a nonce [code]. The spec asks for structured evidence only, escaped strings.

**S13. Old tests execute payloads on the host.** `712016c:tests/test_detoner.py` runs
`detonate.py` with real `pickle.load` in a host subprocess. These tests must not be restored
as they are; their assertions can be kept against the WASM guest.

**S14. Dashboard.** Output escaping is correct (`esc()` on every interpolated field) [code].
Upload limit 32 MB, bound to 127.0.0.1, but one unbounded thread per upload [code]. Moving it
to a JSON viewer removes upload and execution entirely.

## 4. Where the audit pushes back on the target spec

These are not scope changes, they are corrections needed to make the spec's own goals hold.

**4.1 CLEAN must never rest on the emulator alone.** S5 shows a payload can suppress its own
evidence when the recorder lives in its interpreter, and the spec already lists fingerprinting
and dormant payloads as limits. Proposal: **CLEAN requires the static allowlist to pass**, and
`safe_load` re-enforces that allowlist at load time. The dynamic layer can only raise severity
(and explain). A payload that defeats the emulator then gains nothing: what gets loaded is
still restricted to allowlisted globals. Missing or malformed guest result, unexpected exit,
trap, fuel or memory exhaustion = SUSPICIOUS.

**4.2 Pyodide does not run on wasmtime.** Pyodide is built for Emscripten and needs a
JavaScript host **[not verified here; based on Pyodide's documented build target]**.
CPython built for WASI does run on wasmtime-py, measured in §5. Plan uses CPython-on-WASI.

**4.3 There is no Python version in `.keras` metadata.** The project's own
`evil_lambda.keras` has `metadata.json` = `{"keras_version": "3.15.1", "date_saved": ...}`
and the Lambda carries only base64 `code` **[run, read as JSON]**. Worse, marshal data from
CPython 3.13 loaded in the 3.12 guest **without any error**; `co_names` / `co_consts` came
out right, but `dis` produced wrong opcodes (`COPY_FREE_VARS`, `DELETE_NAME` instead of
`LOAD_GLOBAL`, `CALL`) **[run]**. So version mismatch cannot be detected from metadata or
from exceptions. Proposal: every Lambda carrying code is at least SUSPICIOUS; names/consts are
reported as "producer version unknown"; bytecode is executed under fakes only by a guest whose
version matches an explicit hint (if Keras provides one) and otherwise reported as
"cannot analyse". MALICIOUS only from names/consts hitting a sink or a recorded sink call.

**4.4 Lambda layers can never become CLEAN in practice**, because `safe_load` with
`safe_mode=True` refuses them anyway. The Keras emulation therefore serves classification and
evidence (MALICIOUS vs SUSPICIOUS), not admission.

**4.5 Legacy `.h5` in the sandbox needs a pure-Python HDF5 reader.** The WASI guest has no
h5py. A minimal reader for the superblock and the `model_config` attribute is
**[not verified]** feasible; if it is not robust by milestone 2, `.h5` defaults to
"cannot analyse" = SUSPICIOUS and real parsing goes to deep mode.

**4.6 Verdict combination is a max over layers**, never an override:
`final = max(static, dynamic, judge)` with judge allowed only upward, and CLEAN only when
static is CLEAN *and* the dynamic layer finished without alarm or error. This fixes S4 by
construction.

## 5. WebAssembly feasibility, measured **[run]**

Setup: `wasmtime` 49.0.0 from PyPI; CPython 3.12.0 for WASI, VMware Wasm Labs build with
embedded stdlib (26,267,204 bytes, sha256 in `audit/wasm-feasibility/README.md`). Scripts:
`audit/wasm-feasibility/`.

| Requirement | Result |
|---|---|
| Install wasmtime-py | `pip install wasmtime` works on Python 3.13, wheel includes the runtime |
| CPython runs under wasmtime-py | yes; `pickle`, `pickletools`, `dis`, `marshal`, `base64`, `json`, `zipfile` import from the embedded stdlib |
| No host filesystem | `os.listdir('/')` → `FileNotFoundError`; `/etc/passwd` not found |
| One read-only preopen | `preopen_dir(path, "/in", fs_mutable=False)`: read works, write → `PermissionError`; `/in/..` and `/in/../../etc/passwd` → `PermissionError` |
| No network / processes | `socket.connect` → `OSError: Not supported`; `os.system` absent; `subprocess.run` → `OSError: wasi does not support processes` |
| Memory limit | `Store.set_limits(64 MB)`, allocating 200 MB → guest `MemoryError`, host fine; 100 MB under a 256 MB limit succeeds |
| Fuel limit | 2e9 fuel: `while True: pass` traps after 0.315 s; interpreter start + `print` used about 213 M fuel |
| Epoch limit | 1 s deadline: busy loop traps at 0.997 s. **`time.sleep(5)` is not interrupted: trap only at 5.04 s.** Blocking WASI calls ignore epochs |
| Interpreter crash containment | `marshal.loads` on 200,000 nested tuples with a raised recursion limit crashed the guest → wasm trap; host process unaffected |
| Pickle stub detonation | Subclassing `pickle.Unpickler` (the C `_pickle` one) and overriding `find_class` recorded `posix.system` and the call `('echo MARKER')` |
| Cold start | compile `python.wasm`: 2.8 to 3.8 s; serialized module cache 25 MB, then deserialize ≈ 1 ms (cache is valid only for the same engine config) |
| Per-scan time | in-process run of the scan script 0.15 to 0.19 s; **fresh subprocess including Python start and `import wasmtime`: 0.24 to 0.27 s wall** (5 runs) |

Consequences for the design:

1. Run the guest in a **child process** with a wall-clock kill, because epochs do not stop
   blocking calls, and to contain a wasmtime bug outside the caller's process. Also stub
   `time.sleep` in the guest.
2. Use fuel *and* the wall-clock kill; epoch adds nothing once there is a process kill.
3. The VMware build is from 2023 and is used here for measurement only. For shipping, build
   CPython for WASI from a pinned CPython tag in CI (`Tools/wasm/wasi.py`) and publish it in a
   companion wheel (decision D3). Pin wasmtime and record the runtime sha256 in every Report.
4. The guest's Python version is fixed (one build), which is fine for pickle (version-neutral
   opcodes) and is exactly the marshal limitation in §4.3.

Environment limits found for later milestones: this cloud session cannot reach
huggingface.co (proxy 403) or python.org, and `modelscan` has no installable distribution
for its Python 3.13 (`picklescan` 1.0.5 and `fickling` 0.1.12 download fine). The benign
Hugging Face corpus and the modelscan comparison will need your machine or a network
policy change.

## 6. Migration plan

### Decisions I need from you

| # | Decision | My recommendation |
|---|---|---|
| D1 | PR #4: merge into `main` first, or close it | **Merge first.** The new work starts from the fixed baseline and its 40 tests, and the default branch stops shipping H1 to H6 |
| D2 | Package name: rename `sandbox_rce` → `safeloadai` | **Clean rename, no shim.** Not on PyPI, no external users |
| D3 | Where the WASI CPython binary comes from | **Companion wheel** `safeloadai-wasi-runtime` built in CI from a pinned CPython tag. Alternative: download on first use with sha256 pin (needs network once) |
| D4 | Deletions (each listed below) | Approve the list as a whole or strike items |
| D5 | Keep strace mode and the cache | Keep strace inside deep mode only; drop the cache until it can be keyed and signed |
| D6 | Layout: move the project from `SAFE_LOAD_MODEL/` to repo root (`pyproject.toml` at root, `src/safeloadai/`) | **Yes**, so `pip install git+https://...` works without a subdirectory |
| D7 | Default branch | At milestone 8: switch the GitHub default from `claude/pkl-rce-sandbox-pcdsri` to `main`. Only with your word at that point |

Deletion list for D4 (all recoverable from git history): `SAFE_LOAD_MODEL/simple_evil.py`,
`test_lib.py`, `test_1_clean_pkl.py`, `test_2_clean_keras.py`, `test_3_evil_pkl.py`,
`test_4_evil_keras.py`, `test_clean.pkl`, `prezentacja.html`, `schemas/` (replaced by one
Report schema), `tools/eval_static.py` (replaced by `evaluation/`), `sandbox_rce/cache.py`
(if D5 = drop). Old branches stay untouched unless you ask.

### Target layout

```
pyproject.toml            # name safeloadai, Python >=3.11, ruff, pytest config
src/safeloadai/
  __init__.py  api.py  cli.py  errors.py
  parsing/   zipsafe.py pickle_container.py torch_container.py keras_container.py h5_reader.py
  static/    pickle_ops.py allowlists.py keras_config.py lambda_static.py
  sandbox/   runtime.py (wasmtime child process, limits)  guest/ (code copied into the guest)
  emulator/  fakes for os, posix, subprocess, socket, urllib, http, requests, shutil, ctypes,
             importlib, builtins, tensorflow, keras, torch, numpy-lite; recorder
  judge/     client.py prompt.py
  report/    model.py (Report dataclass, JSON) verdict.py (monotone max)
  loaders/   pickle_loader.py (restricted Unpickler) torch_loader.py keras_loader.py
  deep/      docker backend (moved from sandbox.py / detonate*.py), optional
app/                      # Report JSON viewer only
tests/  tests/corpus/     # harmless marker samples generator
evaluation/run_eval.py
docs/  docs/pl/
.github/workflows/ci.yml
```

### Milestones (each ends with tests run and a summary in this thread)

1. **Audit + plan** (this document). Waits for your approval.
2. **Parsers + static.** `zipsafe` (size, ratio, member count, `..` and absolute names,
   duplicates), pickle walker over all pickles in a file, torch zip, keras config, h5 reader
   attempt. Function-level allowlists (exact match). Regression tests for S1, S2, S3, S7, S8
   and H2, plus the restorable old parser tests (`test_parser.py`, `test_parser_keras.py`).
3. **WASM sandbox + fake APIs.** Child-process runtime with memory, fuel, wall-clock kill, one
   read-only preopen; guest Unpickler with recording stubs; Keras graph rebuild with Lambda
   execution under fake globals; anti-emulation flags.
4. **Behaviour monitor + verdict.** Sink taxonomy, fail-closed rules, monotone verdict, Report
   JSON, `scan()` / `safe_load()` / CLI with exit codes. Loaders enforce the allowlist.
5. **Corpus + evaluation.** Marker-only malicious generator (all variants in the spec,
   including the CVE-2024-3660 technique class and S1/S2 styles), benign download script,
   `run_eval.py` with detection, false-positive rate, per-layer contribution, scan time, and
   picklescan / Fickling comparison (modelscan if installable).
6. **Judge.** Structured-only input, upward-only, off by default, key from env.
7. **Docs + CI.** English README with threat model, limitations (the six items from your spec
   plus §4.3), measured table; ruff + pytest in GitHub Actions; `docs/pl/` optional.
8. **Merge to `main`** and default-branch switch, after your approval.

Deep mode (Docker) is designed and moved in milestone 3 or 4 but cannot be verified in this
cloud session. When it is ready I will give you exact PowerShell commands to run it locally.

### Where the work happens

Commits go to `claude/safeloadai-audit-mnvlqm` (this branch, based on `main`). If D1 = merge,
I rebase it onto the new `main` before milestone 2. One PR per milestone into `main`, so each
is reviewable on its own.
