# Threat model

What safeloadai protects, from whom, where the trust boundaries are, and which threats
it addresses or leaves out. Each threat is mapped to:

- **OWASP Top 10 for LLM Applications 2025** (`LLM01`...`LLM10`),
  <https://genai.owasp.org/llm-top-10/>;
- **OWASP Machine Learning Security Top 10** (2023 edition, `ML01`...`ML10`),
  <https://owasp.org/www-project-machine-learning-security-top-10/>;
- **MITRE ATLAS** technique and mitigation IDs, checked against the ATLAS data release
  2026.09 (`mitre-atlas/atlas-data`, `dist/v6/ATLAS-2026.09.yaml`, modified
  2026-09-15), <https://atlas.mitre.org/>.

The detection rules in [HOW_IT_WORKS.md](HOW_IT_WORKS.md#rule-families-and-standards)
carry the same tags.

## Scope in one paragraph

safeloadai answers one question: **will loading this model file with the usual loader
run code or touch the system?** That is the model-file part of the AI supply chain
(**LLM03 Supply Chain**, **ML06 AI Supply Chain Attacks**, ATLAS **AML.T0010.003**
*AI Supply Chain Compromise: Model*, **AML.T0011.000** *User Execution: Unsafe AI
Artifacts*, **AML.T0018.002** *Manipulate AI Model: Embed Malware*). It does **not**
judge what the model computes: backdoors, poisoned weights and biased training data
(**LLM04 Data and Model Poisoning**, **ML02**, **ML10**) are out of scope, because they
leave no trace in the file's structure (see [below](#why-a-file-scanner-cannot-find-backdoors)).

## Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | The user's machine and its data | Loading a hostile pickle runs code with the user's privileges. This is the asset everything else serves. |
| A2 | The correctness of a verdict | A CLEAN verdict on a hostile file is the worst failure (a *bypass*); `safe_load` acts on it. |
| A3 | The scanning host during a scan | Scanning must never run the file's code or let it touch the host, and a file must not exhaust the host's memory or time (T10, T16). |
| A4 | The WASI runtime (`safeloadai-runtime`) | The emulation sandbox is only as good as the pinned CPython-on-WASI build and wasmtime. |
| A5 | The release path (GitHub repository, Actions, PyPI) | A poisoned safeloadai release would turn the scanner into the attack. |
| A6 | The user's Anthropic API key (optional judge) | Only when `--judge` is used. |
| A7 | The evaluation corpus and its labels | Wrong labels make published numbers wrong; downloaded files are hostile. |

## Attackers and their goals

| ID | Attacker | Goal |
|---|---|---|
| G1 | Publisher of a model file (on the Hub, in a repository, sent by mail) | The victim loads the file and the payload runs (A1), helped by a CLEAN verdict (A2). |
| G2 | The same publisher, against the scanner | The payload runs *during the scan* (A3), or escapes the WASI sandbox (A4), or the scan crashes or hangs to wear users down. |
| G3 | The same publisher, against the optional judge | Text in the file (strings, names) tries to talk the LLM judge into a lower verdict. |
| G4 | Supply-chain attacker against safeloadai itself | A malicious release (compromised maintainer account, workflow, dependency or runtime build) (A5, A4). |
| G5 | A user who wants to load a flagged file anyway | Not an attacker, but a risk: overrides that accept more than the user understands. |

## Trust boundaries

```
 untrusted bytes ──► [B1 host: static analysis, no deserialisation]
                          │ read-only copy of the bytes
                          ▼
                     [B2 WASI guest: CPython 3.12 in wasmtime, fakes, fuel, memory cap,
                          │          no network, one read-only directory]
                          │ evidence records (nonce, sequence)  ──► host decides
                          ▼
   optional ──►      [B3 LLM judge: sees a structured summary; can only raise severity]
   optional ──►      [B4 deep mode: the REAL loader in Docker / bubblewrap / nsjail]
                          │
                          ▼
                     [B5 safe_load: restricted unpickler / weights_only / safe_mode, on the
                                    same private copy that was scanned]
   maintainers ──►   [B6 release path: GitHub → Actions → PyPI (Trusted Publishing)]
```

| Boundary | What crosses it | What holds it |
|---|---|---|
| **B1 host ↔ file** | The file's bytes, parsed by safeloadai's own readers (pickle opcode walker, ZIP reader, Keras config reader, joblib decompressor). | Nothing is deserialised, imported or executed on the host. Readers are pure Python with limits (size, members, ratios, opcodes, depth). HDF5 is not parsed on the host at all (it is parsed in B2). Tests and evaluation run under a host-execution guard. An unexpected exception is a tool error (E2xx), never CLEAN. |
| **B2 host ↔ WASI guest** | The bytes in, evidence records out. | wasmtime with fuel, a memory cap and a host-side wall-clock kill in a child process; no network; one read-only preopened directory; pinned runtime sha256 checked on every use (E401). The host validates every record (nonce, sequence); a write without the nonce is tampering (MALICIOUS). **Known weakness:** the recorder runs in the same interpreter as code a file carries (Lambda, dill), so that code can append well-formed records (noise) or keep its later behaviour out of the log; it cannot remove records already received, and an early `proc_exit` makes the run incomplete (0.8.0). Design and limits: [EVIDENCE_CHANNEL.md](EVIDENCE_CHANNEL.md). |
| **B3 host ↔ judge** | A structured summary of the static and emulation evidence (no free text from the file). | The judge can only raise severity (`report.combine` is a max); a sign that the evidence tries to steer it is itself SUSPICIOUS; off by default. |
| **B4 host ↔ deep mode** | The file, mounted alone, into a real loader. | Container or jail without network, read-only root, no capabilities, rlimits. Real code runs here by design; this is why deep mode is off by default and out of scope for bypass reports. Its events can only raise the verdict. |
| **B5 verdict ↔ load** | The scanned bytes into a real loader on the host. | `safe_load` loads the private read-only copy it scanned (no TOCTOU), with loaders that enforce the policy again: an exact-pair `find_class`, `torch.load(weights_only=True)`, Keras `safe_mode=True`. A wrong verdict therefore does not turn into code execution by itself. |
| **B6 maintainers ↔ users** | Source, workflows, wheels. | Actions pinned by SHA, Trusted Publishing (no API tokens), PEP 740 attestations, a required reviewer on the `pypi` environment, protected `v*` tags, OpenSSF Scorecard ([RELEASING.md](RELEASING.md)). |

## Threats in scope

| ID | Threat | Mitigation in safeloadai | OWASP LLM 2025 | OWASP ML 2023 | MITRE ATLAS |
|---|---|---|---|---|---|
| T1 | A pickle, joblib or PyTorch file whose deserialisation imports and calls a sink (`os.system`, `exec`, `subprocess`, sockets, file writes) | Static opcode walk with an exact allowlist; sink imports with a call are MALICIOUS; emulation in B2 records every call | LLM03 | ML06 | AML.T0010.003, AML.T0011.000, AML.T0018.002 |
| T2 | Indirect execution through gadgets: allowlisted-looking modules, `getattr` chains, `functools.partial`, `operator.methodcaller`, re-exported sinks, BUILD-state hooks (0.7.1) | Exact `(module, qualname)` pairs, known-gadget list, getattr rules, BUILD-hook rules, emulation | LLM03 | ML06 | AML.T0011.000, AML.T0018.002 |
| T3 | Keras Lambda layers and custom objects that carry or name code (CVE-2024-3660 style) | Config walk with exact names; Lambda bytecode scanned for sink names and called on fakes in B2; `safe_mode=True` at load | LLM03 | ML06 | AML.T0011.000, AML.T0018.002 |
| T4 | Parser differentials: polyglots (pickle + ZIP + HDF5), trailing data, data before an archive, joblib array bytes read as opcodes by a plain `pickle.load`, CRC tricks (CVE-2025-1944/1945), hidden pickles in archives (CVE-2025-1889) | Every reading a loader could make is analysed; ambiguity is at least SUSPICIOUS | LLM03 | ML06 | AML.T0011.000 |
| T5 | Corrupted files that run their payload before the loader fails, to make other scanners give up (nullifAI style) | A stream the walker cannot finish is SUSPICIOUS, never CLEAN; the walk reports everything it saw before the failure | LLM03 | ML06 | **AML.T0076** *Corrupt AI Model* |
| T6 | Look-alike and typosquatted module names (`kerasx`, Cyrillic `е`) | Look-alike detection makes them RISKY (not overridable) | LLM03 | ML06 | AML.T0010.003 |
| T7 | Code execution on the scanning host during a scan | B1 never deserialises; HDF5 parsed in B2; host-execution guard in tests and evaluation | LLM03 | ML06 | AML.T0011.000 |
| T8 | Escape from the WASI sandbox, or reaching the network or files from it | wasmtime isolation, one read-only directory, no sockets, pinned runtime checked by sha256 (E401) | LLM03 | ML06 | AML.T0011.000 |
| T9 | Forged evidence: the payload writes records that make the log look clean | Records without the nonce are MALICIOUS; out-of-sequence records are tampering; records cannot be removed. Residual risk: appended noise (B2) | LLM03 | ML06 | AML.T0011.000 |
| T10 | Resource exhaustion: decompression bombs, deep nesting, huge opcode counts, guest loops | Limits everywhere; a limit hit on the file is SUSPICIOUS, a sandbox timeout or fuel exhaustion is ERROR (E303, E304) | LLM10 (resource use of the scanning pipeline) | ML06 | - |
| T16 | Availability of the scanner: a file that makes the static analysis *on the host* hold far more memory than its size, so the scan or the process that runs it is killed (a CI job, a Hub-wide sweep), and the file is never judged | Every value the host-side walk holds is charged to a per-scan budget (512 MiB plus twice the file's size, at most 4 GiB; 64 bytes per opcode plus the bytes of each string); running out is ERROR E105, never a crash and never CLEAN. Per-opcode records and the dashboard listing are capped. Found on the 0.8.0 held-out run: a 211 MB pickle took more than 13 GB of host memory in the listing for the dashboard (fixed in 0.8.0) | LLM10 | ML06 | - |
| T11 | Prompt injection into the optional judge through strings in the file | The judge sees a structured summary, can only raise severity, and an injection attempt is itself SUSPICIOUS | LLM01 | - | - |
| T12 | Time-of-check / time-of-use: the file changes between scan and load | `safe_load` scans and loads one private read-only copy and re-checks its sha256 | LLM03 | ML06 | AML.T0010.003 |
| T13 | A compromised or substituted WASI runtime | Exact pin and sha256 check before every use (E401); runtime built from a pinned upstream release | LLM03 | ML06 | AML.T0010.001 *AI Supply Chain Compromise: AI Software* |
| T14 | A malicious safeloadai release (account, workflow or dependency compromise) | SHA-pinned actions, Trusted Publishing, attestations, environment reviewer, tag protection, Scorecard ([RELEASING.md](RELEASING.md)) | LLM03 | ML06 | AML.T0010.001 |
| T15 | Over-broad overrides by the user (G5) | Overrides only for files whose every reason is UNVERIFIABLE, item by item, per sha256, recorded in the report; MALICIOUS and RISKY never overridable; no "allow all" switch | LLM03 | ML06 | AML.T0011.000 |

Relevant ATLAS mitigations: **AML.M0016** *Vulnerability Scanning* (what safeloadai is),
**AML.M0014** *Verify AI Artifacts* (sha256 in every report; known files matched by
exact sha256), **AML.M0017** *AI Model Distribution Methods*. **AML.M0008** *Validate AI
Model* (testing behaviour for backdoor triggers) is the mitigation for the out-of-scope
threats below, and safeloadai does not provide it.

## Threats out of scope

| ID | Threat | Why it is out of scope | Mapping |
|---|---|---|---|
| O1 | **Model backdoors and poisoned weights**: a model that behaves normally except on a trigger, or whose weights were trained on poisoned data | See [below](#why-a-file-scanner-cannot-find-backdoors). | **LLM04 Data and Model Poisoning**; ML02 Data Poisoning, ML10 Model Poisoning; ATLAS AML.T0018.000 *Poison AI Model*, AML.T0043.004 *Insert Backdoor Trigger*, AML.T0020 *Training Data Poisoning*, AML.T0115 *Publish Poisoned AI Artifacts* |
| O2 | Architecture changes that alter behaviour without code (extra layers, rewired graphs) | Same reason as O1: they are valid models. | ATLAS AML.T0018.001 *Modify AI Model Architecture* |
| O3 | Adversarial inputs, model inversion, membership inference, model theft, output integrity | Properties of a model at inference time, not of loading its file. | ML01, ML03, ML04, ML05, ML09 |
| O4 | Bugs in a framework's weight or tensor parsers (libhdf5, h5py, torch storage, numpy) | safeloadai never reads weight values; a memory-safety bug in those parsers is the framework's. | - |
| O5 | TorchScript, ONNX, GGUF, SavedModel, safetensors and every other format safeloadai does not read | UNSUPPORTED (never CLEAN) or, for TorchScript, always SUSPICIOUS. Code in TorchScript runs by design of `torch.jit.load`. safetensors carries no code by design. | LLM03 |
| O6 | Code the user runs next to the model (`trust_remote_code`, `modeling_*.py`, notebooks) | Not a model file. | LLM03; ATLAS AML.T0011.001 *Malicious Package* |
| O7 | What deep mode's real loader does on the real kernel | Deep mode runs real code by design, in a container or jail; its isolation is the backend's. | - |
| O8 | Malicious code in classes the user accepts with an override or `--trust-inert-from` | The user chose to trust that code; the report records it. | LLM03 |
| O9 | A compromised Python environment on the scanning host (malicious numpy, torch, keras installed) | safeloadai and `safe_load` import libraries from that environment. | LLM03 |

### Why a file scanner cannot find backdoors

A backdoor (LLM04) lives in the **values** of the weights, not in the file's structure.
A backdoored ResNet is a valid ResNet: the same layers, the same tensors, the same
pickle opcodes, the same allowlisted classes. It only computes something different when
the input carries the trigger. Telling the two apart needs the *behaviour* of the model:
running it on inputs, which is exactly what safeloadai is built never to do, and even
then it is not decidable in general (the trigger is unknown, the input space is
enormous, and published detection methods such as trigger reconstruction or activation
clustering are statistical and model-specific). That is ATLAS mitigation AML.M0008
*Validate AI Model*, a different tool with different inputs (the model, test data, the
task). safeloadai's guarantee is narrower and checkable: **loading the file does not run
code**. A clean safeloadai verdict says nothing about what the model will predict.

## What a report means under this model

- **CLEAN**: no layer found anything for T1 to T6; `safe_load` would load it with
  enforcing loaders (B5). It is not a statement about O1 to O9.
- **SUSPICIOUS / MALICIOUS**: see [ERRORS.md](ERRORS.md#the-rule) and the README.
- **UNSUPPORTED**: nothing analysed (O5).
- **ERROR**: safeloadai failed; no statement about the file ([ERRORS.md](ERRORS.md)).

Reporting a bypass of anything in "Threats in scope": [SECURITY.md](../SECURITY.md).
