<!-- SPDX-License-Identifier: Apache-2.0 -->
# safeloadai

**safeloadai tells you whether a model file is safe to load before you load it.**
It reads pickle, joblib, PyTorch, Keras and legacy Keras HDF5 files without running
them, and runs whatever code they would run inside a WebAssembly sandbox with fake
APIs. It is beta software (0.7.1): see [LIMITATIONS](#limitations) before relying on it.

> **Scope.** safeloadai checks whether *loading* a model file runs code or touches the
> system: the model-file part of the AI supply chain (OWASP **LLM03:2025 Supply Chain**,
> OWASP ML Top 10 **ML06 AI Supply Chain Attacks**, MITRE ATLAS **AML.T0010.003**,
> **AML.T0011.000**, **AML.T0018.002**). It does **not** detect model backdoors or
> poisoned weights (OWASP **LLM04:2025 Data and Model Poisoning**): those live in the
> weight values and leave the file's structure untouched. A CLEAN verdict says nothing
> about what the model predicts. Full threat model, trust boundaries and out-of-scope
> threats: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Quick start

```bash
pip install safeloadai              # Python 3.11+, Linux, macOS or Windows; nothing is downloaded at run time
safeloadai scan model.pkl           # exit 0 CLEAN, 1 MALICIOUS, 3 SUSPICIOUS, 5 UNSUPPORTED, 6 ERROR
safeloadai scan models/ --json      # a whole directory, JSON reports
safeloadai doctor                   # checks the sandbox runtime and runs it once
```

```python
from safeloadai import scan, safe_load, UnsafeModelError

report = scan("model.pkl")          # never loads the file on this machine
print(report.verdict)               # CLEAN, SUSPICIOUS, MALICIOUS or UNSUPPORTED (None on ERROR)
print(report.reasons)               # why, in plain words

model = safe_load("model.pkl")      # loads only a CLEAN file, else raises UnsafeModelError
```

Supported formats: pickle (`.pkl`, `.pickle`), joblib (uncompressed, zlib, gzip, bz2,
lzma, xz, lz4), PyTorch (`.pt`, `.pth`, `.bin`, zip and legacy), Keras (`.keras`) and
legacy Keras HDF5 (`.h5`, read without h5py or libhdf5). Anything else is UNSUPPORTED,
never CLEAN.

The defaults are the strictest settings. Every option that loosens a verdict is off
by default, is announced on the command line, is recorded in `Report.options`, and is
documented with its risk in [docs/OPTIONS.md](docs/OPTIONS.md).

### Install

`pip install safeloadai` also installs `safeloadai-runtime`, the pinned CPython-on-WASI
runtime. Nothing is downloaded at run time. Compiling that runtime takes a few seconds,
so the compiled module is cached in your per-user cache directory:

| platform | cache directory | fallbacks, in order |
|---|---|---|
| Windows | `%LOCALAPPDATA%\safeloadai` | `%APPDATA%\safeloadai`, `%TEMP%\safeloadai-<user>` |
| macOS | `~/Library/Caches/safeloadai` | none |
| Linux and others | `$XDG_CACHE_HOME/safeloadai` | `~/.cache/safeloadai` (never a shared `/tmp`) |

`SAFELOADAI_HOME` overrides all of them. If no location can be used, the runtime is
compiled in memory for every scan: slower, with the same verdicts. `safeloadai doctor`
shows the location in use, or each location it tried with the error it got. Details:
[docs/OPTIONS.md](docs/OPTIONS.md#compiled-module-cache).

## How it works

```
             model file
                 |
     every reading a loader could make
   (pickle at 0, joblib, ZIP from the end, HDF5)
                 |
     +-----------+------------+
     |                        |
  static analysis        emulation in a WASI sandbox
  (opcodes, imports,     (CPython 3.12 in WebAssembly,
   Keras config,          fake os/subprocess/socket/torch...,
   exact allowlist)       no network, no files, CPU/memory caps)
     |                        |
     +-----------+------------+
                 |
   worst verdict wins: CLEAN / SUSPICIOUS / MALICIOUS / UNSUPPORTED
```

1. **Every reading.** A file can be a pickle for `pickle.load` and a ZIP archive for
   `zipfile` at once (a polyglot). Each reading is analysed on its own, and any
   ambiguity is at least SUSPICIOUS.
2. **Static analysis.** Every pickle opcode is walked. Imports must match an exact
   `(module, qualname)` allowlist; a known sink (`os.system`, `eval`, `read_pickle`, ...)
   that is called is MALICIOUS. Keras configs need exact module and class names.
3. **Emulation.** The file is unpickled (and Keras Lambda layers are called) inside
   CPython compiled to WebAssembly, under wasmtime, with recording fake modules. Process,
   network, file-write or code-execution calls are MALICIOUS.
4. **What may pass outside the allowlist** (0.7.0): a global that is only stored and
   never called; classes the pinned library source shows are state-only; what torch's
   `weights_only=True` loader accepts; profiles of well-known files (Trainer files,
   Ultralytics checkpoints); and a shipped list of reviewed files matched by exact
   sha256. Each only *allows*: none of them lowers a MALICIOUS or RISKY finding, and
   `Report.cleared` says which mechanism accepted what.

`safe_load` loads the same private copy it scanned, with a restricted unpickler,
`torch.load(weights_only=True)` or Keras `safe_mode=True`.
Details: [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md), [docs/PROFILES.md](docs/PROFILES.md),
design decisions in [DECISIONS.md](DECISIONS.md).

### Verdicts and the informed override

Every reason has a category:

- **MALICIOUS:** evidence of a known sink (process, network, file write, code
  execution) or of tampering with the sandbox's evidence.
- **RISKY:** a construct the scanner refuses because it can be abused: code-carrying
  layers, polyglots, parse errors, limits, known gadgets, a module name that imitates
  an allowlisted one (`kerasx`, `sklearn2`, `kеras` with a Cyrillic `е`).
- **UNVERIFIABLE:** a named object whose code the scanner cannot see, such as a class
  outside the allowlist or a custom Keras layer. Nothing in it is known to be dangerous.

A file whose **every** reason is UNVERIFIABLE (a *soft block*) can be accepted item by
item, for that one file, and the acceptance is recorded in the Report. One RISKY or
MALICIOUS reason (a *hard block*) makes an override impossible, and there is no switch
that accepts everything.

```python
model = safe_load("model.pkl", accept_unverified=["mypkg.models.Thing"])       # this file only
```

```bash
safeloadai scan convnext.h5 --accept-unverified LayerScale       # name every item
safeloadai scan model.pkl --trust-inert-from scikit-learn        # judge your installed sklearn's classes
```

Accepting an UNVERIFIABLE item means trusting that class's code; see
[docs/OPTIONS.md](docs/OPTIONS.md#accept_unverified).

### Errors are not verdicts

When safeloadai itself fails (the file cannot be read, a parser hits a bug, the
sandbox crashes or times out, the runtime fails its integrity check), the report says
`status: "error"` with a stable code such as `E302` and has **no verdict**. An ERROR is
never CLEAN and never loadable, and the CLI exits 6 (4 for a runtime integrity
failure). A corrupt file that a loader would also reject is a verdict (SUSPICIOUS), not
an ERROR. With several files, each gets its own result and the exit code follows
MALICIOUS > ERROR > SUSPICIOUS > UNSUPPORTED > CLEAN. Codes and rules:
[docs/ERRORS.md](docs/ERRORS.md).

## Results

Run of 2026-10-20, safeloadai 0.7.0, in a disposable cloud container with
`evaluation/guard.py` on and no `--deep`. Full tables:
[eval-v070](evaluation/results/eval-v070-20261020T063605Z.md). Confusion matrices
(TP/FP/TN/FN with 95 % intervals), the data distribution and the tune/held-out split:
[docs/EVALUATION.md](docs/EVALUATION.md).

**Detection.** "Detected" means any verdict other than CLEAN. safeloadai's verdict was
MALICIOUS on every one of these by default.

| set | safeloadai default | real opt-in | upper bound | picklescan 1.0.5 | fickling 0.1.12 | modelscan 0.8.8 |
|---|---|---|---|---|---|---|
| lab marker payloads (incl. 6 polyglots) | 59 / 59 | 59 / 59 | 56 / 59 | 35 / 59 | 40 / 59 | 24 / 59 |
| mutations (`tests/corpus/mutate.py`) | 774 / 774 | 774 / 774 | 774 / 774 | 678 / 774 | 666 / 774 | 618 / 774 |
| real Hub files flagged by the Hub's scanners, labelled malicious from that evidence | 49 / 49 | 49 / 49 | 49 / 49 | 31 / 49 | 32 / 49 | 29 / 49 |

**Benign Hugging Face files, held-out half** (501 files from repos no review looked at;
the tune half, 432 files, is what lists, policies and profiles were built from). No
benign file is MALICIOUS in any configuration.

| configuration | CLEAN | soft block (UNVERIFIABLE only) | hard block (RISKY) | UNSUPPORTED |
|---|---|---|---|---|
| 0.5.0 default | 352 | 101 | 48 (33 of them not a readable format) | - |
| **0.7.0 default** | **372** | **81** | **15** | **33** |
| 0.7.0 real opt-in: `--trust-inert-from scikit-learn transformers torch` | 372 | 81 | 15 | 33 |
| 0.7.0 upper bound: accept all unverifiable (not recommended) | 453 | 0 | 15 | 33 |

- **Default.** 129 of 501 held-out files are not CLEAN (0.5.0: 149). Of the
  468 files in a format safeloadai reads, 96 are blocked (0.5.0: 116), and
  81 of those are soft blocks a user can accept item by item.
- **Real opt-in** reads the installed source of the named libraries instead of the
  pinned one. Run against the same versions as the pinned policies it changes nothing,
  as it should; it helps when your installed version differs from the pinned one.
- **Upper bound** accepts every UNVERIFIABLE item without reading it. It also lets 3
  lab payloads through (an unknown pickle global, a custom Keras object, a custom
  object in an `.h5`), which is why no switch does this.
- **The known-file list** clears 27 tune files and, by construction, no held-out file.
- **UNSUPPORTED** files are OpenVINO-style `.bin` weights and similar: no pickle,
  archive or HDF5 reading exists, so safeloadai says nothing about them.
- **Other scanners** flag 4 (picklescan), 4 (modelscan) and 183 (fickling) of the 501
  held-out files, but miss many of the malicious files above.

What still blocks held-out files most often: xgboost `Booster` (19 files, kept out by
an owner decision), the authors' own Keras losses and layers, newer Ultralytics heads
(`Segment26`), Keras/torch optimizers and `__main__` classes. The full Pareto table is in
the evaluation report.

**How to read these numbers.** The malicious Hub files are a convenience sample (test
payloads and proofs of concept, mostly simple pickles); they show that what the Hub's
scanners flag is caught, not how safeloadai does against a targeted attacker. The lab
and mutation payloads are marker rebuilds, and the mutation generator was written with
knowledge of the scanner.

### Compared with published work

PickleBall ([arXiv 2508.15987](https://arxiv.org/abs/2508.15987)) also
derives policies from library source code, and enforces them in a loader. It reports 0 %
false negatives and a 20.2 % false-positive rate (benign models it refuses to load) on
its own dataset of pickle-only models. safeloadai's state-only policies follow the same
idea at development time. The numbers are not directly comparable: the datasets differ
(this corpus is stratified across pickle, joblib, PyTorch, Keras and HDF5, and includes
files in formats no tool reads), and the counting differs (safeloadai counts every
non-CLEAN benign file, soft blocks included).

## LIMITATIONS

- **Beta.** The allowlist, policies and profiles cover the library versions and files
  the tune half of the corpus needed. Benign files from other libraries or versions will
  often be SUSPICIOUS (UNVERIFIABLE).
- **Emulation is not execution.** The fake APIs return plausible values, not
  real ones. A payload whose behaviour depends on real results, real files or
  real time may take a different path in the sandbox.
  - **Covered:** introspection (`__subclasses__`, `__globals__`, `type`,
    `_getframe`, dunder `getattr`), sleeping, reading tensor values and
    unknown globals are recorded as anomalies and make the file SUSPICIOUS.
  - **Not covered:** other ways of detecting the emulator are not.
- **The Lambda rule.** Since 0.8.0 a Keras Lambda layer with bytecode is never CLEAN:
  at best SUSPICIOUS (RISKY), because code that runs in the sandbox can hide from the
  recorder (see "Evidence channel"). Emulation still runs and makes it MALICIOUS when it
  sees a dangerous behaviour or an anomaly. The Python version that wrote the bytecode is never guessed, because Keras
  files do not record it. One case stays undetectable: bytecode from another CPython
  version that happens to be byte-identical to valid 3.12 bytecode (for example
  `lambda x: x` from 3.11) passes every check and is emulated as 3.12 bytecode.
- **Evidence channel.** Code that runs in the guest (Keras Lambda bytecode, dill code
  objects) shares the interpreter with the recorder. It can find the nonce and append
  well-formed records of its own, and it can keep its own later behaviour out of the
  log or behave harmlessly when it notices the sandbox. It cannot remove records the
  host has already received, and since 0.8.0 it cannot fake a complete run by writing
  a `done` record and exiting early (the host sees `proc_exit`). Writes without the
  nonce count as tampering and are MALICIOUS. Moving the recorder into host functions
  would not help with the pinned runtime; the design and a proposal are in
  [docs/EVIDENCE_CHANNEL.md](docs/EVIDENCE_CHANNEL.md).
- **An override on UNVERIFIABLE means trusting that class's code.** Accepting it tells
  `safe_load` to import and run whatever the named module does, with your privileges.
  Accept only items whose source you know and trust. Look-alike names of allowlisted
  modules are RISKY instead, but a name that is merely unfamiliar
  (`mycompany.layers.Foo`) can be accepted, and so can a payload hidden behind it.
- **Source-derived policies trust the pinned library versions.** A state-only class
  is judged from the source of the version listed in `static/upstream/REVIEW.md`. If a
  newer version adds a `__setstate__` that does something dangerous, the pinned policy
  does not know. `--trust-inert-from DIST` judges the installed version instead, and so
  trusts that installation (see [docs/OPTIONS.md](docs/OPTIONS.md#trust_inert_from)).
- **Profiles use the file name and the producer's imports.** A file that matches both
  but not the structure gets a RISKY reason; a payload in a file outside any profile is
  judged by the usual rules. A profile never accepts a sink.
- **Known files help only byte-identical files.** The shipped list holds 27 reviewed
  files from the tune half of the corpus; a file that differs by one byte gets no
  benefit. `--no-known-good` turns the list off.
- **Allowlist false positives.**
  - **numpy random state:** `__generator_ctor`, `__randomstate_ctor` and
    `__bit_generator_ctor` call one of their arguments, so they are accepted
    only with the exact arguments numpy itself writes.
  - **TorchScript** is always SUSPICIOUS.
  - **xgboost `Booster`** stays UNVERIFIABLE (it hands raw bytes to a native parser);
    save with `save_model("model.json")` instead.
- **UNSUPPORTED formats.** OpenVINO and CTranslate2 weights and any other format with no pickle, joblib, ZIP or HDF5 reading are UNSUPPORTED. safeloadai
  says nothing about them, and `safe_load` never loads them.
- **joblib.** Supported: joblib 0.10 and newer, one stream of zlib, gzip, bz2, lzma,
  xz or lz4 (lz4 needs `pip install "safeloadai[lz4]"`). SUSPICIOUS by design: the
  multi-file format of joblib < 0.10, structured dtypes holding Python objects, a
  wrapper built another way than joblib's own, array data inside a pickle frame, and
  decompressed output above 1 GiB or a ratio above 1000:1. The check of what a plain
  `pickle.load` would import from joblib's array bytes stops at the first import whose
  top-level module no environment could provide.
- **Legacy HDF5.** Supported: superblock versions 0 to 3, old-style and compact groups,
  fixed and variable-length string attributes. Weight datasets are never read, so bugs
  in libhdf5 or h5py weight parsing are out of scope. SUSPICIOUS by design: external
  links or data files, virtual datasets, driver info, a user block, dense storage, odd
  root attributes, more than 100,000 objects and anything the reader cannot parse.
  Keras 2 Lambda layers are never CLEAN.
- **Polyglot files.** Recognised readings: a pickle at offset 0, a joblib-compressed
  stream at offset 0, a ZIP archive found from its end, and the first HDF5 superblock at
  0, 512, 1024, ... A reading the scanner does not know (another archive format, data a
  custom loader reads at another offset) is not analysed.
- **CRC-32.** A PyTorch member with a bad CRC-32 is analysed anyway and the file is
  RISKY; a `.keras` member with a bad CRC-32 is refused, as `zipfile` refuses it.
- **Lambda models do not load through `safe_load`,** because Keras safe mode refuses
  Lambda bytecode (and they are never CLEAN). Legacy `.h5` files are never loaded by
  `safe_load`.
- **Loading a CLEAN pickle imports allowlisted libraries on your machine,** such as
  numpy and scikit-learn, and runs their reconstruction code. You are trusting them.
- **The WASI sandbox is only as strong as wasmtime** and a third-party CPython WASI
  build (pinned by sha256). Fuel bounds CPU and the host kills the process at the
  wall-clock limit; large or slow models can hit the limits and are then ERROR (E303,
  E304; never CLEAN).
  Files up to 4 GiB are read into memory on the host.
- **Deep mode (`--deep`, off) runs the real loader on the real kernel** in Docker,
  bubblewrap or nsjail. Docker shares the kernel; the nsjail flags have not been
  tested; a payload can print fake events, which can only raise the verdict. The Docker
  backend needs a source checkout.
- **The runtime package is trusted at install time.** safeloadai checks the `.wasm`
  hash before every use, but pip runs whatever a package does when it is installed.
  Install `safeloadai-runtime` only from PyPI under that exact name and version.
- **The judge (`--judge`, off) only adds cost and escalation.** It sees no free text
  and can never lower a verdict.

## Reporting a bypass

A file that safeloadai calls CLEAN but that runs code when loaded is a security bug.
Report it privately through the repository's **Security** tab ("Report a
vulnerability"), with a harmless payload. Details and scope: [SECURITY.md](SECURITY.md).
False positives are welcome as normal issues.

## Development

```bash
python packages/safeloadai-runtime/fetch_runtime.py   # once: download + verify the pinned runtime
pip install ./packages/safeloadai-runtime
pip install -e ".[dev]"
ruff check .
python -m pytest -q
python -m tests.corpus.build_corpus /tmp/corpus
python evaluation/run_eval.py --lab /tmp/corpus --hf /path/to/hf_corpus   # --help for every input
```

- **Safe tests:** a host guard refuses process execution (except the sandbox runner),
  non-loopback network connections and unrestricted unpickling; sample payloads are
  markers only (`echo MARKER`, `/tmp/safeloadai_marker`, 127.0.0.1).
- **CI** builds both wheels, installs them into a clean venv, blocks the network and
  runs the whole suite against the installed wheels on Linux, macOS and Windows with
  Python 3.11 to 3.13. A skipped sandbox test is an error there.
- **Update monitoring detects and never auto-trusts:** Dependabot, a weekly
  `upstream-drift` job that scans models written by the latest libraries and opens an
  issue on drift, and `runtime-watch` for new WASI CPython and wasmtime releases
  ([docs/UPDATING_RUNTIME.md](docs/UPDATING_RUNTIME.md)).
- **Releasing:** `.github/workflows/publish.yml` uploads both packages with PyPI
  Trusted Publishing and PEP 740 attestations, started by hand, to testpypi or pypi,
  behind a required reviewer ([docs/RELEASING.md](docs/RELEASING.md), including how to
  verify a release). Changes are in [CHANGELOG.md](CHANGELOG.md).
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md). Changes to detection carry a
  standard tag such as `[LLM03]` in the title.
- **Evaluation:** [docs/EVALUATION.md](docs/EVALUATION.md), generated from the result
  files: confusion matrices, data distribution, the tune/held-out split.

The report viewer runs with `flask --app app.server run --host 127.0.0.1`; it renders
Report JSON and does not scan files. The audit that started this rewrite is in
[AUDIT.md](AUDIT.md).

## Statement on AI use

This project was written by Bartosz Mosionek together with an LLM assistant (Claude):
code, tests, reviews of library source and documentation. The optional judge uses the
Anthropic API. The author understands the code and takes technical responsibility for
it.

## License

Apache-2.0, see [LICENSE](LICENSE). The `safeloadai-runtime` package also ships CPython
built for WASI under its own licences (`packages/safeloadai-runtime/NOTICE`).
