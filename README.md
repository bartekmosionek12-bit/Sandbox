# safeloadai

safeloadai decides whether a machine-learning model file is safe to load. It
does this before the file is loaded. It handles:

- pickle (`.pkl`, `.pickle`),
- joblib (`.joblib`, `.pkl`; uncompressed or zlib, gzip, bz2, lzma, xz, lz4),
- PyTorch (`.pt`, `.pth`, `.bin`, zip and legacy formats),
- Keras (`.keras`),
- legacy Keras HDF5 (`.h5`, written by tf.keras 2.x or by Keras 3 `model.save("x.h5")`),
  read without h5py or libhdf5.

```python
from safeloadai import scan, safe_load, UnsafeModelError

report = scan("model.pkl")           # never loads the file on this machine
print(report.verdict)                # CLEAN, SUSPICIOUS or MALICIOUS
print(report.to_json(indent=2))

model = safe_load("model.pkl")       # loads only if CLEAN, else raises UnsafeModelError
```

```bash
safeloadai scan models/ --json       # exit 0 CLEAN, 1 MALICIOUS, 3 SUSPICIOUS, 2 usage error
```

## Reason categories and the informed override

Every reason in a Report has a category. It never changes the verdict:

- **MALICIOUS:** evidence of a known sink (process, network, file write, code
  execution) or of tampering with the sandbox's evidence.
- **RISKY:** behaviour or structure the scanner refuses, such as code-carrying
  layers, anomalies in emulation, parse errors, limits, archive tricks,
  known gadgets, or a module name that imitates an allowlisted one (`kerasx`,
  `keras_x`, `tf_evil_pkg`, `sklearn2`, `numpy_`, `nunpy`, `kеras` with a Cyrillic
  `е`): a prefix or suffix of an allowlisted top-level package, an edit
  distance of at most 2, or a homoglyph spelling.
- **UNVERIFIABLE:** a named object whose code the scanner cannot see. Examples
  are a class named without its module in a Keras 2 `.h5` (`LayerScale`), a
  Keras class or custom object outside the known list, or a pickle global
  outside the allowlist that is not a known sink. Each such reason says what
  was found, why it cannot be verified and what you can do. You can re-save the
  model as `.keras`, which records the module, name the exact pickle pair with
  `allow=`, or accept the item.

A file whose **every** reason is UNVERIFIABLE can be accepted, item by item,
for that one file. It stays SUSPICIOUS, and the acceptance is recorded in the
Report (`override`: items, sha256, time, how). One MALICIOUS or RISKY reason
makes an override impossible, and there is no switch that accepts everything.

```python
report = scan("convnext.h5")
report.category, report.unverifiable_items     # ('UNVERIFIABLE', ['LayerScale'])

model = safe_load("model.pkl", accept_unverified=["mypkg.models.Thing"])       # this file only
model = safe_load("model.pkl", accept_unverified={report.sha256: ["mypkg.models.Thing"]})  # pinned to a sha256
```

```bash
safeloadai scan convnext.h5                               # on a terminal: asks, default No
safeloadai scan convnext.h5 --accept-unverified LayerScale  # CI and scripts: name every item
safeloadai scan models/ --accept-unverified <sha256>:LayerScale   # several files: scope by sha256
```

The CLI prompts only when stdin and stdout are both a terminal (and never with
`--json` or `--no-input`). Anywhere else it refuses unless
`--accept-unverified` names every item. A file with an accepted override counts
as exit 0. A legacy `.h5` is still not loaded by `safe_load` after an override
(no loader), so re-save it as `.keras`.

## How it works

A file is CLEAN only if no layer finds anything. The final verdict is the most
severe verdict of any layer, so no layer can lower what another one found.

1. **Container parsing.** Zip archives are opened with limits on member
   count, size, compression ratio and path traversal. The format is detected
   from the content, and a file whose extension does not match its content is
   SUSPICIOUS.
   - **Every reading is analysed.** Loaders disagree about where a file
     starts: `pickle.load`, `joblib.load` and legacy `torch.load` read from
     offset 0, `zipfile` (Keras) finds the archive from its end, and h5py
     looks for the HDF5 superblock at 0, 512, 1024, ... A file can therefore
     be a pickle for one loader and a `.keras` archive for another. The
     scanner lists every reading that parses (a pickle or compressed joblib
     stream at offset 0, a ZIP archive, an HDF5 superblock) and runs each
     through static analysis and emulation; the most severe verdict wins. A
     file with more than one reading, or with bytes in front of an archive or
     superblock that no reading explains, is at least SUSPICIOUS (RISKY).
2. **Static analysis.**
   - **Pickle:** every opcode is walked, STACK_GLOBAL included. Imports must
     match an exact `(module, qualname)` allowlist, and any other import is at
     least SUSPICIOUS. A known sink together with a call opcode is MALICIOUS.
   - **Multi-pickle streams:** every pickle in the stream is walked, including
     legacy PyTorch files that put several pickles back to back.
   - **joblib:** compressed files are recognised by content, the way joblib
     does it, and decompressed in a streaming way with limits on output size
     and compression ratio. The walker follows joblib's format: the raw bytes
     joblib writes after each `NumpyArrayWrapper` are skipped by their exact
     size from shape and dtype, never read as opcodes; object-dtype arrays are
     nested pickles and are walked like any other. Because a plain
     `pickle.load` would read those raw bytes as opcodes, the walker also
     checks what that reading would import (parser differential).
   - **Keras:** `config.json` is walked. Exact module and class names are
     required, and Lambda bytecode is scanned for sink names. The bytecode is
     never unmarshalled on the host.
   - **Legacy HDF5:** the host does not parse HDF5 at all. A small
     standard-library HDF5 reader runs inside the WASI sandbox and returns the
     root attributes `model_config`, `training_config`, `keras_version` and
     `backend`, plus the file's structure. It walks every group and dataset
     header but never reads dataset contents, and it reports external links,
     external or virtual datasets, dense storage, duplicate or non-string
     attributes and every limit it hits. The config then goes through the
     Keras checks with tf.keras 2.x rules (objects without a `module` must use
     an exact built-in class name, Lambda layers may also name a function in a
     module or carry code in `output_shape`, activations must be built-in), and
     `training_config` must use built-in losses, metrics and optimizers.
3. **Fake-API emulation in a WASI sandbox.** The file goes, read-only, to
   CPython 3.12 compiled to WebAssembly and running under wasmtime in a child
   process.
   - **Limits:** a memory cap, fuel as a CPU budget, and a wall-clock kill of
     the process by the host.
   - **Isolation:** no network and no filesystem other than that directory.
   - **Inside the sandbox:** pickles are unpickled with a recording
     `find_class` (joblib streams with joblib's own reading of the array
     data), and Lambda functions are called on fake tensors with fake
     `tf`/`keras`/`torch`/`numpy`/`os`/`subprocess`/`socket`/`builtins`
     modules.
   - **Evidence:** every call is written to a channel that only the host reads.
     Each record carries a random per-scan nonce. Guest stdout and stderr are
     never used as evidence. A record without the nonce is tampering, and
     tampering is MALICIOUS. The host classifies the recorded calls:
     - process, network, file write, code execution and native code: MALICIOUS;
     - environment probes, anomalies, an incomplete run or an import outside
       the allowlist: SUSPICIOUS.
4. **LLM judge, optional (`--judge`).** It receives structured evidence only,
   with no disassembly, logs or other free text from the file. It can raise the
   verdict but never lower it. Without `ANTHROPIC_API_KEY` it is skipped.
5. **Deep mode, optional (`--deep`).** It loads the file with the real
   framework inside Docker, bubblewrap or nsjail and watches what happens. It
   can only add findings, and if no backend is available the scan is
   SUSPICIOUS.

`safe_load` scans a private read-only copy of the file and loads that same
copy. It also enforces the policy itself:

- pickle is read with a restricted unpickler that resolves only allowlisted
  pairs;
- joblib is read by safeloadai's own joblib reader with the same restricted
  `find_class` (numpy is needed, joblib is not);
- PyTorch is loaded with `torch.load(weights_only=True)`;
- Keras is loaded with `keras.saving.load_model(safe_mode=True)`;
- legacy `.h5` is not loaded by `safe_load` (it raises `UnsafeModelError`
  "no loader"); `scan` it and load it yourself.

## Install

```bash
pip install safeloadai
```

That is all: Python 3.11 or newer on Linux, macOS or Windows. The sandbox runtime
(CPython 3.12 compiled to WebAssembly) comes with the `safeloadai-runtime` package,
which `safeloadai` pins to an exact version, and `wasmtime` ships wheels for all three
systems. Nothing is downloaded at install time or at run time: the runtime file is
fetched once, when `safeloadai-runtime` is built, and its SHA-256 is checked again by
safeloadai, against its own pinned value, every time it is loaded. A runtime that
fails that check stops the scan with `RuntimeIntegrityError` (CLI exit code 4); it
never turns into a verdict.

```bash
safeloadai doctor        # checks wasmtime, the runtime and its hash, and runs the sandbox once
```

If the runtime is missing, every file that needs emulation is SUSPICIOUS and the
report says why; `safeloadai doctor` tells you how to fix it. Optional extras:
`[judge]` for the LLM judge, `[dashboard]` for the report viewer.

## Results

Latest local run, 2026-10-18 (0.4.0). It covers 138 files: 53 harmless marker payloads, including rebuilds of public scanner bypasses and CVE-2024-3660, and 85 locally generated benign scikit-learn, numpy, `.keras` and `.h5` models. Setup, caveats and the full tables are in [evaluation/results/README.md](evaluation/results/README.md).

| tool | detected / malicious | false positives / benign | of which UNVERIFIABLE | median s |
|---|---|---|---|---|
| safeloadai 0.2 | 52 / 53 | 49 / 85 | - | 0.40 |
| safeloadai 0.3.0 | 53 / 53 | 23 / 85 | - | 0.41 |
| safeloadai 0.4.0 | 53 / 53 | 2 / 85 | 2 | 0.40 |
| picklescan 1.0.5 | 32 / 53 | 0 / 85 | - | 0.09 |
| fickling 0.1.12 | 36 / 53 | 61 / 85 | - | 0.06 |
| modelscan 0.8.8 | 23 / 53 | 0 / 85 | - | 0.17 |

The other scanners were measured on the same 138 files in the 0.3.0 run and were not re-run for 0.4.0.

How to read the table:

- **The malicious files are lab rebuilds with harmless markers,** not a public malware set.
- **The benign files are not independent of the allowlist,** and they are not Hugging Face models. A false-positive rate on unseen models still needs the Hub set: `evaluation/fetch_benign_hf.py`, then `run_eval.py --hf DIR`.
- **The 2 remaining false positives are SUSPICIOUS and UNVERIFIABLE only:** ConvNeXt saved as legacy `.h5` names `LayerScale` without its module, so the scanner cannot know which class the loading code passes. The pairs that [false-positives-20261018.md](evaluation/results/false-positives-20261018.md) marked safe were added in 0.4.0, each with a justification and a regression test that keeps the malicious variant flagged.
- **3 malicious lab files are UNVERIFIABLE only** (an unknown pickle global and Keras custom objects). An override would let them through, which is why it has to name every item, for one file, and is recorded. The fourth, a `kerasx` look-alike module, is RISKY and cannot be overridden.
- **Format coverage explains some of the other tools' misses.** picklescan and fickling return "clean" for `.keras` and `.h5` files they do not analyse. modelscan without its TensorFlow extra skips `.keras`, and the evaluation does not run it on `.h5`, because modelscan opens those with h5py on the host.

## LIMITATIONS

- **Emulation is not execution.** The fake APIs return plausible values, not
  real ones. A payload whose behaviour depends on real results, real files or
  real time may take a different path in the sandbox.
  - **Covered:** introspection (`__subclasses__`, `__globals__`, `type`,
    `_getframe`, dunder `getattr`), sleeping, reading tensor values and
    unknown globals are recorded as anomalies and make the file SUSPICIOUS.
  - **Not covered:** other ways of detecting the emulator are not.
- **The Lambda rule.** A Keras Lambda layer is CLEAN only if three things hold:
  - static analysis succeeds,
  - emulation completes,
  - neither records a dangerous behaviour or an anomaly.

  Any marshal error, invalid or unexpected opcode for the sandbox's
  CPython 3.12, wrong inline-cache layout, emulation exception, missing stub
  or timeout makes the file SUSPICIOUS. The Python version that wrote the
  bytecode is never guessed, because Keras files do not record it. One case
  stays undetectable: bytecode from another CPython version that happens to be
  byte-identical to valid 3.12 bytecode (for example `lambda x: x` from 3.11)
  passes every check and is emulated as 3.12 bytecode.
- **Evidence channel.** The payload runs in the same guest interpreter as the
  recorder. It can therefore find the nonce and append well-formed records of
  its own. It cannot remove records the host has already received, so it can
  add noise but cannot turn a recorded alarm into a clean log. Writes without
  the nonce count as tampering and are MALICIOUS.
- **An override on UNVERIFIABLE means trusting that class's code.** The scanner
  cannot see the code of an UNVERIFIABLE item, which is what the category
  says. Accepting it tells `safe_load` to import and run whatever the named
  module or the class your loading code passes does, with your privileges.
  The scanner checked everything else in the file, not that code. Accept only
  items whose source you know and trust, for the file you checked. Look-alike
  names of allowlisted modules are RISKY instead, so they cannot be accepted,
  but a name that is merely unfamiliar (`mycompany.layers.Foo`) can be, and
  so can a payload hidden behind it.
- **Allowlist false positives.** The pickle allowlist holds only the exact
  pairs that the tuning corpus and the reviewed false-positive list needed.
  - **Pickle:** benign models that use other classes are SUSPICIOUS (UNVERIFIABLE)
    until you pass them with `allow=[("module", "Qualname")]` or
    `--allow module:Qualname`, or accept them for one file with an override.
  - **numpy random state:** `__generator_ctor`, `__randomstate_ctor` and
    `__bit_generator_ctor` call one of their arguments, so they are accepted
    only with the exact arguments numpy itself writes.
  - **PyTorch:** the allowlist entries have not been checked against real
    checkpoints yet.
  - **TorchScript** is always SUSPICIOUS.
- **joblib.** Supported: joblib 0.10 and newer, uncompressed or compressed with
  one stream of zlib, gzip, bz2, lzma, xz or lz4 (lz4 needs
  `pip install "safeloadai[lz4]"`).
  - **SUSPICIOUS by design:** the legacy multi-file format of joblib < 0.10
    (arrays in side files that joblib opens by name and reads with
    `numpy.load(allow_pickle=True)`), structured dtypes that hold Python
    objects, a wrapper built in any way other than joblib's own, array data
    inside a pickle frame, and decompressed output above 1 GiB or a ratio
    above 1000:1 (after the first MiB).
  - **Parser differential:** the check of what a plain `pickle.load` would
    import from joblib's array bytes stops at the first import whose
    top-level module no environment could provide; a name made of a stdlib or
    common package name and an attribute that does not exist is reported
    anyway (SUSPICIOUS).
- **Legacy HDF5.** Supported: superblock versions 0 to 3, old-style groups
  (symbol tables) and new-style compact groups, fixed and variable-length
  string attributes. Weight datasets are never read, so bugs in a loader's
  weight parsing (libhdf5, h5py, filters) are out of scope: safeloadai cannot
  find them and does not try.
  - **SUSPICIOUS by design:** external links, external data files, virtual
    datasets, superblock driver info (multi-file drivers), a user block,
    dense (fractal heap) storage of the root attributes or of any group's
    links, shared root attributes, a root attribute that is not a scalar
    string, contains NUL bytes or appears twice, an attribute above 16 MiB,
    more than 100,000 objects, and any structure the reader cannot parse.
  - **Keras 2 Lambda layers** are rarely CLEAN: the configs carry no input
    shape for the emulator, and their bytecode usually comes from another
    Python version, so emulation reports an anomaly.
  - **Dense storage** is what h5py writes for a group with more than 8 links
    when the file was created with `libver="latest"`; Keras itself uses the
    default (old-style groups), so such files should be rare. Part of the
    false-positive measurement.
- **Polyglot files.** Recognised readings: a pickle stream at offset 0 (any
  protocol), a joblib-compressed stream at offset 0, a ZIP archive found from
  its end-of-central-directory record, and the first HDF5 superblock at 0, 512,
  1024, ... A reading the scanner does not know (another archive format, a
  second ZIP archive earlier in the file, data a custom loader reads at some
  other offset) is not analysed. A pickle reading needs the bytes at offset 0
  to decode to a STOP, to 8 opcodes, or to an opcode that imports or calls; a
  stream that fails before that cannot make `pickle.load` import anything.
  The HDF5 reading after a user block is SUSPICIOUS by design (see below).
- **CLEAN Lambda models do not load through `safe_load`,** because Keras safe
  mode refuses Lambda bytecode. Load them yourself if you accept that risk.
- **Loading a CLEAN pickle imports allowlisted libraries on your machine,**
  such as numpy and scikit-learn, and runs their reconstruction code. You are
  trusting those libraries.
- **The WASI sandbox is only as strong as wasmtime** and a third-party CPython
  WASI build (pinned by sha256).
  - **Fuel** bounds CPU, and the host kills the process at the wall-clock
    limit.
  - **Large or slow models** can hit the limits and are then SUSPICIOUS.
  - **Memory:** files up to 4 GiB are read into memory on the host.
- **Deep mode runs the real loader on the real kernel.** Docker shares the
  kernel with the host, and the bubblewrap and nsjail profiles are only as
  tight as their flags. The nsjail flags have not been tested. The detoner
  shares stdout with the payload: events are merged and a second result line
  counts as tampering, but a payload can still print fake events, which can
  only raise the verdict.
- **The runtime package is trusted at install time.** safeloadai checks the
  `.wasm` hash before every use, but pip runs whatever a package does when it
  is installed. Install `safeloadai-runtime` only from PyPI under that exact
  name and version (or from a wheel you built with `fetch_runtime.py`).
- **Deep mode's Docker backend needs a source checkout,** because it builds
  its image from `docker/`. Installed from a wheel it reports itself
  unavailable, which makes the deep layer SUSPICIOUS.
- **The judge only adds cost and escalation.** It sees no free text, so it
  cannot reason about content the other layers did not structure.

## Development

```bash
python packages/safeloadai-runtime/fetch_runtime.py   # once: download + verify the pinned runtime
pip install ./packages/safeloadai-runtime
pip install -e ".[dev]"
ruff check .
python -m pytest -q        # SAFELOADAI_WASI_PYTHON=/path/to/python-3.12.0.wasm overrides the runtime (still verified)
python -m tests.corpus.build_corpus /tmp/corpus
python evaluation/run_eval.py --lab /tmp/corpus --benign /path/to/benign   # --hf DIR for fetch_benign_hf.py output
```

How the tests stay safe:

- **Host guard:** during tests a guard refuses process execution (except the
  sandbox runner), non-loopback network connections and unrestricted
  unpickling.
- **Harmless payloads:** sample payloads are markers only (`echo MARKER`,
  `/tmp/safeloadai_marker`, 127.0.0.1) and only ever run inside the sandbox.
- **CI:** builds both wheels (the runtime download happens only in that build
  step and is checked against the pinned sha256), installs them into a clean
  venv, blocks the network, and runs the whole suite against the installed
  wheels on Linux, macOS and Windows with Python 3.11 to 3.13. A skipped sandbox
  test is an error there.

Update monitoring detects and never auto-trusts:

- **Dependabot** opens weekly PRs for pip dependencies and GitHub Actions, which
  are pinned by commit SHA.
- **`upstream-drift`** (weekly, or by hand) installs the latest scikit-learn,
  numpy, keras, wasmtime and, if it installs, tensorflow-cpu. It writes benign
  models, scans them and runs the suite, and opens one issue if anything drifts.
  It never edits an allowlist or opens a PR.
- **`runtime-watch`** (weekly) opens an issue when a newer WASI CPython build or
  wasmtime major exists. The manual update procedure is
  [docs/UPDATING_RUNTIME.md](docs/UPDATING_RUNTIME.md).

Design decisions and their reasons are in [DECISIONS.md](DECISIONS.md), and
the audit that started this rewrite is in [AUDIT.md](AUDIT.md). The report
viewer runs with `flask --app app.server run --host 127.0.0.1`. It renders
Report JSON and does not scan files.

### Releasing

`.github/workflows/publish.yml` uploads both packages with PyPI Trusted Publishing. It runs only when started by hand, and the target is testpypi or pypi. The runtime goes first, and a runtime version that is already published is skipped. The setup it needs is in the workflow's header comment. Changes are listed in [CHANGELOG.md](CHANGELOG.md), and reporting a bypass is described in [SECURITY.md](SECURITY.md).

## Statement on AI use

This is the author's statement from the original project, translated. The
project was written by Bartosz Mosionek together with an LLM assistant
(Claude). The optional judge uses the Anthropic API. The author understands
the code and takes technical responsibility for it.
