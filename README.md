# safeloadai

safeloadai decides whether a machine-learning model file is safe to load. It
does this before the file is loaded. It handles:

- pickle (`.pkl`, `.pickle`, `.joblib`),
- PyTorch (`.pt`, `.pth`, `.bin`, zip and legacy formats),
- Keras (`.keras`),
- legacy HDF5 (`.h5`), which is always reported as SUSPICIOUS for now.

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

## How it works

A file is CLEAN only if no layer finds anything. The final verdict is the most
severe verdict of any layer, so no layer can lower what another one found.

1. **Container parsing.** Zip archives are opened with limits on member
   count, size, compression ratio and path traversal. The format is detected
   from the content, and a file whose extension does not match its content is
   SUSPICIOUS.
2. **Static analysis.**
   - **Pickle:** every opcode is walked, STACK_GLOBAL included. Imports must
     match an exact `(module, qualname)` allowlist, and any other import is at
     least SUSPICIOUS. A known sink together with a call opcode is MALICIOUS.
   - **Multi-pickle streams:** every pickle in the stream is walked, including
     legacy PyTorch files that put several pickles back to back.
   - **Keras:** `config.json` is walked. Exact module and class names are
     required, and Lambda bytecode is scanned for sink names. The bytecode is
     never unmarshalled on the host.
3. **Fake-API emulation in a WASI sandbox.** The file goes, read-only, to
   CPython 3.12 compiled to WebAssembly and running under wasmtime in a child
   process.
   - **Limits:** a memory cap, fuel as a CPU budget, and a wall-clock kill of
     the process by the host.
   - **Isolation:** no network and no filesystem other than that directory.
   - **Inside the sandbox:** pickles are unpickled with a recording
     `find_class`, and Lambda functions are called on fake tensors with fake
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
- PyTorch is loaded with `torch.load(weights_only=True)`;
- Keras is loaded with `keras.saving.load_model(safe_mode=True)`.

## Install

```bash
pip install -e ".[dev]"          # add [judge] for the LLM judge, [dashboard] for the viewer
```

You need Python 3.11 or newer. The library never downloads anything. Put the
pinned WASI runtime in place yourself, or point `SAFELOADAI_WASI_PYTHON` at it:

```bash
mkdir -p ~/.cache/safeloadai/runtime && cd ~/.cache/safeloadai/runtime
curl -fsSLO "https://github.com/vmware-labs/webassembly-language-runtimes/releases/download/python%2F3.12.0%2B20231211-040d5a6/python-3.12.0.wasm"
echo "e5dc5a398b07b54ea8fdb503bf68fb583d533f10ec3f930963e02b9505f7a763  python-3.12.0.wasm" | sha256sum -c -
```

Without the runtime every pickle, PyTorch file and Lambda model is SUSPICIOUS.

## Results

These are the first measurements from `evaluation/run_eval.py`, made on
2026-10-17. Setup and caveats are in
[evaluation/results/README.md](evaluation/results/README.md).

- **Malicious files:** 38 harmless marker payloads from
  `tests/corpus/build_corpus.py`.
- **Benign files:** 35 files, made of the lab corpus controls, locally
  generated numpy and scikit-learn models, and the two clean PoC samples.

| tool | detected / malicious | false positives / benign | errors | unsupported | median s |
|---|---|---|---|---|---|
| safeloadai | 38 / 38 | 7 / 35 | 0 | 0 | 0.50 |
| picklescan 1.0.5 | 22 / 38 | 0 / 35 | 8 | 0 | 0.10 |
| fickling 0.1.12 | 24 / 38 | 25 / 35 | 22 | 0 | 0.08 |
| modelscan 0.8.8 | 21 / 38 | 0 / 35 | 0 | 24 | 0.20 |

How to read the table:

- **Malicious files are lab payloads.** The marker payloads were written for
  this project. They are not a public malware set.
- **The benign numpy and scikit-learn files are not independent of the
  allowlist,** which was tuned on similar models. A false-positive rate on
  unseen models still needs the Hugging Face set:
  `evaluation/fetch_benign_hf.py`, then `run_eval.py --benign DIR`.
- **All 7 safeloadai false positives are `.joblib` files.**
- **Format coverage explains some of the other tools' misses.**
  - picklescan and fickling return "clean" for `.keras` files they do not
    analyse.
  - modelscan without its TensorFlow extra skips them.
  - fickling 0.1.12 fails on common pickle opcodes such as FLOAT.
- **Layer contribution on the 38 malicious files:** static and emulation both
  flagged 33, static alone 4, emulation alone 1.

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
- **Allowlist false positives.** The pickle allowlist holds only the exact
  pairs that the tuning corpus needed.
  - **Pickle:** benign models that use other classes are SUSPICIOUS until you
    pass them with `allow=[("module", "Qualname")]` or `--allow module:Qualname`.
  - **PyTorch:** the allowlist entries have not been checked against real
    checkpoints yet.
  - **joblib, `.h5` and TorchScript** are always SUSPICIOUS.
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
- **The judge only adds cost and escalation.** It sees no free text, so it
  cannot reason about content the other layers did not structure.

## Development

```bash
ruff check .
python -m pytest -q        # set SAFELOADAI_WASI_PYTHON to run the sandbox tests
python -m tests.corpus.build_corpus /tmp/corpus
python evaluation/run_eval.py --lab /tmp/corpus --benign /path/to/benign
```

How the tests stay safe:

- **Host guard:** during tests a guard refuses process execution (except the
  sandbox runner), non-loopback network connections and unrestricted
  unpickling.
- **Harmless payloads:** sample payloads are markers only (`echo MARKER`,
  `/tmp/safeloadai_marker`, 127.0.0.1) and only ever run inside the sandbox.
- **CI:** downloads the pinned runtime, checks its sha256 and fails if the
  sandbox tests would be skipped.

Design decisions and their reasons are in [DECISIONS.md](DECISIONS.md), and
the audit that started this rewrite is in [AUDIT.md](AUDIT.md). The report
viewer runs with `flask --app app.server run --host 127.0.0.1`. It renders
Report JSON and does not scan files.

## Statement on AI use

This is the author's statement from the original project, translated. The
project was written by Bartosz Mosionek together with an LLM assistant
(Claude). The optional judge uses the Anthropic API. The author understands
the code and takes technical responsibility for it.
