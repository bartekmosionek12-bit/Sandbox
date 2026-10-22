# How safeloadai works

A file is CLEAN only if no layer finds anything. The final verdict is the most
severe verdict of any layer, so no layer can lower what another one found. The
README has the short version; this page has the details.

## Layers

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

## What `safe_load` enforces

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

## What lets a file through (0.7.0)

The pickle allowlist is exact `(module, qualname)` pairs. Since 0.7.0 a few more
mechanisms can accept an import outside it. Each one only *allows*: none of them
lowers a MALICIOUS or RISKY finding, and each accepted import is listed in
`Report.cleared` with the mechanism that accepted it.

- **Referenced, not used** (`static/clearance.py`). Importing a global does not run its
  code; calling it does. A global the stream only stores as a value (never calls, never
  hands to a call, a BUILD, a SETITEM on a non-container, a dict key or a persistent id)
  from an inert module of a pinned, known library raises no finding.
- **Source-derived state-only classes** (`static/upstream/policies.json`, generated at
  development time by `tools/gen_policies.py` from pinned wheels and reviewed in
  `static/upstream/REVIEW.md`). A class whose rebuild from a dict state runs none of its
  own code is accepted when the stream does exactly that: `NEWOBJ ()` and one dict
  `BUILD`, never called, never passed around.
- **torch weights-only rules** (`static/upstream/torch_weights_only.py`). A PyTorch
  stream that torch 2.14.1's `weights_only=True` unpickler accepts is CLEAN.
- **Profiles** ([PROFILES.md](PROFILES.md)). A well-known file (transformers Trainer
  files, Ultralytics checkpoints) may use the profile's globals only at the positions
  its producer puts them. A file that has the name and the producer's imports but not
  the structure gets a RISKY reason instead.
- **Reviewed known files** (`safeloadai/data/known_good.tsv`). An exact sha256 match
  with a reviewed tune-split file turns SUSPICIOUS into CLEAN. One changed byte and the
  file gets nothing. `--no-known-good` turns it off.
- **UNSUPPORTED.** A file with no pickle, joblib, ZIP or HDF5 reading at all is
  UNSUPPORTED: not CLEAN, not loadable, not overridable, CLI exit code 5.
- **ERROR is not a verdict.** When safeloadai itself fails (I/O, a parser bug, a
  sandbox crash or timeout, runtime integrity, invalid options), the report has
  `status: "error"` and a code, and no verdict ([ERRORS.md](ERRORS.md)). Only MALICIOUS
  evidence found before the failure still decides.

Every list above is generated or written at development time, reviewed and committed.
Nothing is added to any list while scanning.

## Rule families and standards

Every detection rule belongs to one family, and every family is mapped to the
standards in [THREAT_MODEL.md](THREAT_MODEL.md) (threat IDs T1 to T15 there). A pull
request or commit that changes a family carries its tag in the title (see
[CONTRIBUTING.md](../CONTRIBUTING.md)).

| Family | Where | What it flags | Threat | Tags |
|---|---|---|---|---|
| Sink imports and calls | `static/pickle_static.py`, `behaviour.py` (`SINKS`) | a known sink imported and called; in emulation, any call to a sink | T1 | `[LLM03]` `[ML06]` `[AML.T0011.000]` `[AML.T0018.002]` |
| Exact allowlist | `static/allowlists.py`, `static/clearance.py`, `profiles/`, `known_good.py` | any import outside exact `(module, qualname)` pairs (and the rules that accept some) | T1, T15 | `[LLM03]` `[ML06]` `[AML.T0010.003]` |
| Gadgets and indirection | `static/pickle_static.py` (`_check_getattr`, guarded calls, BUILD hooks), `allowlists.KNOWN_GADGETS` | getattr chains, `partial`, `methodcaller`, hook attributes in BUILD states, re-exported sinks | T2 | `[LLM03]` `[ML06]` `[AML.T0018.002]` |
| Keras code and custom objects | `static/keras_static.py`, `static/h5_static.py`, Lambda emulation | Lambda bytecode, functions named by module, custom objects, non-built-in training config | T3 | `[LLM03]` `[ML06]` `[AML.T0011.000]` |
| Readings and parser differentials | `parsing/views.py`, `static/__init__.py`, `parsing/zipsafe.py`, joblib differential | polyglots, trailing or leading data, refused archives, CRC mismatches, hidden pickles, joblib array bytes a plain `pickle.load` would read | T4 | `[LLM03]` `[ML06]` `[AML.T0011.000]` |
| Corrupt and over-limit streams | `static/pickle_vm.py`, `static/pickle_static.py: walk_problem`, `parsing/decompress.py`, `shared/hdf5_meta.py` | streams a loader rejects or reads differently, limits on size, opcodes, depth, ratio | T5, T10 | `[LLM03]` `[ML06]` `[AML.T0076]` |
| Look-alike names | `static/lookalike.py` | module names imitating allowlisted ones | T6 | `[LLM03]` `[ML06]` `[AML.T0010.003]` |
| Evidence integrity | `sandbox/host.py`, `behaviour.py` | writes without the nonce, broken sequences (tampering) | T9 | `[LLM03]` `[AML.T0011.000]` |
| Judge escalation | `judge.py`, `verdict.judge_layer` | injection attempts in the evidence | T11 | `[LLM01]` |
| Runtime integrity | `sandbox/runtime.py` | a WASI runtime that is not the pinned build (E401) | T13 | `[LLM03]` `[AML.T0010.001]` |

