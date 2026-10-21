# Changelog

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [Semantic Versioning](https://semver.org/). Two packages are released from this repository:

- `safeloadai` (the scanner);
- `safeloadai-runtime` (the pinned sandbox runtime). It has its own version and changes only when the runtime does.

## safeloadai 0.7.1 (unreleased)

### Security
- **A crafted pickle could be reported CLEAN while it ran a library function when loaded,** through `safe_load` as well. A BUILD state that sets a hook attribute (`__setstate__`, `__reduce__`, `__class__`, ...) and a second BUILD on the same object are now RISKY; neither is something pickle writes. The referenced-only rule counts the globals in every earlier BUILD state of a rebuilt object as used, the emulation's fake objects store a dict state the way real classes do, and file-system re-exports (`remove`, `unlink`, `rmtree`, `copyfile`, ...) are sinks. Users of 0.7.0 should upgrade. Regression tests: `tests/test_build_hooks.py`.

## safeloadai 0.7.0

### Added
- **UNSUPPORTED verdict.** A file in no format safeloadai reads (no pickle, joblib, PyTorch, Keras or HDF5 reading of its bytes exists, such as OpenVINO or CTranslate2 `.bin` weights) is UNSUPPORTED instead of SUSPICIOUS. It is never CLEAN, never loadable by `safe_load` and never overridable, and `safeloadai scan` exits with code 5 for it. Files that parse but look odd stay SUSPICIOUS.

- **Referenced-only globals.** A global the pickle only stores (never calls or hands to code), from an inert module of a known library, is no longer UNVERIFIABLE (`Report.cleared`, mechanism `referenced`).
- **Source-derived state-only policies.** 1,881 classes of scikit-learn, transformers' Trainer modules, torch.nn, torchvision, ultralytics, pandas and statsmodels, derived from the pinned library source with `ast` (`tools/gen_policies.py`, `static/upstream/`), are accepted when rebuilt from a dict state.
- **torch weights_only rules.** A PyTorch stream that `torch.load(weights_only=True)` of torch 2.14.1 accepts is CLEAN (`tools/gen_torch_safe_globals.py`).
- **Profiles for well-known files** (`src/safeloadai/profiles/`, docs/PROFILES.md): transformers Trainer files (`training_args.bin`, `optimizer.pt`, `scheduler.pt`, `rng_state*.pth`) and Ultralytics checkpoints. A profile accepts its globals only where the producer puts them (for `training_args.bin`: accelerate's `PartialState` and `AcceleratorConfig`). A file with the name and producer signature but another structure is SUSPICIOUS (RISKY).
- **`trust_inert_from` / `--trust-inert-from DIST`** (off by default): the same state-only analysis on the installed source of the named distributions.
- **Reviewed known files** (`known_good`, on by default; `--no-known-good` turns it off). A file whose exact sha256 is on the shipped list of 27 reviewed tune-split files is CLEAN ("known reviewed file <repo/file>"). MALICIOUS and UNSUPPORTED verdicts are never changed.
- `Report.cleared` lists every import outside the allowlist that one of these rules accepted, with the rule.

### Fixed
- **A pickle that calls `pandas.read_pickle` (or `read_hdf`, `load_model`, ...) on another file is MALICIOUS.** It was UNVERIFIABLE, so it could be accepted item by item (found in the benign Hub corpus: a picklescan-bypass PoC).
- Scanning an empty file no longer crashes (`UnboundLocalError`); it is UNSUPPORTED.
- **The compiled cache falls back instead of silently giving up.** On Windows, a `~/.cache` created by an elevated program made `mkdir` fail with `PermissionError [WinError 5]`, the error was swallowed and every scan recompiled the runtime. A location that cannot be created, written or is not private is now skipped for the next one (Windows: `%APPDATA%`, then a per-user `%TEMP%` directory; POSIX never uses a shared `/tmp`); with none left the runtime is compiled in memory, as before. A new cache directory and its parent are created `0700`, so a umask of `002` (the Ubuntu default for users) no longer makes a fresh cache fail the privacy check. `runtime.compiled_cache_dir()` returns the path and the locations that failed with their errors, and `safeloadai doctor` prints them as `warn` instead of "missing or writable by others" (doctor JSON checks have a new `status` field: `ok`, `warn` or `fail`).

### Changed
- **Beta.** Version 0.7.0, classifier "Development Status :: 4 - Beta", licensed Apache-2.0 (`LICENSE`); `safeloadai-runtime` declares `Apache-2.0 AND PSF-2.0`.
- **Evaluation reports what users meet** (`evaluation/run_eval.py`): benign files are split into CLEAN, soft blocks (UNVERIFIABLE only, overridable item by item), hard blocks (RISKY, MALICIOUS) and UNSUPPORTED. New columns: without the known-file list, and a real opt-in (`trust_inert_from` for scikit-learn, transformers, torch). The old "opt-in" column (every UNVERIFIABLE item accepted) is now "upper bound: accept all unverifiable (not recommended)". A Pareto table lists the entries or rules that would unblock most files. Existing flags are unchanged; `--opt-in-trust`, `--opt-in-site` and `--no-opt-in` are new.
- README rewritten for first-time visitors; the layer-by-layer description moved to docs/HOW_IT_WORKS.md.
- **Compiled-cache location per platform.** The compiled runtime is cached in `%LOCALAPPDATA%\safeloadai` on Windows, `~/Library/Caches/safeloadai` on macOS and `$XDG_CACHE_HOME/safeloadai` or `~/.cache/safeloadai` elsewhere (was `~/.cache/safeloadai` everywhere). `SAFELOADAI_HOME` still overrides it. Verdicts are unchanged.

## safeloadai 0.5.0

### Added
- **Every reading of a file is analysed.** A file can be a valid pickle for `pickle.load` and a valid archive for `zipfile` at the same time (a polyglot). The scanner now finds every reading a loader could make (a pickle or joblib stream at offset 0, a ZIP archive found from its end, an HDF5 superblock after a user block) and analyses each one with its own static and emulation layers; the worst verdict wins. A file with more than one reading is at least SUSPICIOUS (RISKY). The report lists the readings in `views`.
- **Argument-checked allowlist entries.** New pickle globals that would call an argument or run a constructor pass only the way their library writes them: state-only classes (rebuilt from saved state, constructor never called), enum lookups, `pandas._new_Index` with pandas' own `Index`, and `collections.defaultdict` with a builtin factory. Added this way: `TrainingArguments` and its enums, 16 scikit-learn classes, `scipy.sparse.csr_matrix`, `argparse.Namespace` and others (`evaluation/results/allowlist-review-20261019.md`). Keras: five augmentation layers, `OrthogonalInitializer`, `CategoricalFocalCrossentropy`, `R2Score`, the `Subtract`/`TrueDivide` ops.
- **Mutation corpus** (`tests/corpus/mutate.py`): 830 re-encodings of the marker payloads (import and string opcodes, protocol headers, memo tricks, nested pickles, joblib compressors, PyTorch containers, polyglots) plus benign controls.
- **Evaluation:** a stratified ~1,000-file benign Hub fetch with a repo-level tune/held-out split and the Hub's own scan status per file; a fetcher for Hub files the Hub's scanners flag, with labels from that evidence only; `run_eval.py` reports per group (lab, mutations, Hub-flagged, tune, held-out), per format and per library, with RISKY / UNVERIFIABLE / MALICIOUS splits of the false positives, and scans in parallel (`--jobs`).

### Fixed
- **Custom Keras losses and metrics are no longer MALICIOUS.** Keras saves a user's own loss, metric or activation function as `builtins.<name>`, and the static layer treated every `builtins` name as a known sink. A name that Python's `builtins` does not define, and that no sink list names, is now an UNVERIFIABLE custom object. Real builtins such as `eval`, `exec` or `open` stay MALICIOUS.
- **Pickles without a PROTO header** whose first opcode is a newer one (SHORT_BINUNICODE, FRAME, ...) were "unrecognised format" (SUSPICIOUS); `pickle.load` runs them, and they are now analysed (MALICIOUS when they call a sink).
- **PyTorch members with a bad CRC-32** were refused unread. `torch.load` does not check CRC-32, so the member is now analysed and the mismatch is a RISKY reason (Keras archives still refuse it).
- The argument-check value walk visits each container once per stream, so large TF-IDF vocabularies no longer hit its step limit (RISKY false positives).
- `builtins.object` (the base `copyreg._reconstructor` names, and a `make_column_selector` value) is no longer scored as a sink.
- `evaluation/fetch_benign_hf.py` works with huggingface_hub 2.x, which dropped `list_models(library=...)`.

### Changed
- **`builtins.getattr` is judged use by use.**
  - It is MALICIOUS only when its result is called, the attribute is a dunder or sink
    name, or the target is a sink.
  - A method of an allowlisted object or class, stored and never called, is CLEAN.
    That is how pickle writes a bound method, and how Ultralytics checkpoints store
    `Detect.forward`.
  - Any other use is RISKY (not overridable). Before this change, any getattr import
    with a call opcode was MALICIOUS.
- **A pickle reading ends at its first STOP.** Bytes after it are reported as trailing
  data, not as a walker error. A trailing pickle is analysed as a reading of its own.
- **Evidence comes first.** Reasons and findings now list sinks, processes, network
  access, file writes and code execution before everything else.
- **Allowlist from a source review.** 64 classes were added as state-only:
  - 13 `torch.nn` modules;
  - 5 torchvision transforms;
  - 43 Ultralytics classes;
  - 3 xgboost scikit-learn wrappers.

  `torchvision` `InterpolationMode` was added as an enum lookup. `xgboost.core.Booster`
  stays out; it is UNVERIFIABLE with its own explanation (libxgboost parses its raw
  bytes), and docs/OPTIONS.md names the safer `save_model("model.json")` format.
  Details are in `evaluation/results/source-review-20261019.md`.
- **Passing a getattr result to any call is a use.** A method handed to a call or a
  controlled slot (a `defaultdict` factory, numpy's `__generator_ctor`, another
  getattr) is MALICIOUS, like calling it. An allowlisted class is allowed only as
  getattr's first argument.
- **Zero-arg call rule** for reviewed `SimpleNamespace` subclasses (Ultralytics'
  `IterableSimpleNamespace`): an empty argument tuple, a dict BUILD state, and the
  instance is never called or passed to a call.
- **Keras models inside pickles.** Keras 3 pickles a model as an embedded `.keras`
  archive (`getattr(<model class>, "_unpickle_model")(BytesIO(...))`). The scanner now
  recognises that form, analyses the embedded archive as a Keras file of its own
  (static layer and Lambda emulation) and takes its verdict. The pickle keeps a RISKY
  reason, which cannot be overridden, because the loader runs with `safe_mode=False`.
- **dill.** A function dill pickles with its bytecode (`_create_code`) is judged like
  a Keras Lambda: RISKY ("file carries executable Python code"), MALICIOUS when its
  names or constants name a sink, and rebuilt and called on fakes in the WASI sandbox.
  Any dill pickle is RISKY. dill's helpers that import, eval or call an argument are
  known sinks. `_load_type`, a lookup in a fixed type table, is no longer scored as
  code execution by the emulator.
- **Evaluation:** an opt-in run (every UNVERIFIABLE item accepted) is reported next to
  the default run.
- **Report schema 2.2** adds `options`.

### Security
- **Secure defaults and documented options.**
  - Plain `scan(path)` / `safeloadai scan FILE` uses no opt-in rule.
  - Every non-default option is recorded in `Report.options` (name, value, source,
    direction), announced with a warning on stderr, and shown on the verdict line
    (`CLEAN (with options: ...)`).
  - `allow` refuses sinks, known gadgets, `getattr` and wildcards.
  - A config file (`safeloadai.toml`) is read only when named with `--config`.
  - New: `safeloadai options` and `docs/OPTIONS.md`.

## safeloadai 0.4.0

### Added
- **Reason categories.** Every reason in a Report has a category, `MALICIOUS`, `RISKY` or `UNVERIFIABLE`, in `Report.findings`, with the worst one in `Report.category`. The verdict does not change.
  - An UNVERIFIABLE reason names the exact item, such as a class named without its module in a Keras 2 `.h5`, an unknown Keras class or custom object, or a pickle global outside the allowlist that is not a sink.
  - Each one has a plain-language explanation of what was found, why it cannot be verified and what to do.
- **Informed override for UNVERIFIABLE-only files.**
  - API: `safe_load(..., accept_unverified=[...])`, or `{sha256: [...]}`.
  - CLI: `safeloadai scan --accept-unverified [SHA256:]ITEM`, plus an interactive prompt on a terminal (default No) and `--no-input`.
  - It works only when every reason is UNVERIFIABLE and every item is named. It applies to one file and is recorded in `Report.override` (items, sha256, time, how). A file with an accepted override exits 0.
- **Update monitoring that never auto-trusts:**
  - `.github/dependabot.yml` (pip and GitHub Actions, weekly);
  - the `upstream-drift` workflow (latest scikit-learn, numpy, keras, wasmtime, optional tensorflow-cpu; benign models scanned and the suite run; one issue on drift);
  - the `runtime-watch` workflow (newer WASI CPython build or wasmtime major; one issue);
  - `tools/drift_check.py`, `tools/runtime_watch.py` and `docs/UPDATING_RUNTIME.md`.
- The evaluation reports UNVERIFIABLE-only false positives as their own column, and counts malicious files that are UNVERIFIABLE only.
- The report viewer shows categories, explanations and overrides.
- **Look-alike module names are RISKY.** An unknown object from a module that imitates an allowlisted one (`kerasx`, `keras_x`, `tf_evil_pkg`, `tensorflowx`, `sklearn2`, `numpy_`, an edit distance of at most 2 such as `nunpy`, or a homoglyph spelling such as `kеras` with a Cyrillic `е`) is RISKY, not UNVERIFIABLE, so it can never be overridden. Ordinary unknown names such as `mycompany.layers.Foo` stay UNVERIFIABLE. Malicious lab files that are UNVERIFIABLE only went from 4 to 3.
- **A Keras class, function or registered name that names a sink or gadget is never UNVERIFIABLE.** One from a sink module (`subprocess.Popen`, `importlib.import_module`, `shutil.rmtree`, or a registered name `subprocess>Popen`) is a known sink (MALICIOUS), because Keras imports and calls it while deserialising. A sink name in another module, or a known gadget, is RISKY. Before this fix such a `.keras` file was UNVERIFIABLE only and could be overridden.

### Changed
- **Allowlist grown from the reviewed false-positive list** (`evaluation/results/false-positives-20261018.md`). It adds 25 scikit-learn and numpy pairs (including the checked `__generator_ctor`), Keras `LayerScale` and the `keras.src.ops.numpy` `Add` and `Multiply` ops, and TFOpLambda from `keras.src.layers.core.tf_op_layer`, all as exact pairs. False positives on the local benign set dropped from 23/85 to 2/85, and detection stays 53/53.
- **A TFOpLambda whose op is on `TF_OP_ALLOWED` is no longer a finding.** Any other op is still flagged, and file-writing ops such as `io.write_file` are MALICIOUS.
- **`numpy.random._pickle.__generator_ctor` is allowed only with numpy's own arguments.** The already allowed `__randomstate_ctor` and `__bit_generator_ctor` now get the same check, because they call an argument too.
- **Report schema 2.1** adds `findings`, `category` and `override`.
- **Every GitHub Action is pinned by commit SHA.**

### Removed
- **`poc/`.** The clean samples, `evil_custom_object.keras` and `evil_lambda.keras` (the C15 regression) moved to `tests/fixtures/poc/`. The three PoC pickles with non-marker payloads were removed; `tests/corpus/build_corpus.py` generates their marker equivalents.

## safeloadai 0.3.0 / safeloadai-runtime 0.1.0

### Added
- **`pip install safeloadai` is all it takes.** The WASI runtime, unmodified CPython 3.12.0 for WASI, ships in the new `safeloadai-runtime` 0.1.0 package, and `safeloadai` pins that exact version.
  - Nothing is downloaded at install time or at run time.
  - The runtime's SHA-256 is checked against safeloadai's own pin every time it is loaded, and again by the runner on the bytes it compiles.
  - A mismatch raises `RuntimeIntegrityError`, CLI exit code 4.
- **`safeloadai doctor`** checks wasmtime, the runtime file and its hash, and runs the sandbox once.
- **joblib support.**
  - Containers: uncompressed, zlib, gzip, bz2, lzma, xz, and lz4 with the `[lz4]` extra. Decompression is streaming, with limits on output size and ratio.
  - The walker understands `NumpyArrayWrapper`'s array layout: raw array bytes are skipped by exact size, and object arrays are walked as nested pickles.
  - A parser-differential check flags files that a plain `pickle.load` would read differently.
  - `safe_load` reads joblib with its own restricted reader, so joblib is never imported.
- **Legacy Keras HDF5 (`.h5`) support,** with no h5py or libhdf5 on the host.
  - A pure-Python HDF5 metadata reader runs inside the WASI sandbox and returns only the root attributes. Weights are never read.
  - Limits on attribute size, object count, header messages and bytes read.
  - tf.keras 2.x configs are checked against an explicit class list. Named Lambda functions, `output_shape` code and custom losses, metrics and optimizers are flagged, and `training_config` is checked too.
  - External links, external data files, virtual datasets and anything the reader does not model make the file SUSPICIOUS.
- **Pickles hidden in torch zip members without a `.pkl` name are now found** (CVE-2025-1889).
- **The lab corpus has marker rebuilds of public scanner bypasses:**
  - nullifAI;
  - CVE-2025-1716, CVE-2025-1944, CVE-2025-1945 and CVE-2025-1889;
  - `_osx_support`, `pydoc.pipepager`, `timeit`, `cProfile.run`, `functools.partial` and `operator.methodcaller`;
  - CVE-2024-3660 Lambda layers in `.h5` and `.keras`.
- **Evaluation tooling:**
  - `evaluation/guard.py` is a host-execution guard for evaluation runs.
  - `fetch_benign_hf.py` fetches files from Hugging Face, pinned to a commit and with recorded sha256.
  - Per-format rates in `run_eval.py`, and `compare_eval.py` for before/after tables.
  - A false-positive analysis that reports the missing allowlist pair for each case. Pairs are never added automatically.
- **CI:** both wheels are built, installed into a clean venv and tested with the network blocked, on Linux, macOS and Windows with Python 3.11 to 3.13.
- `SECURITY.md`, this changelog, and a PyPI Trusted Publishing workflow that runs only when started by hand.

### Changed
- **The runtime is found in this order:** `SAFELOADAI_WASI_PYTHON`, then `safeloadai_runtime.path()`. The per-user cache download of 0.2 (C9) is gone.
- **Allowlist additions:**
  - `joblib.numpy_pickle.NumpyArrayWrapper`;
  - `__keras_tensor__`, the input marker in Keras 3 functional configs.
- **Wording:** a `TFOpLambda` finding now says that the layer calls a TensorFlow function by name.

### Measured
- **On the local lab plus generated benign set (138 files), compared with 0.2:**
  - detection went from 52/53 to 53/53;
  - false positives went from 49/85 to 23/85.
- **The Hugging Face false-positive run is still pending,** because huggingface.co cannot be reached from the build environment. See `evaluation/results/`.

## Earlier

0.2 and earlier were developed before this changelog existed. See the git history and `AUDIT.md`.
