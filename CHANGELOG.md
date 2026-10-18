# Changelog

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [Semantic Versioning](https://semver.org/). Two packages are released from this repository:

- `safeloadai` (the scanner);
- `safeloadai-runtime` (the pinned sandbox runtime). It has its own version and changes only when the runtime does.

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
