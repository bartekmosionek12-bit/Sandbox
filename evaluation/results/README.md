# Evaluation results

`eval-20261017T140950Z.{json,md}`: first run, made in the development container on 2026-10-17.

## Setup
- **safeloadai:** this branch, Python 3.13 host, CPython 3.12.0 WASI guest under wasmtime 49.0.0.
- **Other tools:** picklescan 1.0.5, fickling 0.1.12 and modelscan 0.8.8, installed in a Python 3.12 venv. modelscan was installed without its TensorFlow extra, so it skips `.keras` files.
- **Lab corpus:** `python -m tests.corpus.build_corpus DIR` produces 48 files: 38 marker payloads and 10 benign controls.
- **Local benign files:** `python evaluation/make_local_benign.py DIR` writes 23 numpy and scikit-learn files, joined by the two clean PoC samples. torch and keras were not installed, so none of their files are included.

## How to read it
- **"Detected" means any verdict other than CLEAN.** An error or "unsupported" from another tool is counted on its own and is not a detection.
- **picklescan and Fickling report "clean" on `.keras` files they do not analyse.** Part of their low detection count is therefore a format they do not cover, not a miss within one.
- **Fickling 0.1.12 failed to parse many benign pickles:** "TODO: Add support for Opcode FLOAT" and similar. Those runs are counted as errors.
- **The local benign files are NOT independent of the pickle allowlist.** The allowlist was built from a scikit-learn and numpy tuning corpus (DECISIONS C5), so their CLEAN results show the emulator does not break on them. They are not a false-positive rate for unseen models.
- **All 7 false positives are `.joblib` files.** joblib writes raw array bytes after the pickle and uses `joblib.numpy_pickle.NumpyArrayWrapper`, so the static layer refuses them by design.
- **The false-positive number that matters is still missing.** It needs the Hugging Face set (`evaluation/fetch_benign_hf.py`), which has not been run: the Hub is not reachable from the container that produced this run.
