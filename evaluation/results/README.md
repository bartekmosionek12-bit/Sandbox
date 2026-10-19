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

## Before / after run, 2026-10-18

Files:
- `eval-before-20261018T125756Z.{json,md}`: origin/main, installed into its own venv.
- `eval-after-20261018T125942Z.{json,md}`: this branch.
- `compare-20261018.md`: the before/after table, produced by `compare_eval.py`.
- `false-positives-20261018.md`: every remaining false positive, the allowlist pair it is missing, and whether adding that pair would be safe. Nothing has been added.

Corpus: 138 files, 53 malicious and 85 benign.
- **Malicious files:** `tests/corpus/build_corpus.py`, now 65 files. It adds marker rebuilds of public scanner bypasses: nullifAI broken streams, CVE-2025-1716 `pip.main`, CVE-2025-1944/1945 zip tricks, CVE-2025-1889 hidden pickle, `_osx_support`, `pydoc.pipepager`, `timeit`, `cProfile.run`, `functools.partial` and `operator.methodcaller`. It also adds the CVE-2024-3660 Lambda `.h5` and `.keras` rebuilds and `.h5` fixtures. Every payload is a harmless marker.
- **Benign files:** `make_local_benign.py`, which now covers more scikit-learn estimators and keras.applications models saved with `weights=None`, as both `.keras` and `.h5`.
- Both runs used the evaluation guard (`guard.py`).

| | before | after |
|---|---|---|
| detection | 52/53 | 53/53 |
| false positives overall | 49/85 | 23/85 |
| false positives, .h5 | 16/16 | 3/16 |
| false positives, .joblib | 17/17 | 8/17 |
| false positives, .keras | 8/19 | 4/19 |
| false positives, pickle | 8/33 | 8/33 |
| median s | 0.40 | 0.38 |

On the same 138 files:

| tool | detected | false positives | notes |
|---|---|---|---|
| picklescan | 32/53 | 0 | 19 errors |
| Fickling | 36/53 | 61 | 40 errors |
| modelscan | 23/53 | 0 | 52 files unsupported; skipped on 20 `.h5` files because it opens them with h5py on the host |

**Still not an independent false-positive rate.** These benign files were generated locally. The Hugging Face set (about 310 files: PyTorch, scikit-learn/joblib, `.keras`, `.h5`) has to be fetched on a machine that can reach huggingface.co. The container blocks it.

```
pip install huggingface_hub
python evaluation/fetch_benign_hf.py --out /tmp/hf_corpus
python -m tests.corpus.build_corpus /tmp/lab
python evaluation/run_eval.py --lab /tmp/lab --hf /tmp/hf_corpus --tool-bin <venv with the other scanners>/bin --label hf
```

## 0.4.0 run, 2026-10-18 (allowlist growth and UNVERIFIABLE)

Files:
- `eval-before-20261018T203358Z.{json,md}`: origin/main at 0.3.0.
- `eval-after-20261018T204757Z.{json,md}`: this branch. It reports itself as 0.3.0 because the version was bumped to 0.4.0 after the run; the code is the same.
- `compare-0.4.0-20261018.md`: the before/after table from `compare_eval.py`.

The corpus is the same 138 files as above, regenerated: 65 lab files from `build_corpus.py`, and benign files from `make_local_benign.py` run three times. The scikit-learn and numpy files come from scikit-learn 1.9.1 and numpy 2.5.4, the `k2_*` files from tf.keras 2.15.1 (Python 3.11) and the `k3_*` files from Keras 3 on JAX. Only safeloadai was run, under the evaluation guard.

| format | FP before | FP after | of which UNVERIFIABLE | detection before | detection after |
|---|---|---|---|---|---|
| pickle | 8/33 | 0/33 | 0 | 32/32 | 32/32 |
| joblib | 8/17 | 0/17 | 0 | - | - |
| .keras | 4/19 | 0/19 | 0 | 13/13 | 13/13 |
| .h5 | 3/16 | 2/16 | 2 | 4/4 | 4/4 |
| torch | - | - | - | 4/4 | 4/4 |
| **all** | **23/85** | **2/85** | **2** | **53/53** | **53/53** |

- **The 2 remaining false positives** are `k2_convnext_tiny.h5` and `k3_convnext_tiny.h5`: `LayerScale` without its module. They are UNVERIFIABLE only, so a user can accept `LayerScale` for that file. Re-saving as `.keras` is CLEAN.
- **4 malicious lab files were UNVERIFIABLE only in this run:** `p_unknown_global.pkl`, `k_custom_object.keras`, `k_prefix_module.keras` and `k2_custom_objects.h5`. Their payloads are names the scanner cannot resolve. An override would let them through, which is why it must name every item for one file and is recorded. After the look-alike change below, 3 remain.
- **`p_numpy_runstring.pkl` and `x_osx_support_read_output.pkl` stay RISKY** (known gadgets), so no override can accept them.

## Look-alike module names, 2026-10-19

Files:
- `eval-lookalike-20261019T043135Z.{json,md}`: this branch with `static/lookalike.py` (DECISIONS V7).
- `compare-lookalike-20261019.md`: compared with `eval-after-20261018T204757Z.json`.

Same 138 files, same tools and versions, only safeloadai, under the evaluation guard.

| | 0.4.0 before the change | after |
|---|---|---|
| detection | 53/53 | 53/53 |
| false positives | 2/85 (both UNVERIFIABLE) | 2/85 (both UNVERIFIABLE) |
| malicious files UNVERIFIABLE only | 4 | 3 |

- **`k_prefix_module.keras` (`kerasx.layers.Dense`) is now RISKY,** so no override can accept it. No verdict changed.
- **3 malicious lab files remain UNVERIFIABLE only:** `p_unknown_global.pkl`, `k_custom_object.keras` and `k2_custom_objects.h5`. Their names do not imitate an allowlisted module, so the scanner cannot tell them from a real custom class. Accepting them means trusting their code (README, LIMITATIONS).
- **Median times are higher for `.keras` and `.h5`** (0.06 s to 0.39 s and 0.62 s to 1.23 s). The run started in a freshly started container with empty caches; the change adds only a string comparison per unknown name. Treat these times as noise, not as a regression.


## Hugging Face runs, 2026-10-19

Files: `eval-hf-20261019T121001Z.*` (93 Hub files) and `eval-hf-full-20261019T123116Z.*` (310 Hub files), reviewed in `review-hf-20261019.md` and `review-hf-full-20261019.md`.

- **Detection:** safeloadai found all 53 lab payloads and all 4 real malicious Keras Lambda models that turned up among the Hub's popular files. picklescan (32/53 lab) and modelscan (23/53 lab) reported all 4 Hub samples clean.
- **False positives:** 120 of 306 genuinely benign Hub files (39%). 82 of them are UNVERIFIABLE only, meaning an import outside the allowlist that the user can accept item by item. `.h5` is lowest at 15%; `.pkl`, `.keras`, `.joblib` and torch files are between 43% and 56%.
- **One scanner bug:** 6 of the false positives are `.keras` files with a custom loss or metric saved as `builtins.<name>`, which the Keras static layer wrongly treats as a known sink.
- **One open question:** a `.pkl` that is a Keras zip with 3.9 MB of leading data was stopped (SUSPICIOUS), but those leading bytes were not analysed.
