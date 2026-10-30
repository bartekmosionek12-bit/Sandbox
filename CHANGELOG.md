# Changelog

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [Semantic Versioning](https://semver.org/). Two packages are released from this repository:

- `safeloadai` (the scanner);
- `safeloadai-runtime` (the pinned sandbox runtime). It has its own version and changes only when the runtime does.

## safeloadai 0.11.0 (unreleased)

In short: `--trust-inert-from` made verdicts stricter instead of looser (it replaced the pinned policies); it now adds to them and still refuses a class to which the installed version adds a hook. It has not yet loosened a verdict on any evaluated file, and the reasons are documented. pandas 3 `Index`/`MultiIndex`, Keras 3 operations and data markers, `TextVectorization`, `RandomBrightness`, `CosineDecayRestarts` and scikit-learn's SGD losses are accepted after a source review; an HDF5 model named `.keras` is read as tf.keras reads it. A new blind split, held-out-4. No rule was loosened by default. Detection unchanged (lab 66/66, mutations 774/774, Hub malicious 49/49); benign FPR on readable files 0.124 to 0.117 (held-out-2), 0.164 to 0.160 (held-out), 0.118 to 0.105 (held-out-3), 0.185 to 0.173 (held-out-4, blind).

### Added
- **held-out-4** (`evaluation/splits/hf-heldout4.txt`, plan committed): 1,792 benign-stratum files from 1,392 repositories in no earlier split, measured once and blind with the frozen scanner; only aggregates are published (`evaluation/results/heldout4-v0110.json`). held-out-3 is reported with the other held-out sets now (its aggregates were read in 0.10.0); `evaluation/hf_heldout3_labels.tsv` holds its labels, with the two files reviewed after the 0.10.0 measurement as benign.
- Evaluation: the `--trust-inert-from` column scans every file again, so a verdict it makes stricter shows (DECISIONS.md T3); the blind aggregate counts how often it disagrees with the default.

### Security
- **`--trust-inert-from`** (DECISIONS.md T1, T2; [docs/OPTIONS.md](docs/OPTIONS.md#trust_inert_from)): the installed analysis replaced the pinned policies for a named distribution and, at the pinned versions, refused 230 classes they accept (old scikit-learn module paths, `Parallel`, DeepSpeed configuration classes). It now adds to them, and removes a pinned class only when the installed source gives it or a base a hook, property setter, metaclass, decorator or slots the pinned review did not see. With the evaluation's versions no pinned class is removed. [LLM03]
- **Reviewed classes** ([evaluation/results/source-review-0.11.0.md](evaluation/results/source-review-0.11.0.md), tune and tune-2 only): pandas `Index` and `MultiIndex` under pandas 3's names, `MultiIndex` only through `_new_Index` with `_new_Index` levels, array codes, plain names and an int or None sortorder, and an empty frame's block manager (pandas 1.4.4, 2.2.3, 3.0.6); nine `keras.src.ops` classes and the `__ellipsis__`, `__slice__` and `__tensor__` markers in the exact form Keras writes (3.0.5, 3.15.1); `RandomBrightness`, `CosineDecayRestarts`; `TextVectorization` only with built-in `standardize`/`split` and an inline vocabulary; scikit-learn's Cython SGD losses (1.0.2, 1.3.2, 1.5.2). Misuse and sinks stay flagged (`tests/test_allowlist_review_0_11_0.py`). [LLM03]

### Changed
- A file named `.keras` whose content is HDF5 from offset 0, with no other reading, is a note instead of an extension mismatch: Keras 3 refuses it and tf.keras 2.x reads it as the HDF5 model safeloadai analyses (DECISIONS.md N6). A userblock, a second reading or any other extension keeps the finding.

### Measured (0.10.0 and 0.11.0 on the same files, same commits and sha256)
- Detection: lab 66/66, mutations 774/774, Hub malicious 49/49, Hub unsafe 5/5 and every malicious file of held-out, held-out-2 and held-out-3, with and without the options; 0 benign files of these sets MALICIOUS. held-out-4 (blind, labels from the automatic rule on Hub evidence, not reviewed): 4 files that rule calls malicious are CLEAN and 1 file benign by selection is MALICIOUS, the same in 0.10.0 and 0.11.0 (EVALUATION.md, held-out-4).
- FPR on readable benign files, default: held-out 0.164 to 0.160, held-out-2 0.124 to 0.117, held-out-3 0.118 to 0.105, held-out-4 0.185 to 0.173. With `--validate-boosters`: 0.117, 0.088, 0.093, 0.169.
- `--trust-inert-from` against the default on benign files: 0.10.0 was stricter on 2, 14, 8 and 5 files of held-out, held-out-2, held-out-3 and held-out-4; 0.11.0 on none, and it loosens none.

## safeloadai 0.10.0 (unreleased)

In short: Core ML, CTranslate2 and whisper.cpp weights are read and CLEAN when valid; scikit-learn's `_loss` alias, training-argument dataclasses, LightGBM's wrappers, pandas `RangeIndex` and Keras top-k metrics are accepted after a source review; pathlib path classes are RISKY instead of MALICIOUS; an opt-in `--validate-boosters`; a new blind split, held-out-3. No rule was loosened by default. Detection unchanged (lab 66/66, mutations 774/774, Hub malicious 49/49); benign FPR on readable files 0.149 to 0.124 (held-out-2), 0.179 to 0.164 (held-out), 0.142 to 0.118 (held-out-3, blind).

### Added
- **No-code formats** ([src/safeloadai/static/model_formats.py](src/safeloadai/static/model_formats.py)): Core ML weight blobs (coremltools 9.0), CTranslate2 `model.bin` (4.6.0) and whisper.cpp ggml models (1.8.2), each checked field by field against its reader; valid is CLEAN, inconsistent is RISKY, readable as anything else is a polyglot. TFLite Model Maker's appended label files are a note, not a second reading. KenLM stays UNSUPPORTED (README, LIMITATIONS).
- **`--validate-boosters`** (`validate_boosters=True`, off by default, looser, recorded and announced; [docs/OPTIONS.md](docs/OPTIONS.md#validate_boosters)): a pickled XGBoost, LightGBM or CatBoost model is accepted for that file only when the class is used exactly as its library writes it and every payload passes a strict structural validator in the WASI sandbox. Payloads over 64 MiB stay UNVERIFIABLE. The default (owner decision A2) is unchanged.
- **held-out-3** (`evaluation/splits/hf-heldout3.txt`, plan committed): 1,842 benign-stratum files from 1,403 repositories in no earlier split, measured once and blind; only aggregates are published (`evaluation/results/heldout3-v0100.json`, `evaluation/blind_aggregate.py`).
- Evaluation: a `--validate-boosters` column, FPR excluding the irreducible floor, time and memory per group with the file behind the peak (`evaluation/make_evaluation_doc.py`), and `evaluation/rescan_boosters.py`.

### Security
- **Reviewed classes** ([evaluation/results/source-review-0.10.0.md](evaluation/results/source-review-0.10.0.md), tune and tune-2 only): scikit-learn's `_loss.*` alias only after a module that registers it was imported, and in `safe_load` only when `sys.modules['_loss']` is scikit-learn's own module; `HistGradientBoostingRegressor`, `_RemainderColsList`, `Bunch`; six training-argument dataclasses (llamafactory, FlagEmbedding, ms-swift, axolotl); `LGBMClassifier`, `LGBMRegressor`; pandas `RangeIndex` with int start, stop and step only; Keras 3 `TopKCategoricalAccuracy` and `SparseTopKCategoricalAccuracy`. Each exact pair with its version; misuse and sinks stay flagged (`tests/test_allowlist_review_0_10_0.py`, `tests/test_sklearn_loss.py`). [LLM03]
- **pathlib path classes** are RISKY, not MALICIOUS: constructing a path parses strings and touches no filesystem; their methods stay sinks (`tests/test_pathlib_classes.py`). Matched by the root package and the exact class name, so the `pathlib._local` module CPython 3.13 writes is covered too. A benign Windows checkpoint was MALICIOUS in 0.9.0.
- `--validate-boosters` never clears a Booster when the sandbox returns fewer results than payloads.

### Changed
- Emulation evidence limits scale with the stream (2 records per opcode, at most 1,000,000 records and 128 MiB); a run that drops records is still SUSPICIOUS, never CLEAN.
- Structure checks follow the loaders where they read a field identically whatever it holds (DECISIONS.md N2 to N4): Core ML `padding_size_in_bits` of byte types, OpenVINO Const regions larger than their tensor, TFLite associated files. Each has a test that a payload in the same place is still caught.

### Fixed
- `--validate-boosters` refused a Booster stored in its `XGBClassifier`'s state (DECISIONS.md B3).

### Measured (0.9.0 and 0.10.0 on the same files, same commits and sha256)
- Detection: lab 66/66, mutations 774/774, Hub malicious 49/49, Hub unsafe 5/5 and every malicious file of held-out and held-out-2, with and without `--validate-boosters`; 0 let through. No benign file is MALICIOUS. On held-out-3, two files the Hub antivirus flags (label from its evidence, not reviewed while blind) are CLEAN in both releases; looked at after the measurement, both are TF-IDF vocabularies holding words such as `runpy` (EVALUATION.md, held-out-3).
- held-out-2 (2,806 benign): UNSUPPORTED 114 to 20, hard blocks 79 to 56, FPR on readable files 0.149 to 0.124 (0.095 with `--validate-boosters`). held-out (496): UNSUPPORTED 33 to 2, FPR 0.179 to 0.164 (0.121). held-out-3 (1,415 benign, blind): UNSUPPORTED 36 to 12, FPR 0.142 to 0.118 (0.106).
- Without the irreducible floor (code the model author wrote: 4.3 %, 6.1 % and 5.0 % of readable files), FPR 0.085, 0.110 and 0.072 by default, 0.055, 0.065 and 0.059 with `--validate-boosters`.
- Time per held-out-2 file: median 0.83 s, p95 3.01 s (0.85 s and 3.15 s in 0.9.0); peak memory 1,256 MiB (1,242 MiB).

## safeloadai 0.9.0

In short: data-only formats (safetensors, GGUF, npy, npz) are read and CLEAN when valid; old module paths of reviewed classes are accepted under the rule of the class they became; trl, sentence-transformers and DeepSpeed configuration classes are accepted after a source review; a new tune-2 split; the root causes of every blocked benign file are measured and published. Detection on the evaluation corpus: 902/902 (unchanged); benign held-out-2 FPR 0.149 (0.169 in 0.8.0), held-out 0.179 (0.181).

### Added
- **Data-only formats** ([src/safeloadai/static/data_formats.py](src/safeloadai/static/data_formats.py)): safetensors (JSON header, dtypes, shapes, offsets that tile the data exactly), GGUF (versions 1 to 3, both byte orders, metadata types, tensor table, alignment and file size), npy (header, dtype without objects, shape against the file size) and npz (a ZIP of npy members only, each header read without decompressing the data). A valid file is CLEAN with the reason "data-only format, no code on load". Any inconsistency (offsets that overlap or leave gaps, a declared size the file does not have, an object dtype, trailing data, a member that is not npy) is SUSPICIOUS (RISKY). A file that reads as a data-only format and as anything else is a polyglot and never CLEAN. A GGUF chat template that reaches Python internals is SUSPICIOUS, and MALICIOUS with a sink. The pre-commit hook scans these extensions too. 75 tests, among them polyglots, header overflows and object arrays (`tests/test_data_formats.py`). [LLM03]
- **Old module paths** (`static/upstream/historical_paths.json`, `HISTORICAL.md`, `tools/gen_historical_paths.py`): 464 module paths that reviewed classes had in older releases (scikit-learn, transformers, trl, sentence-transformers and others, read from PyPI archives, never installed). Each is accepted only as the exact pair found, only under the rule of the class it became (a policy alias only rebuilt from state), and the clearance says "old module path of X". Bare compiled aliases outside the package stay out (`tests/test_historical_paths.py`).
- **tune-2 split** (`evaluation/splits/hf-tune2.txt`, `evaluation/hf_tune2_labels.tsv`): 2,986 files from 2,327 repositories in neither earlier split, for allowlist work. held-out and held-out-2 stay blind.
- **Root causes of blocked benign files** (`evaluation/fp_anatomy.py`, [docs/EVALUATION.md](docs/EVALUATION.md#why-benign-files-are-not-clean-root-causes)): every benign file that is not CLEAN in one class, (a) user-defined classes, (b) custom Keras objects, (c) public-library classes missing from the allowlist, (d) old module paths, (e) formats safeloadai does not parse, (f) everything else. (a)+(b) is the irreducible floor: 119 of 2,806 benign held-out-2 files (4.2 %). Published as aggregates only.
- `run_eval.py` records peak memory (`rss_peak_mb`, `children_rss_peak_mb`).

### Security
- **trl, sentence-transformers and DeepSpeed configuration classes** are accepted in the exact form their libraries write, after a source review of trl 1.16.0, sentence-transformers 6.2.0, transformers and accelerate ([evaluation/results/source-review-4-20261023.md](evaluation/results/source-review-4-20261023.md)): the nine `trl.trainer.*_config` dataclasses, the sentence-transformers training arguments and samplers, `HfDeepSpeedConfig`, `HfTrainerDeepSpeedConfig` and `DeepSpeedPlugin`, only rebuilt from state; three hooks reviewed and pinned by sha256 (`IsotonicRegression.__setstate__`, ultralytics `AAttn.__setstate__`, the `DeepSpeedPlugin.selected` setter); five enums only as a member lookup. A package that replaces its own entry in `sys.modules` with a lazy module is accepted only in the import chain of such a class, never for the referenced-only rule. Trainers and models stay out. Adversarial tests per entry (`tests/test_allowlist_review_20261023.py`). [LLM03]
- **LightGBM and CatBoost models stay off the allowlist**, like XGBoost (owner decision A2, extended): their pickles carry a model in the library's own text or binary format, read by a native parser this review does not cover. The explanation says so.
- `sentence_transformers` is a genuine package, not an imitation of `transformers`; `transformers_evil` and the like stay RISKY.

### Measured (same 4,799 files, same commits and sha256, before and after)
- Detection unchanged: lab 66/66, mutations 774/774, Hub malicious 49/49, Hub unsafe 5/5, every malicious file of tune, held-out and held-out-2; 0 let through. No benign file is MALICIOUS.
- hf-heldout2 (2,806 benign): CLEAN 2,237 to 2,290, soft blocks 360 to 322, hard blocks 94 to 79; FPR 0.169 to 0.149. hf-heldout (496 benign): FPR 0.181 to 0.179. UNSUPPORTED unchanged (114 and 33): the held-out sets have no data-only files.
- Time per Hub file: median 0.67 s, p95 2.51 s (0.68 s and 2.54 s in 0.8.0). Peak memory 1,244 MiB.

## safeloadai 0.8.0 (2026-10-23)

In short: tool errors with stable codes instead of verdicts (E1xx to E5xx, exit code 6); bounded host memory (E105) and an emulation budget that grows with the file (E304 on 1 file of 4799 instead of 51); cloudpickle functions and dill arrays judged by what they do instead of as sinks; SARIF output, a GitHub Action and a pre-commit hook; `scan --malicious-only`; the deep-mode pickle image builds again (`.dockerignore`); a threat model, a vulnerability policy and a generated evaluation page. Detection on the evaluation corpus: 902/902; benign held-out-2 FPR 0.169 (0.185 in 0.7.1).

### Changed
- **Tool errors are no longer verdicts** ([docs/ERRORS.md](docs/ERRORS.md)). When safeloadai itself fails (file missing, unreadable or over 4 GiB; an exception a parser does not expect; the WASI sandbox unavailable, crashed, timed out or out of fuel; the deep sandbox did not run; runtime integrity failure; invalid options passed to `scan()`), the report has `status: "error"`, an `error` `{code, message, layer}` with a stable code (E1xx I/O, E2xx parser, E3xx sandbox, E4xx runtime integrity, E5xx options) and `verdict: null`. These were SUSPICIOUS reasons before (or exceptions, for runtime integrity and options). An ERROR is never CLEAN, never loadable by `safe_load`, never overridable and never changed by the known-file list. MALICIOUS evidence found before a failure still decides; the failure is then listed under `errors`. Report schema 3.0.
- A pickle the walker cannot read because of the file (truncated, a memo entry it never stored, a bad frame, an unknown opcode) stays SUSPICIOUS, now explained in plain words ("pickle is not readable: ..."). An opcode the walker does not model is a tool error (E201).
- **CLI:** a failure on one file no longer aborts a multi-file scan; every file gets its own result (a path that does not exist is an E101 result; it was exit 2 before). New exit code **6** for ERROR; 4 stays for a runtime integrity failure. Precedence: MALICIOUS > ERROR > SUSPICIOUS > UNSUPPORTED > CLEAN.
- `scan()` returns an ERROR report instead of raising `RuntimeIntegrityError` or `OptionError`. `safe_load()` raises `UnsafeModelError` (with `.error`) for a file it cannot read.

- **`--trust-inert-from` is marked experimental** ([docs/OPTIONS.md](docs/OPTIONS.md#trust_inert_from)). It changes no verdict in the 0.8.0 evaluation: for the pinned scikit-learn, transformers and torch it gives the same answers as the shipped policies, and the files it would matter for come from other distributions. It still changes verdicts when the installed version differs from the pinned one (`tests/test_trust_inert_from.py`).

### Added
- **`safeloadai scan --malicious-only`**: binary output (MALICIOUS / NOT-MALICIOUS) for integrations that need it; exit 1 for MALICIOUS, 4 or 6 for an ERROR, 0 otherwise. An output mode only: the verdict, the Report JSON, the SARIF log and `safe_load` are unchanged ([docs/ERRORS.md](docs/ERRORS.md#--malicious-only-binary-output)). `evaluation/malicious_only.py` measures it from an evaluation run.
- **Integrations**: `safeloadai scan --sarif FILE` writes a SARIF 2.1.0 log (`safeloadai/sarif.py`; one result per file that is not CLEAN, rules `safeloadai/malicious`, `error`, `suspicious`, `unverifiable`, `unsupported`; an accepted override is an external suppression, never dropped); a composite **GitHub Action** (`action.yml`) that installs safeloadai, runs `doctor`, scans, uploads SARIF to code scanning and fails on anything not CLEAN (or, with `fail-on: malicious`, on MALICIOUS; an ERROR always fails); a **pre-commit hook** (`.pre-commit-hooks.yaml`); `examples/huggingface_safe_download.py` (download at a pinned commit, scan, `safe_load` only if CLEAN).
- **Threat model** ([docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)): assets, attackers, trust boundaries (host, WASI guest, judge, deep mode, `safe_load`, release path), in-scope and out-of-scope threats mapped to OWASP Top 10 for LLM Applications 2025 (LLM03 core scope; LLM04 out of scope, with why), OWASP ML Security Top 10 (ML06) and MITRE ATLAS (2026.09 IDs). A Scope box at the top of the README; each rule family in docs/HOW_IT_WORKS.md lists its mapping; CONTRIBUTING.md asks for a standard tag on detection changes.
- **Vulnerability handling** (SECURITY.md): 72 h acknowledgement, 7-day triage, 90-day fix target (14 days Critical, 30 High), CVSS 4.0, coordinated disclosure, CVEs through GitHub Security Advisories, OSV and the PyPA advisory database. [docs/INCIDENT_RESPONSE.md](docs/INCIDENT_RESPONSE.md) is the checklist for a confirmed bypass.
- **Release path** ([docs/RELEASING.md](docs/RELEASING.md)): OpenSSF Scorecard workflow; PEP 740 attestations explicitly on in `publish.yml`, and how users verify them; a real upload only from `main`; owner steps for the `pypi` environment reviewer (second maintainer with "Prevent self-review" as the target), `v*` tag and `main` rulesets.
- **docs/EVALUATION.md**, generated from the result JSON by `evaluation/make_evaluation_doc.py`: confusion matrix (TP/FN/FP/TN) per group and format with precision, recall and FPR and 95 % Wilson intervals, UNSUPPORTED and ERROR in their own columns, the data distribution and label origin, the tune/held-out split by repository, and the share of malicious files that are our own lab payloads. A test fails when the page is stale.

### Security
- **Two more known sinks**: `numpy.testing._private.utils.runstring` (exec of a string) and `_osx_support._read_output` / `_find_build_tool` (run a shell command) are MALICIOUS, in pickles and as Keras objects. They were SUSPICIOUS (RISKY, never overridable) before, so `safe_load` already refused them; the change matters for CI that tells MALICIOUS from SUSPICIOUS. No benign file of the evaluation sets names them. [LLM03]
- **Keras Lambda bytecode is never CLEAN** (owner decision, DECISIONS.md L1). A model whose only static finding is Lambda bytecode without sink names was CLEAN when emulation completed and recorded nothing; that code runs in the same sandbox interpreter as the recorder and can hide from it, so the file is now SUSPICIOUS (RISKY), and still MALICIOUS when emulation records a dangerous behaviour. None of the 216 benign Keras files CLEAN in the Hub tune and held-out splits was affected; the two benign Lambda files of the lab corpus are now SUSPICIOUS. [LLM03]
- **A guest that ends itself is never a complete emulation run.** Code that runs in the WASI guest (a Keras Lambda's bytecode, a dill code object) could write a well-formed `done` record and leave with `os._exit(0)`; the run looked complete. The runner now treats every WASI `proc_exit` as status `exit` (the bootstrap always returns from `_start`, which calls no `proc_exit` for status 0), so such a run is incomplete and the file gets an error (E302) instead of the forged log's verdict. Design and remaining limits: [docs/EVIDENCE_CHANNEL.md](docs/EVIDENCE_CHANNEL.md). [LLM03]
- **Fuzzing** ([fuzz/](fuzz/), `.github/workflows/fuzz.yml`, weekly): atheris harnesses for the pickle walker, the ZIP reader, the HDF5 metadata reader, joblib's array layout and the decompressors; `tests/test_fuzz.py` replays every finding and runs a short Hypothesis pass per target. Findings fixed (each now a regression input under `fuzz/regressions/`): a pickle whose GLOBAL could not be resolved made the static layer raise (an ERROR instead of SUSPICIOUS); ZIP archives with a lying local-header offset, corrupt LZMA member data or an unknown "version needed" raised `ValueError`, `LZMAError` or `NotImplementedError` past the ZIP reader instead of being refused.

- **pandas DataFrame and Series, dabl estimators and scikit-learn's `_ThresholdScorer`** are accepted in the exact form their libraries write, after a source review of pandas 1.4.4 and 3.1.0, dabl 0.2.6.2 and 0.3.2 and scikit-learn 1.1.3 and 1.9.1 ([evaluation/results/source-review-3-20261022.md](evaluation/results/source-review-3-20261022.md)): DataFrame, Series, `SingleBlockManager`, `CategoricalDtype`, the three dabl estimators and the scorer only rebuilt from state, with each state's keys and values checked; `BlockManager(blocks, axes)` and `_unpickle_block(array, slice, ndim)` only with those arguments; `average_precision_score` only as the scorer's stored score function, never called (the emulation reports a call to it). Every other use stays SUSPICIOUS; a marker test per entry (`tests/test_allowlist_review_20261022.py`). It clears the 11 dabl pickles of the tune split. [LLM03]

### Fixed
- **`trust_inert_from` cleared no scikit-learn or torch class on Linux or macOS.** Reviewed hooks (`BaseEstimator.__setstate__`, `Module.__setstate__`, ...) were matched by the sha256 of their source text as found in the pinned wheels, which are Windows builds with CRLF line endings; an installed copy with LF never matched. Line endings are normalised before hashing (`sources.source_sha256`); the reviewed digests are recomputed from the same pinned wheels.
- **About 100 more state-only classes, among them `RandomForestClassifier`, `LogisticRegression`, `SVC`, `Ridge`, `ElasticNet`, `LassoCV`, `CountVectorizer` and `KNeighborsClassifier`.** A class body that edits a dict it has just made (`_parameter_constraints.pop("l1_ratio")`) made its whole module "not inert". A builtin method of a dict, list, set, tuple or constant that the class body itself made, with plain data as arguments, is no longer counted as a call; every other call still is (`tests/test_clearance.py`). Regenerated `static/upstream/` (1,979 state-only classes, was 1,881). [LLM03]
- **Polyglot and trailing-data reasons are RISKY, not MALICIOUS.** In a file whose static layer found a sink, every other static reason (trailing data, "readable as more than one format", an unknown import) used to be a MALICIOUS finding as well. Only the sink evidence is MALICIOUS now; the rest are RISKY findings. Verdicts are unchanged: a polyglot without a sink is SUSPICIOUS (RISKY), with a sink MALICIOUS.
- joblib files written with old numpy, which pickled an array's dtype as `numpy.dtype('f8', 0, 1)` instead of `numpy.dtype('f8', False, True)`, were SUSPICIOUS ("opcode walk failed: ... unexpected numpy.dtype arguments"). Both forms are read now (static walker and emulation); any other flags stay SUSPICIOUS.

### Evaluation
- **Final 0.8.0 measurement** (2026-10-22; safeloadai's columns measured again on 2026-10-23 after the fixes below, on the same files) ([docs/EVALUATION.md](docs/EVALUATION.md), README "Results", both generated from `evaluation/results/eval-v080-*.json`): lab 66/66, mutations 774/774, hf-malicious 49/49 detected (0 let through); held-out and a new **held-out-2** (2806 benign files from repositories no earlier corpus used, never used for tuning) measured before (0.7.1) and after on the same files for the default, `--trust-inert-from` and the upper bound; `--malicious-only` detection and false positives on every set. Hub files were downloaded, scanned and deleted in batches (`evaluation/batch_hf.py`); labels of Hub-flagged files come from the Hub's evidence and a manual review written as rules (`evaluation/review_heldout2_labels.py`, `evaluation/hf_batches_labels.tsv`), never from safeloadai. A benign file from a repository whose name declares a proof of concept or scanner test is `unclear`.
- The committed results compare other scanners only as one all-files table; the detailed comparison is kept private until coordinated disclosure (`evaluation/redact_results.py`, `evaluation/private_comparison.py`). modelscan now runs with its tensorflow extra for `.keras` (`evaluation/rescan_tool.py`); its `.h5` scan still does not run on the host.

- **Deep mode's pickle image did not build:** `.dockerignore` left out `docker/requirements-pickle.txt`, which the Dockerfile copies. It is included now.

### Fixed on held-out files
Bugs in the code that the held-out sets showed (owner's decision of 2026-10-23: the held-out rule is about tuning the allowlists, not about bugs). Each was reproduced on a synthetic file of our own, fixed in general and tested; for files of these kinds the held-out measurement is no longer blind ([docs/EVALUATION.md](docs/EVALUATION.md)).
- **Host memory (scanner availability).** A 211 MiB dill pickle took more than 13 GB of host memory: the static listing for the dashboard rendered the whole pickle before it was cut, and every opcode was kept as a record. The listing now stops at its size limit, opcode records are capped (every opcode is still counted), and every value the host-side pickle machine holds is charged to a per-scan budget (512 MiB plus twice the file's size, at most 4 GiB). Running out, or a `MemoryError`, is the new tool error **E105 "resource limit reached"**, never a crash. The file now peaks at 651 MiB. [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) T16. `tests/test_resource_limits.py`.
- **cloudpickle functions and classes were MALICIOUS without a sink.** `builtins.type` and `builtins.staticmethod` (members of `builtins`) were known sinks, and every cloudpickle helper was a `code_exec` sink in the emulation. A function cloudpickle pickles with its bytecode now takes the path of a dill function and a Keras Lambda: RISKY ("file carries executable Python code"), MALICIOUS only with sink names in its code or a sink call when it is emulated. `type`, `staticmethod`, `classmethod`, `property` and dill's `__builtin__.__main__` are class builders (RISKY, never UNVERIFIABLE); cloudpickle's `_builtin_type` is checked against the type names cloudpickle writes and `subimport` by module name. `tests/test_cloudpickle.py`.
- **dill's `_create_array` was a code-execution sink.** It is `f(*args).__setstate__(state)`: with numpy's `_reconstruct` as `f` it rebuilds an array; any other `f` is named as a call of that argument, and a sink as `f` stays MALICIOUS.
- **The emulation's compute budget is fixed no longer** (E304 on large pickles). It grows with the pickle data and its opcode count, up to 250 billion fuel, 120 s and 2 GiB of guest memory (`sandbox.host.scaled_limits`); a file over the ceiling is still ERROR. Limits passed to `scan()` are used as given. Of the 48 held-out files that were E304 and could be downloaded again (51 in the measurement), 47 now finish (31 CLEAN, 16 SUSPICIOUS) and 1 is still E304 (it needs more than the ceiling); scan time on those 48: median 6.6 s, p95 45 s, max 72 s.
- A `MemoryError` in the pickle walker read as "no pickle found" next to an E201; it is E105 now.

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
