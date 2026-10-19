# Full Hugging Face run review, 2026-10-19

Run: `eval-hf-full-20261019T123116Z.{json,md}`. Same setup as `review-hf-20261019.md`: disposable cloud container, safeloadai 0.4.0 on Python 3.13, picklescan 1.0.5, fickling 0.1.12 and modelscan 0.8.8 in a Python 3.12 venv, `guard.py` on, no `--deep`.

`fetch_benign_hf.py --max-mb 100` fetched 310 weight files (4.9 GB) from the most-downloaded Hub repos per format, no `.py` or notebooks. The lab corpus is the same 65 files.

## MALICIOUS verdicts on Hub files: 10

**4 real malicious samples (true positives).** Each is a Keras Lambda layer whose marshalled bytecode names a code-execution sink:

| file | sink names in bytecode | Hub security scan |
|---|---|---|
| `IHasFarms/MaliciousModel/unsafe_model.h5` | `os`, `system` | unsafe |
| `ScanMe/test-models/eval_lambda.h5` | `eval` | unsafe |
| `ScanMe/test-models/eval_lambda.keras` | `eval` | unsafe |
| `hfscanner/model/lambda_attack.h5` | `__import__`, `os`, `system` | not scanned yet |

All three repos are scanner test sets (the last one also holds a `lambda_benign.h5`, which safeloadai did not mark MALICIOUS). picklescan and modelscan reported all four clean; modelscan skips `.h5`. Fickling flags every `.h5` file.

**6 false positives, one scanner bug.** A Keras file saved with a custom loss or metric records it as `builtins.<name>`, and `_promote_sinks` in `static/keras_static.py` treats every name in `builtins` as a known sink:

- `Steenslid/ecg-ptbxl-classification/ecg_cnn_final.keras` (`binary_focal_loss`), with identical copies in `Blagoja/...` and `hellothisisaswin/...`
- `manpreet28111995/eca-ldnet/.../seed17/stage4_best.keras` and `.../seed43/stage4_best.keras` (`stage4_loss_without_none`, `psnr_metric`, `ssim_metric`, `mae_metric`)
- `ZOROD/Boiler_Tube_Early_leak_detection/lstm_best.keras` (`_loss`)

None of these names exists in `builtins`, so Keras cannot import them and nothing runs. Fix to consider: for `builtins`, promote only names `is_dangerous_import` flags and leave the rest UNVERIFIABLE.

## Corrected numbers

306 genuinely benign Hub files after moving the 4 true positives out.

| format | benign files | false positives | rate | MALICIOUS | RISKY | UNVERIFIABLE |
|---|---|---|---|---|---|---|
| `.h5` | 67 | 10 | 15% | 0 | 4 | 6 |
| `.keras` | 49 | 24 | 49% | 6 | 4 | 14 |
| `.joblib` | 53 | 23 | 43% | 0 | 2 | 21 |
| `.pkl` | 27 | 15 | 56% | 0 | 5 | 10 |
| torch (`.bin`, `.pt`) | 110 | 48 | 44% | 0 | 17 | 31 |
| **total** | **306** | **120** | **39%** | **6** | **32** | **82** |

82 of the 120 are UNVERIFIABLE only, so a user can accept them item by item. 38 (12%) need a code change or are refusals by design. Detection: 4/4 real malicious Hub files, 53/53 lab files.

For comparison on the same 306 files: picklescan and modelscan 0 false positives, but 0/4 on the real Hub samples; Fickling flagged most benign pickles and every `.h5`.

## RISKY files worth a second look

- **`a-01a/dogs-vs-cats-svm/svm_vgg16_cats_dogs.pkl`**: a `.pkl` that safeloadai identified as a Keras zip with 3,887,223 bytes before the first ZIP entry (polyglot). The verdict is SUSPICIOUS, so a gate would stop it, but neither layer analysed those leading bytes. If they are a pickle, `pickle.load` would run them while safeloadai only looked at the zip. Worth checking whether format detection should test for a leading pickle before a trailing zip. Not inspected further here, per the evaluation rule of not opening Hub files outside `safeloadai.scan()`.
- `jinaai/jina-embeddings-v2-small-en/pytorch_model.bin`: bad CRC-32 on `data.pkl`, so the archive was refused. Probably a reader incompatibility, not tampering, given the repo has over a million downloads.
- `alltrue-ai/christina-model-1000-small-files`: `.keras` files whose content is a pickle. The Hub's scanner flags another file in that repo as unsafe.
- 16 files in a format safeloadai does not recognise (OpenVINO quantized weights and similar), and 3 Lambda layers with no sink names in their bytecode (`kundajelab/...` x2, `qwertymaninwork/...`).
