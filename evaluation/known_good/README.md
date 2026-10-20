# Reviewed known files (0.7.0 Part 4)

`known_good.tsv` lists files from the **tune** half of the benign Hub corpus (`evaluation/splits/hf-tune.txt`)
that were reviewed by hand and found benign. Each row has the file's sha256, repo, commit, file name and a
reviewer note. The package ships an identical copy (`src/safeloadai/data/known_good.tsv`); `tests/test_known_good.py`
fails when the two differ or when a row's repo is not in the tune split. Held-out files are never added.

An exact sha256 match makes a SUSPICIOUS verdict (RISKY or UNVERIFIABLE findings) CLEAN with the reason
`known reviewed file <repo>/<file>` (`Report.cleared` mechanism `known-file`). A MALICIOUS or UNSUPPORTED verdict is
never changed. `known_good=False` / `--no-known-good` turns the list off.

## How the first list was chosen (2026-10-20)

The review read only the scan reports from `safeloadai.scan()` (imports, structure and reasons); no file was loaded.
A tune file that was SUSPICIOUS after Parts 1–3 was added when all of these held:

- every finding is UNVERIFIABLE (no RISKY reason, no sink);
- every unverifiable item belongs to a public library: scikit-learn, numpy, pandas, stable-baselines3, gymnasium,
  AutoGluon, transformers/accelerate/trl (or another package's `TrainingArguments` subclass) or Keras built-in metrics;
- the Hub's own scan did not call the file `unsafe` or `suspicious`;
- it holds none of the types whose acceptance is the owner's decision (A1 FunctionTransformer, A2 TFSMLayer, A4 xgboost
  Booster).

That gave 27 files. The other 67 SUSPICIOUS tune files were left out, each counted under the first rule it failed:

- 9 have a RISKY finding;
- 17 the Hub calls unsafe (14, among them 11 dabl pickles with the training DataFrame inside) or suspicious (3,
  among them the pandas `read_pickle` PoC, now labelled malicious);
- 23 hold an owner-decision type: 18 an xgboost Booster, 1 a FunctionTransformer, 4 a TFSMLayer;
- 18 refer to user code (`_loss` as a bare module, Keras custom objects, `builtins.<custom loss>`).

No row's sha256 occurs in the held-out half, so the list does not change the held-out measurement.
