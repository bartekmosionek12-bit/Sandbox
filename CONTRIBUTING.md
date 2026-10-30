# Contributing

Thank you for helping. safeloadai is a security tool, so a few rules are stricter
than usual. Security reports go through [SECURITY.md](SECURITY.md), never a public
issue.

## Safety rules (everyone)

- **Never load or deserialise a model file outside `safeloadai.scan()`** on your
  machine: no `pickle.load`, `joblib.load`, `torch.load`, `keras.models.load_model` on
  a file under test. Tests and evaluation runs keep the host-execution guard on
  (`tests/conftest.py`, `evaluation/guard.py`).
- **Payloads are harmless markers only:** `echo MARKER`, a file under
  `/tmp/safeloadai_marker`, a connection to `127.0.0.1`. Never a real command or an
  external host.
- **A real loader may run only inside deep mode's isolation** (container or jail, no
  network, the one file mounted), and only on files from the project's own lab or
  mutation corpus. Never on downloaded files.
- **Never commit downloaded model files.** Commit manifests, hashes and results.
- **Fail closed.** No change may make a verdict less strict by default, make MALICIOUS
  overridable, or turn a tool error into a verdict ([docs/ERRORS.md](docs/ERRORS.md)).
  Options that loosen anything are off by default and documented in
  [docs/OPTIONS.md](docs/OPTIONS.md).

## Standard tags for detection changes

Every pull request title and every commit subject that changes **what is detected**
(a rule, an allowlist entry, a policy, a profile, a sink, a limit, the emulation
fakes) starts with the tag of the standard it serves, from
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and the rule families in
[docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md#rule-families-and-standards):

| Tag | Use it for |
|---|---|
| `[LLM03]` | OWASP LLM03:2025 Supply Chain: almost every detection change (code in model files) |
| `[ML06]` | OWASP ML06:2023 AI Supply Chain Attacks, when the change is specific to classical ML files (scikit-learn, joblib, xgboost) |
| `[AML.T0076]` | corrupt or truncated streams (MITRE ATLAS *Corrupt AI Model*) |
| `[AML.T0018.002]` | code embedded in a model file (ATLAS *Embed Malware*) |
| `[FP]` | a change that only removes false positives (allowlist, policy, profile, known file); it still needs the tag of what it could weaken, e.g. `[LLM03][FP]` |

Examples:

```
[LLM03] Flag hook attributes in BUILD states and repeated BUILDs
[LLM03][FP] Accept sklearn.ensemble._forest.RandomForestClassifier as state-only (source-verified)
[AML.T0076] Explain truncated pickles in plain words
```

Changes that do not touch detection (docs, CI, refactoring with identical verdicts)
need no tag.

## What a detection change needs

1. **A test** that shows the change: a marker payload that is now caught, or a benign
   file that is now CLEAN. A bypass fix always adds a regression test
   ([SECURITY.md](SECURITY.md#every-bypass-becomes-a-regression-test)).
2. **A justification for every allow** (allowlist entry, policy, profile, known file):
   the source lines of the library that show the class or function runs no code of its
   own on load, with the library version. Built only from the **tune** half of the Hub
   corpus; the held-out half is never looked at while tuning
   ([docs/EVALUATION.md](docs/EVALUATION.md)).
3. **The evaluation before and after** for anything that changes verdicts on real
   files (`evaluation/run_eval.py`, `evaluation/compare_eval.py`), with the held-out
   numbers in the pull request.
4. **A changelog entry** under the unreleased version.

## Development

```bash
python packages/safeloadai-runtime/fetch_runtime.py   # once: download + verify the pinned runtime
pip install ./packages/safeloadai-runtime
pip install -e ".[dev]"
ruff check .
python -m pytest -q
```

Code, comments, commit messages and docs are in English. Keep commits small and the
suite green after each one.
