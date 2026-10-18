# Security policy

safeloadai decides whether a model file is safe to load. A file it calls CLEAN that runs code when loaded is a security bug, and we want to hear about it.

## Supported versions

| version | supported |
|---|---|
| 0.3.x | yes |
| < 0.3 | no |

## Reporting a vulnerability

Report it privately through GitHub. On the repository's **Security** tab, choose **Report a vulnerability**, which opens a private advisory. If that is not available, open an issue that says only that you have a security report and how to reach you. Leave the details out of the issue.

Please include:
- **The file,** or a script that builds it. Use a harmless payload such as `echo MARKER`, a file under `/tmp`, or a connection to 127.0.0.1. Never use a real command or an external host.
- **The safeloadai version** and the `safeloadai scan --report` JSON.
- **The loader that runs the code,** with its version: for example `pickle.load`, `joblib.load`, `torch.load` or `keras.models.load_model`.

A confirmed bypass gets a fix and an advisory.

## What counts

**A bypass** is a file that gets a verdict lower than it should, where a documented loader would run attacker-controlled code or touch the system:
- CLEAN for a file that does that;
- SUSPICIOUS for a file whose payload is a known sink.

**These also count:**
- anything that lets a scan run code on the host;
- anything that lets the sandbox reach the network or the file system outside its one file;
- anything that lets the optional judge lower a verdict.

**These are out of scope:**
- **Known limitations** listed in the README's LIMITATIONS section:
  - TorchScript, which is always SUSPICIOUS;
  - bugs in a framework's weight or tensor parsers;
  - ways of telling the emulator apart from real execution that the LIMITATIONS section already names.
- **Deep mode (`--deep`).** It runs real loaders in a container or jail by design.
- **False positives.** Please report them as normal issues.

## Every bypass becomes a regression test

A confirmed bypass is fixed together with a test that rebuilds it with a harmless marker payload. The test goes in `tests/test_audit_regressions.py` or in the lab corpus (`tests/corpus/build_corpus.py`) and stays there. A fix without that test is not merged. The changelog entry for the fix names the report or CVE.

## How the project handles untrusted files

These rules apply to anyone working on the project, including AI agents:
- **No file under test is ever deserialized on the host.** Tests and evaluation runs use a host-execution guard (`tests/conftest.py`, `evaluation/guard.py`).
- **Payloads are markers only.**
- **Downloaded models are never committed.**
