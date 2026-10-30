# Security policy

safeloadai decides whether a model file is safe to load. A file it calls CLEAN that runs code when loaded is a security bug, and we want to hear about it.

## Supported versions

| version | supported |
|---|---|
| 0.8.x (beta, from its release) | yes |
| 0.7.x (beta) | yes, until 0.8.0 has been out for 30 days |
| < 0.7 | no |

Security fixes go into the latest minor version; we release a patch for the previous
minor version only while it is supported.

## Reporting a vulnerability

Report it privately through GitHub. On the repository's **Security** tab, choose **Report a vulnerability**, which opens a private advisory. If that is not available, open an issue that says only that you have a security report and how to reach you. Leave the details out of the issue.

Please include:
- **The file,** or a script that builds it. Use a harmless payload such as `echo MARKER`, a file under `/tmp`, or a connection to 127.0.0.1. Never use a real command or an external host.
- **The safeloadai version** and the `safeloadai scan --report` JSON.
- **The loader that runs the code,** with its version: for example `pickle.load`, `joblib.load`, `torch.load` or `keras.models.load_model`.

A confirmed bypass gets a fix and an advisory.

## What happens after you report

| Step | Target |
|---|---|
| Acknowledgement (a human read it) | within **72 hours** |
| Triage: confirmed or not, severity, affected versions | within **7 days** |
| Fix released | within **90 days**; **14 days** for Critical, **30 days** for High |
| Advisory published | when the fixed version is on PyPI |

We keep you informed at each step and tell you before the advisory is published. If a
target cannot be met, we say why and give a new date.

### Severity

We score every confirmed report with **CVSS 4.0** (base metrics; the vector goes in
the advisory) and map it to the usual rating: None 0, Low 0.1-3.9, Medium 4.0-6.9,
High 7.0-8.9, Critical 9.0-10.0. As a guide:

- a file reported **CLEAN** that runs attacker-chosen code through a documented
  loader, or through `safe_load`: usually **High or Critical**;
- code execution or a sandbox escape **during a scan**: **Critical**;
- a known sink reported **SUSPICIOUS** instead of MALICIOUS (still blocked): **Low**;
- a crash or hang (ERROR) on a crafted file: **Low**, unless it hides a payload.

### Coordinated disclosure

- Please give us **90 days** from your report (or until the fix is released, if that
  is sooner) before you publish details. If the issue is being exploited, we move
  faster and may publish sooner, with you.
- We credit you in the advisory and the changelog unless you ask us not to.
- We do not take legal action against good-faith research that follows this policy
  and uses harmless payloads.

### CVE and advisory databases

- Every confirmed vulnerability in a released version gets a **GitHub Security
  Advisory** (GHSA) on this repository. **GitHub is a CVE Numbering Authority**, so we
  request the **CVE ID** from the draft advisory; you do not need to request one
  yourself.
- Published GitHub advisories for PyPI packages enter the **GitHub Advisory Database**,
  which **OSV** (<https://osv.dev>) imports; from there `pip-audit`, Dependabot and
  other tools warn users of affected versions. We check that the advisory appears on
  osv.dev with the right affected range.
- If it does not appear, we add an entry to the **PyPA advisory database**
  (<https://github.com/pypa/advisory-database>), which OSV also imports.
- The maintainers' checklist for a confirmed bypass is
  [docs/INCIDENT_RESPONSE.md](docs/INCIDENT_RESPONSE.md).

## What counts

**A bypass** is a file that gets a verdict lower than it should, where a documented loader would run attacker-controlled code or touch the system:
- CLEAN for a file that does that;
- SUSPICIOUS for a file whose payload is a known sink.

**These also count:**
- anything that lets a scan run code on the host;
- anything that lets the sandbox reach the network or the file system outside its one file.

**These are out of scope** (the threat model lists them with reasons:
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#threats-out-of-scope)):
- **Model backdoors and poisoned weights** (OWASP LLM04): a file scanner cannot see them.
- **Known limitations** listed in the README's LIMITATIONS section:
  - TorchScript, which is always SUSPICIOUS;
  - bugs in a framework's weight or tensor parsers;
  - ways of telling the emulator apart from real execution that the LIMITATIONS section already names.
- **Deep mode (`--deep`).** It runs real loaders in a container or jail by design.
- **False positives.** Please report them as normal issues.

## Every bypass becomes a regression test

A confirmed bypass is fixed together with a test that rebuilds it with a harmless marker payload. The test goes in `tests/test_audit_regressions.py` or in the lab corpus (`tests/corpus/build_corpus.py`) and stays there. A fix without that test is not merged. The changelog entry for the fix names the report or CVE.

## How the project handles untrusted files

These rules apply to anyone working on the project:
- **No file under test is ever deserialized on the host.** Tests and evaluation runs use a host-execution guard (`tests/conftest.py`, `evaluation/guard.py`).
- **Payloads are markers only.**
- **Downloaded models are never committed.**
