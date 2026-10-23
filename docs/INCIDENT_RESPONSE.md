# Incident response: a confirmed bypass

The maintainers' checklist when a report (or our own review) shows that safeloadai
gives a released version's users a wrong verdict: a hostile file CLEAN, code run during
a scan, a sandbox escape. Timelines and severity are in [SECURITY.md](../SECURITY.md).
Copy this list into the private advisory's description and tick it off there.

Nothing in this process is public until step 8. Do not open issues, public pull
requests or public branches about it, and do not mention it in public commit messages.

## 1. Acknowledge and contain (within 72 hours)

- [ ] Reply to the reporter: received, who handles it, next update by when.
- [ ] Open a **draft GitHub Security Advisory** on the repository (Security → Advisories
      → New draft security advisory) if the report did not arrive as one. Add the
      reporter as a collaborator on it.
- [ ] Reproduce with a **harmless marker payload only** (`echo MARKER`,
      `/tmp/safeloadai_marker`, `127.0.0.1`), with the host-execution guard on. Confirm
      what the documented loader does **only inside deep mode's isolation**, never on
      the host.

## 2. Triage (within 7 days)

- [ ] Affected versions: run the reproduction against each released version still on
      PyPI (`pip install safeloadai==X` in a throwaway venv; scan only).
- [ ] Severity: CVSS 4.0 base vector and score, written into the draft advisory.
- [ ] Root cause in one sentence; other files that share it (search the lab and
      mutation corpus, and think about sibling techniques).
- [ ] Tell the reporter: confirmed, severity, planned release date.

## 3. Private fix branch

- [ ] In the draft advisory, **Start a temporary private fork** and work there (or a
      private branch the reporter cannot see if the reporter should not get access).
- [ ] The fix, as small as possible, fail-closed: when unsure, make the construct
      SUSPICIOUS (RISKY), never CLEAN.

## 4. Regression test

- [ ] A test that rebuilds the bypass with a marker payload, in
      `tests/test_audit_regressions.py` or a dedicated file, and in the lab corpus
      (`tests/corpus/build_corpus.py`) so the evaluation measures it from now on.
- [ ] The test fails on the unfixed code and passes on the fix.
- [ ] Full suite green; evaluation on the lab and mutation corpus shows no new miss
      and the Hub held-out false positives did not jump (`evaluation/compare_eval.py`).

## 5. Release

- [ ] Version bump (patch release for the supported minor versions) and a CHANGELOG
      entry under **Security** that names the GHSA (the CVE once assigned), without
      exploit details beyond what users need.
- [ ] Merge the private fork into `main` from the advisory page.
- [ ] Release with [RELEASING.md](RELEASING.md) (environment reviewer approves; PEP 740
      attestations generated).
- [ ] Verify in a clean venv: `pip install -U safeloadai`, `safeloadai --version`,
      `safeloadai doctor`, the reproduction is now blocked.

## 6. Advisory and CVE

- [ ] Fill in the draft advisory: affected range (`>= first, < fixed`), patched
      versions, CVSS 4.0 vector, CWE (usually CWE-502 and CWE-693), impact,
      workarounds, credit.
- [ ] **Request a CVE ID** from the draft advisory (GitHub is a CNA). Wait for it
      before publishing if it is close; otherwise publish and the CVE follows.
- [ ] Publish the advisory.

## 7. OSV and other databases

- [ ] Within a day or two, check that `https://osv.dev/vulnerability/GHSA-xxxx-xxxx-xxxx`
      exists and that its affected range for PyPI `safeloadai` is right.
- [ ] Check `pip-audit` on a venv with an affected version reports it.
- [ ] If OSV does not have it after a week, open a pull request to the PyPA advisory
      database (<https://github.com/pypa/advisory-database>) with the GHSA as alias.

## 8. Communicate and close

- [ ] GitHub Release for the fixed version links the advisory.
- [ ] Consider yanking the affected versions on PyPI (yank keeps them installable by
      exact pin; it is not a delete). Ask the owner first: it cannot be undone silently.
- [ ] Thank the reporter; agree on the date they may publish their write-up.
- [ ] Short post-mortem in the advisory or `DECISIONS.md`: why the rule missed it,
      what class of files the fix covers, what else was checked.
