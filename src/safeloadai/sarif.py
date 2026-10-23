"""SARIF 2.1.0 output for ``safeloadai scan --sarif FILE`` (0.8.0).

One result per file that is not CLEAN, so a code-scanning view (GitHub, GitLab, an
IDE) shows each blocked model file once, with its verdict and its first reasons:

* ``safeloadai/malicious``: MALICIOUS (level ``error``);
* ``safeloadai/error``: safeloadai could not scan the file (level ``error``; an ERROR
  is never a pass);
* ``safeloadai/suspicious``: SUSPICIOUS with a RISKY reason (level ``warning``);
* ``safeloadai/unverifiable``: SUSPICIOUS, every reason UNVERIFIABLE; an accepted
  override is recorded as an external suppression, never dropped (level ``warning``);
* ``safeloadai/unsupported``: in no format safeloadai reads (level ``warning``).

CLEAN files produce no result. The SARIF file is an output format only: the verdicts,
the exit code and ``safe_load`` are the same with or without it.
"""
from __future__ import annotations

import os
from pathlib import Path

from . import __version__
from .report import Report, Verdict

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/bartekmosionek12-bit/Sandbox"
MAX_FINDINGS = 20

# id: (short description, level, GitHub security-severity, help)
RULES = {
    "safeloadai/malicious": (
        "Model file is MALICIOUS", "error", "9.8",
        "safeloadai found evidence that loading this file runs attacker-controlled code (a known sink, "
        "a recorded dangerous behaviour, or tampering). Do not load it."),
    "safeloadai/error": (
        "safeloadai could not scan the model file", "error", "7.0",
        "safeloadai failed on this file (the error code is in the message; see docs/ERRORS.md). "
        "The file was not judged safe and safe_load refuses it."),
    "safeloadai/suspicious": (
        "Model file is SUSPICIOUS", "warning", "7.0",
        "The file has behaviour or structure safeloadai refuses (RISKY). safe_load refuses it; "
        "no override exists for a RISKY reason."),
    "safeloadai/unverifiable": (
        "Model file references code safeloadai cannot verify", "warning", "5.0",
        "Every reason is UNVERIFIABLE: the file names objects whose code safeloadai cannot see. "
        "An informed, per-file override (--accept-unverified) is possible; see docs/OPTIONS.md."),
    "safeloadai/unsupported": (
        "Model file is in no format safeloadai reads", "warning", "5.0",
        "Nothing was analysed, so the file is not CLEAN and safe_load refuses it."),
}


def rule_of(report: Report) -> str | None:
    if not report.ok:
        return "safeloadai/error"
    if report.verdict is Verdict.MALICIOUS:
        return "safeloadai/malicious"
    if report.verdict is Verdict.UNSUPPORTED:
        return "safeloadai/unsupported"
    if report.verdict is Verdict.SUSPICIOUS:
        return "safeloadai/unverifiable" if report.unverifiable_only else "safeloadai/suspicious"
    return None


def _uri(path: str, base: str) -> tuple[str, str | None]:
    """(uri, uriBaseId): relative to ``base`` when the file is under it, else a file URI."""
    absolute = os.path.abspath(path)
    try:
        rel = os.path.relpath(absolute, base)
    except ValueError:  # another drive on Windows
        rel = None
    if rel is None or rel == os.pardir or rel.startswith(os.pardir + os.sep):
        return Path(absolute).as_uri(), None
    return rel.replace(os.sep, "/"), "%SRCROOT%"


def _message(report: Report) -> str:
    if not report.ok:
        return f"ERROR {report.error['code']}: {report.error['message']}"
    lines = [f"{report.verdict.value} ({report.file_format}, sha256 {report.sha256})"]
    lines += [f"[{f['category']}] {f['text']}" for f in report.findings[:MAX_FINDINGS]]
    if len(report.findings) > MAX_FINDINGS:
        lines.append(f"... and {len(report.findings) - MAX_FINDINGS} more reasons (see the Report JSON)")
    return "\n".join(lines)


def _result(report: Report, base: str) -> dict | None:
    rule = rule_of(report)
    if rule is None:
        return None
    uri, base_id = _uri(report.path, base)
    location = {"uri": uri, **({"uriBaseId": base_id} if base_id else {})}
    result = {
        "ruleId": rule,
        "ruleIndex": list(RULES).index(rule),
        "level": RULES[rule][1],
        "message": {"text": _message(report)},
        "locations": [{"physicalLocation": {"artifactLocation": location, "region": {"startLine": 1}}}],
        # model files are binary: the file's hash identifies the result across runs
        "partialFingerprints": {"safeloadaiFile/v1": f"{report.sha256}:{rule}"},
        "properties": {"verdict": report.outcome, "sha256": report.sha256, "fileFormat": report.file_format,
                       "category": report.category,
                       "options": [o["name"] for o in report.options]},
    }
    if not report.ok:
        result["properties"]["errorCode"] = report.error["code"]
    if report.accepted and not report.clean:
        items = ", ".join(report.override.get("items", []))
        result["suppressions"] = [{"kind": "external", "status": "accepted",
                                   "justification": f"--accept-unverified for this file's sha256: {items}"}]
    return result


def to_sarif(reports: list[Report], base: str | None = None) -> dict:
    """The SARIF log for ``reports``. ``base`` (default: the current directory) is
    %SRCROOT%: paths under it are written relative to it."""
    base = os.path.abspath(base or os.getcwd())
    rules = [{"id": rule_id, "name": rule_id.split("/")[1].capitalize(),
              "shortDescription": {"text": short}, "fullDescription": {"text": text},
              "help": {"text": text}, "defaultConfiguration": {"level": level},
              "properties": {"tags": ["security", "model-file"], "security-severity": severity}}
             for rule_id, (short, level, severity, text) in RULES.items()]
    results = [r for r in (_result(report, base) for report in reports) if r is not None]
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "safeloadai", "version": __version__, "semanticVersion": __version__,
                                "informationUri": INFORMATION_URI, "rules": rules}},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": Path(base).as_uri() + "/"}},
            "results": results,
            "invocations": [{"executionSuccessful": all(r.ok for r in reports)}],
            "properties": {"filesScanned": len(reports)},
        }],
    }
