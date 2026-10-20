"""Reviewed benign files, by exact sha256 (0.7.0 Part 4).

The list (``data/known_good.tsv``, a copy of ``evaluation/known_good/known_good.tsv``)
holds files from the evaluation's tune split only, each reviewed by hand from its scan
report and the producing library, with a note. An exact sha256 match turns a SUSPICIOUS
verdict (RISKY or UNVERIFIABLE findings) into CLEAN; a MALICIOUS or UNSUPPORTED verdict is
never changed. A file that differs by one byte does not match. ``known_good=False`` /
``--no-known-good`` turns the list off. Nothing is added at run time.
"""
from __future__ import annotations

import os
from functools import cache

from .report import Report, Verdict

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "known_good.tsv")
COLUMNS = ("sha256", "repo", "revision", "file", "note")


@cache
def entries() -> dict[str, dict]:
    """sha256 -> {"sha256", "repo", "revision", "file", "note"}."""
    out: dict[str, dict] = {}
    with open(PATH, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip() or line.startswith("#"):
                continue
            fields = line.rstrip("\n").split("\t")
            if len(fields) != len(COLUMNS) or len(fields[0]) != 64:
                raise ValueError(f"malformed known_good entry: {line!r}")
            row = dict(zip(COLUMNS, fields, strict=True))
            out[row["sha256"]] = row
    return out


def apply(report: Report) -> bool:
    """Clear a SUSPICIOUS report of a listed file. Returns whether it was cleared."""
    if report.verdict is not Verdict.SUSPICIOUS:
        return False
    entry = entries().get(report.sha256)
    if entry is None:
        return False
    name = f"{entry['repo']}/{entry['file']}"
    pairs = sorted({tuple(f["pair"]) for f in report.findings if f.get("pair")})
    report.cleared.append({
        "item": name, "mechanism": "known-file",
        "detail": f"known reviewed file {name} (revision {entry['revision'][:12]}): {entry['note']}",
        "layer": "known-file", "pairs": [list(p) for p in pairs],
        "findings": report.findings, "reasons": report.reasons, "category": report.category,
    })
    report.verdict = Verdict.CLEAN
    report.reasons = [f"known reviewed file {name}"]
    report.findings = []
    report.category = None
    return True
