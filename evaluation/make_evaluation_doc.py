"""Write docs/EVALUATION.md from an evaluation result file (run_eval.py's JSON).

Every number in the page comes from the JSON; nothing is typed by hand.

    python evaluation/make_evaluation_doc.py                                  # the default result file
    python evaluation/make_evaluation_doc.py evaluation/results/eval-v070-20261020T063605Z.json
    python evaluation/make_evaluation_doc.py --check                          # exit 1 if the page is stale

Definitions (also stated in the page):

* A file's prediction is **positive** when the tool blocks it for a reason about the file:
  for safeloadai SUSPICIOUS or MALICIOUS, for another scanner "flagged".
* **UNSUPPORTED** (the tool reads no format in the file) and **ERROR** (the tool failed)
  are counted in their own columns. They are never a detection and never a miss, and
  they are left out of precision, recall and FPR.
* TP: malicious and positive. FN: malicious and CLEAN. FP: benign and positive.
  TN: benign and CLEAN. Files labelled "unclear" are counted apart.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RESULT = os.path.join(ROOT, "evaluation", "results", "eval-v070-20261020T063605Z.json")
OUT = os.path.join(ROOT, "docs", "EVALUATION.md")
SPLITS = os.path.join(ROOT, "evaluation", "splits")
GROUP_ORDER = ("lab", "mutations", "hf-malicious", "hf-tune", "hf-heldout")
GROUP_TEXT = {
    "lab": "Lab corpus: marker payloads and benign controls built by `tests/corpus/build_corpus.py`",
    "mutations": "Mutations of the lab payloads (encodings, containers, nesting) by `tests/corpus/mutate.py`",
    "hf-malicious": "Hub files the Hub's own scanners flag (`evaluation/fetch_malicious_hf.py`)",
    "hf-tune": "Benign Hub corpus, tune half (the only half the allowlist reviews looked at)",
    "hf-heldout": "Benign Hub corpus, held-out half (never looked at while tuning)",
}
LABEL_ORIGIN = {
    "lab": "by construction (we wrote the payload or the benign control)",
    "mutations": "by construction (a mutation keeps its source file's label)",
    "hf-malicious": "Hub scanner evidence plus manual review of that evidence (`evaluation/hf_malicious_labels.tsv`); "
                    "never safeloadai's verdict",
    "hf-tune": "benign by selection (popular repositories of known libraries); files the Hub flags were reviewed "
               "by hand and relabelled",
    "hf-heldout": "same as hf-tune",
}
POSITIVE = {"SUSPICIOUS", "MALICIOUS"}


def wilson(k: int, n: int, z: float = 1.96) -> str:
    """95 % Wilson score interval of k/n, as "[lo, hi]"."""
    if n == 0:
        return "-"
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return f"[{max(0.0, centre - half):.3f}, {min(1.0, centre + half):.3f}]"


def ratio(k: int, n: int) -> str:
    return f"{k / n:.3f}" if n else "-"


def rate(k: int, n: int) -> str:
    """k/n with its interval, or "-" when there is nothing to measure."""
    return f"{ratio(k, n)} {wilson(k, n)}" if n else "-"


def outcome(result: dict, own: bool) -> str:
    """positive / clean / unsupported / error / skipped for one tool's result on one file."""
    if own:
        if result.get("outcome") == "error" or result.get("block") == "error":
            return "error"
        verdict = result.get("verdict")
        if verdict == "UNSUPPORTED":
            return "unsupported"
        if verdict == "CLEAN":
            return "clean"
        return "positive" if verdict in POSITIVE else "error"
    value = result.get("outcome", "error")
    return {"flagged": "positive"}.get(value, value)


def matrix(entries: list[dict], tool: str) -> dict:
    own = tool == "safeloadai"
    m = Counter()
    for entry in entries:
        result = entry["results"].get(tool)
        if result is None:
            continue
        got = outcome(result, own)
        label = entry["label"]
        if label == "unclear":
            m["unclear_" + ("positive" if got == "positive" else "other")] += 1
        elif got in ("unsupported", "error", "skipped"):
            m[f"{label}_{got}"] += 1
        elif label == "malicious":
            m["tp" if got == "positive" else "fn"] += 1
        else:
            m["fp" if got == "positive" else "tn"] += 1
    return m


def matrix_row(name: str, m: Counter) -> str:
    tp, fn, fp, tn = m["tp"], m["fn"], m["fp"], m["tn"]
    unsupported = m["malicious_unsupported"] + m["benign_unsupported"]
    errors = m["malicious_error"] + m["benign_error"]
    skipped = m["malicious_skipped"] + m["benign_skipped"]
    return (f"| {name} | {tp} | {fn} | {fp} | {tn} | {ratio(tp, tp + fp)} | {rate(tp, tp + fn)} | "
            f"{rate(fp, fp + tn)} | {unsupported} | {errors} | {skipped} |")


MATRIX_HEAD = ("| {first} | TP | FN | FP | TN | precision | recall [95 % CI] | FPR [95 % CI] | UNSUPPORTED | "
               "ERROR | skipped |\n|---|---|---|---|---|---|---|---|---|---|---|")


def by_group(entries: list[dict]) -> dict[str, list[dict]]:
    groups = defaultdict(list)
    for entry in entries:
        groups[entry["group"]].append(entry)
    return {g: groups[g] for g in GROUP_ORDER if g in groups}


def split_repos() -> dict[str, int]:
    out = {}
    for name in ("hf-tune", "hf-heldout"):
        path = os.path.join(SPLITS, f"{name}.txt")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                out[name] = sum(1 for line in fh if line.strip() and not line.startswith("#"))
    return out


def render(data: dict, source: str) -> str:
    entries = data["entries"]
    tools = [t for t in data["tools"] if not t.startswith("safeloadai")]
    groups = by_group(entries)
    lines = [
        "# Evaluation",
        "",
        f"<!-- Generated by evaluation/make_evaluation_doc.py from {source}. Do not edit by hand. -->",
        "",
        f"Numbers from `{source}`: safeloadai {data['safeloadai']}, Python {data['python']}, "
        f"{data['platform']}, {len(entries)} files, run {data['created']}. Every number on this page is "
        "generated from that file by `evaluation/make_evaluation_doc.py`; CI checks that the page is current.",
        "",
        "## How to read the numbers",
        "",
        "- **Positive** means the tool blocks the file for a reason about the file: SUSPICIOUS or MALICIOUS for "
        "safeloadai, \"flagged\" for the other scanners.",
        "- **UNSUPPORTED** (the tool reads no format in the file) and **ERROR** (the tool itself failed; "
        "[ERRORS.md](ERRORS.md)) have their own columns. They are never a detection and never a miss, and they are "
        "left out of precision, recall and FPR. \"skipped\" is a file a scanner chose not to open.",
        "- **TP** malicious and positive, **FN** malicious and CLEAN (a miss), **FP** benign and positive, **TN** "
        "benign and CLEAN. Files whose label is unclear are counted apart.",
        "- precision = TP / (TP + FP), recall = TP / (TP + FN), FPR = FP / (FP + TN). The intervals are 95 % "
        "Wilson score intervals: with a few dozen files per cell they are wide, and they say so.",
        "- safeloadai runs with its defaults (no options, the shipped known-file list on).",
        "",
        "## Data",
        "",
        "### Where the files come from",
        "",
        "| group | what it is | how the label was decided | malicious | benign | unclear |",
        "|---|---|---|---|---|---|",
    ]
    for group, rows in groups.items():
        labels = Counter(e["label"] for e in rows)
        lines.append(f"| {group} | {GROUP_TEXT.get(group, group)} | {LABEL_ORIGIN.get(group, '-')} | "
                     f"{labels['malicious']} | {labels['benign']} | {labels['unclear']} |")
    total = Counter(e["label"] for e in entries)
    lines.append(f"| **all** | | | **{total['malicious']}** | **{total['benign']}** | **{total['unclear']}** |")

    formats = sorted({e["format"] for e in entries})
    lines += ["", "### Files per group and format", "",
              "| group | " + " | ".join(formats) + " | total |", "|---|" + "---|" * (len(formats) + 1)]
    for group, rows in groups.items():
        count = Counter(e["format"] for e in rows)
        lines.append(f"| {group} | " + " | ".join(str(count[f]) for f in formats) + f" | {len(rows)} |")

    hub = [e for e in entries if e["group"] in ("hf-tune", "hf-heldout")]
    if hub:
        libraries = sorted({e.get("library") or "-" for e in hub})
        lines += ["", "### Benign Hub files per library stratum", "",
                  "| stratum | hf-tune | hf-heldout |", "|---|---|---|"]
        for lib in libraries:
            tune = sum(1 for e in hub if (e.get("library") or "-") == lib and e["group"] == "hf-tune")
            held = sum(1 for e in hub if (e.get("library") or "-") == lib and e["group"] == "hf-heldout")
            lines.append(f"| {lib} | {tune} | {held} |")

    own_made = sum(1 for e in entries if e["label"] == "malicious" and e["group"] in ("lab", "mutations"))
    lines += [
        "",
        "### An honest note on the malicious side",
        "",
        f"{own_made} of the {total['malicious']} malicious files ({ratio(own_made, total['malicious'])}) are our own "
        "lab payloads and their mutations. They are built to cover every technique we know of (public scanner "
        "bypasses rebuilt with marker payloads, every pickle encoding, every container), so they measure coverage "
        "of known techniques, not how often real attacks are caught. The real-world malicious files are the Hub "
        "files the Hub's scanners flag; there are few, many are proofs of concept rather than attacks, and their "
        "labels come from the Hub's evidence, not from ground truth. A recall of 1.0 on this corpus is therefore "
        "not a claim that safeloadai catches every attack: it says no file in this corpus got through.",
    ]

    repos = split_repos()
    lines += [
        "",
        "### Tune and held-out split (overfitting)",
        "",
        "The benign Hub corpus is split in two by a hash of the repository id "
        "(`evaluation/fetch_benign_hf.py: split_of`), so every file of one repository is on the same side and a "
        "repository's sibling files cannot leak into the other half. Allowlist reviews, policies, profiles and the "
        "known-file list were built from the tune half only (`evaluation/splits/hf-tune.txt`). The held-out half "
        "(`evaluation/splits/hf-heldout.txt`) is the false-positive rate we report. A large gap between the two "
        "FPRs is what overfitting to the tune half looks like.",
        "",
        "| split | repositories | files | benign | FPR (safeloadai) [95 % CI] |",
        "|---|---|---|---|---|",
    ]
    for group in ("hf-tune", "hf-heldout"):
        rows = groups.get(group, [])
        m = matrix(rows, "safeloadai")
        lines.append(f"| {group} | {repos.get(group, '-')} | {len(rows)} | "
                     f"{sum(1 for e in rows if e['label'] == 'benign')} | {rate(m['fp'], m['fp'] + m['tn'])} |")

    lines += ["", "## Confusion matrix per group", "",
              "Precision depends on each group's mix of malicious and benign files. The benign Hub groups hold "
              "only a handful of malicious files, so their precision says little; read their FPR. The lab, "
              "mutation and hf-malicious groups are mostly malicious; read their recall.", "",
              "### all labelled files", "", MATRIX_HEAD.format(first="tool")]
    for tool in ["safeloadai", *tools]:
        lines.append(matrix_row(tool, matrix(entries, tool)))
    lines.append("")
    for group, rows in groups.items():
        lines += [f"### {group}", "", MATRIX_HEAD.format(first="tool")]
        for tool in ["safeloadai", *tools]:
            lines.append(matrix_row(tool, matrix(rows, tool)))
        unclear = matrix(rows, "safeloadai")
        if unclear["unclear_positive"] or unclear["unclear_other"]:
            lines.append("")
            lines.append(f"Unclear labels in this group: {unclear['unclear_positive'] + unclear['unclear_other']} "
                         f"(safeloadai positive on {unclear['unclear_positive']}).")
        lines.append("")

    lines += ["## safeloadai per group and format", "", MATRIX_HEAD.format(first="group / format")]
    for group, rows in groups.items():
        for fmt in sorted({e["format"] for e in rows}):
            lines.append(matrix_row(f"{group} / {fmt}", matrix([e for e in rows if e["format"] == fmt],
                                                                "safeloadai")))

    blocks = Counter(e["results"]["safeloadai"].get("block") for e in entries
                     if e["label"] == "benign" and e["group"] == "hf-heldout")
    held = sum(blocks.values())
    lines += [
        "",
        "## What a user meets on held-out benign files",
        "",
        "A false positive is not one thing. A *soft block* has only UNVERIFIABLE reasons and can be accepted "
        "item by item for that file; a *hard block* has a RISKY or MALICIOUS reason and cannot.",
        "",
        "| CLEAN | soft block | hard block | UNSUPPORTED | ERROR | total |",
        "|---|---|---|---|---|---|",
        f"| {blocks['clean']} | {blocks['soft']} | {blocks['hard']} | {blocks['unsupported']} | {blocks['error']} | "
        f"{held} |",
        "",
        "## Limits of this evaluation",
        "",
        "- The other scanners are measured on every file here, including formats they do not read; their "
        "UNSUPPORTED, ERROR and skipped columns show that part. A comparison restricted to the formats each tool "
        "supports is a separate table (planned for 0.8.0).",
        "- Model backdoors and poisoned weights (OWASP LLM04) are not measured: a file scanner cannot see them "
        "([THREAT_MODEL.md](THREAT_MODEL.md)).",
        "- Regenerate this page after a new run: `python evaluation/make_evaluation_doc.py RESULT.json`.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("result", nargs="?", default=DEFAULT_RESULT, help="run_eval.py JSON")
    parser.add_argument("--out", default=OUT)
    parser.add_argument("--check", action="store_true", help="exit 1 if --out differs from what would be written")
    args = parser.parse_args(argv)
    with open(args.result, encoding="utf-8") as fh:
        data = json.load(fh)
    text = render(data, os.path.relpath(args.result, ROOT).replace(os.sep, "/"))
    if args.check:
        current = open(args.out, encoding="utf-8").read() if os.path.exists(args.out) else ""
        if current != text:
            print(f"{args.out} is stale: run python evaluation/make_evaluation_doc.py", file=sys.stderr)
            return 1
        return 0
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
