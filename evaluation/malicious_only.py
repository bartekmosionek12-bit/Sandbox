"""Measure ``safeloadai scan --malicious-only`` from an evaluation run.

    python evaluation/malicious_only.py evaluation/results/eval-<label>-<stamp>.json [...]

``--malicious-only`` is an output mode: it prints MALICIOUS or NOT-MALICIOUS and exits 1
only for MALICIOUS (an ERROR still exits 4 or 6). The verdict does not change, so its
numbers follow from the per-file verdicts ``run_eval.py`` already records; nothing is
scanned here. For each group the table compares the default reading (any verdict other
than CLEAN blocks) with the binary one (only MALICIOUS blocks):

* detection: malicious files blocked, out of all malicious files;
* false positives: benign files blocked, out of all benign files;
* errors: files safeloadai could not scan (they exit 4 or 6 in both modes, so they are
  neither detections nor passes; listed on their own).

Files labelled ``unclear`` count in neither rate.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict


def measure(entries: list[dict]) -> dict[str, dict]:
    groups: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    for entry in entries:
        result = entry["results"]["safeloadai"]
        verdict = result.get("verdict") if result.get("outcome") != "error" else None
        for name in (entry["group"], "all"):
            row = groups[name]
            if entry["label"] not in ("malicious", "benign"):
                row["unclear"] += 1
                continue
            row[entry["label"]] += 1
            if verdict is None:
                row[f"{entry['label']}_errors"] += 1
                continue
            row[f"{entry['label']}_default"] += verdict != "CLEAN"
            row[f"{entry['label']}_binary"] += verdict == "MALICIOUS"
    return {name: dict(row) for name, row in groups.items()}


def _rate(num: int, den: int) -> str:
    return f"{num} / {den} ({100 * num / den:.1f}%)" if den else "-"


def markdown(groups: dict[str, dict], title: str) -> str:
    lines = [f"## {title}", "",
             "| group | detection, default | detection, --malicious-only | FP, default | FP, --malicious-only | "
             "errors (mal / benign) | unclear |", "|---|---|---|---|---|---|---|"]
    for name in sorted(groups, key=lambda n: (n == "all", n)):
        g = defaultdict(int, groups[name])
        lines.append(f"| {name} | {_rate(g['malicious_default'], g['malicious'])} | "
                     f"{_rate(g['malicious_binary'], g['malicious'])} | {_rate(g['benign_default'], g['benign'])} | "
                     f"{_rate(g['benign_binary'], g['benign'])} | {g['malicious_errors']} / {g['benign_errors']} | "
                     f"{g['unclear']} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("runs", nargs="+", help="run_eval.py JSON results")
    args = parser.parse_args(argv)
    for path in args.runs:
        with open(path, encoding="utf-8") as fh:
            run = json.load(fh)
        print(markdown(measure(run["entries"]), f"{run['label']} ({run['created']}, safeloadai {run['safeloadai']})"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
