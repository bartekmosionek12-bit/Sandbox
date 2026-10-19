"""Before / after table from two ``run_eval.py`` results.

    python evaluation/compare_eval.py BEFORE.json AFTER.json [--out results/compare.md]

Files are matched by (source, file). The table shows, for each tool, detection
rate, false-positive rate (overall and per format), the false positives that are
UNVERIFIABLE only (safeloadai; a separate column, still counted as false positives)
and median time, and lists every file whose safeloadai verdict changed.
"""
from __future__ import annotations

import argparse
import json


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _cell(s: dict | None, key: str) -> str:
    if not s:
        return "-"
    if key == "detection":
        return f"{s['detected']}/{s['malicious']} ({s['detection_rate']})" if s["malicious"] else "-"
    if key == "fp":
        return f"{s['false_positives']}/{s['benign']} ({s['fp_rate']})" if s["benign"] else "-"
    if key == "unverifiable":
        return str(s["unverifiable_fp"]) if "unverifiable_fp" in s and s["benign"] else "-"
    return str(s.get("seconds_median"))


def compare(before: dict, after: dict) -> str:
    lines = [f"# Before / after: {before.get('label')} ({before.get('safeloadai', '?')}) vs "
             f"{after.get('label')} ({after.get('safeloadai', '?')})", "",
             "| tool | detection before | detection after | FP before | FP after | FP UNVERIFIABLE before | "
             "FP UNVERIFIABLE after | median s before | median s after |", "|---|---|---|---|---|---|---|---|---|"]
    tools = list(dict.fromkeys([*before["summary"], *after["summary"]]))
    for tool in tools:
        b, a = before["summary"].get(tool), after["summary"].get(tool)
        lines.append(f"| {tool} | {_cell(b, 'detection')} | {_cell(a, 'detection')} | {_cell(b, 'fp')} | "
                     f"{_cell(a, 'fp')} | {_cell(b, 'unverifiable')} | {_cell(a, 'unverifiable')} | "
                     f"{_cell(b, 'time')} | {_cell(a, 'time')} |")
    lines += ["", "## safeloadai per format", "",
              "| format | detection before | detection after | FP before | FP after | FP UNVERIFIABLE before | "
              "FP UNVERIFIABLE after | median s before | median s after |", "|---|---|---|---|---|---|---|---|---|"]
    bf = before["summary"]["safeloadai"].get("per_format", {})
    af = after["summary"]["safeloadai"].get("per_format", {})
    for fmt in sorted(set(bf) | set(af)):
        b, a = bf.get(fmt), af.get(fmt)
        lines.append(f"| {fmt} | {_cell(b, 'detection')} | {_cell(a, 'detection')} | {_cell(b, 'fp')} | "
                     f"{_cell(a, 'fp')} | {_cell(b, 'unverifiable')} | {_cell(a, 'unverifiable')} | "
                     f"{_cell(b, 'time')} | {_cell(a, 'time')} |")
    old = {(e["source"], e["file"]): e for e in before["entries"]}
    changed = []
    for e in after["entries"]:
        prev = old.get((e["source"], e["file"]))
        if prev is None:
            continue
        v_old = prev["results"]["safeloadai"].get("verdict", prev["results"]["safeloadai"]["outcome"])
        v_new = e["results"]["safeloadai"].get("verdict", e["results"]["safeloadai"]["outcome"])
        if v_old != v_new:
            changed.append(f"| {e['file']} | {e['label']} | {v_old} | {v_new} |")
    new_files = [e for e in after["entries"] if (e["source"], e["file"]) not in old]
    lines += ["", f"## Verdict changes ({len(changed)})", ""]
    if changed:
        lines += ["| file | label | before | after |", "|---|---|---|---|", *changed]
    else:
        lines.append("None.")
    if new_files:
        lines += ["", f"{len(new_files)} files exist only in the after run (new corpus entries)."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("before")
    parser.add_argument("after")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    text = compare(_load(args.before), _load(args.after))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
