"""The full comparison with other scanners, for coordinated disclosure: written only to a
git-ignored directory.

    python evaluation/private_comparison.py FULL.json [FULL.json ...] --out private/eval-080/comparison

The public results carry one "all files" table (``redact_results.py``). This writes the
tables that are withheld until coordinated disclosure with the affected projects is
complete, ready to publish unchanged afterwards:

* three variants per group and per format: all files; files in a format that scanner
  supports; the common subset every scanner supports;
* detection per lab and mutation technique (the manifest category);
* the files each scanner lets through (CLEAN on a malicious file), with the reason class.

Input: unredacted ``run_eval.py`` results (per-file results of every tool). Support is
decided from the format safeloadai detected in the bytes and the file extension, by the
scanners' documented coverage (the same matrix as ``third_party_misses.py``); a scanner's
own "clean" on a format it does not read is not support.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict

OTHER = ("picklescan", "fickling", "modelscan")
MODELSCAN_TORCH_EXT = {".bin", ".pt", ".pth", ".ckpt"}
MODELSCAN_PICKLE_EXT = {".pkl", ".pickle", ".joblib", ".dill", ".dat", ".data"}


def supported(tool: str, entry: dict) -> bool:
    """Does ``tool`` analyse the reading a loader makes of this file?"""
    fmt = (entry["results"].get("safeloadai") or {}).get("file_format") or entry.get("format")
    ext = os.path.splitext(entry["file"])[1].lower()
    if fmt in ("h5", "hdf5", "keras", "unknown", None):
        return False
    if fmt == "joblib":  # a compressed joblib container; a plain joblib file is detected as pickle
        return False
    if tool in ("picklescan", "fickling"):
        if fmt in ("torch", "zip"):
            return tool == "picklescan"
        return fmt == "pickle"
    if ext in MODELSCAN_TORCH_EXT or fmt in ("torch", "zip"):
        return True
    return ext in MODELSCAN_PICKLE_EXT and fmt == "pickle"


def outcome(entry: dict, tool: str) -> str | None:
    result = entry["results"].get(tool)
    if result is None:
        return None
    if tool == "safeloadai":
        if result.get("outcome") == "error":
            return "error"
        return {"CLEAN": "clean", "UNSUPPORTED": "unsupported"}.get(result.get("verdict"), "positive")
    return {"flagged": "positive"}.get(result.get("outcome"), result.get("outcome"))


def counts(entries: list[dict], tool: str) -> Counter:
    c = Counter()
    for e in entries:
        got = outcome(e, tool)
        if got is None or e["label"] not in ("malicious", "benign"):
            continue
        c[e["label"]] += 1
        if got == "positive":
            c["detected" if e["label"] == "malicious" else "fp"] += 1
        elif got in ("error", "unsupported", "skipped"):
            c[got] += 1
    return c


def row(name: str, entries: list[dict], tools: list[str]) -> list[str]:
    out = []
    for tool in tools:
        c = counts(entries, tool)
        out.append(f"| {name} | {tool} | {c['detected']} / {c['malicious']} | {c['fp']} / {c['benign']} | "
                   f"{c['error']} | {c['unsupported']} | {c['skipped']} |")
    return out


HEAD = ["| set | tool | detected / malicious | FP / benign | errors | unsupported | skipped |",
        "|---|---|---|---|---|---|---|"]


def variant(title: str, entries: list[dict], tools: list[str], pick) -> list[str]:
    lines = ["", f"## {title}", ""]
    groups = defaultdict(list)
    for e in entries:
        groups[e["group"]].append(e)
    lines += ["### per group", "", *HEAD]
    for tool in tools:
        for group, rows in groups.items():
            lines += row(group, [e for e in rows if pick(tool, e)], [tool])
    lines += ["", "### per format", "", *HEAD]
    formats = sorted({e.get("format") or "-" for e in entries})
    for tool in tools:
        for fmt in formats:
            chosen = [e for e in entries if (e.get("format") or "-") == fmt and pick(tool, e)]
            if chosen:
                lines += row(fmt, chosen, [tool])
    return lines


def render(entries: list[dict], sources: list[str]) -> str:
    tools = ["safeloadai", *[t for t in OTHER if any(t in e["results"] for e in entries)]]
    common = [e for e in entries if all(supported(t, e) for t in tools if t != "safeloadai")]
    lines = ["# Comparison with other scanners (withheld until coordinated disclosure)", "",
             "Sources: " + ", ".join(f"`{s}`" for s in sources) + f". {len(entries)} files.", "",
             "\"supported\" follows the scanners' documented coverage, decided from the format safeloadai detected "
             "in the bytes and the extension (`evaluation/private_comparison.py: supported`)."]
    lines += variant("Variant 1: all files", entries, tools, lambda t, e: True)
    lines += variant("Variant 2: files in a format that scanner supports", entries, tools,
                     lambda t, e: t == "safeloadai" or supported(t, e))
    lines += variant("Variant 3: common subset (every scanner supports the file)", common, tools, lambda t, e: True)
    lines += ["", "## Detection per technique (lab and mutations)", "",
              "| technique | files | " + " | ".join(tools) + " |", "|---|---|" + "---|" * len(tools)]
    by_technique = defaultdict(list)
    for e in entries:
        if e["group"] in ("lab", "mutations") and e["label"] == "malicious":
            by_technique[f"{e['group']}: {e.get('category') or '-'}"].append(e)
    for technique, rows in sorted(by_technique.items()):
        lines.append(f"| {technique} | {len(rows)} | " + " | ".join(
            str(sum(1 for e in rows if outcome(e, t) == "positive")) for t in tools) + " |")
    lines += ["", "## Malicious files each scanner does not flag", ""]
    for tool in tools:
        missed = [e for e in entries if e["label"] == "malicious" and outcome(e, tool) not in (None, "positive")]
        lines += [f"### {tool}: {len(missed)}", "", "| file | group | format | outcome | format supported |",
                  "|---|---|---|---|---|"]
        lines += [f"| {e['file']} | {e['group']} | {e.get('format')} | {outcome(e, tool)} | "
                  f"{'yes' if tool == 'safeloadai' or supported(tool, e) else 'no'} |" for e in missed]
        lines.append("")
    return "\n".join(lines) + "\n"


def ignored(path: str) -> bool:
    probe = os.path.join(path, "probe")
    return subprocess.run(["git", "check-ignore", "-q", probe], cwd=os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))).returncode == 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("results", nargs="+", help="unredacted run_eval.py JSON files")
    parser.add_argument("--out", required=True, help="a git-ignored directory (for example under private/)")
    args = parser.parse_args(argv)
    out = os.path.abspath(args.out)
    if not ignored(out):
        parser.error(f"{args.out} is not git-ignored; these tables stay private until disclosure is complete")
    os.makedirs(out, exist_ok=True)
    entries, seen = [], set()
    for path in args.results:
        with open(path, encoding="utf-8") as fh:
            for e in json.load(fh)["entries"]:
                key = (e["group"], e["file"])
                if key not in seen:
                    seen.add(key)
                    entries.append(e)
    if not any(t in e["results"] for e in entries for t in OTHER):
        print("no per-file results of other scanners: pass the unredacted files", file=sys.stderr)
        return 1
    with open(os.path.join(out, "comparison.md"), "w", encoding="utf-8") as fh:
        fh.write(render(entries, [os.path.basename(p) for p in args.results]))
    print(f"wrote {os.path.join(out, 'comparison.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
