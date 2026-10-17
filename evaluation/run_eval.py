"""Evaluate safeloadai against the lab corpus and benign model files, and compare
with other scanners (modelscan, picklescan, Fickling) when they are installed.

    python evaluation/run_eval.py --lab DIR [--benign DIR ...] [--tool-bin DIR] [--out DIR]

``--lab`` is a directory written by ``tests/corpus/build_corpus.py`` (it has a
manifest.json). Every model file under a ``--benign`` directory counts as benign.
Other scanners are run as command-line tools on the same files; none of them is
asked to load a model. Results go to ``<out>/eval-<UTC timestamp>.json`` and a
Markdown summary next to it.

"Detected" means any verdict other than CLEAN. For other tools, an error or an
unsupported file is counted separately and is not a detection.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from safeloadai import scan  # noqa: E402
from safeloadai.parsing.detect import EXTENSION_HINTS  # noqa: E402

MODEL_EXTENSIONS = tuple(EXTENSION_HINTS)
TOOL_TIMEOUT_S = 300
ERROR_MARKERS = ("Traceback", "NotImplementedError", "Parsing errors", "Error:")

# tool -> (argv prefix, exit code -> outcome). Outcomes: clean, flagged, error, unsupported.
TOOLS = {
    "picklescan": (["picklescan", "--path"], {0: "clean", 1: "flagged"}),
    "fickling": (["fickling", "--check-safety"], {0: "clean", 1: "flagged"}),
    "modelscan": (["modelscan", "-p"], {0: "clean", 1: "flagged", 2: "error", 3: "unsupported"}),
}


def _files(directory: str) -> list[str]:
    found = []
    for root, dirs, names in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        found.extend(os.path.join(root, n) for n in sorted(names) if n.lower().endswith(MODEL_EXTENSIONS))
    return found


def load_entries(lab: str | None, benign: list[str]) -> list[dict]:
    entries = []
    if lab:
        with open(os.path.join(lab, "manifest.json"), encoding="utf-8") as fh:
            for item in json.load(fh):
                entries.append(dict(item, path=os.path.join(lab, item["file"]), source="lab"))
    for directory in benign:
        for path in _files(directory):
            entries.append({"file": os.path.relpath(path, directory), "path": path, "label": "benign",
                            "category": "benign_external", "expected": "CLEAN",
                            "source": os.path.basename(os.path.normpath(directory))})
    return entries


def run_safeloadai(path: str) -> dict:
    started = time.perf_counter()
    try:
        report = scan(path)
    except Exception as exc:  # noqa: BLE001 - a crash is a result to report
        return {"outcome": "error", "error": f"{type(exc).__name__}: {exc}",
                "seconds": time.perf_counter() - started}
    layers = {layer.name: layer.verdict.value for layer in report.layers}
    return {"outcome": "clean" if report.clean else "flagged", "verdict": report.verdict.value,
            "layers": layers, "timings_ms": report.timings_ms, "reasons": report.reasons[:5],
            "seconds": time.perf_counter() - started}


def run_tool(name: str, path: str, tool_bin: str | None) -> dict:
    argv, codes = TOOLS[name]
    exe = os.path.join(tool_bin, argv[0]) if tool_bin else shutil.which(argv[0])
    started = time.perf_counter()
    try:
        with tempfile.TemporaryDirectory() as scratch:  # fickling writes safety_results.json to the cwd
            proc = subprocess.run([exe, *argv[1:], os.path.abspath(path)], capture_output=True, text=True,
                                  timeout=TOOL_TIMEOUT_S, cwd=scratch)
    except subprocess.TimeoutExpired:
        return {"outcome": "error", "error": "timeout", "seconds": TOOL_TIMEOUT_S}
    output = ((proc.stdout or "") + (proc.stderr or "")).replace(os.path.dirname(path) + os.sep, "")
    outcome = codes.get(proc.returncode, "error")
    if outcome == "flagged" and name == "fickling" and any(m in output for m in ERROR_MARKERS):
        outcome = "error"  # fickling exits 1 for parse failures too
    return {"outcome": outcome, "exit_code": proc.returncode, "seconds": time.perf_counter() - started,
            "output_tail": output.strip()[-300:]}


def available_tools(tool_bin: str | None) -> list[str]:
    found = []
    for name, (argv, _codes) in TOOLS.items():
        exe = os.path.join(tool_bin, argv[0]) if tool_bin else shutil.which(argv[0])
        if exe and os.path.exists(exe):
            found.append(name)
    return found


def _rate(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def _percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(q * len(ordered)))], 4)


def summarise(entries: list[dict], tools: list[str]) -> dict:
    summary = {}
    for tool in ["safeloadai", *tools]:
        rows = [(e, e["results"][tool]) for e in entries]
        mal = [(e, r) for e, r in rows if e["label"] == "malicious"]
        ben = [(e, r) for e, r in rows if e["label"] == "benign"]
        tp = sum(r["outcome"] == "flagged" for _, r in mal)
        fp = sum(r["outcome"] == "flagged" for _, r in ben)
        seconds = [r["seconds"] for _, r in rows]
        summary[tool] = {
            "malicious": len(mal), "benign": len(ben), "detected": tp,
            "detection_rate": _rate(tp, len(mal)), "false_positives": fp, "fp_rate": _rate(fp, len(ben)),
            "errors": sum(r["outcome"] == "error" for _, r in rows),
            "unsupported": sum(r["outcome"] == "unsupported" for _, r in rows),
            "seconds_median": round(statistics.median(seconds), 4) if seconds else None,
            "seconds_p95": _percentile(seconds, 0.95), "seconds_max": round(max(seconds), 4) if seconds else None,
        }

    rank = {"CLEAN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
    contribution = {"static_only": 0, "emulation_only": 0, "both": 0, "neither": 0}
    strict = 0
    per_category: dict[str, dict] = {}
    for e in entries:
        r = e["results"]["safeloadai"]
        if e["label"] != "malicious" or r["outcome"] == "error":
            continue
        layers = r.get("layers", {})
        s, m = layers.get("static") != "CLEAN", layers.get("emulation") != "CLEAN"
        contribution["both" if s and m else "static_only" if s else "emulation_only" if m else "neither"] += 1
        strict += rank.get(r.get("verdict"), 0) >= rank[e["expected"]]
        cat = per_category.setdefault(e["category"], {"total": 0, "detected": 0})
        cat["total"] += 1
        cat["detected"] += r["outcome"] == "flagged"
    summary["safeloadai"].update(layer_contribution=contribution, reached_expected_severity=strict,
                                 per_category=per_category)
    return summary


def markdown(summary: dict, entries: list[dict], tools: list[str]) -> str:
    lines = ["| tool | detected / malicious | false positives / benign | errors | unsupported | median s | p95 s |",
             "|---|---|---|---|---|---|---|"]
    for tool, s in summary.items():
        lines.append(f"| {tool} | {s['detected']} / {s['malicious']} | {s['false_positives']} / {s['benign']} | "
                     f"{s['errors']} | {s['unsupported']} | {s['seconds_median']} | {s['seconds_p95']} |")
    c = summary["safeloadai"]["layer_contribution"]
    lines += ["", "safeloadai layer contribution on malicious files: "
              f"static only {c['static_only']}, emulation only {c['emulation_only']}, both {c['both']}, "
              f"neither {c['neither']}.", "", "| file | label | expected | safeloadai | " + " | ".join(tools) + " |",
              "|---|---|---|---|" + "---|" * len(tools)]
    for e in entries:
        res = e["results"]
        cells = [res["safeloadai"].get("verdict", res["safeloadai"]["outcome"])] + [res[t]["outcome"] for t in tools]
        lines.append(f"| {e['file']} | {e['label']} | {e['expected']} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--lab", help="lab corpus directory (with manifest.json)")
    parser.add_argument("--benign", action="append", default=[], help="directory of benign model files")
    parser.add_argument("--tool-bin", help="directory holding the other scanners' executables")
    parser.add_argument("--tools", help="comma-separated subset of: " + ",".join(TOOLS))
    parser.add_argument("--out", default=os.path.join(ROOT, "evaluation", "results"))
    args = parser.parse_args(argv)
    if not args.lab and not args.benign:
        parser.error("give --lab and/or --benign")

    tools = available_tools(args.tool_bin)
    if args.tools:
        tools = [t for t in args.tools.split(",") if t in tools]
    entries = load_entries(args.lab, args.benign)
    for i, entry in enumerate(entries, 1):
        entry["results"] = {"safeloadai": run_safeloadai(entry["path"])}
        for tool in tools:
            entry["results"][tool] = run_tool(tool, entry["path"], args.tool_bin)
        print(f"[{i}/{len(entries)}] {entry['file']}: "
              + ", ".join(f"{k}={v.get('verdict', v['outcome'])}" for k, v in entry["results"].items()),
              file=sys.stderr)

    summary = summarise(entries, tools)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    os.makedirs(args.out, exist_ok=True)
    result = {"created": stamp, "python": sys.version.split()[0], "tools": tools, "summary": summary,
              "entries": [{k: v for k, v in e.items() if k != "path"} for e in entries]}
    json_path = os.path.join(args.out, f"eval-{stamp}.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    md_path = os.path.join(args.out, f"eval-{stamp}.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(markdown(summary, entries, tools))
    print(json.dumps(summary, indent=2))
    print(f"wrote {json_path} and {md_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
