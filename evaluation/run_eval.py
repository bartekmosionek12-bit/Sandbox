"""Evaluate safeloadai against the lab corpus and real model files, and compare it
with other scanners (modelscan, picklescan, Fickling) when they are installed.

    python evaluation/run_eval.py --lab DIR [--hf DIR] [--benign DIR ...] [--tool-bin DIR] [--label after]

* ``--lab``: a directory written by ``tests/corpus/build_corpus.py`` (manifest.json).
* ``--hf``: a directory written by ``evaluation/fetch_benign_hf.py`` (manifest.jsonl);
  its files count as benign, and repo id, commit and sha256 go into the results.
* ``--benign``: any other directory of benign model files.

The run is under the evaluation guard (``evaluation/guard.py``): framework loaders
cannot be imported, pickle.load/loads and process creation are refused (except the
sandbox runner and the other scanners' executables), sockets reach loopback only.
safeloadai only ever calls ``scan()``. The other scanners run as their own
processes; modelscan is not run on ``.h5`` files, because it reads them with h5py
on the host (counted as "skipped").

Results go to ``<out>/eval-<label>-<UTC timestamp>.json`` and a Markdown summary
next to it: detection rate and false-positive rate overall and per format, median
time, and for every remaining safeloadai false positive the allowlist entries it
is missing (review them; nothing is added automatically). ``compare_eval.py``
turns two runs (before / after) into one table.

"Detected" means any verdict other than CLEAN. For other tools, an error, an
unsupported file or a skipped file is counted separately and is not a detection.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guard import activate  # noqa: E402

from safeloadai import __version__, scan  # noqa: E402
from safeloadai.parsing.detect import EXTENSION_HINTS  # noqa: E402

MODEL_EXTENSIONS = tuple(EXTENSION_HINTS)
TOOL_TIMEOUT_S = 300
ERROR_MARKERS = ("Traceback", "NotImplementedError", "Parsing errors", "Error:")

# tool -> (argv prefix, exit code -> outcome). Outcomes: clean, flagged, error, unsupported, skipped.
TOOLS = {
    "picklescan": (["picklescan", "--path"], {0: "clean", 1: "flagged"}),
    "fickling": (["fickling", "--check-safety"], {0: "clean", 1: "flagged"}),
    "modelscan": (["modelscan", "-p"], {0: "clean", 1: "flagged", 2: "error", 3: "unsupported"}),
}
# (tool, extension) pairs not run: the tool would deserialize or open the file with a
# framework library on the host.
SKIP = {("modelscan", ".h5"): "modelscan reads .h5 with h5py on the host"}
EXT_FORMAT = {".pkl": "pickle", ".pickle": "pickle", ".joblib": "joblib", ".pt": "torch", ".pth": "torch",
              ".bin": "torch", ".keras": "keras", ".h5": "h5", ".hdf5": "h5"}


def _files(directory: str) -> list[str]:
    found = []
    for root, dirs, names in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        found.extend(os.path.join(root, n) for n in sorted(names) if n.lower().endswith(MODEL_EXTENSIONS))
    return found


def _ext(path: str) -> str:
    return os.path.splitext(path)[1].lower()


def load_entries(lab: str | None, hf: str | None, benign: list[str]) -> list[dict]:
    entries = []
    if lab:
        with open(os.path.join(lab, "manifest.json"), encoding="utf-8") as fh:
            for item in json.load(fh):
                entries.append(dict(item, path=os.path.join(lab, item["file"]), source="lab"))
    if hf:
        with open(os.path.join(hf, "manifest.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                item = json.loads(line)
                entries.append({"file": f"{item['repo_id']}/{item['filename']}", "path": os.path.join(hf, item["path"]),
                                "label": "benign", "category": f"hf_{item['format']}", "expected": "CLEAN",
                                "source": "hf", "repo_id": item["repo_id"], "revision": item["revision"],
                                "sha256": item["sha256"], "size": item["size"]})
    for directory in benign:
        for path in _files(directory):
            entries.append({"file": os.path.relpath(path, directory), "path": path, "label": "benign",
                            "category": "benign_external", "expected": "CLEAN",
                            "source": os.path.basename(os.path.normpath(directory))})
    for entry in entries:
        entry.setdefault("format", EXT_FORMAT.get(_ext(entry["path"]), "other"))
    return entries


def _missing_entries(report) -> list[str]:
    """Allowlist entries a flagged benign file would need, from the static and emulation layers."""
    out = []
    for layer in report.layers:
        details = layer.details or {}
        for key in ("unknown_imports", "suspicious_imports"):
            for imp in details.get(key) or []:
                out.append(f"{imp.get('module')}.{imp.get('symbol')}")
        for reason in layer.reasons:
            if "import outside the allowlist: " in reason:
                out.append(reason.split("import outside the allowlist: ", 1)[1].split(";")[0].strip())
    return sorted(set(out))


def run_safeloadai(path: str) -> dict:
    started = time.perf_counter()
    try:
        report = scan(path)
    except Exception as exc:  # noqa: BLE001 - a crash is a result to report
        return {"outcome": "error", "error": f"{type(exc).__name__}: {exc}",
                "seconds": time.perf_counter() - started}
    layers = {layer.name: layer.verdict.value for layer in report.layers}
    result = {"outcome": "clean" if report.clean else "flagged", "verdict": report.verdict.value,
              "file_format": report.file_format, "layers": layers, "timings_ms": report.timings_ms,
              "reasons": report.reasons[:8], "seconds": time.perf_counter() - started}
    if not report.clean:
        result["missing"] = _missing_entries(report)
    return result


def run_tool(name: str, path: str, tool_bin: str | None) -> dict:
    if (name, _ext(path)) in SKIP:
        return {"outcome": "skipped", "reason": SKIP[(name, _ext(path))], "seconds": 0.0}
    argv, codes = TOOLS[name]
    exe = _tool_exe(name, tool_bin)
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


def _tool_exe(name: str, tool_bin: str | None) -> str | None:
    argv0 = TOOLS[name][0][0]
    if tool_bin:
        for candidate in (argv0, argv0 + ".exe"):
            path = os.path.join(tool_bin, candidate)
            if os.path.exists(path):
                return path
        return None
    return shutil.which(argv0)


def available_tools(tool_bin: str | None) -> list[str]:
    return [name for name in TOOLS if _tool_exe(name, tool_bin)]


def _rate(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def _percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(q * len(ordered)))], 4)


def _stats(rows: list[tuple[dict, dict]]) -> dict:
    mal = [(e, r) for e, r in rows if e["label"] == "malicious"]
    ben = [(e, r) for e, r in rows if e["label"] == "benign"]
    tp = sum(r["outcome"] == "flagged" for _, r in mal)
    fp = sum(r["outcome"] == "flagged" for _, r in ben)
    seconds = [r["seconds"] for _, r in rows if r["outcome"] != "skipped"]
    return {
        "malicious": len(mal), "benign": len(ben), "detected": tp,
        "detection_rate": _rate(tp, len(mal)), "false_positives": fp, "fp_rate": _rate(fp, len(ben)),
        "errors": sum(r["outcome"] == "error" for _, r in rows),
        "unsupported": sum(r["outcome"] == "unsupported" for _, r in rows),
        "skipped": sum(r["outcome"] == "skipped" for _, r in rows),
        "seconds_median": round(statistics.median(seconds), 4) if seconds else None,
        "seconds_p95": _percentile(seconds, 0.95), "seconds_max": round(max(seconds), 4) if seconds else None,
    }


def summarise(entries: list[dict], tools: list[str]) -> dict:
    summary = {}
    formats = sorted({e["format"] for e in entries})
    for tool in ["safeloadai", *tools]:
        rows = [(e, e["results"][tool]) for e in entries]
        summary[tool] = _stats(rows)
        summary[tool]["per_format"] = {f: _stats([(e, r) for e, r in rows if e["format"] == f]) for f in formats}

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


def false_positives(entries: list[dict]) -> dict:
    """Missing allowlist entry -> files that need it, over safeloadai's benign false positives."""
    needs: dict[str, list[str]] = defaultdict(list)
    other: Counter = Counter()
    for e in entries:
        r = e["results"]["safeloadai"]
        if e["label"] != "benign" or r["outcome"] != "flagged":
            continue
        missing = r.get("missing") or []
        for item in missing:
            needs[item].append(e["file"])
        if not missing:
            other[(r.get("reasons") or ["?"])[0][:160]] += 1
    return {"missing": {k: sorted(v) for k, v in sorted(needs.items(), key=lambda kv: -len(kv[1]))},
            "other_reasons": dict(other.most_common())}


def markdown(summary: dict, fps: dict, entries: list[dict], tools: list[str], meta: dict) -> str:
    lines = [f"# Evaluation {meta['label']} ({meta['created']})", "",
             f"safeloadai {meta['safeloadai']}, Python {meta['python']}, {meta['platform']}. "
             f"{len(entries)} files.", "",
             "| tool | detected / malicious | false positives / benign | errors | unsupported | skipped | "
             "median s | p95 s |", "|---|---|---|---|---|---|---|---|"]
    for tool, s in summary.items():
        lines.append(f"| {tool} | {s['detected']} / {s['malicious']} | {s['false_positives']} / {s['benign']} | "
                     f"{s['errors']} | {s['unsupported']} | {s['skipped']} | {s['seconds_median']} | "
                     f"{s['seconds_p95']} |")
    lines += ["", "## Per format", "", "| format | tool | detected / malicious | FP / benign | FP rate | median s |",
              "|---|---|---|---|---|---|"]
    for fmt in sorted(summary["safeloadai"]["per_format"]):
        for tool, s in summary.items():
            p = s["per_format"][fmt]
            lines.append(f"| {fmt} | {tool} | {p['detected']} / {p['malicious']} | {p['false_positives']} / "
                         f"{p['benign']} | {p['fp_rate']} | {p['seconds_median']} |")
    c = summary["safeloadai"]["layer_contribution"]
    lines += ["", "safeloadai layer contribution on malicious files: "
              f"static only {c['static_only']}, emulation only {c['emulation_only']}, both {c['both']}, "
              f"neither {c['neither']}.", "", "## safeloadai false positives", ""]
    if fps["missing"]:
        lines += ["Allowlist entries the flagged benign files would need (review each; none is added "
                  "automatically):", "", "| missing entry | files | examples |", "|---|---|---|"]
        for item, files in fps["missing"].items():
            lines.append(f"| `{item}` | {len(files)} | {', '.join(files[:3])} |")
    if fps["other_reasons"]:
        lines += ["", "False positives without a missing entry (first reason):", ""]
        lines += [f"- {count} x {reason}" for reason, count in fps["other_reasons"].items()]
    if not fps["missing"] and not fps["other_reasons"]:
        lines.append("None.")
    lines += ["", "## Files", "", "| file | label | expected | safeloadai | " + " | ".join(tools) + " |",
              "|---|---|---|---|" + "---|" * len(tools)]
    for e in entries:
        res = e["results"]
        cells = [res["safeloadai"].get("verdict", res["safeloadai"]["outcome"])] + [res[t]["outcome"] for t in tools]
        lines.append(f"| {e['file']} | {e['label']} | {e['expected']} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--lab", help="lab corpus directory (with manifest.json)")
    parser.add_argument("--hf", help="Hugging Face corpus directory (with manifest.jsonl)")
    parser.add_argument("--benign", action="append", default=[], help="directory of benign model files")
    parser.add_argument("--tool-bin", help="directory holding the other scanners' executables")
    parser.add_argument("--tools", help="comma-separated subset of: " + ",".join(TOOLS))
    parser.add_argument("--label", default="run", help="name of this run, e.g. before / after")
    parser.add_argument("--out", default=os.path.join(ROOT, "evaluation", "results"))
    args = parser.parse_args(argv)
    if not args.lab and not args.hf and not args.benign:
        parser.error("give --lab, --hf and/or --benign")

    tools = available_tools(args.tool_bin)
    if args.tools:
        tools = [t for t in args.tools.split(",") if t in tools]
    platform.uname()  # cached before the guard (Windows Python 3.11 runs "ver" for it)
    activate(tuple(_tool_exe(t, args.tool_bin) for t in tools))

    entries = load_entries(args.lab, args.hf, args.benign)
    for i, entry in enumerate(entries, 1):
        entry["results"] = {"safeloadai": run_safeloadai(entry["path"])}
        for tool in tools:
            entry["results"][tool] = run_tool(tool, entry["path"], args.tool_bin)
        print(f"[{i}/{len(entries)}] {entry['file']}: "
              + ", ".join(f"{k}={v.get('verdict', v['outcome'])}" for k, v in entry["results"].items()),
              file=sys.stderr)

    summary = summarise(entries, tools)
    fps = false_positives(entries)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    meta = {"label": args.label, "created": stamp, "python": sys.version.split()[0], "safeloadai": __version__,
            "platform": f"{platform.system()} {platform.machine()}"}
    os.makedirs(args.out, exist_ok=True)
    result = {**meta, "tools": tools, "summary": summary, "false_positives": fps,
              "entries": [{k: v for k, v in e.items() if k != "path"} for e in entries]}
    base = os.path.join(args.out, f"eval-{args.label}-{stamp}")
    with open(base + ".json", "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    with open(base + ".md", "w", encoding="utf-8") as fh:
        fh.write(markdown(summary, fps, entries, tools, meta))
    print(json.dumps({t: {k: v for k, v in s.items() if k != "per_format"} for t, s in summary.items()}, indent=2))
    print(f"wrote {base}.json and {base}.md", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
