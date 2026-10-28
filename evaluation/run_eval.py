"""Evaluate safeloadai against the lab corpus and real model files, and compare it
with other scanners (modelscan, picklescan, Fickling) when they are installed.

    python evaluation/run_eval.py --lab DIR [--mutations DIR] [--hf DIR] [--hf-malicious DIR --labels FILE]
                                  [--benign DIR ...] [--tool-bin DIR] [--jobs N] [--label after]

* ``--lab``: a directory written by ``tests/corpus/build_corpus.py`` (manifest.json).
* ``--mutations``: a directory written by ``tests/corpus/mutate.py`` (manifest.json).
* ``--hf``: a directory written by ``evaluation/fetch_benign_hf.py`` (manifest.jsonl);
  its files count as benign, and repo id, commit and sha256 go into the results.
  Each file is in the "tune" or "held-out" group by its repo (``split_of``); the
  headline false-positive rate is the held-out one.
* ``--hf-malicious``: a directory written by ``evaluation/fetch_malicious_hf.py``,
  labelled by the reviewed ``--labels`` file (files labelled ``unclear`` are reported
  but count in neither rate).
* ``--benign``: any other directory of benign model files.

The run is under the evaluation guard (``evaluation/guard.py``): framework loaders
cannot be imported, pickle.load/loads and process creation are refused (except the
sandbox runner and the other scanners' executables), sockets reach loopback only.
safeloadai only ever calls ``scan()``. The other scanners run as their own
processes; modelscan is not run on ``.h5`` files, because it reads them with h5py
on the host (counted as "skipped").

Next to the default run the results carry three more safeloadai columns: the default with
the reviewed known-file list off, the opt-in (``--trust-inert-from`` for ``--opt-in-trust``
distributions, by default scikit-learn, transformers and torch; ``--opt-in-site DIR`` finds
them unpacked in DIR without making them importable; ``--no-opt-in`` leaves it out), and
the upper bound (every UNVERIFIABLE item of every file accepted; not recommended). For
benign files each column is split into CLEAN, soft block (UNVERIFIABLE only), hard block
(RISKY or MALICIOUS) and UNSUPPORTED, and a Pareto table lists the rules that unblocked
Hub files and the entries still missing, on tune and on held-out.

Results go to ``<out>/eval-<label>-<UTC timestamp>.json`` and a Markdown summary
next to it: detection rate and false-positive rate overall and per format, how many
flagged files are UNVERIFIABLE only (a user could accept them with an informed
override; reported as their own column, never subtracted from the false positives),
median time, and for every remaining safeloadai false positive the allowlist entries it
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

from fetch_benign_hf import split_of  # noqa: E402
from guard import activate  # noqa: E402

from safeloadai import __version__, override, scan  # noqa: E402
from safeloadai.parsing.detect import SCAN_EXTENSIONS  # noqa: E402

MODEL_EXTENSIONS = SCAN_EXTENSIONS
# Columns next to the default run (each a result per file, like another tool):
# * UPPER_BOUND: every UNVERIFIABLE item accepted (accept_unverified for all of them). An
#   upper bound on what overrides can do, not a recommendation: it lets malicious lab
#   files whose every reason is UNVERIFIABLE through. Called "safeloadai opt-in" before 0.7.0.
# * TRUST: the real opt-in, default + trust_inert_from for the distributions named with
#   --opt-in-trust (scikit-learn, transformers and torch unless given).
# * NO_KNOWN_GOOD: default with the reviewed known-file list turned off (known_good=False).
UPPER_BOUND = "safeloadai upper bound"
OLD_UPPER_BOUND = "safeloadai opt-in"
TRUST = "safeloadai trust-inert-from"
NO_KNOWN_GOOD = "safeloadai without known-file list"
COLUMN_TITLES = {UPPER_BOUND: "upper bound: accept all unverifiable (not recommended)",
                 TRUST: "opt-in: --trust-inert-from", NO_KNOWN_GOOD: "default without the known-file list"}
DEFAULT_TRUST = ("scikit-learn", "transformers", "torch")
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
              ".bin": "torch", ".keras": "keras", ".h5": "h5", ".hdf5": "h5", ".safetensors": "safetensors",
              ".gguf": "gguf", ".npy": "numpy", ".npz": "numpy", ".onnx": "onnx", ".tflite": "tflite",
              ".msgpack": "msgpack", ".xml": "openvino"}


def _files(directory: str) -> list[str]:
    found = []
    for root, dirs, names in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        found.extend(os.path.join(root, n) for n in sorted(names) if n.lower().endswith(MODEL_EXTENSIONS))
    return found


def _ext(path: str) -> str:
    return os.path.splitext(path)[1].lower()


def read_labels(path: str) -> dict[tuple[str, str], tuple[str, str]]:
    """(repo, file) -> (label, reason) from a reviewed label file (tab-separated)."""
    labels = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            repo, name, _commit, _sha, label, reason = line.rstrip("\n").split("\t", 5)
            labels[(repo, name)] = (label, reason)
    return labels


def _jsonl(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def load_entries(lab: str | None, hf: str | None, benign: list[str], mutations: str | None = None,
                 hf_malicious: str | None = None, labels: str | None = None) -> list[dict]:
    entries = []
    reviewed = read_labels(labels) if labels else {}
    for directory, source in ((lab, "lab"), (mutations, "mutations")):
        if not directory:
            continue
        with open(os.path.join(directory, "manifest.json"), encoding="utf-8") as fh:
            for item in json.load(fh):
                entries.append(dict(item, path=os.path.join(directory, item["file"]), source=source,
                                    group=source))
    if hf:
        for item in _jsonl(os.path.join(hf, "manifest.jsonl")):
            split = item.get("split") or split_of(item["repo_id"])
            entries.append({"file": f"{item['repo_id']}/{item['filename']}", "path": os.path.join(hf, item["path"]),
                            "label": "benign", "category": f"hf_{item['format']}", "expected": "CLEAN",
                            "source": "hf", "group": f"hf-{split}", "split": split,
                            "library": item.get("stratum") or item.get("library") or item["format"],
                            "hub_scan": item.get("hub_scan", "unknown"), "repo_id": item["repo_id"],
                            "revision": item["revision"], "sha256": item["sha256"], "size": item["size"]})
            if item.get("companions"):  # files a loader reads beside it (0.10.0: an OpenVINO .xml)
                entries[-1]["companions"] = [{k: c[k] for k in ("file", "sha256", "size")} for c in item["companions"]]
            label, reason = reviewed.get((item["repo_id"], item["filename"]), ("benign", None))
            if label != "benign":  # a scanner test file the benign discovery picked up
                entries[-1].update(label=label, label_reason=reason,
                                   expected="MALICIOUS" if label == "malicious" else "SUSPICIOUS")
    if hf_malicious:
        for item in _jsonl(os.path.join(hf_malicious, "manifest.jsonl")):
            label, reason = reviewed.get((item["repo_id"], item["filename"]),
                                         (item["proposed_label"], item["label_reason"]))
            entries.append({"file": f"{item['repo_id']}/{item['filename']}",
                            "path": os.path.join(hf_malicious, item["path"]), "label": label,
                            "category": f"hf_flagged_{item['format']}",
                            "expected": {"malicious": "MALICIOUS", "benign": "CLEAN"}.get(label, "SUSPICIOUS"),
                            "source": "hf-malicious", "group": item.get("group", "hf-malicious"),
                            "label_reason": reason,
                            "hub_scan": item.get("hub_scan"), "repo_id": item["repo_id"],
                            "revision": item["revision"], "sha256": item["sha256"], "size": item["size"]})
    for directory in benign:
        for path in _files(directory):
            entries.append({"file": os.path.relpath(path, directory), "path": path, "label": "benign",
                            "category": "benign_external", "expected": "CLEAN",
                            "source": os.path.basename(os.path.normpath(directory)), "group": "benign"})
    for entry in entries:
        entry["format"] = EXT_FORMAT.get(_ext(entry["path"]), "other")
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


def block_of(verdict: str | None, unverifiable_only: bool) -> str:
    """What a user experiences: clean, soft (UNVERIFIABLE only: overridable item by item),
    hard (RISKY or MALICIOUS), unsupported, or error."""
    if verdict is None:
        return "error"
    if verdict.startswith("CLEAN"):
        return "clean"
    if verdict == "UNSUPPORTED":
        return "unsupported"
    return "soft" if verdict == "SUSPICIOUS" and unverifiable_only else "hard"


def _error_column(report, seconds: float) -> dict:
    """A tool error (docs/ERRORS.md): its own outcome, never a detection or a miss."""
    return {"outcome": "error", "verdict": None, "error": f"{report.error['code']}: {report.error['message']}",
            "error_code": report.error["code"], "category": None, "unverifiable_only": False,
            "seconds": seconds, "block": "error", "cleared": []}


def _column(report, seconds: float) -> dict:
    if not report.ok:
        return _error_column(report, seconds)
    return {"outcome": "clean" if report.clean else "flagged", "verdict": report.verdict.value,
            "category": report.category, "unverifiable_only": report.unverifiable_only, "seconds": seconds,
            "block": block_of(report.verdict.value, report.unverifiable_only),
            "cleared": sorted({c["mechanism"] for c in report.cleared})}


def peak_rss_mb() -> dict:
    """Peak resident memory so far of this scanning process and of its sandbox children (MiB).
    Workers are reused, so the value is the peak over every scan the worker ran up to now; the
    run's maximum is the peak memory of a scan (0.9.0)."""
    try:
        import resource
    except ImportError:  # Windows
        return {}
    scale = 1024 * 1024 if sys.platform == "darwin" else 1024  # ru_maxrss: bytes on macOS, KiB on Linux
    own = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024 / scale / 1024
    children = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024 / scale / 1024
    return {"rss_peak_mb": round(own, 1), "children_rss_peak_mb": round(children, 1)}


def run_safeloadai(path: str, trust: tuple[str, ...] = ()) -> dict:
    result = _run_safeloadai(path, trust)
    result.update(peak_rss_mb())
    return result


def _run_safeloadai(path: str, trust: tuple[str, ...] = ()) -> dict:
    started = time.perf_counter()
    try:
        report = scan(path)
    except Exception as exc:  # noqa: BLE001 - a crash is a result to report
        return {"outcome": "error", "error": f"{type(exc).__name__}: {exc}",
                "seconds": time.perf_counter() - started}
    seconds = time.perf_counter() - started
    if not report.ok:
        result = _error_column(report, seconds)
        result.update(file_format=report.file_format, timings_ms=report.timings_ms, reasons=report.reasons[:8])
        for column in ("no_known_good", "upper_bound"):
            result[column] = _error_column(report, seconds)
        if trust:
            result["trust"] = _error_column(report, seconds)
        return result
    layers = {layer.name: layer.verdict.value for layer in report.layers}
    result = {"outcome": "clean" if report.clean else "flagged", "verdict": report.verdict.value,
              "file_format": report.file_format, "layers": layers, "timings_ms": report.timings_ms,
              "reasons": report.reasons[:8], "seconds": seconds,
              "category": report.category, "unverifiable_only": report.unverifiable_only,
              "block": block_of(report.verdict.value, report.unverifiable_only),
              # what accepted the imports outside the allowlist, by rule (Part 1-4)
              "cleared": [{"item": c["item"], "mechanism": c["mechanism"]} for c in report.cleared]}
    known = next((c for c in report.cleared if c["mechanism"] == "known-file"), None)
    if not report.clean:
        result["missing"] = _missing_entries(report)
        result["unverifiable_items"] = report.unverifiable_items if report.unverifiable_only else []
    # Without the known-file list: the verdict the list replaced (recorded in the entry).
    if known:
        only = known["category"] == "UNVERIFIABLE"
        result["missing"] = sorted({f"{p[0]}.{p[1]}" for p in known["pairs"]})
        result["no_known_good"] = {"outcome": "flagged", "verdict": "SUSPICIOUS", "category": known["category"],
                                   "unverifiable_only": only, "seconds": seconds,
                                   "block": block_of("SUSPICIOUS", only)}
    else:
        result["no_known_good"] = {k: result[k] for k in ("outcome", "verdict", "category", "unverifiable_only",
                                                          "seconds", "block")}
    # The real opt-in: trust_inert_from for the named distributions. A file CLEAN by default
    # is not scanned again: with the installed versions equal to the pins, the option only
    # widens the pinned analysis (docs/OPTIONS.md).
    if trust:
        if report.clean:
            result["trust"] = dict(result["no_known_good"], outcome="clean", verdict=report.verdict.value,
                                   category=None, unverifiable_only=False, block="clean")
        else:
            t = time.perf_counter()
            try:
                result["trust"] = _column(scan(path, trust_inert_from=trust), time.perf_counter() - t)
            except Exception as exc:  # noqa: BLE001
                result["trust"] = {"outcome": "error", "error": f"{type(exc).__name__}: {exc}", "seconds": 0.0,
                                   "block": "error"}
    # The upper bound: the same report with every UNVERIFIABLE item accepted, as a user who
    # passes --accept-unverified for each of them would (refused on any RISKY or MALICIOUS reason).
    accepted = override.apply(report, report.unverifiable_items, how="api") if not report.clean else False
    result["upper_bound"] = {"outcome": "clean" if report.clean or accepted else "flagged",
                             "verdict": "CLEAN (accepted)" if accepted else report.verdict.value,
                             "category": report.category, "seconds": seconds,
                             "block": "clean" if report.clean or accepted else result["block"]}
    return result


def _init_worker(allowed: tuple, site: str | None = None) -> None:
    platform.uname()
    use_site(site)
    activate(allowed)


def use_site(site: str | None) -> None:
    """Let importlib.metadata find the distributions unpacked in ``site`` (``*.dist-info``
    next to the sources) for --trust-inert-from, without putting ``site`` on sys.path:
    nothing there can be imported. Evaluation only: the library itself finds installed
    distributions."""
    if not site:
        return
    from importlib import metadata

    original = metadata.distribution

    def distribution(name: str):
        for dist in metadata.distributions(path=[site]):
            if dist.metadata["Name"] and _norm(dist.metadata["Name"]) == _norm(name):
                return dist
        return original(name)

    metadata.distribution = distribution


def _norm(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def trust_available(names: tuple[str, ...], site: str | None) -> tuple[str, ...]:
    """The named distributions importlib.metadata can find (installed or in ``site``)."""
    from importlib import metadata

    use_site(site)
    found = []
    for name in names:
        try:
            metadata.distribution(name)
            found.append(name)
        except metadata.PackageNotFoundError:
            print(f"--opt-in-trust: {name} is neither installed nor in --opt-in-site; left out", file=sys.stderr)
    return tuple(found)


def _ready(_i: int) -> bool:
    time.sleep(0.2)
    return True


def _evaluate(job: tuple) -> dict:
    path, tools, tool_bin = job[:3]
    trust = job[3] if len(job) > 3 else ()
    results = {"safeloadai": run_safeloadai(path, trust)}
    for tool in tools:
        results[tool] = run_tool(tool, path, tool_bin)
    return results


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
    # flagged files whose every reason is UNVERIFIABLE (safeloadai only; other tools report none)
    unverifiable_fp = sum(r["outcome"] == "flagged" and bool(r.get("unverifiable_only")) for _, r in ben)
    unverifiable_detected = sum(r["outcome"] == "flagged" and bool(r.get("unverifiable_only")) for _, r in mal)
    seconds = [r["seconds"] for _, r in rows if r["outcome"] != "skipped"]
    flagged_ben = [r for _, r in ben if r["outcome"] == "flagged"]
    # What a user meets on benign files (safeloadai columns only; other tools have no "block")
    blocks = Counter(_block(r) for _, r in ben)
    return {
        "benign_clean": blocks["clean"], "benign_soft": blocks["soft"], "benign_hard": blocks["hard"],
        "benign_unsupported": blocks["unsupported"],
        "missed": sum(_block(r) == "clean" for _, r in mal),
        "unclear": sum(e["label"] not in ("malicious", "benign") for e, _ in rows),
        # safeloadai only: how its benign false positives split by category.
        "fp_malicious_verdict": sum(r.get("verdict") == "MALICIOUS" for r in flagged_ben),
        "fp_risky": sum(r.get("category") == "RISKY" for r in flagged_ben),
        "unverifiable_share": _rate(unverifiable_fp, len(ben)),
        "risky_share": _rate(sum(r.get("category") == "RISKY" for r in flagged_ben), len(ben)),
        "malicious": len(mal), "benign": len(ben), "detected": tp,
        "detection_rate": _rate(tp, len(mal)), "false_positives": fp, "fp_rate": _rate(fp, len(ben)),
        "unverifiable_fp": unverifiable_fp, "unverifiable_detected": unverifiable_detected,
        "errors": sum(r["outcome"] == "error" for _, r in rows),
        "unsupported": sum(r["outcome"] == "unsupported" for _, r in rows),
        "skipped": sum(r["outcome"] == "skipped" for _, r in rows),
        "seconds_median": round(statistics.median(seconds), 4) if seconds else None,
        "seconds_p95": _percentile(seconds, 0.95), "seconds_max": round(max(seconds), 4) if seconds else None,
        "rss_peak_mb_max": max(rss) if (rss := [r["rss_peak_mb"] for _, r in rows if "rss_peak_mb" in r]) else None,
    }


def _block(result: dict) -> str:
    if "block" in result:
        return result["block"]
    if result.get("outcome") == "clean":
        return "clean"
    if result.get("outcome") != "flagged":
        return result.get("outcome", "error")
    return block_of(result.get("verdict"), bool(result.get("unverifiable_only")))


GROUP_ORDER = ("lab", "mutations", "hf-malicious", "hf-unsafe", "hf-tune", "hf-tune2", "hf-heldout", "hf-heldout2",
               "benign")


def groups_of(entries: list[dict]) -> list[str]:
    present = {e.get("group", e.get("source")) for e in entries}
    return [g for g in GROUP_ORDER if g in present] + sorted(present - set(GROUP_ORDER))


def summarise_groups(entries: list[dict], tools: list[str]) -> dict:
    """group -> tool -> stats, with per-format and (Hub groups) per-library breakdowns."""
    out = {}
    for group in groups_of(entries):
        members = [e for e in entries if e.get("group", e.get("source")) == group]
        out[group] = {}
        for tool in ["safeloadai", *tools]:
            rows = [(e, e["results"][tool]) for e in members]
            stats = _stats(rows)
            stats["per_format"] = {f: _stats([(e, r) for e, r in rows if e["format"] == f])
                                   for f in sorted({e["format"] for e in members})}
            libraries = sorted({e["library"] for e in members if e.get("library")})
            if libraries:
                stats["per_library"] = {lib: _stats([(e, r) for e, r in rows if e.get("library") == lib])
                                        for lib in libraries}
            out[group][tool] = stats
    return out


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
    """Missing allowlist entry -> files that need it, over safeloadai's benign false positives.
    Held-out Hub files are left out: the allowlist review must not see them."""
    needs: dict[str, list[str]] = defaultdict(list)
    other: Counter = Counter()
    for e in entries:
        r = e["results"]["safeloadai"]
        if e["label"] != "benign" or r["outcome"] != "flagged" or e.get("group") in ("hf-heldout", "hf-heldout2"):
            continue
        missing = r.get("missing") or []
        for item in missing:
            needs[item].append(e["file"])
        if not missing:
            other[(r.get("reasons") or ["?"])[0][:160]] += 1
    return {"missing": {k: sorted(v) for k, v in sorted(needs.items(), key=lambda kv: -len(kv[1]))},
            "other_reasons": dict(other.most_common())}


MECHANISM_PART = {"referenced": "Part 1: referenced only", "policy": "Part 2: source policy",
                  "inert-class": "Part 2: --trust-inert-from", "torch-weights-only": "Part 2: torch weights_only",
                  "profile": "Part 3: profile", "known-file": "Part 4: known file"}
HUB_SPLITS = {"hf-tune": "tune", "hf-heldout": "heldout"}


def pareto(entries: list[dict], limit: int = 25) -> list[dict]:
    """Rules that unblocked benign Hub files (what accepted their imports) and entries still
    missing, with the files each unblocks on tune and on held-out. A missing entry unblocks
    a file only when it is the file's last missing entry; ``needed`` counts every file."""
    rows: dict[tuple[str, str], dict] = {}

    def row(kind: str, item: str) -> dict:
        return rows.setdefault((kind, item), {"rule": kind, "item": item, "tune": 0, "heldout": 0,
                                              "needed_tune": 0, "needed_heldout": 0})

    for e in entries:
        split = HUB_SPLITS.get(e.get("group"))
        if e["label"] != "benign" or split is None:
            continue
        r = e["results"]["safeloadai"]
        if r.get("outcome") == "clean":
            for c in r.get("cleared") or []:
                item = "reviewed file list" if c["mechanism"] == "known-file" else c["item"]
                found = row(c["mechanism"], item)
                found[split] += 1
                found["needed_" + split] += 1
        elif r.get("outcome") == "flagged":
            missing = r.get("missing") or []
            for item in missing:
                found = row("missing", item)
                found["needed_" + split] += 1
                found[split] += len(missing) == 1
    ordered = sorted(rows.values(), key=lambda x: (-x["tune"], -x["heldout"], -x["needed_tune"], x["item"]))
    return ordered[:limit]


def cleared_files(entries: list[dict]) -> list[dict]:
    """Benign Hub files CLEAN only because a 0.7.0 rule accepted something, with the rules."""
    out = []
    for e in entries:
        r = e["results"]["safeloadai"]
        if e["label"] == "benign" and e.get("group") in HUB_SPLITS and r.get("outcome") == "clean" and r.get("cleared"):
            out.append({"file": e["file"], "group": e["group"],
                        "mechanisms": sorted({c["mechanism"] for c in r["cleared"]})})
    return out


def user_view(groups: dict, columns: list[str]) -> list[str]:
    lines = ["", "## What users meet", "",
             "Benign files: CLEAN loads; a soft block (UNVERIFIABLE only) can be accepted item by item; a hard "
             "block (RISKY or MALICIOUS) cannot; UNSUPPORTED is a format safeloadai cannot read.", "",
             "| group | configuration | CLEAN | soft block | hard block | UNSUPPORTED | benign |",
             "|---|---|---|---|---|---|---|"]
    for group, per_tool in groups.items():
        if not per_tool["safeloadai"]["benign"]:
            continue
        for column in columns:
            p = per_tool[column]
            lines.append(f"| {group} | {COLUMN_TITLES.get(column, 'default')} | {p['benign_clean']} | "
                         f"{p['benign_soft']} | {p['benign_hard']} | {p['benign_unsupported']} | {p['benign']} |")
    lines += ["", "| group | configuration | detected / malicious | let through |", "|---|---|---|---|"]
    for group, per_tool in groups.items():
        if not per_tool["safeloadai"]["malicious"]:
            continue
        for column in columns:
            p = per_tool[column]
            lines.append(f"| {group} | {COLUMN_TITLES.get(column, 'default')} | {p['detected']} / {p['malicious']} "
                         f"| {p['missed']} |")
    upper = sum(per_tool[UPPER_BOUND]["missed"] for g, per_tool in groups.items()
                if g == "lab" and UPPER_BOUND in per_tool)
    if "lab" in groups and UPPER_BOUND in groups["lab"]:
        lines += ["", f"The upper bound accepts every UNVERIFIABLE item of every file. It lets {upper} lab "
                  "file(s) through, which is why an override must name each item of one file and is not "
                  "recommended in bulk."]
    return lines


def pareto_markdown(rows: list[dict], files: list[dict]) -> list[str]:
    lines = ["", "## Pareto: rules and missing entries", "",
             "Benign Hub files a rule unblocked (it accepted an import the file needed), and entries still "
             "missing (unblocked = the file's last missing entry; needed = every file that lacks it). Held-out "
             "counts are measurement only: no rule or entry was chosen from them.", "",
             "| rule / missing entry | mechanism | unblocked tune | unblocked held-out | needed tune | "
             "needed held-out |", "|---|---|---|---|---|---|"]
    for r in rows:
        mechanism = MECHANISM_PART.get(r["rule"], "missing")
        lines.append(f"| `{r['item']}` | {mechanism} | {r['tune']} | {r['heldout']} | {r['needed_tune']} | "
                     f"{r['needed_heldout']} |")
    counts: Counter = Counter()
    for f in files:
        for m in f["mechanisms"]:
            counts[(f["group"], m)] += 1
    lines += ["", "### Which rule cleared each file", "",
              "| group | mechanism | files |", "|---|---|---|"]
    for (group, m), n in sorted(counts.items()):
        lines.append(f"| {group} | {MECHANISM_PART.get(m, m)} | {n} |")
    lines += ["", "| file | group | mechanisms |", "|---|---|---|"]
    lines += [f"| {f['file']} | {f['group']} | {', '.join(MECHANISM_PART.get(m, m) for m in f['mechanisms'])} |"
              for f in files]
    return lines


def _group_table(title: str, rows: dict[str, dict], tools: list[str], first: str) -> list[str]:
    lines = ["", f"### {title}", "",
             f"| {first} | tool | detected / malicious | FP / benign | FP rate | FP MALICIOUS | FP RISKY | "
             "FP UNVERIFIABLE | errors | median s | p95 s |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for key, per_tool in rows.items():
        for tool in ["safeloadai", *tools]:
            p = per_tool[tool]
            own = tool == "safeloadai"
            lines.append(f"| {key} | {tool} | {p['detected']} / {p['malicious']} | {p['false_positives']} / "
                         f"{p['benign']} | {p['fp_rate']} | {p['fp_malicious_verdict'] if own else '-'} | "
                         f"{p['fp_risky'] if own else '-'} | {p['unverifiable_fp'] if own else '-'} | "
                         f"{p['errors']} | {p['seconds_median']} | {p['seconds_p95']} |")
    return lines


def group_markdown(groups: dict, tools: list[str]) -> list[str]:
    lines = ["", "## Per group", "",
             "Groups: `lab` and `mutations` are generated marker payloads; `hf-malicious` are Hub files the Hub's "
             "scanners flag, labelled from that evidence; `hf-tune` and `hf-heldout` are the two halves of the "
             "benign Hub corpus, split by repo. The allowlist review looked only at `hf-tune`; the headline "
             "false-positive rate is `hf-heldout`. FP MALICIOUS / RISKY / UNVERIFIABLE split safeloadai's false "
             "positives by category."]
    for group, per_tool in groups.items():
        lines += _group_table(f"{group}: total", {"all": per_tool}, tools, "set")
        fmts = sorted(per_tool["safeloadai"]["per_format"])
        lines += _group_table(f"{group}: per format",
                              {f: {t: per_tool[t]["per_format"][f] for t in per_tool} for f in fmts}, tools, "format")
        libs = sorted(per_tool["safeloadai"].get("per_library", {}))
        if libs:
            lines += _group_table(f"{group}: per library",
                                  {lib: {t: per_tool[t]["per_library"][lib] for t in per_tool} for lib in libs},
                                  tools, "library")
    return lines


def markdown(summary: dict, fps: dict, entries: list[dict], tools: list[str], meta: dict,
             groups: dict | None = None) -> str:
    columns = ["safeloadai", *[t for t in (NO_KNOWN_GOOD, TRUST, UPPER_BOUND) if t in tools]]
    lines = [f"# Evaluation {meta['label']} ({meta['created']})", "",
             f"safeloadai {meta['safeloadai']}, Python {meta['python']}, {meta['platform']}. "
             f"{len(entries)} files.", "",
             "| tool | detected / malicious | false positives / benign | of which UNVERIFIABLE | errors | "
             "unsupported | skipped | median s | p95 s |", "|---|---|---|---|---|---|---|---|---|"]
    for tool, s in summary.items():
        unv = s.get("unverifiable_fp", 0) if tool == "safeloadai" else "-"
        lines.append(f"| {tool} | {s['detected']} / {s['malicious']} | {s['false_positives']} / {s['benign']} | "
                     f"{unv} | {s['errors']} | {s['unsupported']} | {s['skipped']} | {s['seconds_median']} | "
                     f"{s['seconds_p95']} |")
    lines += ["", "\"of which UNVERIFIABLE\": false positives whose every reason is UNVERIFIABLE, so a user "
              "could accept them, item by item, for that one file. They still count as false positives. "
              f"Malicious files that are UNVERIFIABLE only: {summary['safeloadai'].get('unverifiable_detected', 0)} "
              "(an override would let these through, which is why it names every item).",
              "", "## Per format", "",
              "| format | tool | detected / malicious | FP / benign | FP UNVERIFIABLE | FP rate | median s |",
              "|---|---|---|---|---|---|---|"]
    for fmt in sorted(summary["safeloadai"]["per_format"]):
        for tool, s in summary.items():
            p = s["per_format"][fmt]
            unv = p.get("unverifiable_fp", 0) if tool == "safeloadai" else "-"
            lines.append(f"| {fmt} | {tool} | {p['detected']} / {p['malicious']} | {p['false_positives']} / "
                         f"{p['benign']} | {unv} | {p['fp_rate']} | {p['seconds_median']} |")
    if groups:
        lines += user_view(groups, columns)
    lines += pareto_markdown(pareto(entries), cleared_files(entries))
    if groups:
        lines += group_markdown(groups, tools)
    c = summary["safeloadai"]["layer_contribution"]
    lines += ["", "safeloadai layer contribution on malicious files: "
              f"static only {c['static_only']}, emulation only {c['emulation_only']}, both {c['both']}, "
              f"neither {c['neither']}.", "", "## safeloadai false positives", ""]
    if fps["missing"]:
        lines += ["Allowlist entries the flagged benign files would need, over every group except `hf-heldout` "
                  "(review each; none is added automatically):", "",
                  "| missing entry | files | examples |", "|---|---|---|"]
        for item, files in fps["missing"].items():
            lines.append(f"| `{item}` | {len(files)} | {', '.join(files[:3])} |")
    if fps["other_reasons"]:
        lines += ["", "False positives without a missing entry (first reason):", ""]
        lines += [f"- {count} x {reason}" for reason, count in fps["other_reasons"].items()]
    if not fps["missing"] and not fps["other_reasons"]:
        lines.append("None.")
    lines += ["", "## Files", "", "| file | group | label | expected | safeloadai | " + " | ".join(tools) + " |",
              "|---|---|---|---|---|" + "---|" * len(tools)]
    for e in entries:
        res = e["results"]
        # an ERROR has verdict None (docs/ERRORS.md)
        cells = [res["safeloadai"].get("verdict") or str(res["safeloadai"]["outcome"]).upper()]
        cells += [str(res.get(t, {}).get("outcome")) for t in tools]
        lines.append(f"| {e['file']} | {e.get('group', e.get('source'))} | {e['label']} | {e['expected']} | "
                     + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def resummarise(path: str, labels: str | None, label: str, out: str) -> int:
    """Rebuild the summaries of an earlier run, with the reviewed labels applied again to
    its Hub entries (a label fixed after the run needs no new scan)."""
    with open(path, encoding="utf-8") as fh:
        run = json.load(fh)
    reviewed = read_labels(labels) if labels else {}
    entries = run["entries"]
    for e in entries:
        if e.get("repo_id") and (e["repo_id"], e["file"][len(e["repo_id"]) + 1:]) in reviewed:
            lab, reason = reviewed[(e["repo_id"], e["file"][len(e["repo_id"]) + 1:])]
            e.update(label=lab, label_reason=reason,
                     expected={"malicious": "MALICIOUS", "benign": "CLEAN"}.get(lab, "SUSPICIOUS"))
    for e in entries:  # "safeloadai opt-in" before 0.7.0 is the upper bound
        if OLD_UPPER_BOUND in e["results"]:
            e["results"][UPPER_BOUND] = e["results"].pop(OLD_UPPER_BOUND)
    tools = [UPPER_BOUND if t == OLD_UPPER_BOUND else t for t in run["tools"]]
    summary, groups, fps = summarise(entries, tools), summarise_groups(entries, tools), false_positives(entries)
    meta = {k: run[k] for k in ("created", "python", "safeloadai", "platform")}
    meta["label"] = label
    base = os.path.join(out, f"eval-{label}-{run['created']}")
    with open(base + ".json", "w", encoding="utf-8") as fh:
        json.dump({**run, "label": label, "tools": tools, "summary": summary, "groups": groups,
                   "false_positives": fps, "pareto": pareto(entries), "cleared_files": cleared_files(entries),
                   "relabelled_from": os.path.basename(path)}, fh, indent=2)
    with open(base + ".md", "w", encoding="utf-8") as fh:
        fh.write(markdown(summary, fps, entries, tools, meta, groups))
    print(f"wrote {base}.json and {base}.md", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--lab", help="lab corpus directory (with manifest.json)")
    parser.add_argument("--mutations", help="mutation corpus directory (with manifest.json)")
    parser.add_argument("--hf", help="Hugging Face corpus directory (with manifest.jsonl)")
    parser.add_argument("--hf-malicious", help="flagged Hub files (fetch_malicious_hf.py output)")
    parser.add_argument("--labels", help="reviewed label file for --hf-malicious")
    parser.add_argument("--jobs", type=int, default=1, help="files scanned in parallel (each worker is guarded)")
    parser.add_argument("--from-json", help="re-summarise an earlier run (labels re-applied, nothing scanned)")
    parser.add_argument("--benign", action="append", default=[], help="directory of benign model files")
    parser.add_argument("--tool-bin", help="directory holding the other scanners' executables")
    parser.add_argument("--tools", help="comma-separated subset of: " + ",".join(TOOLS))
    parser.add_argument("--label", default="run", help="name of this run, e.g. before / after")
    parser.add_argument("--out", default=os.path.join(ROOT, "evaluation", "results"))
    parser.add_argument("--opt-in-trust", action="append", metavar="DIST",
                        help="distribution for the opt-in column (--trust-inert-from); repeatable; "
                             f"default: {', '.join(DEFAULT_TRUST)}")
    parser.add_argument("--opt-in-site", metavar="DIR",
                        help="directory with unpacked distributions (*.dist-info next to the sources) for the "
                             "opt-in column; found through importlib.metadata only, never importable")
    parser.add_argument("--no-opt-in", action="store_true", help="leave out the opt-in column")
    args = parser.parse_args(argv)
    if args.from_json:
        return resummarise(args.from_json, args.labels, args.label, args.out)
    if not (args.lab or args.hf or args.benign or args.mutations or args.hf_malicious):
        parser.error("give --lab, --mutations, --hf, --hf-malicious and/or --benign")

    tools = available_tools(args.tool_bin)
    if args.tools:
        tools = [t for t in args.tools.split(",") if t in tools]
    platform.uname()  # cached before the guard (Windows Python 3.11 runs "ver" for it)
    allowed = tuple(_tool_exe(t, args.tool_bin) for t in tools)
    entries = load_entries(args.lab, args.hf, args.benign, args.mutations, args.hf_malicious, args.labels)
    trust = () if args.no_opt_in else trust_available(tuple(args.opt_in_trust or DEFAULT_TRUST), args.opt_in_site)
    COLUMN_TITLES[TRUST] = f"opt-in: --trust-inert-from {' '.join(trust)}"
    jobs = [(entry["path"], tuple(tools), args.tool_bin, trust) for entry in entries]
    if args.jobs > 1:
        import multiprocessing
        from concurrent.futures import ProcessPoolExecutor

        pool = ProcessPoolExecutor(args.jobs, mp_context=multiprocessing.get_context("spawn"),
                                   initializer=_init_worker, initargs=(allowed, args.opt_in_site))
        list(pool.map(_ready, range(args.jobs)))  # workers exist (and are guarded) before the guard goes up here
        activate(allowed)
        results = pool.map(_evaluate, jobs)
    else:
        activate(allowed)
        results = map(_evaluate, jobs)
    for i, (entry, result) in enumerate(zip(entries, results, strict=True), 1):
        entry["results"] = result
        for key, column in (("no_known_good", NO_KNOWN_GOOD), ("trust", TRUST), ("upper_bound", UPPER_BOUND)):
            if key in result["safeloadai"]:
                result[column] = result["safeloadai"].pop(key)
            elif key != "trust" or trust:
                result[column] = dict(result["safeloadai"])  # an error: the same in every column
        print(f"[{i}/{len(entries)}] {entry['file']}: "
              + ", ".join(f"{k}={v.get('verdict', v['outcome'])}" for k, v in entry["results"].items()),
              file=sys.stderr)
    if args.jobs > 1:
        pool.shutdown()

    tools = [NO_KNOWN_GOOD, *([TRUST] if trust else []), UPPER_BOUND, *tools]
    summary = summarise(entries, tools)
    groups = summarise_groups(entries, tools)
    fps = false_positives(entries)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    meta = {"label": args.label, "created": stamp, "python": sys.version.split()[0], "safeloadai": __version__,
            "platform": f"{platform.system()} {platform.machine()}"}
    os.makedirs(args.out, exist_ok=True)
    meta["opt_in_trust"] = list(trust)
    result = {**meta, "tools": tools, "summary": summary, "groups": groups, "false_positives": fps,
              "pareto": pareto(entries), "cleared_files": cleared_files(entries),
              "entries": [{k: v for k, v in e.items() if k != "path"} for e in entries]}
    base = os.path.join(args.out, f"eval-{args.label}-{stamp}")
    with open(base + ".json", "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    with open(base + ".md", "w", encoding="utf-8") as fh:
        fh.write(markdown(summary, fps, entries, tools, meta, groups))
    print(json.dumps({t: {k: v for k, v in s.items() if k != "per_format"} for t, s in summary.items()}, indent=2))
    print(f"wrote {base}.json and {base}.md", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
