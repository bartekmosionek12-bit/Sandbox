"""Classify the lab and mutation files that picklescan, fickling or modelscan did not flag.

    python evaluation/third_party_misses.py --corpus LAB_DIR --corpus MUTATIONS_DIR \
        --tool-bin VENV/bin --out private/third-party-misses/results

For every file labelled malicious in the corpus manifests, each scanner is run the way
``run_eval.py`` runs it, on our own marker files only (``echo MARKER``,
``/tmp/safeloadai_marker``, 127.0.0.1). A file a scanner did not flag gets one class:

* ``unsupported`` (a): the scanner does not analyse this format, by the support matrix
  read from its source (``supported()`` below; the matrix with source links is kept with
  the private results as ``scanner_support.md``);
* ``error`` (b): the scanner exited with an error code or reported an error;
* ``clean`` (c): the format is supported, the scanner did not error, and it said the
  file is safe. An exit code that means "nothing scanned" on a format the scanner
  supports counts here when its summary still reads as safe; the row keeps
  ``outcome: skipped``. Only these are candidates; confirming one is a separate step
  inside deep mode's isolation.

The script only reads files and starts the scanners as their own processes, under the
evaluation guard. It never loads a file. Results are written to ``--out``, which must
be a directory ignored by git: findings about other projects are private until they
are disclosed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import guard  # noqa: E402

TOOLS = {
    "picklescan": ["picklescan", "--path"],
    "fickling": ["fickling", "--check-safety"],
    "modelscan": ["modelscan", "-p"],
}
VERSIONS = {"picklescan": "1.0.5", "fickling": "0.1.12", "modelscan": "0.8.8"}
TIMEOUT_S = 300

# Extension lists from the pinned sources (scanner_support.md).
PICKLESCAN_TORCH_EXT = {".bin", ".pt", ".pth", ".ckpt"}
PICKLESCAN_PICKLE_EXT = {".pkl", ".pickle", ".joblib", ".dat", ".data"}
MODELSCAN_PICKLE_EXT = {".pkl", ".pickle", ".joblib", ".dill", ".dat", ".data"}
MODELSCAN_TORCH_EXT = {".bin", ".pt", ".pth", ".ckpt"}


def content_format(data: bytes) -> str:
    """pickle, joblib (compressed), torch (ZIP), keras (ZIP), h5, zip or unknown."""
    from safeloadai.parsing import detect

    fmt = detect.detect(data)
    if fmt == "unknown" and (data.startswith(b"PK\x03\x04") or b"PK\x05\x06" in data[-65_557:]):
        return "zip"
    return fmt


def pickle_at_start(data: bytes) -> bool:
    from safeloadai.parsing.views import pickle_at_start as at_start

    return at_start(data)


def supported(tool: str, name: str, data: bytes) -> tuple[bool, str]:
    """Does ``tool`` analyse the reading a loader makes of this file? (bool, why)."""
    ext = os.path.splitext(name)[1].lower()
    fmt = content_format(data)
    raw_pickle = pickle_at_start(data)
    if fmt == "joblib":
        return False, "compressed joblib container: no decompression in the scanner"
    if fmt == "h5":
        return False, "HDF5 is not analysed" if tool != "modelscan" else "modelscan .h5 needs h5py; not run"
    if fmt == "keras":
        return False, ("Keras ZIP members are not pickles" if tool != "modelscan"
                       else "modelscan .keras needs the tensorflow extra (not installed)")
    if tool == "fickling":
        if fmt in ("torch", "zip") and not raw_pickle:
            return False, "the --check-safety CLI does not unpack ZIP archives"
        return (True, "raw pickle stream") if raw_pickle else (False, "not a pickle stream")
    if tool == "picklescan":
        if fmt in ("torch", "zip"):
            return True, "ZIP members with a pickle extension or magic"
        return (True, "raw pickle stream") if raw_pickle else (False, "not a pickle stream")
    # modelscan dispatches by extension
    if ext in MODELSCAN_TORCH_EXT:
        return True, "PyTorch extension (ZIP members or legacy magic)"
    if fmt in ("torch", "zip"):
        return True, "ZIP members by extension"
    if ext in MODELSCAN_PICKLE_EXT:
        return (True, "pickle extension") if raw_pickle else (False, "not a pickle stream")
    return False, f"no modelscan scanner for extension {ext or '(none)'!r}"


def run(tool: str, path: str, tool_bin: str) -> dict:
    exe = os.path.join(tool_bin, TOOLS[tool][0])
    try:
        with tempfile.TemporaryDirectory() as scratch:  # fickling writes safety_results.json to the cwd
            proc = subprocess.run([exe, *TOOLS[tool][1:], os.path.abspath(path)], capture_output=True, text=True,
                                  timeout=TIMEOUT_S, cwd=scratch)
    except subprocess.TimeoutExpired:
        return {"exit_code": None, "output": "timeout", "outcome": "error"}
    output = (proc.stdout or "") + (proc.stderr or "")
    return {"exit_code": proc.returncode, "output": output[-4000:], "outcome": outcome(tool, proc.returncode, output)}


def _count(pattern: str, text: str) -> int:
    found = re.search(pattern, text)
    return int(found.group(1)) if found else 0


def outcome(tool: str, code: int, output: str) -> str:
    """flagged, clean or error, from the exit code and the scanner's own summary."""
    if tool == "picklescan":
        if _count(r"Infected files: (\d+)", output) or "FOUND" in output:
            return "flagged"  # picklescan exits 2 on a parse error even after finding a global
        return "clean" if code == 0 else "error"
    if tool == "modelscan":
        if _count(r"Total Issues: (\d+)", output):
            return "flagged"
        if "--- Errors ---" in output:
            return "error"  # also with exit 3: a scanner was chosen and failed
        if code == 0:
            return "clean"
        return "skipped" if code == 3 else "error"  # 3: nothing was scanned
    if code == 1 and not any(m in output for m in ("Traceback", "NotImplementedError", "Error:")):
        return "flagged"
    return "clean" if code == 0 else "error"


def classify(tool: str, result: dict, is_supported: bool) -> str:
    if result["outcome"] == "flagged":
        return "flagged"
    if not is_supported:
        return "unsupported"
    if result["outcome"] == "error":
        return "error"
    return "clean"  # also "skipped" on a supported format, whose summary reads as safe


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--reclassify", action="store_true",
                        help="recompute classes from --out/misses.json without running the scanners")
    parser.add_argument("--corpus", action="append", required=True, help="corpus directory with manifest.json")
    parser.add_argument("--tool-bin", required=True, help="bin directory of the venv with the pinned scanners")
    parser.add_argument("--out", required=True, help="private output directory (git-ignored)")
    args = parser.parse_args(argv)
    check = subprocess.run(["git", "check-ignore", "-q", args.out], cwd=os.path.dirname(HERE))
    if check.returncode != 0:
        parser.error(f"{args.out} is not ignored by git; results about other projects must stay private")
    guard.activate(tuple(os.path.join(args.tool_bin, t[0]) for t in TOOLS.values()))
    rows = []
    if args.reclassify:
        with open(os.path.join(args.out, "misses.json"), encoding="utf-8") as fh:
            rows = json.load(fh)
        for row in rows:
            for tool, scan in row["scanners"].items():
                if scan["exit_code"] is not None:
                    scan["outcome"] = outcome(tool, scan["exit_code"], scan["output"])
                scan["cls"] = classify(tool, scan, scan["supported"])
    for corpus in [] if args.reclassify else args.corpus:
        with open(os.path.join(corpus, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        for entry in manifest:
            if entry["label"] != "malicious":
                continue
            path = os.path.join(corpus, entry["file"])
            with open(path, "rb") as fh:
                data = fh.read()
            row = {"file": entry["file"], "corpus": os.path.basename(os.path.normpath(corpus)),
                   "sha256": hashlib.sha256(data).hexdigest(), "format": content_format(data),
                   "technique": entry.get("category"), "scanners": {}}
            for tool in TOOLS:
                ok, why = supported(tool, entry["file"], data)
                result = run(tool, path, args.tool_bin)
                row["scanners"][tool] = dict(result, version=VERSIONS[tool], supported=ok, support_note=why,
                                             cls=classify(tool, result, ok))
            rows.append(row)
            print(entry["file"], {t: r["cls"] for t, r in row["scanners"].items()}, file=sys.stderr)
    corpora = {os.path.basename(os.path.normpath(c)): c for c in args.corpus}
    for row in rows:
        if all(s["cls"] == "flagged" for s in row["scanners"].values()):
            continue
        row["safeloadai"] = run_safeloadai(os.path.join(corpora[row["corpus"]], row["file"]))
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "misses.json"), "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=1)
    with open(os.path.join(args.out, "misses.md"), "w", encoding="utf-8") as fh:
        fh.write(markdown(rows))
    return 0


def run_safeloadai(path: str) -> dict:
    """safeloadai's own verdict on a file a scanner missed (scan() only, never a load)."""
    from safeloadai.pipeline import scan

    report = scan(path)
    if not report.ok:
        return {"verdict": "ERROR", "error": report.error["code"], "evidence": [report.error["message"][:200]]}
    return {"verdict": report.verdict.value, "category": report.category,
            "layers": {layer.name: layer.verdict.value for layer in report.layers},
            "evidence": [f"[{f['layer']}/{f['category']}] {f['text'][:200]}" for f in report.findings[:3]]}


def markdown(rows: list[dict]) -> str:
    lines = ["# Third-party scanner misses (private)", "",
             f"{len(rows)} malicious lab and mutation files.", "",
             "| scanner | version | flagged | (a) unsupported | (b) error | (c) clean |", "|---|---|---|---|---|---|"]
    for tool in TOOLS:
        c = Counter(r["scanners"][tool]["cls"] for r in rows)
        lines.append(f"| {tool} | {VERSIONS[tool]} | {c['flagged']} | {c['unsupported']} | {c['error']} | "
                     f"{c['clean']} |")
    ours = [r for r in rows if "safeloadai" in r]
    verdicts = Counter(r["safeloadai"]["verdict"] for r in ours)
    lines += ["", "## safeloadai on the same files", "",
              f"{len(ours)} files missed by at least one scanner: "
              + ", ".join(f"{v} {n}" for v, n in sorted(verdicts.items())) + ".", "",
              "| file | missed by | safeloadai | evidence |", "|---|---|---|---|"]
    for r in ours:
        missed = ", ".join(f"{t} ({s['cls']})" for t, s in r["scanners"].items() if s["cls"] != "flagged")
        evidence = "<br>".join(e.replace("|", "\\|") for e in r["safeloadai"]["evidence"][:2])
        lines.append(f"| `{r['file']}` | {missed} | {r['safeloadai']['verdict']} | {evidence} |")
    for tool in TOOLS:
        lines += ["", f"## {tool}", "", "| class | file | format | technique | sha256 | exit | note |",
                  "|---|---|---|---|---|---|---|"]
        for r in rows:
            s = r["scanners"][tool]
            if s["cls"] == "flagged":
                continue
            lines.append(f"| {s['cls']} | `{r['file']}` | {r['format']} | {r['technique']} | "
                         f"`{r['sha256'][:16]}` | {s['exit_code']} | {s['support_note']}"
                         f"{' (scanner skipped it)' if s['outcome'] == 'skipped' else ''} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
