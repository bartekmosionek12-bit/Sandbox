"""Upstream-drift check: scan freshly generated benign models and report what changed.

    python tools/drift_check.py BENIGN_DIR [--freeze pip-freeze.txt] [--out drift.md] [--extra NOTE.md ...]

Run by the ``upstream-drift`` workflow after ``evaluation/make_local_benign.py`` has
written benign models with the LATEST scikit-learn, numpy, keras and tensorflow.
Every file is only scanned (``safeloadai.scan``), under the evaluation guard. Any
file that differs from its expected result is drift: a class was added, renamed or
moved upstream, or the scanner broke on a new layout. The Markdown report lists the names the flagged files
need, the library versions and a diff against the expected result.

The expected result is CLEAN for every file except the few listed in
``tools/drift_expected.json``, which must come back exactly as recorded there (verdict,
UNVERIFIABLE-only, same items). A listed file that comes back CLEAN is drift too.

This tool never edits an allowlist. Adding a name stays a reviewed, human change
(DECISIONS.md, U2). Exit code 0: every file as expected; 1: drift found; 2: nothing to scan.
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "evaluation"))

EXPECTED_PATH = os.path.join(ROOT, "tools", "drift_expected.json")
LIBRARIES = ("numpy", "scikit-learn", "joblib", "keras", "tensorflow", "tensorflow-cpu", "tf-keras", "jax",
             "h5py", "wasmtime", "safeloadai", "safeloadai-runtime")


def names_needed(report) -> list[str]:
    """Names outside the allowlists that a flagged file uses (static and emulation layers)."""
    out = set()
    for layer in report.layers:
        details = layer.details or {}
        for key in ("unknown_imports", "suspicious_imports"):
            for imp in details.get(key) or []:
                out.add(f"{imp.get('module')}.{imp.get('symbol')}")
        for reason in layer.reasons:
            if "import outside the allowlist: " in reason:
                out.add(reason.split("import outside the allowlist: ", 1)[1].split(";")[0].strip())
    return sorted(out)


def versions(freeze_text: str) -> dict[str, str]:
    found = {}
    for line in freeze_text.splitlines():
        name, sep, version = line.partition("==")
        name = name.strip().lower().replace("_", "-")  # pip freeze writes tensorflow_cpu
        if sep and name in LIBRARIES:
            found[name] = version.strip()
    return found


def load_expected(path: str = EXPECTED_PATH) -> dict[str, dict]:
    """The recorded non-CLEAN results, by file name (every other file is expected CLEAN)."""
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)["files"]


def _line(r: dict) -> str:
    """One comparable line per file: an UNVERIFIABLE-only result is named by its items, so it
    matches a recorded one exactly; anything else shows its first reasons."""
    if r["verdict"] == "CLEAN":
        return f"{r['file']}: CLEAN"
    if r.get("unverifiable_only"):
        return f"{r['file']}: {r['verdict']} (UNVERIFIABLE only: {', '.join(r['unverifiable_items'])})"
    return f"{r['file']}: {r['verdict']} ({'; '.join(r['reasons'][:3])})"


def _expected_line(name: str, expected: dict[str, dict]) -> str:
    if name not in expected:
        return f"{name}: CLEAN"
    e = expected[name]
    return _line({"file": name, "verdict": e["verdict"], "unverifiable_only": e.get("unverifiable_only", False),
                  "unverifiable_items": sorted(e.get("unverifiable_items", [])), "reasons": ["(recorded)"]})


def build_report(results: list[dict], library_versions: dict[str, str], extras: list[str] = (),
                 expected: dict[str, dict] | None = None) -> tuple[str, bool]:
    """Markdown body and whether drift was found. ``results``: {file, verdict, names, reasons,
    unverifiable_only, unverifiable_items}; ``expected``: the recorded non-CLEAN results."""
    expected = expected or {}
    flagged = [r for r in results if _line(r) != _expected_line(r["file"], expected)]
    needs: dict[str, list[str]] = defaultdict(list)
    for r in flagged:
        for name in r["names"]:
            needs[name].append(r["file"])
    lines = ["Benign models written with the latest upstream libraries were scanned by safeloadai.", ""]
    if flagged:
        lines.append(f"**{len(flagged)} of {len(results)} benign files differ from the expected result.** Nothing "
                     "was added to any allowlist: review each name below and add it, if it is safe, in a reviewed "
                     "change with a regression test (DECISIONS.md, U2).")
    else:
        known = sum(1 for r in results if r["file"] in expected)
        lines.append(f"All {len(results)} benign files match the expected result"
                     + (f" ({known} recorded in tools/drift_expected.json, the rest CLEAN)." if known else ": CLEAN."))
    lines += ["", "## Names the flagged files need", ""]
    if needs:
        lines += ["| name | files |", "|---|---|"]
        lines += [f"| `{name}` | {', '.join(sorted(files)[:5])} |" for name, files in sorted(needs.items())]
    else:
        lines.append("None." if not flagged else "None by name; see the reasons in the diff.")
    lines += ["", "## Library versions", "", "| library | version |", "|---|---|"]
    lines += [f"| {name} | {version} |" for name, version in sorted(library_versions.items())]
    want = [_expected_line(r["file"], expected) for r in results]
    actual = [_line(r) for r in results]
    diff = list(difflib.unified_diff(want, actual, "expected", "scanned", lineterm="", n=0))
    lines += ["", "## Diff against the expected result", "", "```diff", *(diff or ["(no difference)"]), "```"]
    for extra in extras:
        lines += ["", extra.rstrip()]
    return "\n".join(lines) + "\n", bool(flagged)


def scan_dir(directory: str) -> list[dict]:
    from guard import activate

    activate()
    from safeloadai import scan
    from safeloadai.parsing.detect import EXTENSION_HINTS

    results = []
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if not (os.path.isfile(path) and name.lower().endswith(tuple(EXTENSION_HINTS))):
            continue
        report = scan(path)
        results.append({"file": name, "verdict": report.outcome,
                        "names": names_needed(report) if not report.clean else [],
                        "reasons": [r[:200] for r in report.reasons[:5]],
                        "unverifiable_only": report.unverifiable_only,
                        "unverifiable_items": report.unverifiable_items if report.unverifiable_only else []})
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("directory")
    parser.add_argument("--freeze", help="pip freeze output of the venv that wrote the files")
    parser.add_argument("--out", help="write the Markdown report here")
    parser.add_argument("--extra", action="append", default=[], help="Markdown file to append (repeatable)")
    args = parser.parse_args(argv)
    freeze = ""
    if args.freeze and os.path.exists(args.freeze):
        with open(args.freeze, encoding="utf-8") as fh:
            freeze = fh.read()
    results = scan_dir(args.directory) if os.path.isdir(args.directory) else []
    extras = []
    for path in args.extra:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                extras.append(fh.read())
    text, drift = build_report(results, versions(freeze), extras, load_expected())
    if not results:
        text = "No benign file was generated: make_local_benign.py failed with the latest libraries.\n\n" + text
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(text)
    if not results:
        return 2
    return 1 if drift else 0


if __name__ == "__main__":
    raise SystemExit(main())
