"""Manual review of the held-out-2 files the Hub flags, written as rules over the Hub's own
evidence (never safeloadai's verdict), so the review can be read and re-run.

    python evaluation/review_heldout2_labels.py --work /tmp/hf_batches

Adds one row per flagged held-out-2 file to ``WORK/reviewed-labels.tsv`` (rows already
there, such as the hf-unsafe review, are kept). The Hub marks nearly every pickle that
imports anything outside its own short list as "suspicious"; that is not evidence of a
payload. The rules, in order:

1. **malicious**: the Hub's import scan lists a dangerous import that runs a command
   (``posix.system``, ``os.system``, ``subprocess.*``, ``builtins.eval``/``exec``).
2. **unclear**: a byte-signature hit for code execution, network or system access that the
   import list cannot explain (the import scan failed or is empty), a "getattr"
   obfuscation signature on a file with no import list, or a Hub verdict with no evidence
   at all on the file (Keras and HDF5 files the import scan does not read).
3. **benign**: every other flagged file. Their import lists hold only library classes
   (transformers, torch, accelerate, ultralytics, scikit-learn, numpy, pandas, ...), a
   training script's own ``__main__`` dataclass or estimator (the file names the class;
   its code is not in the file), or ``builtins.getattr`` beside Enum classes, which is how
   Python 3.11 and later pickle an Enum member (``getattr(EnumClass, "NAME")``).
   A ``__main__`` byte signature is that same class import.
"""
from __future__ import annotations

import argparse
import json
import os

COMMAND = {"posix.system", "os.system", "nt.system", "builtins.eval", "builtins.exec", "__builtin__.eval",
           "__builtin__.exec", "subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_output"}
EXPLAINED_SIGNATURES = ("CodeExec___main___", "Obfuscation___builtin___getattr")


def review(e: dict) -> tuple[str, str]:
    ev = e.get("hub_evidence") or {}
    scan = ev.get("pickle_import_scan") or {}
    imports = [f"{i['module']}.{i['name']}" for i in scan.get("pickleImports") or []]
    av = (ev.get("av_scan") or {})
    signatures = av.get("message", "") if av.get("status") not in (None, "safe") else ""
    command = sorted(set(imports) & COMMAND)
    if command:
        return "malicious", f"Hub import scan: {', '.join(command)} runs a command on load"
    if signatures and not imports:
        return "unclear", f"Hub antivirus signature with no import list to explain it: {signatures[:160]}"
    if signatures and not all(any(s in part for s in EXPLAINED_SIGNATURES) for part in signatures.split()
                              if part.startswith("Py.Malware.")):
        if "webbrowser" in signatures and all(i.split(".")[0] in ("numpy", "sklearn") for i in imports):
            return "benign", ("Hub import list holds only scikit-learn and numpy; the webbrowser byte signature "
                              "is not an import (the pickle imports nothing from webbrowser)")
        return "unclear", f"Hub antivirus signature the import list does not explain: {signatures[:160]}"
    if not ev:
        return "benign", "no per-file Hub evidence; benign by selection"
    if not imports:
        return "unclear", f"Hub status {ev.get('status')!r} with no import list or signature (format not read by it)"
    if any(i.endswith(".getattr") for i in imports):
        return "benign", ("Hub import list: library classes and builtins.getattr beside Enum classes "
                          "(Python 3.11+ pickles an Enum member as getattr(EnumClass, name))")
    if any(i.startswith("__main__.") for i in imports):
        return "benign", "Hub import list: library classes and the training script's own __main__ class; no payload"
    return "benign", "Hub import list: library classes only; flagged as outside the Hub's own list, no payload"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--work", required=True)
    args = parser.parse_args(argv)
    path = os.path.join(args.work, "reviewed-labels.tsv")
    rows, seen = [], set()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip() and not line.startswith("#"):
                    rows.append(line.rstrip("\n"))
                    seen.add(tuple(line.split("\t")[:2]))
    counts: dict[str, int] = {}
    with open(os.path.join(args.work, "plan-benign.jsonl"), encoding="utf-8") as fh:
        for line in fh:
            e = json.loads(line)
            if "proposed_label" not in e or (e["repo_id"], e["filename"]) in seen:
                continue
            label, reason = review(e)
            counts[label] = counts.get(label, 0) + 1
            rows.append("\t".join([e["repo_id"], e["filename"], e["revision"], e.get("lfs_sha256") or "-", label,
                                   reason]))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# repo\tfile\tcommit\tsha256\tlabel\treason (Hub evidence, then manual review)\n")
        fh.write("\n".join(rows) + "\n")
    print(f"{path}: added {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
