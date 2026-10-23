"""Take safeloadai's own columns from a newer run of the same files.

    python evaluation/combine_runs.py OLD.json NEW.json --out COMBINED.json

Used when safeloadai was fixed after a measurement: its columns (``safeloadai`` and every
``safeloadai ...`` variant) are run again on the same files (same commit and sha256), and
the other scanners' columns, which did not change, are kept from the first run. Both
inputs are ``batch_hf.py merge`` outputs (or ``run_eval.py`` result files); the output is a
merge file for ``run_eval.py --from-json``. Labels, groups and every other field of an
entry come from NEW, so a label review between the runs applies to both columns.

A file in NEW that OLD did not scan (it was skipped there) gets the other scanners'
columns as ``skipped``; a file in OLD that NEW did not scan is left out and listed under
``skipped_files``. ``meta["combined"]`` records both inputs.
"""
from __future__ import annotations

import argparse
import json
import os
import sys


def own(tool: str) -> bool:
    return tool == "safeloadai" or tool.startswith("safeloadai ")


def combine(old: dict, new: dict, old_name: str, new_name: str) -> dict:
    first = {(e["group"], e["file"]): e for e in old["entries"]}
    others = [t for t in old.get("tools", []) if not own(t)]
    entries = []
    for entry in new["entries"]:
        before = first.pop((entry["group"], entry["file"]), None)
        results = {k: v for k, v in entry["results"].items() if own(k)}
        for tool in others:
            if before is not None and tool in before["results"]:
                results[tool] = before["results"][tool]
            else:
                results[tool] = {"outcome": "skipped", "seconds": 0.0,
                                 "output_tail": "not run: the file was not scanned in the first run"}
        entries.append(dict(entry, results=results))
    skipped = [s for s in new.get("skipped_files", [])]
    skipped += [{"file": e["file"], "reason": "not scanned in the second run", "run": "after",
                 "size": e.get("size") or 0} for e in first.values()]
    tools = [t for t in new.get("tools", []) if own(t)] + others
    meta = {k: v for k, v in new.items() if k not in ("entries", "summary", "groups", "skipped_files", "tools")}
    meta["combined"] = {"safeloadai_columns": new_name, "other_columns": old_name}
    return dict(meta, tools=tools, skipped_files=skipped, entries=entries)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("old", help="the first run: the other scanners' columns come from here")
    parser.add_argument("new", help="the run of safeloadai again on the same files")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    with open(args.old, encoding="utf-8") as fh:
        old = json.load(fh)
    with open(args.new, encoding="utf-8") as fh:
        new = json.load(fh)
    out = combine(old, new, os.path.basename(args.old), os.path.basename(args.new))
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    print(f"{len(out['entries'])} files; {len(out['skipped_files'])} skipped; wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
