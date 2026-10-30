"""Aggregate numbers of a blind split (held-out-3 in 0.10.0, held-out-4 in 0.11.0), and nothing per file.

    python evaluation/blind_aggregate.py --after AFTER.json --before BEFORE.json \\
        --anatomy ANATOMY.json --group hf-heldout3 --out evaluation/results/heldout3-v0100.json

AFTER and BEFORE are ``batch_hf.py merge`` outputs of the same files (kept outside the
repository: they hold per-file results). The output holds counts, rates and timing
percentiles only: no file name, repository, item, reason or per-file value, so it can be
committed and read without looking at the split. Nothing here prints a per-file line.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from make_evaluation_doc import BLOCKS, blocks_of, rule_count, without_rule  # noqa: E402

COLUMNS = ("safeloadai", "safeloadai trust-inert-from", "safeloadai validate-boosters",
           "safeloadai without known-file list", "safeloadai upper bound")


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    return round(values[min(len(values) - 1, int(q * len(values)))], 3)


def blocks(entries: list[dict], tool: str) -> dict:
    c = blocks_of(entries, tool)
    readable = c["clean"] + c["soft"] + c["hard"]
    return {**{b: c[b] for b in BLOCKS}, "benign": sum(c.values()), "readable": readable,
            "fp": c["soft"] + c["hard"], "fpr_readable": round((c["soft"] + c["hard"]) / readable, 4) if readable
            else None}


def summarise(data: dict, group: str) -> dict:
    entries = [e for e in data["entries"] if e.get("group") == group]
    labels = {k: sum(1 for e in entries if e["label"] == k) for k in ("benign", "malicious", "unclear")}
    out = {"safeloadai": data.get("safeloadai"), "created": data.get("created"), "files": len(entries),
           "labels": labels, "poc_rule_unclear": rule_count(entries).get(group, 0), "columns": {}}
    for tool in COLUMNS:
        if not any(tool in e["results"] for e in entries):
            continue
        benign = [e for e in entries if e["label"] == "benign" and tool in e["results"]]
        out["columns"][tool] = {
            "blocks": blocks(entries, tool), "blocks_without_poc_rule": blocks(without_rule(entries), tool),
            "benign_malicious_verdict": sum(1 for e in benign if e["results"][tool].get("verdict") == "MALICIOUS"),
            "malicious_let_through": sum(1 for e in entries if e["label"] == "malicious" and tool in e["results"]
                                         and e["results"][tool].get("verdict") == "CLEAN"),
        }
    trust = [e for e in entries if e["label"] == "benign" and "safeloadai trust-inert-from" in e["results"]]
    if trust:  # counts only: how often the option and the default disagree, in each direction
        clean = [(e["results"]["safeloadai"].get("block") == "clean",
                  e["results"]["safeloadai trust-inert-from"].get("block") == "clean") for e in trust]
        out["trust_vs_default"] = {"loosened": sum(1 for d, t in clean if t and not d),
                                   "tightened": sum(1 for d, t in clean if d and not t)}
    seconds = [e["results"]["safeloadai"]["seconds"] for e in entries if "seconds" in e["results"]["safeloadai"]]
    rss = [max(e["results"]["safeloadai"].get("rss_peak_mb") or 0, e["results"]["safeloadai"].get(
        "children_rss_peak_mb") or 0) for e in entries]
    out["seconds"] = {"median": percentile(seconds, 0.5), "p95": percentile(seconds, 0.95),
                      "max": round(max(seconds), 3) if seconds else None}
    out["rss_peak_mb"] = max(rss) if rss else None
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--after", required=True)
    parser.add_argument("--before")
    parser.add_argument("--anatomy", help="fp_anatomy.py aggregate JSON of the after run")
    parser.add_argument("--group", default="hf-heldout3")
    parser.add_argument("--out", required=True)
    parser.add_argument("--post-review", help="what a review after the measurement found (free text, aggregate)")
    args = parser.parse_args(argv)
    result = {"generated_by": "evaluation/blind_aggregate.py", "group": args.group}
    if args.post_review:
        result["post_review"] = args.post_review
    for name in ("after", "before"):
        path = getattr(args, name)
        if path:
            with open(path, encoding="utf-8") as fh:
                result[name] = summarise(json.load(fh), args.group)
    if args.anatomy:
        with open(args.anatomy, encoding="utf-8") as fh:
            group = json.load(fh)["groups"][args.group]
        result["anatomy"] = {"benign_files": group["benign_files"], "not_clean": group["not_clean"],
                             "floor": group["floor"], "reducible_by_allowlist": group["reducible_by_allowlist"],
                             "classes": {c: {"files": v["files"], "share_of_benign": v["share_of_benign"],
                                             "text": v["text"]} for c, v in group["classes"].items()}}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
