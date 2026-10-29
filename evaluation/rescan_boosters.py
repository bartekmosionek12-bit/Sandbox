"""Scan the --validate-boosters column again after a fix to that option (0.10.0).

    python evaluation/rescan_boosters.py --work /tmp/hf_batches --plan pinned --scanner WORKTREE

Only Hub files whose default result names a Booster class among its missing entries are
downloaded again (pinned to commit and sha256, ``batch_hf.py``'s rules), scanned with
``validate_boosters=True`` by the scanner in ``--scanner`` and deleted.
``WORK/results/PLAN/rescan-boosters.jsonl`` gets one ``{"file", "tool", "result"}`` line
per file, which ``batch_hf.py merge`` lays over the batch results. Nothing is printed per
file, so the script can run on a blind split.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import batch_hf  # noqa: E402

TOOL = "safeloadai validate-boosters"
WORKER = r"""
import json, sys, time
sys.path[:0] = [sys.argv[1], sys.argv[2]]
import guard
guard.activate()
import run_eval
from safeloadai import scan
for line in sys.stdin:
    key, path = json.loads(line)
    t = time.perf_counter()
    try:
        result = run_eval._column(scan(path, validate_boosters=True), time.perf_counter() - t)
    except Exception as exc:  # noqa: BLE001
        result = {"outcome": "error", "error": f"{type(exc).__name__}: {exc}", "seconds": 0.0, "block": "error"}
    print(json.dumps({"file": key, "tool": "safeloadai validate-boosters", "result": result}), flush=True)
"""


def wanted(work: str, plan: str) -> set[str]:
    names = {f"{m}.{q}" for m, q in (("xgboost.core", "Booster"), ("lightgbm.basic", "Booster"))} | {
        f"catboost.core.{n}" for n in ("CatBoost", "CatBoostClassifier", "CatBoostRegressor", "CatBoostRanker")}
    out = set()
    for path in glob.glob(os.path.join(work, "results", plan, "after", "eval-*.json")):
        with open(path, encoding="utf-8") as fh:
            for e in json.load(fh)["entries"]:
                r = e["results"].get("safeloadai") or {}
                if r.get("outcome") != "clean" and names.intersection(r.get("missing") or []):
                    out.add(e["file"])
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--work", required=True)
    parser.add_argument("--plan", required=True, choices=("benign", "unsafe", "pinned"))
    parser.add_argument("--scanner", required=True, help="git worktree whose src/ scans")
    args = parser.parse_args(argv)
    import huggingface_hub as hf

    work = os.path.abspath(args.work)
    keys = wanted(work, args.plan)
    out = os.path.join(work, "results", args.plan, "rescan-boosters.jsonl")
    done = {json.loads(line)["file"] for line in open(out, encoding="utf-8")} if os.path.exists(out) else set()
    plan = [e for e in batch_hf._jsonl(os.path.join(work, "manifest.jsonl"))
            if f"{e['repo_id']}/{e['filename']}" in keys - done]
    directory = os.path.join(work, "batch-boosters")
    worker = subprocess.Popen([sys.executable, "-I", "-c", WORKER, os.path.join(args.scanner, "src"), HERE],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    count = 0
    for e in plan:
        shutil.rmtree(directory, ignore_errors=True)
        os.makedirs(directory)
        key = f"{e['repo_id']}/{e['filename']}"
        try:
            got = batch_hf.download(hf, directory, e["repo_id"], e["revision"], e["filename"], e.get("lfs_sha256"))
        except Exception:  # noqa: BLE001
            continue
        worker.stdin.write(json.dumps([key, os.path.join(directory, got["path"])]) + "\n")
        worker.stdin.flush()
        batch_hf._append(out, json.loads(worker.stdout.readline()))
        count += 1
    shutil.rmtree(directory, ignore_errors=True)
    worker.stdin.close()
    worker.wait()
    print(f"rescanned {count} of {len(keys)} files", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
