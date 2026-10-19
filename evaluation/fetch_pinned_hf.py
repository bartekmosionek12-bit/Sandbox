"""Re-download exactly the Hub files of an earlier evaluation run, pinned to the same commits.

    pip install huggingface_hub
    python evaluation/fetch_pinned_hf.py --from-json evaluation/results/eval-hub-1k-r3-....json \
        --out /tmp/hf_corpus --out-malicious /tmp/hf_malicious

Discovery (``fetch_benign_hf.py``) depends on what the Hub lists today, so two runs a
week apart see different files. This script rebuilds the same corpus from the entries
of a committed results file instead: repo id, commit, file name and sha256. A file
whose sha256 differs from the recorded one is deleted and reported, never scanned.

The same safety rules as ``fetch_benign_hf.py`` apply: files are only downloaded and
hashed, never loaded or opened by a framework. The output directories have the
manifests ``run_eval.py --hf`` and ``--hf-malicious`` read.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fetch_benign_hf import append_manifest, download, read_manifest  # noqa: E402

os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1")


def pinned_entries(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        run = json.load(fh)
    return [e for e in run["entries"] if e.get("repo_id") and e.get("revision") and e.get("sha256")]


def manifest_entry(entry: dict, result: dict) -> dict:
    filename = entry["file"][len(entry["repo_id"]) + 1:]
    fmt = {"pickle": "sklearn", "joblib": "sklearn"}.get(entry["format"], entry["format"])
    out = {"repo_id": entry["repo_id"], "revision": entry["revision"], "filename": filename, "format": fmt,
           "hub_scan": entry.get("hub_scan", "unknown"), "pinned_from": "eval json", **result}
    if entry["group"] == "hf-malicious":
        out.update(proposed_label=entry["label"], label_reason=entry.get("label_reason") or "")
    else:
        out.update(stratum=entry.get("library"), split=entry.get("split"))
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--from-json", required=True, help="an evaluation results file (run_eval.py output)")
    parser.add_argument("--out", default="/tmp/hf_corpus", help="benign corpus directory (tune and held-out)")
    parser.add_argument("--out-malicious", default="/tmp/hf_malicious", help="hf-malicious directory")
    args = parser.parse_args(argv)
    try:
        import huggingface_hub as hub
    except ImportError:
        parser.error("needs the Hub client only: pip install huggingface_hub")
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    failed = 0
    for entry in pinned_entries(args.from_json):
        out = os.path.abspath(args.out_malicious if entry["group"] == "hf-malicious" else args.out)
        if out == repo_root or out.startswith(repo_root + os.sep):
            parser.error(f"{out} is inside the repository; keep downloaded models outside it")
        os.makedirs(out, exist_ok=True)
        filename = entry["file"][len(entry["repo_id"]) + 1:]
        if any(e["repo_id"] == entry["repo_id"] and e["filename"] == filename for e in read_manifest(out)):
            continue
        try:
            result = download(hub, out, entry["repo_id"], entry["revision"], filename, entry["sha256"])
        except Exception as exc:  # noqa: BLE001 - one missing file should not stop the run
            print(f"{entry['file']}: {exc}", file=sys.stderr)
            failed += 1
            continue
        append_manifest(out, manifest_entry(entry, result))
        print(f"{entry['file']} ({result['size']} bytes)", file=sys.stderr)
    print(f"done, {failed} failed", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
