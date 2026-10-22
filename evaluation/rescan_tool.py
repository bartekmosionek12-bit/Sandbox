"""Run one other scanner again on some files of an evaluation, after its setup changed.

    # Hub files: download in batches, scan with the one tool, delete (batch_hf.py's rules)
    python evaluation/rescan_tool.py hub --work /tmp/hf_batches --plan benign --tool modelscan --ext .keras \\
        --tool-bin DIR
    # local corpora: the files are still on disk
    python evaluation/rescan_tool.py local RESULT.json --root lab=DIR --root mutations=DIR \\
        --tool modelscan --ext .keras --tool-bin DIR --out NEW.json

Used when modelscan's tensorflow extra was added: it reads ``.keras`` only with that
extra, so the first runs recorded those files as unsupported. ``hub`` writes
``WORK/results/PLAN/rescan-TOOL.jsonl`` (one ``{"file", "tool", "result"}`` line per
file), which ``batch_hf.py merge`` lays over the batch results. ``local`` writes a copy of
a results file with that tool's results replaced. ``run_eval.SKIP`` still applies (no
``.h5`` through modelscan on the host).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import batch_hf  # noqa: E402
import run_eval  # noqa: E402


def hub(work: str, plan: str, tool: str, exts: tuple[str, ...], tool_bin: str, max_files: int,
        max_gb: float) -> int:
    import huggingface_hub as hf

    entries = [e for e in batch_hf._jsonl(os.path.join(work, f"plan-{plan}.jsonl"))
               if os.path.splitext(e["filename"])[1].lower() in exts]
    out = os.path.join(work, "results", plan, f"rescan-{tool}.jsonl")
    done = {json.loads(line)["file"] for line in open(out, encoding="utf-8")} if os.path.exists(out) else set()
    todo = [e for e in entries if f"{e['repo_id']}/{e['filename']}" not in done]
    for number, batch in enumerate(batch_hf.batches(todo, max_files, int(max_gb * 1024 ** 3)), 1):
        directory = os.path.join(work, "batch")
        if os.path.exists(directory):
            shutil.rmtree(directory)
        os.makedirs(directory)
        scanned = 0
        for e in batch:
            key = f"{e['repo_id']}/{e['filename']}"
            try:
                got = batch_hf.download(hf, directory, e["repo_id"], e["revision"], e["filename"],
                                        e.get("lfs_sha256"))
            except Exception as exc:  # noqa: BLE001
                print(f"{key}: {exc}", file=sys.stderr)
                continue
            path = os.path.join(directory, got["path"])
            batch_hf._append(out, {"file": key, "tool": tool, "result": run_eval.run_tool(tool, path, tool_bin)})
            os.remove(path)
            scanned += 1
        shutil.rmtree(directory)
        print(f"rescan {plan} {number}: {scanned}/{len(batch)} files", file=sys.stderr)
    return 0


def local(result: str, roots: dict[str, str], tool: str, exts: tuple[str, ...], tool_bin: str, out: str) -> int:
    with open(result, encoding="utf-8") as fh:
        run = json.load(fh)
    count, manifests = 0, {}
    for group, root in roots.items():  # a fetched Hub directory names its files in manifest.jsonl
        manifests[group] = {f"{m['repo_id']}/{m['filename']}": os.path.join(root, m["path"])
                            for m in batch_hf._jsonl(os.path.join(root, "manifest.jsonl"))}
    for e in run["entries"]:
        if e["group"] in roots and os.path.splitext(e["file"])[1].lower() in exts:
            path = manifests[e["group"]].get(e["file"]) or os.path.join(roots[e["group"]], e["file"])
            if not os.path.exists(path):
                print(f"{path}: missing", file=sys.stderr)
                return 1
            e["results"][tool] = run_eval.run_tool(tool, path, tool_bin)
            count += 1
    run.setdefault("rescans", []).append({"tool": tool, "ext": list(exts), "files": count})
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(run, fh, indent=1, sort_keys=True)
    print(f"rescanned {count} files with {tool}; wrote {out}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("hub", "local"):
        p = sub.add_parser(name)
        p.add_argument("--tool", required=True, choices=tuple(run_eval.TOOLS))
        p.add_argument("--ext", action="append", required=True, help="file extension to rescan; repeatable")
        p.add_argument("--tool-bin", required=True)
        if name == "hub":
            p.add_argument("--work", required=True)
            p.add_argument("--plan", required=True, choices=("benign", "unsafe", "pinned"))
            p.add_argument("--batch-files", type=int, default=200)
            p.add_argument("--batch-gb", type=float, default=4.0)
        else:
            p.add_argument("result")
            p.add_argument("--root", action="append", required=True, help="GROUP=DIR; repeatable")
            p.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    exts = tuple(x.lower() for x in args.ext)
    tool_bin = os.path.abspath(args.tool_bin)
    if args.cmd == "hub":
        return hub(os.path.abspath(args.work), args.plan, args.tool, exts, tool_bin, args.batch_files, args.batch_gb)
    roots = dict(r.split("=", 1) for r in args.root)
    return local(args.result, roots, args.tool, exts, tool_bin, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
