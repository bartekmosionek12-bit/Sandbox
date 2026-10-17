"""Download benign model files from the Hugging Face Hub for false-positive
measurement. Run it on your own machine; it is never run by tests or CI.

    python evaluation/fetch_benign_hf.py OUT_DIR [--list evaluation/hf_benign.txt] [--max-mb 200]

Files are written as OUT_DIR/<repo with / replaced by __>/<file>, plus
OUT_DIR/manifest.json with URL, size and sha256. The files are only downloaded,
never loaded. Then: python evaluation/run_eval.py --benign OUT_DIR
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

HF = "https://huggingface.co/{repo}/resolve/main/{file}"


def read_list(path: str) -> list[tuple[str, str]]:
    pairs = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                repo, file = line.split(None, 1)
                pairs.append((repo, file.strip()))
    return pairs


def fetch(repo: str, file: str, out: str, max_bytes: int) -> dict:
    url = HF.format(repo=repo, file=file)
    target_dir = os.path.join(out, repo.replace("/", "__"))
    os.makedirs(target_dir, exist_ok=True)
    target = os.path.join(target_dir, os.path.basename(file))
    digest, size = hashlib.sha256(), 0
    request = urllib.request.Request(url, headers={"User-Agent": "safeloadai-eval"})
    with urllib.request.urlopen(request, timeout=60) as resp, open(target + ".part", "wb") as fh:  # noqa: S310
        while chunk := resp.read(1 << 20):
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"larger than {max_bytes} bytes")
            digest.update(chunk)
            fh.write(chunk)
    os.replace(target + ".part", target)
    return {"repo": repo, "file": file, "url": url, "path": os.path.relpath(target, out), "size": size,
            "sha256": digest.hexdigest()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Download benign models from the Hugging Face Hub.")
    parser.add_argument("out")
    parser.add_argument("--list", default=os.path.join(os.path.dirname(__file__), "hf_benign.txt"))
    parser.add_argument("--max-mb", type=int, default=200)
    args = parser.parse_args(argv)
    manifest, failed = [], []
    for repo, file in read_list(args.list):
        try:
            manifest.append(fetch(repo, file, args.out, args.max_mb * 1024 * 1024))
            print(f"ok    {repo}/{file}")
        except (urllib.error.URLError, ValueError, OSError) as exc:
            failed.append({"repo": repo, "file": file, "error": str(exc)})
            print(f"skip  {repo}/{file}: {exc}", file=sys.stderr)
    with open(os.path.join(args.out, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump({"downloaded": manifest, "failed": failed}, fh, indent=2)
    print(f"{len(manifest)} downloaded, {len(failed)} skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
