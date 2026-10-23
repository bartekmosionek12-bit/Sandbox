"""Download a model file from the Hugging Face Hub, scan it, and load it only if CLEAN.

    pip install safeloadai huggingface_hub
    python examples/huggingface_safe_download.py ORG/REPO FILENAME --revision COMMIT_SHA

What it does, in order:

1. ``hf_hub_download`` fetches exactly one file at a pinned revision (a commit sha, so
   the bytes cannot change between review and use). Downloading only writes bytes to
   the cache; nothing is deserialized.
2. ``safeloadai.scan`` reads the file without loading it and prints the verdict and
   its first reasons.
3. Only with ``--load``: ``safeloadai.safe_load`` scans a private copy again and loads
   that same copy only if the verdict is CLEAN (with restricted loaders:
   allowlisted pickle globals only, ``torch.load(weights_only=True)``, Keras
   ``safe_mode=True``). Anything else raises ``UnsafeModelError``; there is no switch
   that loads a file anyway.

Exit code: 0 CLEAN, 1 MALICIOUS, 3 SUSPICIOUS, 5 UNSUPPORTED, 6 ERROR (as ``safeloadai
scan``), 2 for a usage or download error.
"""
from __future__ import annotations

import argparse
import re
import sys

EXIT = {"CLEAN": 0, "MALICIOUS": 1, "SUSPICIOUS": 3, "UNSUPPORTED": 5, "ERROR": 6}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("repo_id", help="for example openai-community/gpt2")
    parser.add_argument("filename", help="file in the repository, for example pytorch_model.bin")
    parser.add_argument("--revision", required=True,
                        help="the commit sha to download (a branch or tag can move after you scanned it)")
    parser.add_argument("--repo-type", default="model", choices=("model", "dataset", "space"))
    parser.add_argument("--load", action="store_true", help="load the file with safe_load if it is CLEAN")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision):
        parser.error("--revision must be a full 40-character commit sha")

    from huggingface_hub import hf_hub_download

    import safeloadai

    try:
        path = hf_hub_download(args.repo_id, args.filename, revision=args.revision, repo_type=args.repo_type)
    except Exception as exc:  # noqa: BLE001 - network, auth, missing file
        print(f"download failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    report = safeloadai.scan(path)
    print(f"{report.outcome}  {args.repo_id}@{args.revision[:12]}/{args.filename}  sha256 {report.sha256}")
    if not report.ok:
        print(f"    [{report.error['code']}] {report.error['message']}")
    for finding in report.findings[:10]:
        print(f"    [{finding['category']}] {finding['text']}")

    if args.load and report.clean:
        obj = safeloadai.safe_load(path)  # scans its own private copy again before loading
        print(f"loaded: {type(obj).__module__}.{type(obj).__qualname__}")
    elif args.load:
        print("not loaded: only a CLEAN file is loaded", file=sys.stderr)
    return EXIT[report.outcome]


if __name__ == "__main__":
    raise SystemExit(main())
