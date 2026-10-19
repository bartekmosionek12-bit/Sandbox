"""Download real model files from the Hugging Face Hub for the false-positive measurement.

Run this on your own machine (it needs huggingface.co); tests and CI never run it.

    pip install huggingface_hub
    python evaluation/fetch_benign_hf.py --out /tmp/hf_corpus            # discover ~310 files
    python evaluation/fetch_benign_hf.py --out /tmp/hf_corpus --list evaluation/hf_benign.txt

Safety rules this script follows:

* Every file is treated as potentially malicious, whatever its repo, stars or name.
  Nothing is loaded, opened by a framework or deserialized here: files are only
  downloaded and hashed. The only consumer is ``run_eval.py``, which calls
  ``scan()`` under the evaluation guard.
* Only model weight files are fetched, by file name: ``.bin .pt .pth .pkl .pickle
  .joblib .keras .h5``. No ``.py``, notebooks, setup scripts or any other code;
  ``trust_remote_code`` does not exist here because no model class is ever built.
* Downloads are file-level (``huggingface_hub.hf_hub_download``) pinned to the
  commit the listing returned, into ``OUT/files/<repo with / as __>/``.
  ``OUT/manifest.jsonl`` records repo id, commit hash, file name, size and the
  sha256 computed here (checked against the Hub's LFS sha256 when it has one).
* Keep OUT outside the repository (the default is /tmp/hf_corpus; ``hf_corpus/``
  is in .gitignore as well). Never commit downloaded model files; commit only the
  results that ``run_eval.py`` writes.

Hosts: the Hub API and file downloads (huggingface.co; large files are redirected
to Hugging Face's own storage CDN). Telemetry is switched off.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import UTC, datetime

os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1")

FORMATS = {
    ".bin": "torch", ".pt": "torch", ".pth": "torch",
    ".pkl": "sklearn", ".pickle": "sklearn", ".joblib": "sklearn",
    ".keras": "keras", ".h5": "h5",
}
# format -> (target number of files, Hub library filters to search, file-name preference)
PLAN = {
    "torch": (110, ["pytorch"], ("pytorch_model.bin",)),
    "sklearn": (80, ["sklearn", "scikit-learn", "skops", "joblib"], ()),
    "keras": (50, ["keras", "tf-keras"], ("model.keras",)),
    "h5": (70, ["keras", "tf-keras", "tf"], ("tf_model.h5", "model.h5")),
}
MAX_FILES_PER_REPO = 2


def file_format(name: str) -> str | None:
    return FORMATS.get(os.path.splitext(name)[1].lower())


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def read_manifest(out: str) -> list[dict]:
    path = os.path.join(out, "manifest.jsonl")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def append_manifest(out: str, entry: dict) -> None:
    with open(os.path.join(out, "manifest.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")


def read_list(path: str) -> list[tuple[str, str]]:
    pairs = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                repo, name = line.split(None, 1)
                pairs.append((repo, name.strip()))
    return pairs


def candidate_files(info, wanted: str, max_bytes: int, prefer: tuple[str, ...]) -> list[tuple[str, int, str | None]]:
    """(file name, size, lfs sha256) of weight files of format ``wanted`` in one repo."""
    out = []
    for sibling in info.siblings or []:
        name = sibling.rfilename
        if file_format(name) != wanted or sibling.size is None or sibling.size > max_bytes or sibling.size == 0:
            continue
        lfs = getattr(sibling, "lfs", None)
        lfs_sha = getattr(lfs, "sha256", None) if lfs is not None else None
        out.append((name, sibling.size, lfs_sha))
    out.sort(key=lambda f: (os.path.basename(f[0]) not in prefer, f[1]))
    return out[:MAX_FILES_PER_REPO]


def download(api_module, out: str, repo_id: str, revision: str, name: str, lfs_sha: str | None) -> dict:
    target_dir = os.path.join(out, "files", repo_id.replace("/", "__"))
    path = api_module.hf_hub_download(repo_id=repo_id, filename=name, revision=revision, local_dir=target_dir)
    digest = sha256_file(path)
    if lfs_sha and digest != lfs_sha:
        os.remove(path)
        raise ValueError(f"sha256 {digest} does not match the Hub's LFS sha256 {lfs_sha}")
    return {"path": os.path.relpath(path, out), "size": os.path.getsize(path), "sha256": digest}


def discover(hub, out: str, max_bytes: int, only: set[str], done: set[tuple[str, str]], scale: float) -> int:
    api = hub.HfApi()
    fetched = 0
    for fmt, (target, libraries, prefer) in PLAN.items():
        if only and fmt not in only:
            continue
        target = max(1, round(target * scale))
        have = sum(1 for repo, name in done if file_format(name) == fmt)
        seen_repos: set[str] = set()
        for library in libraries:
            if have >= target:
                break
            try:
                models = api.list_models(filter=library, sort="downloads", limit=target * 6)
            except Exception as exc:  # noqa: BLE001 - one failed listing should not stop the run
                print(f"listing {library}: {exc}", file=sys.stderr)
                continue
            for model in models:
                if have >= target:
                    break
                if model.id in seen_repos or getattr(model, "private", False) or getattr(model, "gated", False):
                    continue
                seen_repos.add(model.id)
                try:
                    info = api.model_info(model.id, files_metadata=True)
                except Exception as exc:  # noqa: BLE001
                    print(f"{model.id}: {exc}", file=sys.stderr)
                    continue
                if getattr(info, "gated", False) or getattr(info, "disabled", False):
                    continue
                for name, _size, lfs_sha in candidate_files(info, fmt, max_bytes, prefer):
                    if (model.id, name) in done or have >= target:
                        continue
                    entry = _fetch_one(hub, out, model.id, info.sha, name, lfs_sha, fmt, library,
                                       getattr(model, "downloads", None))
                    if entry:
                        done.add((model.id, name))
                        have += 1
                        fetched += 1
        print(f"{fmt}: {have}/{target} files", file=sys.stderr)
    return fetched


def _fetch_one(hub, out, repo_id, revision, name, lfs_sha, fmt, library, downloads) -> dict | None:
    try:
        result = download(hub, out, repo_id, revision, name, lfs_sha)
    except Exception as exc:  # noqa: BLE001
        print(f"{repo_id} {name}: {exc}", file=sys.stderr)
        return None
    entry = {"repo_id": repo_id, "revision": revision, "filename": name, "format": fmt, "library": library,
             "downloads": downloads, "lfs_sha256": lfs_sha, "fetched_at": datetime.now(UTC).isoformat(), **result}
    append_manifest(out, entry)
    print(f"{repo_id}@{revision[:10]} {name} ({result['size']} bytes)", file=sys.stderr)
    return entry


def from_list(hub, out: str, pairs: list[tuple[str, str]], max_bytes: int, done: set[tuple[str, str]]) -> int:
    api = hub.HfApi()
    fetched = 0
    for repo_id, name in pairs:
        if (repo_id, name) in done or file_format(name) is None:
            continue
        try:
            info = api.model_info(repo_id, files_metadata=True)
        except Exception as exc:  # noqa: BLE001
            print(f"{repo_id}: {exc}", file=sys.stderr)
            continue
        sibling = next((s for s in info.siblings or [] if s.rfilename == name), None)
        if sibling is None or sibling.size is None or sibling.size > max_bytes:
            print(f"{repo_id} {name}: missing or larger than the limit", file=sys.stderr)
            continue
        lfs = getattr(sibling, "lfs", None)
        if _fetch_one(hub, out, repo_id, info.sha, name, getattr(lfs, "sha256", None) if lfs else None,
                      file_format(name), "list", getattr(info, "downloads", None)):
            done.add((repo_id, name))
            fetched += 1
    return fetched


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="/tmp/hf_corpus")
    parser.add_argument("--list", help="explicit '<repo> <file>' list instead of discovery")
    parser.add_argument("--max-mb", type=int, default=300, help="skip files larger than this")
    parser.add_argument("--formats", help="comma-separated subset of: " + ",".join(PLAN))
    parser.add_argument("--scale", type=float, default=1.0, help="multiply every per-format target")
    args = parser.parse_args(argv)
    try:
        import huggingface_hub as hub
    except ImportError:
        parser.error("needs the Hub client only: pip install huggingface_hub")
    out = os.path.abspath(args.out)
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if out == repo_root or out.startswith(repo_root + os.sep):
        parser.error(f"--out {out} is inside the repository; keep downloaded models outside it")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "README.txt"), "w", encoding="utf-8") as fh:
        fh.write("Untrusted model files downloaded by safeloadai's evaluation/fetch_benign_hf.py.\n"
                 "Never load them; only scan them. Do not commit them.\n")
    done = {(e["repo_id"], e["filename"]) for e in read_manifest(out)}
    started = time.time()
    max_bytes = args.max_mb * 1024 * 1024
    if args.list:
        fetched = from_list(hub, out, read_list(args.list), max_bytes, done)
    else:
        only = set(args.formats.split(",")) if args.formats else set()
        fetched = discover(hub, out, max_bytes, only, done, args.scale)
    total = len(read_manifest(out))
    print(f"fetched {fetched} new files ({total} in {out}/manifest.jsonl) in {time.time() - started:.0f}s",
          file=sys.stderr)
    print(f"next: python evaluation/run_eval.py --hf {out} --lab <lab dir> --tool-bin <venv>/bin", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
