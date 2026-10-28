"""Download real model files from the Hugging Face Hub for the false-positive measurement.

Run this on your own machine (it needs huggingface.co); tests and CI never run it.

    pip install huggingface_hub
    python evaluation/fetch_benign_hf.py --out /tmp/hf_corpus            # discover ~1,000 files
    python evaluation/fetch_benign_hf.py --out /tmp/hf_corpus --seed /tmp/old_corpus  # reuse earlier downloads
    python evaluation/fetch_benign_hf.py --out /tmp/hf_corpus --list evaluation/hf_benign.txt

Safety rules this script follows:

* Every file is treated as potentially malicious, whatever its repo, stars or name.
  Nothing is loaded, opened by a framework or deserialized here: files are only
  downloaded and hashed. The only consumer is ``run_eval.py``, which calls
  ``scan()`` under the evaluation guard.
* Only model weight files are fetched, by file name: ``.bin .pt .pth .pkl .pickle
  .joblib .keras .h5`` (and, for tune-2 only, the data formats ``.safetensors .gguf
  .npy .npz``). No ``.py``, notebooks, setup scripts or any other code;
  ``trust_remote_code`` does not exist here because no model class is ever built.
* Downloads are file-level (``huggingface_hub.hf_hub_download``) pinned to the
  commit the listing returned, into ``OUT/files/<repo with / as __>/``.
  ``OUT/manifest.jsonl`` records repo id, commit hash, file name, size and the
  sha256 computed here (checked against the Hub's LFS sha256 when it has one).
* Per file the manifest also records the stratum, the Hub library tag the listing
  used, the repo's download count, and the Hub's own security-scan result for that
  file when the API exposes it (``hub_scan``: unsafe, suspicious, no_issue,
  not_scanned or unknown).
* Every repo is assigned to the "tune" or "held-out" half by a hash of its id
  (``split_of``), never by file, so all files of one repo are on the same side.
  The allowlist review may only look at the tune half; the false-positive rate is
  reported on the held-out half. ``--write-splits DIR`` writes both repo lists.
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
    # data-only formats (0.9.0 structural validators); only the tune2 plan asks for them
    ".safetensors": "safetensors", ".gguf": "gguf", ".npy": "numpy", ".npz": "numpy",
}
# stratum -> what to fetch. ``filters`` are Hub library tags (``search`` is a free-text
# query for the one stratum without a tag); ``names`` restricts to exact file names,
# ``prefer`` orders a repo's files. Targets add up to about 1,000 files.
STRATA = {
    "torch_transformers": {"fmt": "torch", "target": 250, "filters": ["transformers", "pytorch"],
                           "prefer": ("pytorch_model.bin",)},
    "torch_training_args": {"fmt": "torch", "target": 60, "filters": ["transformers"],
                            "names": ("training_args.bin",)},
    "torch_ultralytics": {"fmt": "torch", "target": 60, "filters": ["ultralytics"], "prefer": ()},
    "torch_timm": {"fmt": "torch", "target": 60, "filters": ["timm"], "prefer": ("pytorch_model.bin",)},
    "torch_sentence_transformers": {"fmt": "torch", "target": 60, "filters": ["sentence-transformers"],
                                    "prefer": ("pytorch_model.bin",)},
    "sklearn": {"fmt": "sklearn", "target": 150, "filters": ["sklearn", "scikit-learn", "skops", "joblib"],
                "prefer": ()},
    "sklearn_gbdt": {"fmt": "sklearn", "target": 50, "filters": ["xgboost", "lightgbm", "catboost"], "prefer": ()},
    "pandas": {"fmt": "sklearn", "target": 20, "search": ["pandas", "dataframe"], "prefer": ()},
    "keras": {"fmt": "keras", "target": 140, "filters": ["keras", "tf-keras"], "prefer": ("model.keras",)},
    "h5": {"fmt": "h5", "target": 150, "filters": ["keras", "tf-keras", "tf"], "prefer": ("tf_model.h5", "model.h5")},
}
# Data-only strata, planned for tune-2 only (batch_hf.py --split tune2), each a fixed target.
# NumPy files have no Hub tag of their own: the repos of common library tags are searched.
DATA_STRATA = {
    "safetensors": {"fmt": "safetensors", "target": 150, "filters": ["safetensors"], "prefer": ("model.safetensors",)},
    "gguf": {"fmt": "gguf", "target": 75, "filters": ["gguf"], "prefer": ()},
    "numpy": {"fmt": "numpy", "target": 75, "filters": ["sklearn", "keras", "pytorch", "audio"], "prefer": ()},
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


def candidate_files(info, wanted: str, max_bytes: int, prefer: tuple[str, ...],
                    names: tuple[str, ...] = ()) -> list[tuple[str, int, str | None]]:
    """(file name, size, lfs sha256) of weight files of format ``wanted`` in one repo."""
    out = []
    for sibling in info.siblings or []:
        name = sibling.rfilename
        if file_format(name) != wanted or sibling.size is None or sibling.size > max_bytes or sibling.size == 0:
            continue
        if names and os.path.basename(name) not in names:
            continue
        lfs = getattr(sibling, "lfs", None)
        lfs_sha = getattr(lfs, "sha256", None) if lfs is not None else None
        out.append((name, sibling.size, lfs_sha))
    out.sort(key=lambda f: (os.path.basename(f[0]) not in prefer, f[1]))
    return out[:MAX_FILES_PER_REPO]


# A loader reads these files next to the weights file (0.10.0): the OpenVINO IR .xml of a
# .bin. They are fetched from the same commit when the repo has them, recorded in the
# manifest under ``companions`` and never scanned as files of their own.
COMPANION_MAX_BYTES = 256 * 1024 * 1024


def companion_names(name: str) -> list[str]:
    stem, ext = os.path.splitext(name)
    return [stem + ".xml"] if ext.lower() == ".bin" else []


def download(api_module, out: str, repo_id: str, revision: str, name: str, lfs_sha: str | None) -> dict:
    target_dir = os.path.join(out, "files", repo_id.replace("/", "__"))
    path = api_module.hf_hub_download(repo_id=repo_id, filename=name, revision=revision, local_dir=target_dir)
    digest = sha256_file(path)
    if lfs_sha and digest != lfs_sha:
        os.remove(path)
        raise ValueError(f"sha256 {digest} does not match the Hub's LFS sha256 {lfs_sha}")
    result = {"path": os.path.relpath(path, out), "size": os.path.getsize(path), "sha256": digest}
    companions = [c for c in (_companion(api_module, out, target_dir, repo_id, revision, n)
                              for n in companion_names(name)) if c]
    if companions:
        result["companions"] = companions
    return result


def _companion(api_module, out: str, target_dir: str, repo_id: str, revision: str, name: str) -> dict | None:
    try:
        path = api_module.hf_hub_download(repo_id=repo_id, filename=name, revision=revision, local_dir=target_dir)
    except Exception as exc:  # noqa: BLE001 - most .bin files have no .xml (EntryNotFoundError)
        if type(exc).__name__ not in ("EntryNotFoundError", "RemoteEntryNotFoundError"):
            print(f"{repo_id}/{name}: companion not fetched ({type(exc).__name__})", file=sys.stderr)
        return None
    if os.path.getsize(path) > COMPANION_MAX_BYTES:
        os.remove(path)
        return None
    return {"file": name, "path": os.path.relpath(path, out), "size": os.path.getsize(path),
            "sha256": sha256_file(path)}


def split_of(repo_id: str) -> str:
    """"tune" or "heldout", fixed by the repo id alone (so every file of a repo is on one side)."""
    return "tune" if int(hashlib.sha256(repo_id.encode()).hexdigest(), 16) % 2 == 0 else "heldout"


def hub_scan_level(info, name: str) -> str:
    """The Hub's own security-scan result for one file, as the API reports it."""
    status = getattr(info, "security_repo_status", None) or getattr(info, "securityRepoStatus", None)
    if not isinstance(status, dict):
        return "unknown"
    for item in status.get("filesWithIssues") or []:
        if isinstance(item, dict) and item.get("path") == name:
            return str(item.get("level") or "issue")
    return "no_issue" if status.get("scansDone") else "not_scanned"


def _model_info(api, repo_id: str):
    for attempt in range(4):
        try:
            try:
                return api.model_info(repo_id, files_metadata=True, securityStatus=True)
            except TypeError:  # an older client without securityStatus
                return api.model_info(repo_id, files_metadata=True)
        except Exception as exc:  # noqa: BLE001
            if "429" in str(exc) and attempt < 3:
                time.sleep(30 * (attempt + 1))
                continue
            raise
    return None


def _listing(api, stratum: dict, target: int, expand: list[str] | None = None):
    extra = {"expand": expand} if expand else {}
    for library in stratum.get("filters", []):
        yield library, lambda lib=library: api.list_models(filter=lib, sort="downloads", limit=target * 10, **extra)
    for query in stratum.get("search", []):
        yield query, lambda q=query: api.list_models(search=q, sort="downloads", limit=target * 10, **extra)


def discover(hub, out: str, max_bytes: int, only: set[str], done: set[tuple[str, str]], scale: float,
             seed: str | None = None) -> int:
    api = hub.HfApi()
    fetched = 0
    entries = read_manifest(out)
    seeds = {(e["repo_id"], e["filename"], e["revision"]): e for e in read_manifest(seed)} if seed else {}
    for name, stratum in STRATA.items():
        fmt = stratum["fmt"]
        if only and name not in only and fmt not in only:
            continue
        target = max(1, round(stratum["target"] * scale))
        have = sum(1 for e in entries if e.get("stratum", e.get("format")) in (name,))
        seen_repos: set[str] = set()
        for tag, listing in _listing(api, stratum, target):
            if have >= target:
                break
            try:
                models = listing()
            except Exception as exc:  # noqa: BLE001 - one failed listing should not stop the run
                print(f"listing {tag}: {exc}", file=sys.stderr)
                continue
            for model in models:
                if have >= target:
                    break
                if model.id in seen_repos or getattr(model, "private", False) or getattr(model, "gated", False):
                    continue
                seen_repos.add(model.id)
                try:
                    info = _model_info(api, model.id)
                except Exception as exc:  # noqa: BLE001
                    print(f"{model.id}: {exc}", file=sys.stderr)
                    continue
                if info is None or getattr(info, "gated", False) or getattr(info, "disabled", False):
                    continue
                for fname, _size, lfs_sha in candidate_files(info, fmt, max_bytes, stratum.get("prefer", ()),
                                                             stratum.get("names", ())):
                    if (model.id, fname) in done or have >= target:
                        continue
                    extra = {"stratum": name, "split": split_of(model.id), "hub_scan": hub_scan_level(info, fname)}
                    entry = _fetch_one(hub, out, model.id, info.sha, fname, lfs_sha, fmt, tag,
                                       getattr(model, "downloads", None), extra, seeds, seed)
                    if entry:
                        done.add((model.id, fname))
                        entries.append(entry)
                        have += 1
                        fetched += 1
        print(f"{name}: {have}/{target} files", file=sys.stderr)
    return fetched


def _fetch_one(hub, out, repo_id, revision, name, lfs_sha, fmt, library, downloads, extra=None,
               seeds=None, seed=None) -> dict | None:
    try:
        reused = (seeds or {}).get((repo_id, name, revision))
        if reused and lfs_sha in (None, reused.get("sha256")):
            result = _link_seed(out, seed, reused)
        else:
            result = download(hub, out, repo_id, revision, name, lfs_sha)
    except Exception as exc:  # noqa: BLE001
        print(f"{repo_id} {name}: {exc}", file=sys.stderr)
        return None
    entry = {"repo_id": repo_id, "revision": revision, "filename": name, "format": fmt, "library": library,
             "downloads": downloads, "lfs_sha256": lfs_sha, "fetched_at": datetime.now(UTC).isoformat(),
             **(extra or {}), **result}
    append_manifest(out, entry)
    print(f"{repo_id}@{revision[:10]} {name} ({result['size']} bytes)", file=sys.stderr)
    return entry


def _link_seed(out: str, seed: str, entry: dict) -> dict:
    """Reuse a file an earlier run downloaded at the same commit (hard link, hash re-checked)."""
    source = os.path.join(seed, entry["path"])
    target = os.path.join(out, entry["path"])
    os.makedirs(os.path.dirname(target), exist_ok=True)
    if not os.path.exists(target):
        os.link(source, target)
    digest = sha256_file(target)
    if digest != entry["sha256"]:
        raise ValueError(f"seed file {source} changed: sha256 {digest}")
    return {"path": entry["path"], "size": os.path.getsize(target), "sha256": digest}


def write_splits(manifest: list[dict], directory: str) -> None:
    """Commit-able repo lists of the two halves."""
    os.makedirs(directory, exist_ok=True)
    repos = sorted({e["repo_id"] for e in manifest})
    for half in ("tune", "heldout"):
        with open(os.path.join(directory, f"hf-{half}.txt"), "w", encoding="utf-8") as fh:
            fh.write(f"# {half} half of the Hugging Face benign corpus: split_of(repo_id) == {half!r}\n")
            fh.writelines(f"{r}\n" for r in repos if split_of(r) == half)


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
    parser.add_argument("--formats", help="comma-separated strata or formats: " + ",".join(STRATA))
    parser.add_argument("--scale", type=float, default=1.0, help="multiply every per-stratum target")
    parser.add_argument("--seed", help="an earlier corpus directory whose files (same repo, file, commit) are reused")
    parser.add_argument("--write-splits", metavar="DIR", help="write hf-tune.txt and hf-heldout.txt to DIR")
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
        fetched = discover(hub, out, max_bytes, only, done, args.scale, args.seed)
    total = len(read_manifest(out))
    if args.write_splits:
        write_splits(read_manifest(out), args.write_splits)
    print(f"fetched {fetched} new files ({total} in {out}/manifest.jsonl) in {time.time() - started:.0f}s",
          file=sys.stderr)
    print(f"next: python evaluation/run_eval.py --hf {out} --lab <lab dir> --tool-bin <venv>/bin", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
