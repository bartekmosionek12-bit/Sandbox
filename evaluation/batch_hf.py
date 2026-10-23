"""Measure safeloadai on many more Hub files without keeping them: plan, then download,
scan and delete in batches.

    pip install huggingface_hub
    # 1. plan (Hub API only, nothing downloaded)
    python evaluation/batch_hf.py plan-benign --work /tmp/hf_batches --target 3000
    python evaluation/batch_hf.py plan-benign --work /tmp/hf_tune2 --split tune2 --target 3000
    python evaluation/batch_hf.py plan-unsafe --work /tmp/hf_batches
    # 2. download a batch, scan it with every tool, write the results, delete the files; repeat
    python evaluation/batch_hf.py run --work /tmp/hf_batches --plan benign \\
        --tool-bin DIR --opt-in-site DIR
    # 3. the labels for review, and one results file from all batches
    python evaluation/batch_hf.py labels --work /tmp/hf_batches --out evaluation/hf_heldout2_labels.tsv
    python evaluation/batch_hf.py merge --work /tmp/hf_batches --work /tmp/hf_pinned \\
        --add private/eval-080/eval-final-corpora-STAMP.json --out private/eval-080/eval-NAME.json

**held-out-2** is a third benign split: repos that no earlier corpus used (not in
``evaluation/splits/hf-tune.txt`` or ``hf-heldout.txt``, nor in any committed results
file or the hf-malicious manifest), with the same strata as ``fetch_benign_hf.py``. It
is never used for tuning: no allowlist entry may be chosen from it.

**tune-2** (``--split tune2``, 0.9.0) is a second tuning split planned the same way from
repos no earlier corpus used, held-out-2 included, with the same strata scaled to its
target plus three data-only strata (``DATA_STRATA``: safetensors, GGUF, NumPy) for the
structural validators. Allowlist work may read it, like the tune half.

**unsafe** files are Hub files the Hub's own scanners flag (``filesWithIssues``) that
no earlier corpus has, from the repos the benign planning visited and from the
searches of ``fetch_malicious_hf.py``. They are only scanned. Their labels come from
the Hub's per-file evidence (``proposed_label``) and a manual review of that evidence,
never from safeloadai's verdict. A held-out-2 file the Hub flags gets the same
treatment: it is benign only after that review.

Disk: at most ``--batch-files`` files (default 200) and ``--batch-gb`` GiB (default 4)
are on disk at once, plus the other scanners' temporary copies. After a batch is
scanned and its results JSON is written, its files are deleted; ``WORK/manifest.jsonl``
keeps repo, commit, file, sha256, size, format, library, downloads and the Hub's scan
status of every file, so each one can be fetched again (``fetch_pinned_hf.py``).

The safety rules of ``fetch_benign_hf.py`` apply: files are only downloaded (pinned to
the planned commit, weight-file extensions only) and hashed; the only consumer is
``run_eval.py``, which calls ``scan()`` under the evaluation guard. Keep WORK outside
the repository.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fetch_benign_hf import (  # noqa: E402
    DATA_STRATA,
    STRATA,
    _listing,
    _model_info,
    candidate_files,
    download,
    file_format,
    hub_scan_level,
)
from fetch_malicious_hf import _security, candidate_repos, flagged_files, proposed_label  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
SPLIT = "heldout2"
# Splits planned here (repos no earlier corpus used). A file the Hub flags is ``unclear`` in
# them until reviewed. tune2 may be read for allowlist work; heldout2 never.
NEW_SPLITS = (SPLIT, "tune2")
DOWNLOAD_THREADS = 8
LISTING_EXPAND = ["siblings", "sha", "gated", "private", "downloads"]
FLAGGED_LEVELS = frozenset({"unsafe", "suspicious", "caution", "error", "issue"})
DEFAULT_MAX_MB = 100


def _jsonl(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _append(path: str, entry: dict) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")


def used_repos(work: str) -> set[str]:
    """Every repo an earlier corpus used: the split lists, committed results, hf-malicious."""
    repos: set[str] = set()
    for name in ("hf-tune.txt", "hf-heldout.txt", "hf-tune2.txt"):
        path = os.path.join(HERE, "splits", name)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                repos.update(line.split("#", 1)[0].strip() for line in fh if line.split("#", 1)[0].strip())
    for path in glob.glob(os.path.join(HERE, "results", "eval-*.json")):
        with open(path, encoding="utf-8") as fh:
            run = json.load(fh)
        repos.update(e["repo_id"] for e in run.get("entries", []) if e.get("repo_id"))
    for name in ("hf_malicious_labels.tsv", "hf_batches_labels.tsv", "hf_tune2_labels.tsv"):
        path = os.path.join(HERE, name)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                repos.update(line.split("\t", 1)[0] for line in fh if line.strip() and not line.startswith("#"))
    return repos


def _planned(work: str) -> set[tuple[str, str]]:
    return {(e["repo_id"], e["filename"]) for name in ("plan-benign.jsonl", "plan-unsafe.jsonl")
            for e in _jsonl(os.path.join(work, name))}


def _evidence(api, repo_id: str, revision: str, names: list[str]) -> dict:
    try:
        return {p.path: _security(getattr(p, "security", None))
                for p in api.get_paths_info(repo_id, names, expand=True, revision=revision)}
    except Exception as exc:  # noqa: BLE001 - gated or private repos have no evidence
        print(f"{repo_id}: no scan evidence ({type(exc).__name__})", file=sys.stderr)
        return {}


def _plan_entry(info, model, name, size, lfs_sha, fmt, library, stratum, evidence=None, split=SPLIT) -> dict:
    level = hub_scan_level(info, name)
    entry = {"repo_id": info.id, "revision": info.sha, "filename": name, "size": size, "lfs_sha256": lfs_sha,
             "format": fmt, "library": library, "stratum": stratum, "split": split,
             "downloads": getattr(model, "downloads", None) if model is not None else getattr(info, "downloads", None),
             "hub_scan": level, "planned_at": datetime.now(UTC).isoformat()}
    if level in FLAGGED_LEVELS:
        label, reason = proposed_label((evidence or {}).get(name))
        entry.update(hub_evidence=(evidence or {}).get(name), proposed_label=label, label_reason=reason)
    return entry


def plan_benign(work: str, target: int, max_bytes: int, split: str = SPLIT) -> int:
    """Pick about ``target`` files from repos no earlier corpus used. Flagged files found on
    the way go to the unsafe plan as well (scanned once, as held-out-2 files). tune2 adds
    the data-only strata (their fixed targets come out of ``target``)."""
    import huggingface_hub as hub

    api = hub.HfApi()
    used, planned = used_repos(work), _planned(work)
    plan = os.path.join(work, "plan-benign.jsonl")
    strata = dict(STRATA, **DATA_STRATA) if split == "tune2" else STRATA
    have = {s: 0 for s in strata}
    for e in _jsonl(plan):
        have[e["stratum"]] = have.get(e["stratum"], 0) + 1
    fixed = sum(s["target"] for s in DATA_STRATA.values()) if split == "tune2" else 0
    scale = (target - fixed) / sum(s["target"] for s in STRATA.values())
    added = 0
    for stratum, spec in strata.items():
        goal = spec["target"] if stratum in DATA_STRATA else max(1, round(spec["target"] * scale))
        seen: set[str] = set()
        # the listing carries each repo's file names, so only repos with a file of the
        # stratum's format cost a model_info call (sizes, LFS hashes and scan status)
        for tag, listing in _listing(api, spec, goal * 4, LISTING_EXPAND):
            if have[stratum] >= goal:
                break
            try:
                models = listing()
            except Exception as exc:  # noqa: BLE001
                print(f"listing {tag}: {exc}", file=sys.stderr)
                continue

            def wanted(model, spec=spec, seen=seen) -> bool:
                if model.id in used or model.id in seen or getattr(model, "private", False) \
                        or getattr(model, "gated", False):
                    return False
                seen.add(model.id)
                names = [s.rfilename for s in getattr(model, "siblings", None) or []]
                return not names or any(file_format(n) == spec["fmt"] and (not spec.get("names") or
                                                                          os.path.basename(n) in spec["names"])
                                        for n in names)

            for model, info in _infos(api, (m for m in models if wanted(m)),
                                      lambda stratum=stratum, goal=goal: have[stratum] >= goal):
                if have[stratum] >= goal:
                    break
                if isinstance(info, Exception):
                    print(f"{model.id}: {info}", file=sys.stderr)
                    continue
                if info is None or getattr(info, "gated", False) or getattr(info, "disabled", False):
                    continue
                files = [f for f in candidate_files(info, spec["fmt"], max_bytes, spec.get("prefer", ()),
                                                    spec.get("names", ())) if (model.id, f[0]) not in planned]
                flagged = [f[0] for f in files if hub_scan_level(info, f[0]) in FLAGGED_LEVELS]
                evidence = _evidence(api, model.id, info.sha, flagged) if flagged else {}
                for name, size, lfs_sha in files:
                    if have[stratum] >= goal:
                        break
                    entry = _plan_entry(info, model, name, size, lfs_sha, spec["fmt"], tag, stratum, evidence,
                                        split)
                    _append(plan, entry)
                    planned.add((model.id, name))
                    have[stratum] += 1
                    added += 1
        print(f"{stratum}: {have[stratum]}/{goal} planned", file=sys.stderr)
    return added


def _infos(api, models, done, chunk: int = 32, threads: int = 16):
    """(model, model_info or the exception) for each listed model, ``chunk`` at a time
    fetched in parallel; stops between chunks once ``done()``."""
    from concurrent.futures import ThreadPoolExecutor

    def info(model):
        try:
            return model, _model_info(api, model.id)
        except Exception as exc:  # noqa: BLE001
            return model, exc

    batch = []
    with ThreadPoolExecutor(threads) as pool:
        for model in models:
            batch.append(model)
            if len(batch) >= chunk:
                yield from pool.map(info, batch)
                batch = []
                if done():
                    return
        if batch:
            yield from pool.map(info, batch)


PINNED_GROUPS = ("hf-tune", "hf-heldout")


def plan_pinned(work: str, source: str, groups: tuple[str, ...] = PINNED_GROUPS) -> int:
    """The files of ``groups`` in an earlier results file (by default benign tune and held-out),
    pinned to their commit and sha256 (``fetch_pinned_hf.py``'s rule), so before/after is
    measured on exactly the same files. Each entry keeps its group and label."""
    with open(source, encoding="utf-8") as fh:
        entries = json.load(fh)["entries"]
    plan = os.path.join(work, "plan-pinned.jsonl")
    planned = {(e["repo_id"], e["filename"]) for e in _jsonl(plan)}
    added = 0
    for e in entries:
        if e.get("group") not in groups or not e.get("sha256"):
            continue
        name = e["file"][len(e["repo_id"]) + 1:]
        if (e["repo_id"], name) in planned:
            continue
        fmt = {"pickle": "sklearn", "joblib": "sklearn"}.get(e["format"], e["format"])
        _append(plan, {"repo_id": e["repo_id"], "revision": e["revision"], "filename": name, "size": e["size"],
                       "lfs_sha256": e["sha256"], "format": fmt, "library": e.get("library"),
                       "stratum": e.get("library"), "split": e.get("split"), "hub_scan": e.get("hub_scan", "unknown"),
                       "label": e["label"], "label_reason": e.get("label_reason") or "",
                       "group": e["group"], "pinned_from": os.path.basename(source)})
        added += 1
    return added


def plan_unsafe(work: str, max_bytes: int) -> int:
    """Hub-flagged weight files of the search repos that no earlier corpus has."""
    import huggingface_hub as hub

    api = hub.HfApi()
    with open(os.path.join(HERE, "hf_malicious_labels.tsv"), encoding="utf-8") as fh:
        have = {tuple(line.split("\t", 2)[:2]) for line in fh if line.strip() and not line.startswith("#")}
    for path in glob.glob(os.path.join(HERE, "results", "eval-*.json")):
        with open(path, encoding="utf-8") as fh:
            have |= {(e["repo_id"], e["file"][len(e["repo_id"]) + 1:])
                     for e in json.load(fh).get("entries", []) if e.get("repo_id")}
    planned = _planned(work)
    plan = os.path.join(work, "plan-unsafe.jsonl")
    added = 0
    for repo_id in candidate_repos(api):
        try:
            info = _model_info(api, repo_id)
        except Exception as exc:  # noqa: BLE001
            print(f"{repo_id}: {exc}", file=sys.stderr)
            continue
        if info is None or getattr(info, "gated", False) or getattr(info, "private", False):
            continue  # files of a gated repo cannot be downloaded without an account
        files = [f for f in flagged_files(info, max_bytes) if (repo_id, f[0]) not in have | planned]
        if not files:
            continue
        evidence = _evidence(api, repo_id, info.sha, [f[0] for f in files])
        for name, size, lfs_sha, _level in files:
            entry = _plan_entry(info, None, name, size, lfs_sha, file_format(name), "search", "unsafe", evidence)
            entry.update(split="unsafe", group="hf-unsafe")
            _append(plan, entry)
            planned.add((repo_id, name))
            added += 1
    return added


def batches(entries: list[dict], max_files: int, max_bytes: int) -> list[list[dict]]:
    out, current, size = [], [], 0
    for e in entries:
        if current and (len(current) >= max_files or size + e["size"] > max_bytes):
            out.append(current)
            current, size = [], 0
        current.append(e)
        size += e["size"]
    if current:
        out.append(current)
    return out


def run(work: str, which: str, max_files: int, max_gb: float, eval_args: list[str], limit: int | None,
        final: bool = False, before: str | None = None, skip_before: frozenset[str] = frozenset(),
        skip: frozenset[str] = frozenset(), scanner: str | None = None) -> int:
    """Download, scan and delete one batch after another. A batch whose results file
    exists is skipped, so an interrupted run continues where it stopped. ``before`` is a
    checkout of the previous release: its run_eval.py and src/ scan the same files first
    (results/<plan>/before; this tree's results go to results/<plan>/after). While the plan
    may still grow, the last batch is left for later unless it is full (``final`` runs it).
    ``skip_before`` names files (``repo/file``) the previous release cannot scan in this
    machine's memory: they are left out of its run, so before/after pairs leave them out.
    ``skip`` leaves files out of both runs (this release cannot scan them here either); each
    is recorded in ``WORK/skipped.jsonl`` and reported apart. ``scanner`` is a checkout
    (git worktree) whose run_eval.py and src/ make the after column instead of this tree,
    so a long run keeps one scanner version while this tree changes. Up to
    ``DOWNLOAD_THREADS`` files of a batch download at once."""
    from concurrent.futures import ThreadPoolExecutor

    import huggingface_hub as hub

    entries = _jsonl(os.path.join(work, f"plan-{which}.jsonl"))
    todo = batches(entries, max_files, int(max_gb * 1024 ** 3))
    results = os.path.join(work, "results", which)
    os.makedirs(results, exist_ok=True)
    done = 0
    for number, batch in enumerate(todo, 1):
        if limit is not None and done >= limit:
            break
        label = f"{which}-{number:03d}"
        size = sum(e["size"] for e in batch)
        full = len(batch) >= max_files or size + max(e["size"] for e in batch) > max_gb * 1024 ** 3
        if number == len(todo) and not (full or final):
            print(f"{label}: {len(batch)} files, not full; left for a later run (--final runs it)", file=sys.stderr)
            break
        if glob.glob(os.path.join(results, "after", f"eval-{label}-*.json")):
            continue
        directory = os.path.join(work, "batch")
        if os.path.exists(directory):
            shutil.rmtree(directory)
        os.makedirs(directory)
        fetched = []

        def fetch(e: dict, directory=directory):
            try:
                return e, download(hub, directory, e["repo_id"], e["revision"], e["filename"], e.get("lfs_sha256"))
            except Exception as exc:  # noqa: BLE001
                return e, exc

        with ThreadPoolExecutor(DOWNLOAD_THREADS) as threads:
            for e, got in threads.map(fetch, batch):  # in plan order, whatever finishes first
                if isinstance(got, Exception):
                    print(f"{e['repo_id']}/{e['filename']}: {got}", file=sys.stderr)
                    _append(os.path.join(work, "failed.jsonl"), dict(e, error=f"{type(got).__name__}: {got}"))
                    continue
                entry = dict(e, **got, fetched_at=datetime.now(UTC).isoformat(), batch=label)
                _append(os.path.join(directory, "manifest.jsonl"), entry)
                fetched.append(entry)
        print(f"{label}: {len(fetched)}/{len(batch)} files, "
              f"{sum(e['size'] for e in fetched) / 1024 ** 2:.0f} MiB", file=sys.stderr)
        if fetched:
            labels = os.path.join(work, f"labels-{which}.tsv")
            write_labels(work, labels)
            source = ["--hf-malicious", directory] if which == "unsafe" else ["--hf", directory]
            runs = [("after", os.path.join(scanner, "evaluation") if scanner else HERE, eval_args)]
            if before:  # the same files with the release before this one, safeloadai only, same opt-in site
                site = eval_args[eval_args.index("--opt-in-site"):][:2] if "--opt-in-site" in eval_args else []
                runs.insert(0, ("before", os.path.join(before, "evaluation"),
                                ["--jobs", eval_args[1], "--tools", "", *site]))
            started = time.time()
            for name, evaluation, run_args in runs:
                left_out = skip | (skip_before if name == "before" else frozenset())
                files = [source[0], _without(directory, left_out, name)] if left_out else source
                out = os.path.join(results, name)
                os.makedirs(out, exist_ok=True)
                env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(evaluation), "src"))
                command = [sys.executable, os.path.join(evaluation, "run_eval.py"), *files, "--labels", labels,
                           "--label", label, "--out", out, *run_args]
                code = subprocess.call(command, cwd=os.path.dirname(evaluation), env=env)
                if code != 0 or not glob.glob(os.path.join(out, f"eval-{label}-*.json")):
                    print(f"{label} ({name}): run_eval exited {code}; files kept in {directory} for a retry",
                          file=sys.stderr)
                    return 1
            print(f"{label}: scanned in {time.time() - started:.0f} s", file=sys.stderr)
            for entry in fetched:  # the manifest outlives the files
                _append(os.path.join(work, "manifest.jsonl"), {k: v for k, v in entry.items() if k != "path"})
        shutil.rmtree(directory)
        for name in ("before", "after"):
            shutil.rmtree(f"{directory}-{name}", ignore_errors=True)
        done += 1
    return 0


def _without(directory: str, skip: frozenset[str], name: str) -> str:
    """A copy of a batch directory (hard links) whose manifest leaves out ``skip``."""
    copy = f"{directory}-{name}"
    if os.path.exists(copy):
        shutil.rmtree(copy)
    os.makedirs(copy)
    with open(os.path.join(copy, "manifest.jsonl"), "w", encoding="utf-8") as fh:
        for e in _jsonl(os.path.join(directory, "manifest.jsonl")):
            if f"{e['repo_id']}/{e['filename']}" in skip:
                print(f"{e['repo_id']}/{e['filename']}: left out of the {name} run", file=sys.stderr)
                _append(os.path.join(os.path.dirname(directory), "skipped.jsonl"),
                        {"file": f"{e['repo_id']}/{e['filename']}", "run": name, "size": e["size"],
                         "reason": "out of memory on this machine"})
                continue
            target = os.path.join(copy, e["path"])
            os.makedirs(os.path.dirname(target), exist_ok=True)
            os.link(os.path.join(directory, e["path"]), target)
            fh.write(json.dumps(e, sort_keys=True) + "\n")
    return copy


DECLARED_POC = re.compile(r"(^|[-_/])(poc|exploits?|bypass|malicious|backdoor|mfv|rce|evil|payloads?|"
                          r"huntr|hfscanner)([-_/]|$)")


def declared_poc(label: str, reason: str, repo_id: str) -> tuple[str, str]:
    """A file labelled benign from a repository whose name declares a vulnerability proof of
    concept or a scanner test is ``unclear``: being in a popular-library stratum and not
    flagged by the Hub says nothing about it. Decided from the name, never from a verdict."""
    if label == "benign" and DECLARED_POC.search(repo_id.lower()):
        return "unclear", "repository name declares a proof of concept or scanner test; contents not reviewed"
    return label, reason


def write_labels(work: str, path: str) -> None:
    """Labels for run_eval: the reviewed file (WORK/reviewed-labels.tsv) when a file has a
    row there, else the label the Hub's evidence proposes. A held-out-2 file the Hub does
    not flag is benign; one it flags is ``unclear`` until reviewed."""
    reviewed = {}
    review = os.path.join(work, "reviewed-labels.tsv")
    if os.path.exists(review):
        with open(review, encoding="utf-8") as fh:
            for line in fh:
                if line.strip() and not line.startswith("#"):
                    repo, name, _commit, _sha, label, reason = line.rstrip("\n").split("\t", 5)
                    reviewed[(repo, name)] = (label, reason)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# repo\tfile\tcommit\tsha256\tlabel\treason (Hub evidence, then manual review)\n")
        for e in _jsonl(os.path.join(work, "plan-pinned.jsonl")):  # labels as reviewed before
            label, reason = declared_poc(e["label"], e["label_reason"], e["repo_id"])
            fh.write("\t".join([e["repo_id"], e["filename"], e["revision"], e["lfs_sha256"], label,
                                reason.replace("\t", " ")]) + "\n")
        for name in ("plan-benign.jsonl", "plan-unsafe.jsonl"):
            for e in _jsonl(os.path.join(work, name)):
                flagged = "proposed_label" in e
                default = (e["proposed_label"], e["label_reason"]) if flagged else ("benign", "")
                if flagged and e.get("split") in NEW_SPLITS and default[0] != "malicious":
                    default = ("unclear", "Hub flags it; benign only after review: " + default[1])
                label, reason = declared_poc(*reviewed.get((e["repo_id"], e["filename"]), default), e["repo_id"])
                fh.write("\t".join([e["repo_id"], e["filename"], e["revision"], e.get("lfs_sha256") or "-",
                                    label, reason.replace("\t", " ")]) + "\n")


PLAN_GROUP = {"tune": "hf-tune", "heldout": "hf-heldout", SPLIT: "hf-heldout2", "tune2": "hf-tune2"}


def plan_labels(work: str) -> dict[str, tuple[str, str, str]]:
    """(group, label, reason) per ``repo/file``, from the plans and the labels as reviewed
    now: a batch's results keep the label it was scanned with, which a later review may
    have changed, and the release before this one does not know the newer groups."""
    labels = os.path.join(work, "labels-merge.tsv")
    write_labels(work, labels)
    current = {}
    with open(labels, encoding="utf-8") as fh:
        for line in fh:
            if line.strip() and not line.startswith("#"):
                repo, name, _commit, _sha, label, reason = line.rstrip("\n").split("\t", 5)
                current[f"{repo}/{name}"] = (label, reason)
    os.remove(labels)
    out = {}
    for name in ("plan-pinned.jsonl", "plan-benign.jsonl", "plan-unsafe.jsonl"):
        for e in _jsonl(os.path.join(work, name)):
            key = f"{e['repo_id']}/{e['filename']}"
            group = "hf-unsafe" if name == "plan-unsafe.jsonl" else e.get("group") or PLAN_GROUP[e["split"]]
            out[key] = (group, *current[key])
    return out


def merge(works: list[str], out: str, column: str = "after", add: list[str] | None = None) -> int:
    """One results file from every batch of every working directory (entries concatenated;
    group and label from the plans and the current review), plus whole results files
    (``add``: the lab, mutation and hf-malicious run), taken as they are."""
    latest = {}  # a batch retried after a failed run has several files: the last one counts
    for w in works:
        for p in sorted(glob.glob(os.path.join(w, "results", "*", column, "eval-*.json"))):
            latest[(os.path.dirname(p), os.path.basename(p).rsplit("-", 1)[0])] = (w, p)
    files = sorted(latest.values(), key=lambda item: item[1])
    if not files:
        print("no batch results", file=sys.stderr)
        return 1
    planned = {w: plan_labels(w) for w in works}
    rescans = {}  # rescan_tool.py: one tool run again after its setup changed (after column only)
    for w in works if column == "after" else []:
        for path in glob.glob(os.path.join(w, "results", "*", "rescan-*.jsonl")):
            for row in _jsonl(path):
                rescans.setdefault(row["file"], {})[row["tool"]] = row["result"]
    entries, meta = [], None
    for work, path in files:
        with open(path, encoding="utf-8") as fh:
            run_ = json.load(fh)
        meta = meta or {k: v for k, v in run_.items() if k not in ("entries", "summary", "groups",
                                                                     "false_positives", "pareto", "cleared_files")}
        for e in run_["entries"]:
            group, label, reason = planned[work][e["file"]]
            results = dict(e["results"], **rescans.get(e["file"], {}))
            entries.append(dict(e, path=None, group=group, label=label, label_reason=reason, results=results))
    for path in add or []:
        with open(path, encoding="utf-8") as fh:
            entries.extend(json.load(fh)["entries"])
    meta["batches"] = [os.path.basename(p) for _, p in files] + [os.path.basename(p) for p in add or []]
    skipped = {row["file"]: row for w in works for row in _jsonl(os.path.join(w, "skipped.jsonl"))
               if row["run"] == column}
    meta["skipped_files"] = sorted(skipped.values(), key=lambda row: row["file"])
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(dict(meta, entries=entries), fh, indent=1, sort_keys=True)
    print(f"merged {len(files)} batches, {len(entries)} entries into {out}; "
          f"summarise with run_eval.py --from-json {out}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("plan-benign", "plan-unsafe", "plan-pinned", "run", "labels", "merge"):
        p = sub.add_parser(name)
        p.add_argument("--work", required=True, action="append" if name == "merge" else "store",
                       help="working directory outside the repository (merge: repeat for several)")
        if name in ("plan-benign", "plan-unsafe"):
            p.add_argument("--max-mb", type=float, default=DEFAULT_MAX_MB)
        if name == "plan-pinned":
            p.add_argument("--from-json", required=True, help="an evaluation results file (run_eval.py output)")
            p.add_argument("--group", action="append", help=f"groups to pin (default: {', '.join(PINNED_GROUPS)})")
        if name == "plan-benign":
            p.add_argument("--target", type=int, default=3000)
            p.add_argument("--split", choices=NEW_SPLITS, default=SPLIT)
        if name == "run":
            p.add_argument("--plan", choices=("benign", "unsafe", "pinned"), required=True)
            p.add_argument("--batch-files", type=int, default=200)
            p.add_argument("--batch-gb", type=float, default=4.0)
            p.add_argument("--batches", type=int, help="stop after this many batches")
            p.add_argument("--final", action="store_true", help="also run the last batch when it is not full")
            p.add_argument("--before", help="checkout of the previous release (git worktree) for the before column")
            p.add_argument("--skip-before", action="append", default=[], metavar="REPO/FILE",
                           help="a file the previous release cannot scan here (out of memory); repeatable")
            p.add_argument("--skip", action="append", default=[], metavar="REPO/FILE",
                           help="a file left out of both runs (out of memory here too); repeatable")
            p.add_argument("--jobs", default="4")
            p.add_argument("--scanner", help="checkout (git worktree) that scans the after column instead of this tree")
            p.add_argument("--tool-bin", help="directory with picklescan, fickling and modelscan")
            p.add_argument("--opt-in-site", help="unpacked distributions for the --trust-inert-from column")
        if name in ("labels", "merge"):
            p.add_argument("--out", required=True)
        if name == "merge":
            p.add_argument("--column", choices=("before", "after"), default="after")
            p.add_argument("--add", action="append", default=[], help="a whole results file to include as it is")
    args = parser.parse_args(argv)
    works = [os.path.abspath(w) for w in (args.work if isinstance(args.work, list) else [args.work])]
    if any(os.path.commonpath([w, REPO_ROOT]) == REPO_ROOT for w in works):
        parser.error("--work must be outside the repository (downloaded model files are never committed)")
    work = works[0]
    os.makedirs(work, exist_ok=True)
    if args.cmd == "plan-benign":
        print(f"planned {plan_benign(work, args.target, int(args.max_mb * 1024 * 1024), args.split)} files",
              file=sys.stderr)
    elif args.cmd == "plan-pinned":
        groups = tuple(args.group) if args.group else PINNED_GROUPS
        print(f"planned {plan_pinned(work, args.from_json, groups)} files", file=sys.stderr)
    elif args.cmd == "plan-unsafe":
        print(f"planned {plan_unsafe(work, int(args.max_mb * 1024 * 1024))} files", file=sys.stderr)
    elif args.cmd == "run":
        extra = ["--jobs", args.jobs]
        if args.tool_bin:
            extra += ["--tool-bin", os.path.abspath(args.tool_bin), "--tools", "picklescan,fickling,modelscan"]
        else:
            extra += ["--tools", ""]
        extra += ["--opt-in-site", os.path.abspath(args.opt_in_site)] if args.opt_in_site else []
        before = os.path.abspath(args.before) if args.before else None
        return run(work, args.plan, args.batch_files, args.batch_gb, extra, args.batches, args.final, before,
                   frozenset(args.skip_before), frozenset(args.skip),
                   os.path.abspath(args.scanner) if args.scanner else None)
    elif args.cmd == "labels":
        write_labels(work, args.out)
    else:
        return merge(works, args.out, args.column, args.add)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
