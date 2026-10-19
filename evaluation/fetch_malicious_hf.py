"""Download Hub weight files that the Hub's own scanners flag, for the detection measurement.

    python evaluation/fetch_malicious_hf.py --out /tmp/hf_malicious
    python evaluation/fetch_malicious_hf.py --out /tmp/hf_malicious --labels evaluation/hf_malicious_labels.tsv

The same safety rules as ``fetch_benign_hf.py`` apply, with more reason: these files
are expected to be malicious. Nothing is loaded, opened by a framework or
deserialised; files are only downloaded (pinned to a commit, weight-file
extensions only) and hashed. The only consumer is ``run_eval.py --hf-malicious``,
which calls ``scan()`` under the evaluation guard.

Candidates are (1) public scanner test sets and (2) repos found by searching the Hub
for words such as "malicious" or "exploit". A file is kept only when the Hub's
security scan marks it unsafe or suspicious. Per file the manifest records the Hub's
evidence (``get_paths_info(expand=True)``: the pickle-import scan with each import's
safety, and the antivirus scan message), never anything we derived by reading the
file.

Labels come from that evidence alone, by the rule in ``proposed_label``, and are then
reviewed by hand; ``--labels FILE`` writes ``<repo> <file> <label> <reason>`` lines
for that review. A file the evidence does not settle (a pickle whose only "dangerous"
import is ``getattr``, a Keras file the Hub did not scan) is ``unclear`` and stays out
of the detection rate.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fetch_benign_hf import (  # noqa: E402
    _model_info,
    append_manifest,
    download,
    file_format,
    read_manifest,
)

# Public scanner test sets (each repo states that its files are test payloads).
KNOWN_REPOS = (
    "ScanMe/test-models",
    "IHasFarms/MaliciousModel",
    "hfscanner/model",
    "mcpotato/42-eicar-street",
    "ykilcher/totally-harmless-model",
)
SEARCH_TERMS = ("malicious", "exploit", "rce", "payload", "backdoor", "poc", "evil", "unsafe", "pickle",
                "bypass", "reverse-shell", "picklescan", "vulnerable", "pwn", "malware", "trojan")
SEARCH_LIMIT = 60
MAX_REPOS = 600

# Imports the Hub reports as "dangerous" that run code or touch the system by themselves.
SINK_IMPORTS = {
    ("builtins", "eval"), ("builtins", "exec"), ("builtins", "compile"), ("builtins", "__import__"),
    ("builtins", "open"), ("builtins", "breakpoint"),
    ("__builtin__", "eval"), ("__builtin__", "exec"), ("__builtin__", "__import__"), ("__builtin__", "open"),
}
SINK_MODULES = {"os", "posix", "nt", "subprocess", "runpy", "socket", "webbrowser", "pty", "shutil",
                "requests", "urllib", "httplib", "http", "sys", "ctypes", "pip", "importlib", "code",
                "commands", "pdb", "timeit", "cProfile", "profile", "aiohttp"}


def proposed_label(security: dict | None) -> tuple[str, str]:
    """(label, reason) from the Hub's evidence for one file: malicious, unclear."""
    if not security:
        return "unclear", "no per-file scan evidence"
    av = security.get("av_scan") or {}
    pis = security.get("pickle_import_scan") or {}
    dangerous = [(i.get("module", ""), i.get("name", "")) for i in pis.get("pickleImports") or []
                 if i.get("safety") == "dangerous"]
    sinks = sorted({f"{m}.{n}" for m, n in dangerous
                    if (m, n) in SINK_IMPORTS or m.split(".")[0] in SINK_MODULES})
    if sinks:
        return "malicious", "Hub pickle scan: dangerous import " + ", ".join(sinks)
    if av.get("status") not in (None, "safe") and "signature" in str(av.get("message", "")).lower():
        return "malicious", "Hub antivirus scan: " + str(av.get("message"))[:200]
    if dangerous:
        return "unclear", "Hub pickle scan: only " + ", ".join(sorted({f"{m}.{n}" for m, n in dangerous}))
    return "unclear", f"Hub status {security.get('status')!r} with no dangerous import or signature"


def _security(info) -> dict | None:
    if info is None:
        return None
    return {"status": getattr(info, "status", None), "safe": getattr(info, "safe", None),
            "av_scan": getattr(info, "av_scan", None), "pickle_import_scan": getattr(info, "pickle_import_scan", None)}


def flagged_files(info, max_bytes: int) -> list[tuple[str, int, str | None, str]]:
    status = getattr(info, "security_repo_status", None) or {}
    levels = {i.get("path"): i.get("level") for i in status.get("filesWithIssues") or [] if isinstance(i, dict)}
    out = []
    for sibling in info.siblings or []:
        name = sibling.rfilename
        if name not in levels or file_format(name) is None:
            continue
        if sibling.size is None or sibling.size == 0 or sibling.size > max_bytes:
            continue
        lfs = getattr(sibling, "lfs", None)
        out.append((name, sibling.size, getattr(lfs, "sha256", None) if lfs is not None else None, levels[name]))
    return out


def candidate_repos(api) -> list[str]:
    repos = list(KNOWN_REPOS)
    for term in SEARCH_TERMS:
        try:
            for model in api.list_models(search=term, limit=SEARCH_LIMIT):
                repos.append(model.id)
        except Exception as exc:  # noqa: BLE001
            print(f"search {term!r} failed: {exc}", file=sys.stderr)
    seen: set[str] = set()
    return [r for r in repos if not (r in seen or seen.add(r))][:MAX_REPOS]


def fetch(out: str, max_bytes: int) -> int:
    import huggingface_hub as hub

    api = hub.HfApi()
    done = {(e["repo_id"], e["filename"]) for e in read_manifest(out)}
    fetched = 0
    for repo_id in candidate_repos(api):
        try:
            info = _model_info(api, repo_id)
        except Exception as exc:  # noqa: BLE001
            print(f"{repo_id}: {exc}", file=sys.stderr)
            continue
        files = [f for f in flagged_files(info, max_bytes) if (repo_id, f[0]) not in done] if info else []
        if not files:
            continue
        try:
            evidence = {p.path: p for p in api.get_paths_info(repo_id, [f[0] for f in files], expand=True,
                                                             revision=info.sha)}
        except Exception as exc:  # noqa: BLE001 - gated or private repos are skipped
            print(f"{repo_id}: no scan evidence ({type(exc).__name__}), skipped", file=sys.stderr)
            continue
        for name, _size, lfs_sha, level in files:
            security = _security(getattr(evidence.get(name), "security", None))
            label, reason = proposed_label(security)
            try:
                entry = download(hub, out, repo_id, info.sha, name, lfs_sha)
            except Exception as exc:  # noqa: BLE001
                print(f"{repo_id}/{name}: {exc}", file=sys.stderr)
                continue
            entry.update({"repo_id": repo_id, "revision": info.sha, "filename": name, "format": file_format(name),
                          "hub_scan": level, "hub_evidence": security, "proposed_label": label,
                          "label_reason": reason, "downloads": getattr(info, "downloads", None),
                          "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
            append_manifest(out, entry)
            fetched += 1
            print(f"{repo_id}@{info.sha[:10]} {name} [{level}] -> {label}: {reason[:100]}")
    return fetched


def write_labels(out: str, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# repo<TAB>file<TAB>commit<TAB>sha256<TAB>label<TAB>reason (from the Hub's scan evidence only;\n"
                 "# reviewed by hand, see evaluation/results/review-hf-malicious-*.md)\n")
        for e in sorted(read_manifest(out), key=lambda e: (e["repo_id"], e["filename"])):
            fh.write("\t".join([e["repo_id"], e["filename"], e["revision"], e["sha256"], e["proposed_label"],
                                e["label_reason"]]) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", default="/tmp/hf_malicious")
    parser.add_argument("--max-mb", type=float, default=100)
    parser.add_argument("--labels", help="write the label file for review to this path (no download)")
    args = parser.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    if args.labels:
        write_labels(args.out, args.labels)
        return 0
    n = fetch(args.out, int(args.max_mb * 1024 * 1024))
    print(f"fetched {n} flagged files ({len(read_manifest(args.out))} in {args.out}/manifest.jsonl)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
