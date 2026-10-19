"""Generate the source-derived data in src/safeloadai/static/upstream/ (development time only).

    python tools/gen_policies.py [--wheels DIR] [--check]

Reads the wheels pinned in tools/upstream_pins.json (downloaded from files.pythonhosted.org
when missing and verified against the pinned sha256). Each wheel is read as a zip archive
with ``zipfile`` and its ``.py`` members are parsed with ``ast``: nothing is installed,
extracted, imported or run (safeloadai.static.sources says what the analysis checks).

Writes three files, each reviewed and committed like an allowlist change:

* ``inert_modules.json``: for every module of the known distributions whose import chain
  is inert (the module and every package between it and the distribution's top-level
  package only define things), the names its top level binds. Part 1 of 0.7.0: a global
  of such a module that a pickle only references (stores, never calls or hands to a
  call) is no finding.
* ``policies.json``: the classes of the libraries in ``policy_scope`` that are
  state-only (sources.SourceIndex.state_only), with their MRO and reviewed hooks. A
  pickle may rebuild them from a dict state (NEWOBJ () + BUILD), never call them.
* ``REVIEW.md``: what was generated, every hook implementation that keeps a class from
  being state-only (with its sha256, for review), and the skops trusted types, which
  are candidates only: trusted in the skops format, not in pickle.

``--check`` regenerates into memory and exits 1 if the committed files differ (CI).
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from safeloadai.static import sources  # noqa: E402

PINS = os.path.join(ROOT, "tools", "upstream_pins.json")
OUT = os.path.join(ROOT, "src", "safeloadai", "static", "upstream")
DEFAULT_CACHE = os.path.join(os.path.expanduser("~"), ".cache", "safeloadai-upstream")


def load_pins() -> dict:
    with open(PINS, encoding="utf-8") as fh:
        return json.load(fh)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(pins: dict, cache: str) -> dict[str, str]:
    """distribution -> local wheel path, every file verified against its pinned sha256."""
    os.makedirs(cache, exist_ok=True)
    paths = {}
    for dist, pin in pins["distributions"].items():
        path = os.path.join(cache, pin["file"])
        if not os.path.exists(path):
            print(f"downloading {pin['file']}", file=sys.stderr)
            with urllib.request.urlopen(pin["url"], timeout=600) as resp, open(path + ".part", "wb") as out:
                while chunk := resp.read(1 << 20):
                    out.write(chunk)
            os.replace(path + ".part", path)
        got = sha256_file(path)
        if got != pin["sha256"]:
            raise SystemExit(f"{pin['file']}: sha256 {got} does not match the pin {pin['sha256']}")
        paths[dist] = path
    return paths


def inert_chain(index: sources.SourceIndex, module: str, top: str) -> str | None:
    """None when importing ``module`` runs only definitions below the trusted top-level
    package ``top``; otherwise why not."""
    if not sources.library_module(module):
        return "test, command-line or denied module"
    parts = module.split(".")
    for i in range(len(parts), 1, -1):
        name = ".".join(parts[:i])
        if index.module(name) is None:
            if i == len(parts):
                return "no source"
            continue  # a namespace package: no __init__ runs
        why = index.inert(name)
        if why:
            return f"{name}: {why}"
    if parts[0] != top:
        return "outside the distribution"
    return None


def generate(pins: dict, wheels: dict[str, str]) -> dict[str, str]:
    dists = pins["distributions"]
    read, owner = sources.wheel_reader(wheels[d] for d in dists)
    index = sources.SourceIndex(read, known_tops=[t for pin in dists.values() if not pin.get("candidates_only")
                                                  for t in pin["top_level"]])
    top_of = {top: dist for dist, pin in dists.items() for top in pin["top_level"]}
    versions = {dist: {"version": pin["version"], "wheel_sha256": pin["sha256"], "top_level": pin["top_level"]}
                for dist, pin in dists.items()}

    modules: dict[str, list[str]] = {}
    not_inert: collections.Counter = collections.Counter()
    not_inert_why: collections.Counter = collections.Counter()
    for module in sorted(owner):
        top = module.split(".")[0]
        dist = top_of.get(top)
        if dist is None or dists[dist].get("candidates_only"):
            continue
        why = inert_chain(index, module, top)
        if why:
            not_inert[top] += 1
            if why != "test, command-line or denied module":
                not_inert_why[why.split(": ", 1)[-1].split(" (")[0][:90]] += 1
            continue
        modules[module] = sorted(index.module(module).names)

    scope = tuple(pins["policy_scope"])
    state_only: dict[str, dict] = {}
    blocked_by: collections.Counter = collections.Counter()
    totals: collections.Counter = collections.Counter()
    for module in sorted(modules):
        if not any(module == s or module.startswith(s + ".") for s in scope):
            continue
        for cls in index.classes(module):
            totals["classes"] += 1
            verdict = index.state_only(module, cls.name)
            if verdict.state_only:
                if cls.pickled_module != module and cls.pickled_module not in modules:
                    totals["pickled elsewhere"] += 1
                    continue
                state_only[f"{cls.pickled_module}:{cls.name}"] = {
                    "distribution": top_of[module.split(".")[0]],
                    "mro": [f"{m}.{n}" for m, n in verdict.mro],
                    "reviewed_hooks": sorted(verdict.reviewed_hooks),
                }
                continue
            for reason in verdict.reasons:
                if "(sha256 " in reason and " defines " in reason:
                    blocked_by[reason] += 1
                else:
                    blocked_by[_reason_kind(reason)] += 1

    skops = _skops_candidates(index, state_only)
    header = {"generated_by": "tools/gen_policies.py", "distributions": versions}
    inert_json = json.dumps({**header, "modules": modules}, sort_keys=True, separators=(",", ":")) + "\n"
    policies_json = json.dumps({**header, "scope": list(scope), "state_only": state_only},
                               sort_keys=True, separators=(",", ":")) + "\n"
    review = _review(versions, modules, not_inert, not_inert_why, totals, state_only, blocked_by, skops)
    return {"inert_modules.json": inert_json, "policies.json": policies_json, "REVIEW.md": review}


def _reason_kind(reason: str) -> str:
    for marker in ("is not Python source the index reads", "does not resolve", "has the metaclass",
                   "is decorated with", "is a property with a setter", "is a property with a deleter",
                   "defines __slots__", "is assigned, not defined", "differs from the reviewed source",
                   "is not a class"):
        if marker in reason:
            return f"(any class) {marker}"
    return reason


def _skops_candidates(index: sources.SourceIndex, state_only: dict) -> list[tuple[str, str]]:
    """The sklearn internal types skops 0.16 names in skops/io/_trusted_types.py (the
    public estimators it trusts are computed at import time with all_estimators() and
    cannot be read statically). Each is a candidate: (name, its pickle policy status)."""
    import ast

    facts = index.module("skops.io._trusted_types")
    out = []
    if not facts or not facts.tree:
        return out
    for node in ast.walk(facts.tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("sklearn"):
            for alias in node.names:
                if node.module == "sklearn.utils":
                    continue
                key = f"{node.module}:{alias.name}"
                status = "state-only in pickle" if key in state_only else "not state-only in pickle"
                out.append((key, status))
    return sorted(out)


def _review(versions, modules, not_inert, not_inert_why, totals, state_only, blocked_by, skops) -> str:
    lines = ["# Source-derived data: review summary", "",
             "Generated by `tools/gen_policies.py` from the pinned wheels (read with `ast`, never "
             "imported). Regenerate after changing `tools/upstream_pins.json`; CI fails on an "
             "unreviewed difference.", "", "| distribution | version | wheel sha256 |", "|---|---|---|"]
    lines += [f"| {d} | {v['version']} | `{v['wheel_sha256'][:16]}...` |" for d, v in sorted(versions.items())]
    per_dist = collections.Counter(m.split(".")[0] for m in modules)
    lines += ["", "## Inert modules (Part 1)", "", "| top-level package | inert import chain | not inert |",
              "|---|---|---|"]
    lines += [f"| {top} | {n} | {not_inert.get(top, 0)} |" for top, n in sorted(per_dist.items())]
    lines += ["", "(The not-inert count includes test and command-line modules.) Most frequent other reasons, "
              "first offending statement per module:", "", "| reason | modules |", "|---|---|"]
    lines += [f"| `{r.replace('|', '/')}` | {n} |" for r, n in not_inert_why.most_common(40)]
    lines += ["",
              "## State-only classes (Part 2)", "",
              f"{len(state_only)} of {totals['classes']} classes in scope are state-only "
              f"({totals['pickled elsewhere']} more record a `__module__` outside the inert modules and are left out).",
              "", "Why the others are not, most frequent first (a hook line is one implementation, by sha256; "
              "reviewing it as benign for a dict-state BUILD means adding it to "
              "`sources.REVIEWED_HOOKS`):", "", "| reason | classes |", "|---|---|"]
    lines += [f"| {r.replace('|', '/')} | {n} |" for r, n in blocked_by.most_common(60)]
    lines += ["", "## skops trusted types: candidates only", "",
              "skops trusts these types in its own format, where it rebuilds them itself. That says nothing "
              "about pickle, so each is listed with its pickle status and nothing is added because of skops.",
              "", "| type | pickle |", "|---|---|"]
    lines += [f"| `{k}` | {s} |" for k, s in skops]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--wheels", default=DEFAULT_CACHE, help="wheel cache directory")
    parser.add_argument("--check", action="store_true", help="fail if the committed files differ")
    args = parser.parse_args(argv)
    pins = load_pins()
    files = generate(pins, fetch(pins, args.wheels))
    changed = []
    for name, text in files.items():
        path = os.path.join(OUT, name)
        old = open(path, encoding="utf-8").read() if os.path.exists(path) else None
        if old != text:
            changed.append(name)
            if not args.check:
                os.makedirs(OUT, exist_ok=True)
                with open(path, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
    if args.check and changed:
        print("upstream data differs from the pinned sources: " + ", ".join(changed)
              + "\nrun python tools/gen_policies.py and review the diff", file=sys.stderr)
        return 1
    print(("unchanged" if not changed else "wrote " + ", ".join(changed)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
