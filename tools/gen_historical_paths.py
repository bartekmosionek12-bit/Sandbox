"""Old module paths of reviewed classes (0.9.0; development time only).

    python tools/gen_historical_paths.py [--check] [--only DIST]

A pickle records a class by the module that defined it when the file was written. A
scikit-learn 0.21 forest is ``sklearn.ensemble.forest.RandomForestClassifier``; the
reviewed class is ``sklearn.ensemble._forest.RandomForestClassifier``. This tool reads
older releases of each reviewed library from PyPI (``tools/pypi_archives.py``: archives
verified against PyPI's sha256 and read, never installed, extracted, imported or built)
and writes ``src/safeloadai/static/upstream/historical_paths.json``: the exact old
``module:name`` of each reviewed class, the current pair it is, and every release read in
which that path defined it. No prefix and no pattern ever reaches the scanner: each entry
is one exact pair.

An old path is accepted only when all of these hold (the same rules as the pinned
policies, applied to the old release's own source):

1. **Same class.** The release defines a class of the same name at that path (a
   ``ClassDef``, or the ``__module__`` its body sets), the reviewed class is from the same
   distribution, and the path maps to the current one by a rename that keeps the class:
   the same path with leading underscores removed from its parts
   (``ensemble.forest`` -> ``ensemble._forest``, ``numpy.core`` -> ``numpy._core``), the
   parent of the current module (a module later split into a package), or the current
   path with one more part (``ultralytics.yolo.utils.loss`` -> ``ultralytics.utils.loss``),
   or the class name is defined only once in both the old and the current release.
2. **Same review.** In that release the class is state-only (``sources.SourceIndex``:
   NEWOBJ () + dict BUILD runs no code of the class beyond reviewed hooks, by sha256:
   ``sources.REVIEWED_HOOKS`` or, for old releases, ``sources.REVIEWED_OLD_HOOKS``), and
   importing its module runs only definitions (``gen_policies.inert_chain``). Bases from
   another library resolve against that library's pinned release.
3. **Compiled classes** (Cython: no Python source) keep the form of the reviewed pair
   (an exact allowlist entry). An old name is accepted only from the type name compiled
   into the release's extension module (``tp_name``, read as bytes, never loaded), when
   it is the reviewed module path or its last parts (scikit-learn 1.5.0 built
   ``sklearn._loss._loss`` types as ``_loss.CyHalfBinomialLoss``).

Accepted old paths take the reviewed pair's form, never a looser one: a state-only
policy class stays state-only; a class on the plain allowlist (``PICKLE_GLOBALS``) is
accepted under its old path only as state-only. pandas classes with their own argument
checks (``allowlists.PANDAS_*``) keep their exact pairs only and are not aliased.

``--check`` regenerates into memory and exits 1 if the committed file differs.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

from safeloadai.static import allowlists as al  # noqa: E402
from safeloadai.static import sources  # noqa: E402
from tools.gen_policies import inert_chain, load_pins  # noqa: E402
from tools.pypi_archives import Archives, spread  # noqa: E402

OUT = os.path.join(ROOT, "src", "safeloadai", "static", "upstream", "historical_paths.json")
REVIEW = os.path.join(ROOT, "src", "safeloadai", "static", "upstream", "HISTORICAL.md")
FINAL = re.compile(r"\d+(\.\d+)*(\.post\d+)?")
# distribution -> top-level package, which releases are read, and the pinned distributions
# whose source resolves bases from other libraries
DISTRIBUTIONS = {
    "scikit-learn": {"top": "sklearn", "select": "all", "bases": ("scipy", "numpy")},
    "scipy": {"top": "scipy", "select": "minor", "bases": ("numpy",)},
    "pandas": {"top": "pandas", "select": "minor", "bases": ("numpy",)},
    "statsmodels": {"top": "statsmodels", "select": "all", "bases": ("pandas", "scipy", "numpy")},
    "xgboost": {"top": "xgboost", "select": "all", "bases": ("scikit-learn", "numpy")},
    "lightgbm": {"top": "lightgbm", "select": "all", "bases": ("scikit-learn", "numpy")},
    "ultralytics": {"top": "ultralytics", "select": "spread:60", "bases": ("torch", "torchvision")},
    "torch": {"top": "torch", "select": "spread:10", "bases": ()},
    "torchvision": {"top": "torchvision", "select": "minor", "bases": ("torch",)},
    "transformers": {"top": "transformers", "select": "minor", "bases": ("torch",)},
    "accelerate": {"top": "accelerate", "select": "minor", "bases": ("torch",)},
}
# pairs with argument checks keyed on the exact pair (pickle_static): never aliased
NOT_ALIASED = (al.PANDAS_STATE_ONLY | al.PANDAS_CALLS | frozenset(al.BUILD_STATE_KEYS) | frozenset(al.PANDAS_INDEX_KEYS)
               | {al.PANDAS_NEW_INDEX, al.DEFAULTDICT, al.SKLEARN_THRESHOLD_SCORER} | al.SCORER_FUNCTIONS
               | al.GUARDED_CALLS)


def reviewed_forms() -> dict[tuple[str, str], str]:
    """Every reviewed pair -> its form: policy, state-only, zero-arg, enum or allowlist."""
    from safeloadai.static import upstream

    forms: dict[tuple[str, str], str] = {}
    for key in upstream._load("policies.json")["state_only"]:
        module, name = key.split(":", 1)
        forms[(module, name)] = "policy"
    for pair in al.PICKLE_GLOBALS:
        forms.setdefault(pair, "allowlist")
    for pair in al.STATE_ONLY_CLASSES:
        forms[pair] = "state-only"
    for pair in al.ZERO_ARG_CLASSES:
        forms[pair] = "zero-arg"
    for pair in al.ENUM_CLASSES:
        forms[pair] = "enum"
    # the old paths accepted by the previous run are not reviewed pairs of their own
    aliases = set(upstream._historical())
    return {p: f for p, f in forms.items() if p not in NOT_ALIASED and p not in aliases}


def select(versions: list[str], how: str, pinned: str) -> list[str]:
    finals = [v for v in versions if FINAL.fullmatch(v)]
    if pinned in finals:
        finals = finals[:finals.index(pinned)]  # older than the pinned release
    if how == "all":
        return finals
    if how == "minor":  # the last release of every major.minor
        last = {}
        for v in finals:
            last[".".join(v.split(".")[:2])] = v
        return list(last.values())
    return spread(finals, int(how.split(":")[1]))


def _normal(module: str) -> tuple[str, ...]:
    return tuple(p.lstrip("_") for p in module.split("."))


def same_lineage(old: str, current: str, unique: bool) -> str | None:
    """Why ``old`` is the same class's earlier module path, or None."""
    if _normal(old) == _normal(current):
        return "underscore rename"
    if current.rpartition(".")[0] == old:
        return "module split into a package"
    o, c = old.split("."), current.split(".")
    if len(o) == len(c) + 1 and any(o[:i] + o[i + 1:] == c for i in range(1, len(o))):
        return "package level removed"
    if unique:
        return "class name defined once in both releases"
    return None


class Index(sources.SourceIndex):
    """The scanner's SourceIndex (hooks reviewed for older releases included)."""


def class_sites(index: Index, modules, names: set[str]) -> dict[str, set[str]]:
    """class name -> modules (as pickle records them) that define it, for ``names``."""
    out: dict[str, set[str]] = collections.defaultdict(set)
    for module in modules:
        if not sources.library_module(module):
            continue
        facts = index.module(module)
        if not facts or not facts.tree:
            continue
        for cls in index.classes(module):
            if cls.name in names:
                out[cls.name].add(cls.pickled_module)
    return out


TP_NAME = re.compile(rb"([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\.([A-Za-z_][A-Za-z0-9_]*)\x00")


def compiled_names(src, module: str) -> set[tuple[str, str]]:
    """(module, name) type names compiled into the extension module ``module`` of a
    release (bytes of the shared library, never loaded)."""
    member = src.modules.get(module)
    if not member or not member[0].endswith((".so", ".pyd")):
        return set()
    data = src._read_member(member[0])
    return {(m.group(1).decode(), m.group(2).decode()) for m in TP_NAME.finditer(data)}


def generate(archives: Archives, only: set[str] | None = None) -> tuple[dict, str]:
    pins = load_pins()["distributions"]
    forms = reviewed_forms()
    by_top: dict[str, dict[tuple[str, str], str]] = collections.defaultdict(dict)
    for pair, form in forms.items():
        by_top[pair[0].split(".")[0]][pair] = form
    paths: dict[str, dict] = {}
    read_log: dict[str, list[str]] = {}
    rejected: collections.Counter = collections.Counter()
    unreviewed_hooks: dict[str, set[str]] = collections.defaultdict(set)
    for dist, spec in DISTRIBUTIONS.items():
        if only and dist not in only:
            continue
        top = spec["top"]
        reviewed = by_top.get(top, {})
        if not reviewed:
            continue
        pinned = pins.get(dist, {}).get("version") or archives.latest(dist)
        current_src = archives.source(dist, pinned)
        base_srcs = [archives.source(b, pins[b]["version"]) for b in spec["bases"] if b in pins]
        names = {n for _, n in reviewed}
        current_index = Index(current_src.read, known_tops=[top])
        current_sites = class_sites(current_index, current_src.modules, names)
        compiled = {p for p in reviewed if current_src.modules.get(p[0], ("",))[0].endswith((".so", ".pyd", ".pyx"))}
        versions = select(archives.versions(dist), spec["select"], pinned)
        read_log[dist] = []
        for version in versions:
            try:
                src = archives.source(dist, version)
            except Exception as exc:  # noqa: BLE001 - one unreadable release is reported, not fatal
                print(f"{dist} {version}: {exc}", file=sys.stderr)
                continue
            if src is None or top not in src.top_levels():
                continue
            read_log[dist].append(version)
            print(f"{dist} {version}", file=sys.stderr)

            def read(module: str, src=src, top=top, base_srcs=base_srcs):
                if module.split(".")[0] == top:
                    return src.read(module)
                for base in base_srcs:
                    found = base.read(module) if base else None
                    if found:
                        return found
                return None

            index = Index(read, known_tops=[top] + [t for b in base_srcs if b for t in b.top_levels()])
            sites = class_sites(index, src.modules, names)
            for (module, name), form in sorted(reviewed.items()):
                if (module, name) in compiled:
                    continue
                for old in sorted(sites.get(name, ())):
                    if old == module or (old, name) in forms:
                        continue
                    unique = len(sites[name]) == 1 and len(current_sites.get(name, ())) == 1
                    why = same_lineage(old, module, unique)
                    if not why:
                        continue
                    verdict = index.state_only(old, name)
                    inert = inert_chain(index, old, top)
                    if not verdict.state_only or inert:
                        rejected[(dist, f"{old}:{name}")] += 1
                        for reason in verdict.reasons:
                            if "not reviewed" in reason or "differs from the reviewed" in reason:
                                unreviewed_hooks[reason.split(" (sha256")[0] + reason[reason.find("(sha256"):]].add(
                                    f"{dist} {version}")
                        continue
                    key = f"{old}:{name}"
                    entry = paths.setdefault(key, {"current": f"{module}:{name}", "distribution": dist,
                                                   "form": "state-only" if form == "allowlist" else form,
                                                   "kind": "source", "rename": why, "versions": []})
                    if entry["current"] != f"{module}:{name}":
                        entry["conflict"] = True
                    entry["versions"].append(version)
            for module, name in sorted(compiled):
                for found_module, found_name in compiled_names(src, module):
                    if found_name != name or found_module == module:
                        continue
                    if not (module.endswith("." + found_module)) or (found_module, name) in forms:
                        continue
                    if found_module.split(".")[0] != top:
                        # a bare extension name (scikit-learn 1.5 to 1.8 wrote `_loss.CyHalfBinomialLoss`):
                        # pickle.load would import any top-level `_loss` on sys.path. Not the
                        # library's module path; kept out (tune review of 2026-10-22).
                        continue
                    key = f"{found_module}:{name}"
                    entry = paths.setdefault(key, {"current": f"{module}:{name}", "distribution": dist,
                                                   "form": forms[(module, name)], "kind": "compiled",
                                                   "rename": "type name compiled without the package path",
                                                   "versions": []})
                    entry["versions"].append(version)
            # the compiled module's other reviewed globals (Cython unpickle helpers) under the same name
        for key, entry in list(paths.items()):
            if entry["kind"] != "compiled" or entry["distribution"] != dist:
                continue
            old_module = key.split(":")[0]
            current_module = entry["current"].split(":")[0]
            for (module, name), form in reviewed.items():
                if module == current_module and name.startswith("__pyx_unpickle_") \
                        and name.removeprefix("__pyx_unpickle_") == entry["current"].split(":")[1]:
                    paths.setdefault(f"{old_module}:{name}", dict(entry, current=f"{module}:{name}", form=form))
    paths = {k: v for k, v in paths.items() if not v.get("conflict")}
    data = {"generated_by": "tools/gen_historical_paths.py",
            "read": {d: {"versions": v} for d, v in sorted(read_log.items())},
            "paths": dict(sorted(paths.items()))}
    return data, review_text(data, rejected, unreviewed_hooks)


def review_text(data: dict, rejected, unreviewed_hooks) -> str:
    lines = ["# Old module paths of reviewed classes: review summary", "",
             "Generated by `tools/gen_historical_paths.py` (releases read from PyPI archives, never installed or "
             "imported). Each accepted path is listed with the releases in which it defined the class.", "",
             "| distribution | releases read | accepted old paths |", "|---|---|---|"]
    per = collections.Counter(v["distribution"] for v in data["paths"].values())
    for dist, entry in data["read"].items():
        vs = entry["versions"]
        lines.append(f"| {dist} | {len(vs)} ({vs[0] if vs else '-'} to {vs[-1] if vs else '-'}) | {per[dist]} |")
    lines += ["", "## Accepted", "", "| old path | current | form | how | releases |", "|---|---|---|---|---|"]
    for key, v in data["paths"].items():
        vs = v["versions"]
        span = vs[0] if len(vs) == 1 else f"{vs[0]} to {vs[-1]} ({len(vs)} read)"
        lines.append(f"| `{key}` | `{v['current']}` | {v['form']} | {v['rename']} | {span} |")
    lines += ["", "## Not accepted: hooks without a review", "",
              "Same class, same lineage, but a hook (or a property setter) whose exact source was not reviewed. "
              "Reviewing one as benign for a dict-state BUILD means adding its sha256 to "
              "`sources.REVIEWED_OLD_HOOKS`.", "", "| hook | releases |", "|---|---|"]
    for hook, where in sorted(unreviewed_hooks.items(), key=lambda kv: -len(kv[1]))[:80]:
        lines.append(f"| {hook.replace('|', '/')} | {len(where)} |")
    lines += ["", f"Candidate old paths rejected at least once: {len(rejected)}."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if the committed file differs")
    parser.add_argument("--only", action="append", help="limit to these distributions (no write with --check)")
    parser.add_argument("--cache", default=None)
    args = parser.parse_args(argv)
    archives = Archives(args.cache) if args.cache else Archives()
    data, review = generate(archives, set(args.only) if args.only else None)
    text = json.dumps(data, indent=1, sort_keys=True) + "\n"
    if args.check:
        old = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else None
        if old != text:
            print("historical_paths.json differs: run python tools/gen_historical_paths.py and review",
                  file=sys.stderr)
            return 1
        return 0
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    with open(REVIEW, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(review)
    print(f"wrote {len(data['paths'])} old paths", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
