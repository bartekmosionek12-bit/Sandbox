"""Why benign files are not CLEAN: classify every non-CLEAN benign file of a split by root
cause, from the scan evidence in a results file only (0.9.0, FP anatomy).

    python evaluation/fp_anatomy.py evaluation/results/eval-v080-20261023T061458Z.json \\
        --group hf-heldout2 --out evaluation/results/fp-anatomy-heldout2-v080.json \\
        --private private/fp-anatomy

Nothing is downloaded from the Hub and no model file is read: the input is what
``run_eval.py`` recorded per file (verdict, category, reasons and the ``missing`` items:
every import or Keras object outside the allowlist). Whether a module belongs to a public
library is checked against PyPI releases (``tools/pypi_archives.py``: archives read, never
installed or imported). The public output holds aggregate numbers only; the per-file
account goes to ``--private`` (``private/`` is never committed).

Root causes, per item, then per file:

* **a** user-defined classes: ``__main__``, or a module that no public package has (the
  module path is in no release of a PyPI distribution of that top-level name, checked on
  the latest release and up to ``VERSIONS_CHECKED`` releases spread over its history);
* **b** custom Keras objects of the model author: a registered name ``Custom>X`` or
  ``<package>>X`` whose package is not public, an object without a module (``None.X``) or
  a function (``builtins.f``) whose name no public Keras API exports, a training-config
  loss or metric name Keras does not know, a class from a non-public module in a Keras file;
* **c** classes from known public libraries (the standard library included) missing from
  the allowlist, including the reasons that follow from them (an allowlisted-module
  lookalike, an unexpected call);
* **d** old module paths of already reviewed classes: the same top-level package (or a
  bare Cython module name that is the last part of the reviewed module) and the same class
  name as an allowlisted or state-only class, under another module path;
* **e** data-only formats safeloadai does not parse (verdict UNSUPPORTED);
* **f** other: code in the file (Keras Lambda, dill or cloudpickle code), call gadgets,
  emulation that did not complete, unreadable or inconsistent structure, an argument
  check that failed, and tool errors.

A file counts once, under the first class it has in the order a, b, f, e, c, d: a file
with any a or b item cannot become CLEAN by allowlist work, so a + b is the **irreducible
floor**; f stays blocked by a reason that is not an allowlist entry; c and d are what
allowlist work can reduce. The ``any`` counts give every file with at least one item of a
class.
"""
from __future__ import annotations

import argparse
import ast
import builtins
import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

from tools.pypi_archives import Archives, spread  # noqa: E402

CLASSES = ("a", "b", "f", "e", "c", "d")
CLASS_TEXT = {
    "a": "user-defined classes (__main__, modules in no public package)",
    "b": "custom Keras objects registered by the model author",
    "c": "classes from known public libraries missing from the allowlist",
    "d": "old module paths of already reviewed classes",
    "e": "data-only formats safeloadai does not parse (UNSUPPORTED)",
    "f": "other (code in the file, emulation limits, structure, tool errors)",
}
BLOCKS = ("UNVERIFIABLE", "RISKY", "MALICIOUS", "UNSUPPORTED", "ERROR")
VERSIONS_CHECKED = 6
# top-level import name -> PyPI distribution, where they differ (checked by hand on PyPI)
DISTRIBUTION_OF = {
    "sklearn": "scikit-learn", "imblearn": "imbalanced-learn", "pycrfsuite": "python-crfsuite",
    "sklearn_crfsuite": "sklearn-crfsuite", "swift": "ms-swift", "keras_cv": "keras-cv", "keras_hub": "keras-hub",
    "keras_nlp": "keras-nlp", "tf_keras": "tf-keras", "autoai_libs": "autoai-libs", "doclayout_yolo": "doclayout-yolo",
    "FlagEmbedding": "FlagEmbedding", "yaml": "PyYAML", "cv2": "opencv-python", "PIL": "Pillow",
    "skimage": "scikit-image", "attr": "attrs", "google": None, "sentence_transformers": "sentence-transformers",
}
KERAS_ARCHIVES = (("keras", None), ("tf-keras", None))
KERAS_FORMATS = ("keras", "h5")
REGISTERED = re.compile(r"^(?P<pkg>[^>]+)>(?P<name>.+?)(\.registered_name)?$")
CODE_REASONS = (("keras-lambda", ("Lambda",)),
                ("serialized-code", ("executable Python code", "pickle written by dill",
                                     "pickle written by cloudpickle", "dill:", "bytecode",
                                     "Keras loader on embedded bytes")),
                ("emulation-incomplete", ("emulation did not complete",)),
                ("structure", ("does not match its content", "not readable", "CRC-", "polyglot",
                               "more than one format", "neither a Keras nor a PyTorch", "legacy joblib",
                               "copyreg extension", "no emulator for format")),
                ("argument-check", ("is called with arguments", "is passed as a value", "may only be")))
# reasons that only restate an item outside the allowlist
ITEM_REASONS = ("outside the allowlist", "unexpected_call", "imitates the allowlisted module", "unpickling raised",
                "missing stub", "introspection:")


def reviewed_pairs() -> set[tuple[str, str]]:
    """Every (module, name) the scanner of this tree accepts by review: the allowlists and
    the generated state-only policies."""
    from safeloadai.static import allowlists as al
    from safeloadai.static import upstream

    pairs: set[tuple[str, str]] = set()
    for value in vars(al).values():
        if isinstance(value, frozenset) and value and all(isinstance(p, tuple) and len(p) == 2 for p in value):
            pairs |= {p for p in value if all(isinstance(x, str) for x in p)}
    for key in upstream._load("policies.json")["state_only"]:
        module, name = key.split(":", 1)
        pairs.add((module, name))
    return pairs


def keras_public_names(archives: Archives) -> tuple[set[str], dict]:
    """Every name the public API of Keras 3 and tf-keras exports (``keras/api`` and
    ``tf_keras/api`` package files), from the latest release of each."""
    names: set[str] = set()
    used = {}
    for dist, _ in KERAS_ARCHIVES:
        version = archives.latest(dist)
        src = archives.source(dist, version)
        used[dist] = version
        for module in src.modules:
            parts = module.split(".")
            if len(parts) < 2 or parts[1] != "api":
                continue
            found = src.read(module)
            if not found:
                continue
            try:
                tree = ast.parse(found[0])
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    names |= {a.asname or a.name for a in node.names}
    return names, used


class PublicModules:
    """Is a module path part of a public PyPI distribution?"""

    def __init__(self, archives: Archives):
        self.archives = archives
        self.checked: dict[str, list[str]] = defaultdict(list)  # distribution -> versions read
        self._cache: dict[str, bool] = {}
        self._dists: dict[str, list[str]] = {}

    def distributions(self, top: str) -> list[str]:
        if top not in self._dists:
            names = [DISTRIBUTION_OF[top]] if top in DISTRIBUTION_OF else [top, top.replace("_", "-")]
            found = []
            for name in dict.fromkeys(n for n in names if n):
                try:
                    if self.archives.project(name):
                        found.append(name)
                except Exception as exc:  # noqa: BLE001 - PyPI unreachable: recorded, not guessed
                    print(f"PyPI {name}: {exc}", file=sys.stderr)
            self._dists[top] = found
        return self._dists[top]

    def public(self, module: str, name: str | None = None) -> bool:
        """True when a release of a PyPI distribution of the module's top-level name has
        the module, and, when ``name`` is given and the module is Python source, binds that
        name at its top level (a top-level package name alone, e.g. a PyPI project called
        ``architectures``, says nothing about a user's ``architectures.GapModel``)."""
        key = f"{module}:{name}"
        if key in self._cache:
            return self._cache[key]
        top = module.split(".")[0]
        if top in sys.stdlib_module_names or top in ("__builtin__", "copy_reg"):
            self._cache[key] = True
            return True
        found = False
        for dist in self.distributions(top):
            versions = self.archives.versions(dist)
            latest = self.archives.latest(dist)
            order = [latest] + [v for v in reversed(spread(versions, VERSIONS_CHECKED)) if v != latest]
            for version in order:
                try:
                    src = self.archives.source(dist, version)
                except Exception as exc:  # noqa: BLE001
                    print(f"{dist} {version}: {exc}", file=sys.stderr)
                    continue
                if src is None:
                    continue
                if version not in self.checked[dist]:
                    self.checked[dist].append(version)
                if top not in src.top_levels():
                    break  # the distribution does not provide this package at all
                if src.has_module(module) and (name is None or binds(src, module, name)):
                    found = True
                    break
            if found:
                break
        self._cache[key] = found
        return found


def binds(src, module: str, name: str) -> bool:
    """Does the module bind ``name`` at its top level? A compiled module, a star import or
    a module ``__getattr__`` cannot be read statically and counts as yes."""
    found = src.read(module)
    if found is None:
        return True
    try:
        tree = ast.parse(found[0])
    except SyntaxError:
        return True
    head = name.split(".")[0]
    for node in ast.walk(tree):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == head:
            return True
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == "*" or (alias.asname or alias.name).split(".")[0] == head:
                    return True
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and node.id == head:
            return True
        if isinstance(node, ast.FunctionDef) and node.name == "__getattr__":
            return True
    return False


def split_item(item: str) -> tuple[str, str]:
    module, _, name = item.rpartition(".")
    return module, name


class Classifier:
    def __init__(self, reviewed: set[tuple[str, str]], keras_names: set[str], public: PublicModules):
        from safeloadai.static import allowlists as al

        self.reviewed = reviewed
        self.reviewed_by_name: dict[str, set[str]] = defaultdict(set)
        for module, name in reviewed:
            self.reviewed_by_name[name].add(module)
        self.keras_names = keras_names
        self.public = public
        self.gadgets = set(al.KNOWN_GADGETS) | set(al.GETATTR)
        self.code_modules = set(al.DILL_MODULES) | set(al.CLOUDPICKLE_MODULES)
        self.dangerous = set(al.DANGEROUS_MODULES) - {"builtins", "__builtin__"}

    def old_path(self, module: str, name: str) -> bool:
        for other in self.reviewed_by_name.get(name, ()):
            if other == module:
                continue
            if other.split(".")[0] == module.split(".")[0] or other.endswith("." + module):
                return True
        return False

    def keras_item(self, item: str) -> str:
        if item.startswith("loss/metric."):
            name = item.split(".", 1)[1]
            return "c" if name in self.keras_names else "b"
        registered = REGISTERED.match(item.removeprefix("builtins.").removeprefix("None."))
        if registered:
            pkg = registered.group("pkg")
            if pkg == "Custom":
                return "b"
            return "c" if self.public.distributions(pkg) and self.public.public(pkg) else "b"
        module, name = split_item(item)
        if module == "None":
            return "c" if name in self.keras_names or name.startswith("__") else "b"
        if module == "builtins":
            return "c" if name in self.keras_names else "b"
        if module == "__main__":
            return "b"
        if self.old_path(module, name):
            return "d"
        return "c" if self.public.public(module, name) else "b"

    def pickle_item(self, item: str) -> str:
        module, name = split_item(item)
        if module in ("builtins", "__builtin__") and (module, name) not in self.gadgets:
            return "c" if hasattr(builtins, name) else "a"
        if (module, name) in self.gadgets or module in self.code_modules or module.split(".")[0] in self.dangerous:
            return "f"
        if module == "__main__" or module.startswith("__main__."):
            return "a"
        if self.old_path(module, name):
            return "d"
        return "c" if self.public.public(module, name) else "a"

    def file(self, entry: dict) -> dict:
        result = entry["results"]["safeloadai"]
        verdict = result.get("verdict")
        block = ("ERROR" if verdict is None else "UNSUPPORTED" if verdict == "UNSUPPORTED"
                 else "MALICIOUS" if verdict == "MALICIOUS" else result.get("category") or "UNVERIFIABLE")
        items = {}
        keras = entry.get("format") in KERAS_FORMATS
        for item in result.get("missing") or []:
            items[item] = self.keras_item(item) if keras else self.pickle_item(item)
        subtypes = set()
        if verdict is None:
            subtypes.add("tool-error")
        for reason in result.get("reasons") or []:
            if any(marker in reason for marker in ITEM_REASONS):
                if not items and ("unpickling raised" in reason or "missing stub" in reason):
                    subtypes.add("emulation-anomaly")  # no item it could follow from
                continue
            for subtype, markers in CODE_REASONS:
                if any(marker in reason for marker in markers):
                    subtypes.add(subtype)
                    break
        if any(c == "f" for c in items.values()):
            subtypes.add("call-gadget-or-code-module")
        if block == "RISKY" and not subtypes and not any(c in ("a", "b") for c in items.values()) \
                and not any("imitates the allowlisted module" in r for r in result.get("reasons") or []):
            subtypes.add("risky-reason-next-to-library-classes")
        present = set(items.values()) - {"f"}
        if subtypes:
            present.add("f")
        if verdict == "UNSUPPORTED":
            present.add("e")
        primary = next((c for c in CLASSES if c in present), "f")
        if primary == "f" and not subtypes:
            subtypes.add("no-evidence-recorded")
        return {"file": entry["file"], "format": entry.get("format"), "library": entry.get("library"),
                "block": block, "primary": primary, "present": sorted(present), "f_subtypes": sorted(subtypes),
                "items": items}


def analyse(entries: list[dict], group: str, classifier: Classifier) -> tuple[dict, list[dict]]:
    benign = [e for e in entries if e.get("group") == group and e.get("label") == "benign"]
    flagged = [e for e in benign if (e["results"]["safeloadai"].get("verdict") or "") != "CLEAN"]
    rows = [classifier.file(e) for e in flagged]
    n, k = len(benign), len(rows)

    def share(x: int, d: int) -> float | None:
        return round(x / d, 4) if d else None

    primary = Counter(r["primary"] for r in rows)
    anyof = Counter(c for r in rows for c in r["present"])
    by_block = {c: Counter(r["block"] for r in rows if r["primary"] == c) for c in CLASSES}
    block_totals = Counter(r["block"] for r in rows)
    f_sub = Counter(s for r in rows if r["primary"] == "f" for s in r["f_subtypes"])
    formats = {c: Counter(r["format"] for r in rows if r["primary"] == c) for c in CLASSES}
    floor = primary["a"] + primary["b"]
    reducible = primary["c"] + primary["d"]
    c_items = Counter(i for r in rows if r["primary"] == "c" for i, cl in r["items"].items() if cl == "c")
    native = {"xgboost.core.Booster", "lightgbm.basic.Booster", "catboost.core.CatBoostClassifier",
              "catboost.core.CatBoostRegressor", "catboost.core.CatBoost"}
    c_native = sum(1 for r in rows if r["primary"] == "c"
                   and {i for i, cl in r["items"].items() if cl == "c"} <= native
                   and any(i in native for i in r["items"]))
    summary = {
        "group": group, "benign_files": n, "not_clean": k, "not_clean_share": share(k, n),
        "classes": {c: {"text": CLASS_TEXT[c], "files": primary[c], "share_of_benign": share(primary[c], n),
                        "share_of_not_clean": share(primary[c], k),
                        "by_block": {b: by_block[c][b] for b in BLOCKS},
                        "by_format": dict(sorted(formats[c].items()))} for c in CLASSES},
        "any": {c: {"files": anyof[c], "share_of_benign": share(anyof[c], n)} for c in CLASSES},
        "by_block": {b: block_totals[b] for b in BLOCKS},
        "floor": {"files": floor, "share_of_benign": share(floor, n), "share_of_not_clean": share(floor, k)},
        "reducible_by_allowlist": {"files": reducible, "share_of_benign": share(reducible, n),
                                   "share_of_not_clean": share(reducible, k),
                                   "only_native_parser_classes": c_native},
        "f_subtypes": dict(f_sub.most_common()),
        "distinct_c_items": len(c_items),
    }
    return summary, rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("result", help="run_eval.py results JSON")
    parser.add_argument("--group", action="append", required=True, help="group to analyse (repeatable)")
    parser.add_argument("--out", required=True, help="public aggregate JSON")
    parser.add_argument("--private", help="directory for the per-file account (never committed)")
    parser.add_argument("--cache", default=None, help="PyPI archive cache")
    args = parser.parse_args(argv)
    with open(args.result, encoding="utf-8") as fh:
        data = json.load(fh)
    archives = Archives(args.cache) if args.cache else Archives()
    keras_names, keras_versions = keras_public_names(archives)
    public = PublicModules(archives)
    classifier = Classifier(reviewed_pairs(), keras_names, public)
    out = {"generated_by": "evaluation/fp_anatomy.py", "source": os.path.basename(args.result),
           "safeloadai": data.get("safeloadai"), "created": data.get("created"), "groups": {}}
    private_rows = {}
    for group in args.group:
        summary, rows = analyse(data["entries"], group, classifier)
        out["groups"][group] = summary
        private_rows[group] = rows
    out["public_check"] = {"keras_api": keras_versions,
                           "distributions": {d: v for d, v in sorted(public.checked.items())},
                           "versions_checked_per_distribution": VERSIONS_CHECKED}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
        fh.write("\n")
    if args.private:
        os.makedirs(args.private, exist_ok=True)
        base = os.path.join(args.private, os.path.splitext(os.path.basename(args.out))[0])
        with open(base + "-files.json", "w", encoding="utf-8") as fh:
            json.dump(private_rows, fh, indent=1, sort_keys=True)
    for group, s in out["groups"].items():
        print(f"{group}: {s['not_clean']} of {s['benign_files']} benign files not CLEAN", file=sys.stderr)
        for c in CLASSES:
            row = s["classes"][c]
            print(f"  {c}: {row['files']:4d}  {row['share_of_benign']:.3f} of benign  ({CLASS_TEXT[c]})",
                  file=sys.stderr)
        print(f"  floor (a+b): {s['floor']['files']} = {s['floor']['share_of_benign']:.3f} of benign", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
