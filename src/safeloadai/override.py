"""UNVERIFIABLE reasons and the informed, per-file override.

A reason is UNVERIFIABLE when the scanner found a named object whose code it cannot
see: a class named without its module in a Keras 2 ``.h5`` config, a Keras class or
custom object outside the known list, a pickle global outside the allowlist that is
not a known sink. The verdict stays SUSPICIOUS. Each such reason carries the exact
``item`` a user would have to accept and a plain-language explanation.

The override (``apply``) is possible only when EVERY reason on the file is
UNVERIFIABLE: one MALICIOUS or RISKY reason and it is refused, always. It names the
exact items accepted, is bound to the file's sha256, and is recorded in the Report
(items, sha256, time, how it was given), whether it was accepted or refused.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime

from .report import Report

SHA256 = re.compile(r"[0-9a-f]{64}\Z")
HOW = frozenset({"api", "cli-flag", "cli-prompt", "config"})
# Report.options source for each way an override is given
SOURCE = {"api": "argument", "cli-flag": "CLI flag --accept-unverified", "cli-prompt": "interactive prompt",
          "config": "config file"}

# --- explanations -----------------------------------------------------------------------


def bare_keras_class(name: str) -> str:
    return (f"The legacy .h5 config names the class '{name}' without its module. Keras resolves such a "
            "name from the custom_objects the loading code passes, so the scanner cannot know which code "
            f"would run. Re-save the model as .keras (which records the module), or accept '{name}' for "
            "this file if you know the exact class your code passes.")


def keras_class(module: str, name: str) -> str:
    return (f"The config names {module}.{name}, which is not on safeloadai's list of Keras classes. "
            f"Loading imports {module} and builds the object with its code, which the scanner cannot see. "
            f"Accept '{module}.{name}' for this file only if you know and trust that exact module.")


def keras_registered(name: str) -> str:
    return (f"The config refers to the registered custom object '{name}'. Keras looks it up among the "
            "objects the loading code registers, so the scanner cannot know which code would run. Re-save "
            f"the model without it, or accept '{name}' for this file if you know which class it is.")


def keras_named(kind: str, name: str) -> str:
    return (f"The config uses a {kind} called '{name}' that is not built into Keras. Keras resolves it from "
            "the custom_objects the loading code passes, so the scanner cannot know which code would run. "
            f"Accept '{name}' for this file if you know the exact function your code passes.")


def keras_function(module: str, name: str) -> str:
    return (f"The config names the function {module}.{name}, which is not a built-in Keras function. "
            f"Loading imports {module} and uses that function, whose code the scanner cannot see. "
            f"Accept '{module}.{name}' for this file only if you know and trust that exact module.")


def keras_custom_builtin(name: str) -> str:
    return (f"The config names the function '{name}' under the module 'builtins'. That is how Keras saves a "
            "loss, metric or activation the model's author wrote. Keras does not take it from Python's "
            "builtins: it looks the name up among its own functions and the custom_objects your loading code "
            "passes, and loading fails if neither has it. The scanner cannot see that code. Accept "
            f"'builtins.{name}' for this file only if you know the exact function your code passes.")


# Globals whose reason is UNVERIFIABLE for a reason of their own (owner's decisions).
_PICKLE_GLOBAL_EXPLANATIONS = {
    ("xgboost.core", "Booster"): (
        "The pickle rebuilds xgboost.core.Booster. Its __setstate__ hands the raw model bytes from the file to "
        "libxgboost's native C++ parser (XGBoosterUnserializeFromBuffer); no Python code is chosen by the file, "
        "but the scanner cannot check that parser's memory safety against hostile bytes. Prefer a model saved "
        "with Booster.save_model('model.json') or ('model.ubj') and loaded with load_model; accept "
        "'xgboost.core.Booster' for this file only if you trust its source."),
    # Owner decision of 2026-10-23 (DECISIONS.md A2): the same holds for LightGBM and CatBoost.
    ("lightgbm.basic", "Booster"): (
        "The pickle rebuilds lightgbm.basic.Booster. Its __setstate__ hands the model string from the file to "
        "LightGBM's native C++ parser (LGBM_BoosterLoadModelFromString); no Python code is chosen by the file, "
        "but the scanner cannot check that parser's memory safety against hostile bytes. Prefer a model saved "
        "with Booster.save_model('model.txt') and loaded with lightgbm.Booster(model_file=...); accept "
        "'lightgbm.basic.Booster' for this file only if you trust its source."),
    **{("catboost.core", name): (
        f"The pickle rebuilds catboost.core.{name}. Its __setstate__ hands the serialized model from the file to "
        "CatBoost's native C++ library (_deserialize_model); no Python code is chosen by the file, but the "
        "scanner cannot check that library's memory safety against hostile bytes. Prefer a model saved with "
        "save_model('model.cbm') or ('model.json', format='json') and loaded with load_model; accept "
        f"'catboost.core.{name}' for this file only if you trust its source.")
       for name in ("CatBoost", "CatBoostClassifier", "CatBoostRegressor", "CatBoostRanker")},
}


def pickle_global(module: str, name: str) -> str:
    special = _PICKLE_GLOBAL_EXPLANATIONS.get((module, name))
    if special:
        return special
    return (f"The pickle imports {module}.{name}, which is not on the allowlist and is not a known sink. "
            f"Unpickling imports {module} and calls {name}, and the scanner cannot see that code. If you "
            f"know and trust it, name the exact pair yourself (allow=[('{module}', '{name}')] or "
            f"--allow {module}:{name}) or accept '{module}.{name}' for this file.")


# --- the override ---------------------------------------------------------------------------


def items_for(report: Report, accept: Iterable[str] | Mapping[str, Iterable[str]] | None) -> list[str] | None:
    """The items ``accept`` names for this report's file.

    A plain list applies to the one file being scanned; a mapping ``{sha256: [items]}``
    applies only through the entry for this file's sha256. None when nothing applies.
    """
    if accept is None:
        return None
    if isinstance(accept, Mapping):
        for sha, items in accept.items():
            if str(sha).lower() == report.sha256:
                return _items(items)
        return None
    return _items(accept)


def _items(items) -> list[str]:
    if isinstance(items, str):
        raise TypeError("accept_unverified takes a list of item names, not a single string")
    return sorted({str(item) for item in items})


def apply(report: Report, items: Iterable[str] | None, *, how: str, config_path: str | None = None) -> bool:
    """Try the override for ``report``'s file; record the outcome in ``report.override``.

    Accepted only if the verdict is SUSPICIOUS, every reason is UNVERIFIABLE, and
    ``items`` names every UNVERIFIABLE item. Returns whether it was accepted.
    """
    if how not in HOW:
        raise ValueError(f"how must be one of {sorted(HOW)}")
    requested = sorted({str(i) for i in items or ()})
    if requested:
        source = SOURCE[how] if how != "config" else f"config file {config_path or ''}".strip()
        report.options = [o for o in report.options if o["name"] != "accept_unverified"]
        report.options.append({"name": "accept_unverified", "value": requested, "source": source,
                               "direction": "looser"})
    if report.clean:
        return True
    record = {"accepted": False, "items": [], "requested": requested, "sha256": report.sha256,
              "time": datetime.now(UTC).isoformat(timespec="seconds"), "how": how, "refused_because": None}
    report.override = record
    if not report.ok:
        record["refused_because"] = (f"safeloadai failed on this file ({report.error['code']}); a tool error "
                                     "is never accepted")
        return False
    blocking = [f for f in report.findings if f["category"] != "UNVERIFIABLE"]
    if report.verdict.value != "SUSPICIOUS" or blocking or not report.findings:
        kinds = sorted({f["category"] for f in blocking}) or [report.verdict.value]
        record["refused_because"] = ("the file has " + " and ".join(kinds) + " reasons; only a file whose every "
                                     "reason is UNVERIFIABLE can be accepted")
        return False
    needed = report.unverifiable_items
    missing = [item for item in needed if item not in requested]
    if missing:
        record["refused_because"] = "not accepted: " + ", ".join(missing)
        return False
    record.update(accepted=True, items=needed, refused_because=None)
    unused = [item for item in requested if item not in needed]
    if unused:
        record["unused"] = unused
    return True


def accepted_pickle_pairs(report: Report) -> frozenset[tuple[str, str]]:
    """The exact (module, qualname) pairs an accepted override covers, for the restricted loaders."""
    if not report.accepted or report.clean:
        return frozenset()
    return frozenset(tuple(f["pair"]) for f in report.findings
                     if f["category"] == "UNVERIFIABLE" and f.get("pair"))
