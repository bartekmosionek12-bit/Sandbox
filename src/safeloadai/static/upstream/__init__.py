"""Source-derived data, generated at development time by ``tools/gen_policies.py`` from the
library versions pinned in ``tools/upstream_pins.json`` (read with ``ast``, never imported),
reviewed and committed. Nothing here is computed or extended at run time.

* ``inert_modules.json``: modules of known libraries whose import runs only definitions
  (and in-process calls into the library itself), with the names their top level binds.
* ``policies.json``: classes of selected libraries that are state-only: rebuilding an
  instance from a dict state (NEWOBJ () + BUILD) runs no code of the class beyond
  reviewed hooks (``sources.REVIEWED_HOOKS``).
* ``historical_paths.json`` (0.9.0, ``tools/gen_historical_paths.py``): earlier module paths
  of reviewed classes, read from older releases on PyPI (``sklearn.ensemble.forest`` before
  ``sklearn.ensemble._forest``). An old path is accepted under the form of the class it
  became (policy, state-only, zero-arg, enum or allowlist), only when the old release
  defined the same class there and it was state-only in that release too.
"""
from __future__ import annotations

import json
import os
from functools import cache

_HERE = os.path.dirname(os.path.abspath(__file__))


@cache
def _load(name: str) -> dict:
    with open(os.path.join(_HERE, name), encoding="utf-8") as fh:
        return json.load(fh)


def distributions() -> dict[str, dict]:
    """distribution -> {"version", "wheel_sha256"} the data was generated from."""
    return _load("policies.json")["distributions"]


@cache
def _inert() -> dict[str, frozenset[str]]:
    return {module: frozenset(names) for module, names in _load("inert_modules.json")["modules"].items()}


def inert_definition(module: str, name: str) -> bool:
    """Is ``module.name`` a name the top level of an inert library module binds itself?
    A dotted qualname (``Class.attr``) is never one: reaching it runs attribute lookups."""
    names = _inert().get(module)
    return names is not None and "." not in name and name in names


@cache
def _state_only() -> dict[tuple[str, str], dict]:
    out = {}
    for key, entry in _load("policies.json")["state_only"].items():
        module, _, name = key.partition(":")
        out[(module, name)] = entry
    return out


def state_only(pair: tuple[str, str]) -> dict | None:
    """The policy entry of a state-only class ({"distribution", "mro", "reviewed_hooks"}).
    For an old module path of a policy class, the entry of the class it became, with
    ``historical`` ({"current", "versions", "distribution"}) added."""
    found = _state_only().get(pair)
    if found is not None:
        return found
    old = historical(pair)
    if old is None or old["form"] != "policy":
        return None
    module, _, name = old["current"].partition(":")
    current = _state_only().get((module, name))
    return dict(current, historical=old) if current else None


@cache
def _historical() -> dict[tuple[str, str], dict]:
    out = {}
    for key, entry in _load("historical_paths.json")["paths"].items():
        module, _, name = key.partition(":")
        out[(module, name)] = entry
    return out


def historical(pair: tuple[str, str]) -> dict | None:
    """The entry of an old module path of a reviewed class ({"current", "distribution",
    "form", "kind", "rename", "versions"}), or None."""
    return _historical().get(pair)


def historical_by_form(form: str) -> frozenset[tuple[str, str]]:
    """Old module paths accepted under ``form`` (state-only, zero-arg, enum, allowlist)."""
    return frozenset(pair for pair, entry in _historical().items() if entry["form"] == form)


def span(entry: dict) -> str:
    """'scikit-learn 0.10 to 0.13.1' for a historical entry."""
    vs = entry["versions"]
    return f"{entry['distribution']} {vs[0]}" + (f" to {vs[-1]}" if len(vs) > 1 else "")


def excluded(pair: tuple[str, str]) -> str | None:
    """Why a class is kept out of every state-only rule, the pinned policies and
    ``trust_inert_from`` alike (owner decisions, ``policy_exclude`` in tools/upstream_pins.json)."""
    return _load("policies.json").get("excluded", {}).get(f"{pair[0]}:{pair[1]}")


def label(distribution: str) -> str:
    entry = distributions().get(distribution) or {}
    return f"{distribution} {entry.get('version', '?')}"
