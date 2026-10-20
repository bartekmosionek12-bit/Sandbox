"""Source-derived data, generated at development time by ``tools/gen_policies.py`` from the
library versions pinned in ``tools/upstream_pins.json`` (read with ``ast``, never imported),
reviewed and committed. Nothing here is computed or extended at run time.

* ``inert_modules.json``: modules of known libraries whose import runs only definitions
  (and in-process calls into the library itself), with the names their top level binds.
* ``policies.json``: classes of selected libraries that are state-only: rebuilding an
  instance from a dict state (NEWOBJ () + BUILD) runs no code of the class beyond
  reviewed hooks (``sources.REVIEWED_HOOKS``).
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
    """The policy entry of a state-only class ({"distribution", "mro", "reviewed_hooks"})."""
    return _state_only().get(pair)


def label(distribution: str) -> str:
    entry = distributions().get(distribution) or {}
    return f"{distribution} {entry.get('version', '?')}"
