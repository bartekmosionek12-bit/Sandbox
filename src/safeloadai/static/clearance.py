"""Which globals outside the allowlist a pickle may still import (0.7.0, Parts 1 and 2).

**Referenced or used (Part 1).** Importing a global does not run its code; calling it
does. After the walk, :func:`used_globals` finds every Global stand-in whose value can
reach code while the pickle loads:

* the callable of any call (REDUCE, NEWOBJ, NEWOBJ_EX, OBJ, INST) and anything inside
  its arguments, at any depth, including inside the arguments and state of objects
  passed along (the callee may call them);
* the target of a BUILD, and the globals in its state unless the target is an instance
  of a class whose dict-state BUILD only stores (allowlisted or state-only) and the
  state is a dict;
* the target of ``builtins.getattr`` once the getattr result is used;
* items appended or set into an object that is not a plain container (a method of its
  class receives them), dict keys and set members (they are hashed), and persistent
  ids (``persistent_load`` receives them).

Everything else is only referenced: stored as a value in the object graph. A global
that is only referenced, from a module of a known library whose import is inert
(``upstream.inert_modules``), raises no finding. Anything else keeps the old rules.

**State-only classes (Part 2).** A class the pinned source analysis
(``upstream.policies``) or, on request, the analysis of the installed version
(``trust_inert_from``) finds state-only is accepted like the reviewed
``STATE_ONLY_CLASSES``: only rebuilt from its saved state (NEWOBJ () + one dict BUILD),
never called, never passed around as a value.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import upstream
from .allowlists import GETATTR, KNOWN_GADGETS, STATE_ONLY_CLASSES
from .lookalike import imitates
from .pickle_vm import Global, Obj, class_of
from .sources import DENIED_MODULES

# Obj targets whose SETITEM/APPEND only store (their classes are allowlisted containers).
PLAIN_CONTAINERS = frozenset({("collections", "OrderedDict"), ("collections", "defaultdict"),
                              ("collections", "Counter")})
MAX_USE_WALK = 10_000_000


@dataclass
class Clearance:
    """The state-only sources one scan may use. ``installed`` maps a distribution named
    in ``trust_inert_from`` to (SourceIndex over its installed files, version, top-level
    packages); for those packages it replaces the pinned policies."""

    installed: dict[str, tuple] = field(default_factory=dict)
    _cache: dict = field(default_factory=dict)

    def state_only(self, pair: tuple[str, str]) -> tuple[str, str] | None:
        """(mechanism, detail) when ``pair`` is a state-only class, else None."""
        if pair in self._cache:
            return self._cache[pair]
        found = None
        top = pair[0].split(".")[0]
        for dist, (index, version, tops) in self.installed.items():
            if top in tops:
                found = _installed_state_only(index, pair, dist, version)
                break
        else:
            entry = upstream.state_only(pair)
            if entry:
                found = ("policy", f"state-only class ({upstream.label(entry['distribution'])} source)")
        self._cache[pair] = found
        return found

    def is_state_only(self, pair) -> bool:
        return pair in STATE_ONLY_CLASSES or (pair is not None and self.state_only(pair) is not None)


def _installed_state_only(index, pair, dist: str, version: str):
    module, name = pair
    if "." in name or index.module(module) is None:
        return None
    parts = module.split(".")
    for i in range(len(parts), 1, -1):
        sub = ".".join(parts[:i])
        if index.module(sub) is not None and index.inert(sub):
            return None
    verdict = index.state_only(module, name)
    if not verdict.state_only:
        return None
    return ("inert-class", f"CLEAN by inert-class rule ({dist} {version})")


DEFAULT = Clearance()


def referenced_ok(module: str, name: str) -> bool:
    """May a global that is only referenced be imported without a finding?"""
    if module.split(".")[0] in DENIED_MODULES or (module, name) in KNOWN_GADGETS or (module, name) in GETATTR:
        return False
    if imitates(module):
        return False
    return upstream.inert_definition(module, name)


def used_globals(calls: list[tuple], uses: list[tuple], stores_only) -> set[int] | None:
    """ids of the Global stand-ins whose value reaches code while loading; None when the
    walk ran out of budget (then every global counts as used). ``stores_only(obj)``
    says whether a dict-state BUILD on ``obj`` only stores."""
    used: set[int] = set()
    seen: set[int] = set()
    steps = [0]

    def mark(value) -> bool:
        todo = [value]
        while todo:
            item = todo.pop()
            steps[0] += 1
            if steps[0] > MAX_USE_WALK:
                return False
            if id(item) in seen:
                continue
            if isinstance(item, Global):
                used.add(id(item))
                seen.add(id(item))
            elif isinstance(item, Obj):
                seen.add(id(item))
                todo += [item.func, item.args, item.state]
            elif isinstance(item, (tuple, list, set, frozenset)):
                seen.add(id(item))
                todo.extend(item)
            elif isinstance(item, dict):
                seen.add(id(item))
                todo.extend(v for kv in item.items() for v in kv)
        return True

    for how, func, args, _pos in calls:
        if how == "build":
            state = args[0] if isinstance(args, tuple) and args else args
            if isinstance(func, Obj) and isinstance(state, dict) and stores_only(func):
                continue
            ok = mark(func) and mark(state)
        elif isinstance(func, Global) and func.pair in GETATTR:
            ok = mark(func)  # getattr does not call its target; using the result marks it
        else:
            ok = mark(func) and mark(args)
        if not ok:
            return None
    for kind, items, target, _pos in uses:
        if kind == "setitem" and class_of(target) in PLAIN_CONTAINERS:
            ok = mark(items[0::2])  # keys are hashed, values stored
        elif kind == "append" and class_of(target) in PLAIN_CONTAINERS:
            ok = True
        else:
            ok = mark(items)
        if not ok:
            return None
    return used
