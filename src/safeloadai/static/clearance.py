"""Which globals outside the allowlist a pickle may still import (0.7.0, Parts 1 and 2).

**Referenced or used (Part 1).** Importing a global does not run its code; calling it
does. After the walk, :func:`used_globals` finds every Global stand-in whose value can
reach code while the pickle loads:

* the callable of any call (REDUCE, NEWOBJ, NEWOBJ_EX, OBJ, INST) and anything inside
  its arguments, at any depth, including inside the arguments and state of objects
  passed along (the callee may call them);
* the target of a BUILD, and the globals in its state unless the target is an instance
  of a class whose dict-state BUILD only stores (allowlisted or state-only), the state
  is a dict that sets no hook attribute (``BUILD_HOOK_KEYS``) and it is the object's
  first BUILD (a second one calls the ``__setstate__`` an earlier state may have stored,
  so the globals in every earlier state of that object count as used too);
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

import contextlib
import contextvars
from dataclasses import dataclass, field

from . import upstream
from .allowlists import BUILD_HOOK_KEYS, GETATTR, KNOWN_GADGETS, STATE_ONLY_CLASSES
from .lookalike import imitates
from .pickle_vm import Global, Obj, class_of
from .sources import DENIED_MODULES
from .sources import library_module as sources_library_module

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
        if not (isinstance(pair, tuple) and len(pair) == 2 and all(isinstance(p, str) for p in pair)):
            return None  # a global whose module or name is not a string (found by fuzzing, 0.8.0)
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
    if "." in name or index.module(module) is None or not sources_library_module(module):
        return None
    if upstream.excluded(pair):
        return None  # an owner decision keeps it out, whatever the installed source says
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
# The clearance of the scan in progress (pipeline.scan sets it for trust_inert_from).
ACTIVE: contextvars.ContextVar[Clearance] = contextvars.ContextVar("safeloadai_clearance", default=DEFAULT)


def for_distributions(names: tuple[str, ...]) -> Clearance:
    """A Clearance that judges the classes of the named installed distributions from
    their installed source (one index over all of them, so a base class from another
    named distribution resolves). Nothing is imported: files come from each
    distribution's RECORD via importlib.metadata."""
    if not names:
        return DEFAULT
    from . import sources

    readers, versions, tops = [], {}, {}
    for name in names:
        read, version, modules = sources.installed_reader(name)
        readers.append(read)
        versions[name] = version
        tops[name] = frozenset(m.split(".")[0] for m in modules)

    def read(module: str):
        for reader in readers:
            found = reader(module)
            if found is not None:
                return found
        return None

    known = {t for pin in upstream.distributions().values() for t in pin.get("top_level", ())}
    index = sources.SourceIndex(read, known_tops=known | {t for ts in tops.values() for t in ts})
    return Clearance(installed={name: (index, versions[name], tops[name]) for name in names})


@contextlib.contextmanager
def active(value: Clearance):
    token = ACTIVE.set(value)
    try:
        yield value
    finally:
        ACTIVE.reset(token)


def referenced_ok(module: str, name: str) -> bool:
    """May a global that is only referenced be imported without a finding?"""
    if module.split(".")[0] in DENIED_MODULES or (module, name) in KNOWN_GADGETS or (module, name) in GETATTR:
        return False
    if imitates(module):
        return False
    return upstream.inert_definition(module, name)


def sets_hook(state) -> bool:
    """Does a BUILD state (a dict, or a (dict, slotstate) pair) set a hook attribute?"""
    parts = state if isinstance(state, tuple) and len(state) == 2 else (state,)
    return any(isinstance(part, dict) and any(isinstance(key, str) and key in BUILD_HOOK_KEYS for key in part)
               for part in parts)


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

    built: dict[int, list] = {}
    for how, func, args, _pos in calls:
        if how == "build":
            state = args[0] if isinstance(args, tuple) and args else args
            earlier = built.setdefault(id(func), [])
            earlier.append(state)
            if (len(earlier) == 1 and isinstance(func, Obj) and isinstance(state, dict)
                    and not sets_hook(state) and stores_only(func)):
                continue
            ok = mark(func) and all(mark(s) for s in earlier)
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


# --- torch.load(weights_only=True) ------------------------------------------------------

_WO_BUILD = frozenset({"torch.Tensor", "torch.nn.parameter.Parameter", "collections.OrderedDict"})
_WO_SETITEM = frozenset({("collections", "OrderedDict"), ("collections", "Counter")})


def _full(pair) -> str:
    return f"{pair[0]}.{pair[1]}"


def weights_only_ok(report: dict, calls: list[tuple], uses: list[tuple]) -> str | None:
    """None when torch's weights-only unpickler (the pinned version,
    upstream/torch_weights_only.py) would accept this stream: only its opcodes, only its
    globals (compared as full paths, never from a blocked module), NEWOBJ and REDUCE only
    on those globals, BUILD only on Tensor, Parameter, OrderedDict or an allowed type,
    APPEND only to a list, SETITEM only to a dict, OrderedDict or Counter, and persistent
    ids that are a ("storage", ...) tuple or an int. Otherwise the first rule it breaks."""
    from .upstream import torch_weights_only as wo

    if report["error"]:
        return "the walk failed"
    ops = set(report.get("opcode_counts") or {o["name"] for o in report["opcodes"]}) - wo.OPCODES
    if ops:
        return f"opcodes torch does not implement: {', '.join(sorted(ops))}"
    for imp in report["imports"]:
        if imp["module"] is None or imp["module"] in wo.BLOCKED_MODULES:
            return f"blocked or unresolved import at {imp['pos']}"
        if f"{imp['module']}.{imp['symbol']}" not in wo.ALLOWED:
            return f"{imp['module']}.{imp['symbol']} is not a torch weights-only global"
    for how, func, _args, pos in calls:
        if how in ("newobj", "reduce"):
            if not (isinstance(func, Global) and _full(func.pair) in wo.ALLOWED):
                return f"{how.upper()} at {pos} on something that is not an allowed global"
        elif how == "build":
            pair = class_of(func)
            if pair is None or (_full(pair) not in wo.ALLOWED and _full(pair) not in _WO_BUILD):
                return f"BUILD at {pos} on something torch does not build"
        else:
            return f"{how.upper()} at {pos}"
    for kind, items, target, pos in uses:
        if kind == "append":
            return f"APPEND at {pos} to something that is not a list"
        if kind == "setitem" and class_of(target) not in _WO_SETITEM:
            return f"SETITEM at {pos} on something that is not a dict, OrderedDict or Counter"
        if kind == "persid":
            pid = items[0]
            if isinstance(pid, int) and not isinstance(pid, bool):
                continue
            head = pid[0] if isinstance(pid, tuple) and pid else None
            if isinstance(head, bytes):
                head = head.decode("ascii", "replace")
            if not (isinstance(pid, tuple) and (not pid or head == "storage")):
                return f"persistent id at {pos} is not a storage reference"
    return None
