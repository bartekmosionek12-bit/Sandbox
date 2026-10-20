"""Profiles for well-known files (0.7.0 Part 3).

A profile describes a file a known producer writes: a file-name pattern, the producer, the
exact globals the file needs beyond the default rules, and where in the file's structure
each of them may appear. It only ALLOWS, and only inside that structure:

* name matches, producer signature present, structure matches: the profile's globals are
  accepted at their allowed positions (``report["cleared"]`` mechanism ``"profile"``);
  everything else in the file is judged by the usual rules, so a MALICIOUS or RISKY
  finding is never lowered;
* name matches and the producer signature is present, but the structure does not match:
  no profile applies and the file gets a RISKY reason (a well-known file that is not
  shaped like one);
* name does not match, or no producer signature: nothing changes.

Every profile is written by hand from the producer's source (``source`` says which
versions were read), reviewed and committed; nothing is added at run time. See
docs/PROFILES.md.
"""
from __future__ import annotations

import fnmatch
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..static.pickle_vm import Global, Obj, class_of

Pair = tuple[str, str]


@dataclass(frozen=True)
class Profile:
    name: str
    producer: str
    patterns: tuple[str, ...]  # fnmatch patterns on the base file name (case-sensitive)
    source: str  # producer versions whose source confirmed the structure
    check: Callable[[Any], tuple[dict[int, tuple[Obj, Any]], str | None]]
    # globals the profile accepts at their allowed position -> review note
    clears: dict[Pair, str] = field(default_factory=dict)
    # globals whose position the profile constrains (always includes ``clears``)
    placed: Callable[[Pair], bool] = lambda pair: False
    # producer signature, from the stream's imports (names alone are not enough for
    # generic names such as best.pt)
    engaged: Callable[[list[dict]], bool] = lambda imports: True

    def matches_name(self, file_name: str) -> bool:
        base = file_name.replace("\\", "/").rsplit("/", 1)[-1]
        return any(fnmatch.fnmatchcase(base, p) for p in self.patterns)

    def is_placed(self, pair: Pair) -> bool:
        return pair in self.clears or self.placed(pair)


@dataclass
class Outcome:
    profile: Profile
    mismatch: str | None  # None: the structure matches


def find(file_name: str | None) -> Profile | None:
    from .registry import PROFILES

    if not file_name:
        return None
    for profile in PROFILES:
        if profile.matches_name(file_name):
            return profile
    return None


def evaluate(file_name: str | None, imports: list[dict], root: Any, calls: list[tuple],
             uses: list[tuple]) -> Outcome | None:
    """The profile outcome for one reading, or None when no profile is engaged."""
    profile = find(file_name)
    if profile is None or not profile.engaged(imports):
        return None
    accepted, why = profile.check(root)
    if why is None:
        why = _validate(profile, accepted, calls, uses)
    return Outcome(profile, why)


# --- structure helpers shared by the profiles ------------------------------------------

def rebuilt_instance(value) -> bool:
    """``cls.__new__(cls)`` (NEWOBJ with no arguments) plus one dict state with str keys."""
    return (isinstance(value, Obj) and value.how == "newobj" and isinstance(value.func, Global)
            and value.args == () and isinstance(value.state, dict)
            and all(isinstance(k, str) for k in value.state))


def str_keyed_dict(value) -> bool:
    return isinstance(value, dict) and all(isinstance(k, str) for k in value)


def stray(profile: Profile, root, accepted: dict[int, tuple[Obj, Any]]) -> str | None:
    """A placed global or instance anywhere in the tree outside the accepted positions."""
    seen: set[int] = set()
    stack = [root]
    while stack:
        value = stack.pop()
        if isinstance(value, (Obj, dict, list, tuple, set, frozenset)):
            if id(value) in seen:
                if id(value) in accepted:
                    return f"{_name(value)} appears more than once"
                continue
            seen.add(id(value))
        if isinstance(value, Global):
            if profile.is_placed(value.pair):
                return f"{value.module}.{value.name} appears as a value"
        elif isinstance(value, Obj):
            pair = class_of(value)
            if pair and profile.is_placed(pair) and id(value) not in accepted:
                return f"{_name(value)} outside its allowed position"
            if not (isinstance(value.func, Global) and id(value) in accepted):
                stack.append(value.func)
            stack.extend([value.args, value.state])
        elif isinstance(value, dict):
            stack.extend(value.keys())
            stack.extend(value.values())
        elif isinstance(value, (list, tuple, set, frozenset)):
            stack.extend(value)
    return None


def _name(obj: Obj) -> str:
    pair = class_of(obj)
    return f"{pair[0]}.{pair[1]} instance" if pair else "an object"


def _shallow(value, out: list) -> None:
    """Globals and Objs inside containers, without descending into an Obj."""
    stack, seen = [value], set()
    while stack:
        v = stack.pop()
        if isinstance(v, (Global, Obj)):
            out.append(v)
            continue
        if isinstance(v, (dict, list, tuple, set, frozenset)):
            if id(v) in seen:
                continue
            seen.add(id(v))
            stack.extend(v.items() if isinstance(v, dict) else v)


_CONSTRUCT = ("reduce", "newobj", "newobj_ex", "obj", "inst")


def _validate(profile: Profile, accepted: dict[int, tuple[Obj, Any]], calls: list[tuple],
              uses: list[tuple]) -> str | None:
    """Every call and use the stream makes of a placed global agrees with the tree: each
    accepted instance is built once (NEWOBJ ()) and gets one dict BUILD, and no placed
    global or accepted instance reaches any other call or use."""

    def placed(v) -> bool:
        if isinstance(v, Global):
            return profile.is_placed(v.pair)
        return isinstance(v, Obj) and id(v) in accepted

    built: dict[Pair, int] = {}
    builds: dict[int, int] = {}
    for how, func, args, _pos in calls:
        found: list = []
        if how in _CONSTRUCT and isinstance(func, Global) and profile.is_placed(func.pair):
            built[func.pair] = built.get(func.pair, 0) + 1
            _shallow(args, found)
        elif how == "build":
            if isinstance(func, Obj) and id(func) in accepted:
                builds[id(func)] = builds.get(id(func), 0) + 1
            _shallow(args, found)
            # an accepted instance is allowed in the dict state of its own parent
            found = [v for v in found if not (isinstance(v, Obj) and id(v) in accepted
                                              and accepted[id(v)][1] is func)]
        else:
            found.append(func)
            _shallow(args, found)
        for v in found:
            if placed(v):
                return f"{_label(v)} is passed to a call ({how})"
    for kind, items, target, _pos in uses:
        if isinstance(target, Obj) and id(target) in accepted:
            return f"{_label(target)} receives {kind}"
        found = []
        _shallow(items, found)
        if any(placed(v) for v in found):
            return f"a profile global is used as {kind}"
    expected: dict[Pair, int] = {}
    for obj, _parent in accepted.values():
        pair = class_of(obj)
        expected[pair] = expected.get(pair, 0) + 1
        if builds.get(id(obj), 0) != 1:
            return f"{_label(obj)} is not rebuilt by exactly one BUILD"
    for pair, count in built.items():
        if count != expected.get(pair, 0):
            return f"{pair[0]}.{pair[1]} is constructed outside its allowed position"
    return None


def _label(v) -> str:
    if isinstance(v, Global):
        return f"{v.module}.{v.name}"
    return _name(v)
