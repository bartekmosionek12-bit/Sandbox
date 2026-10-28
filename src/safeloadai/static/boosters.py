"""``--validate-boosters`` (off by default): accept the gradient-boosting Boosters whose
model bytes pass the strict structural validator (shared/booster_check.py, run in the
WASI sandbox).

Without the option a pickled ``xgboost.core.Booster``, ``lightgbm.basic.Booster`` or
CatBoost model stays UNVERIFIABLE (owner decision A2): its ``__setstate__`` hands bytes from
the file to a native C++ parser. With the option, the class is cleared for this file only
when every use of it in the stream is the one its library writes and every payload passes
the validator:

* the class global is used only as ``NEWOBJ cls ()`` (``copyreg.__newobj__``, protocol 2+);
  it is not called with arguments, passed as a value, or used any other way;
* each instance gets exactly one BUILD with a plain dict state, is never called, and no
  item is set or appended on it;
* the state's payload is what the library's ``__getstate__`` writes and its ``__setstate__``
  reads (xgboost: ``handle``, a bytearray; lightgbm: ``_handle`` (4.x) and ``handle`` (3.x),
  str, both checked when both are present; catboost: ``__model``, bytes) or None (then
  nothing native runs);
* catboost: the evaluation results ``__setstate__`` hands to Cython are plain numbers.

Everything else leaves the class UNVERIFIABLE, exactly as without the option; nothing here
can make a verdict stricter or looser than that. The clearance is recorded in the report
(``cleared``, mechanism ``validated-booster``) with the library version the payload names.
docs/OPTIONS.md states the residual risk: the native parser is trusted with bytes that are
consistent in every length, index and reference the validator checks.
"""
from __future__ import annotations

from .clearance import PLAIN_CONTAINERS
from .pickle_vm import Global, Obj, class_of

CATBOOST_CLASSES = ("CatBoost", "CatBoostClassifier", "CatBoostRegressor", "CatBoostRanker")
# (module, qualname) -> library of the validator
BOOSTERS: dict[tuple[str, str], str] = {
    ("xgboost.core", "Booster"): "xgboost",
    ("lightgbm.basic", "Booster"): "lightgbm",
    **{("catboost.core", name): "catboost" for name in CATBOOST_CLASSES},
}
MECHANISM = "validated-booster"
BYTEARRAY = frozenset({("builtins", "bytearray"), ("__builtin__", "bytearray")})
CODECS_ENCODE = ("_codecs", "encode")  # how protocols 0 to 2 write bytes: encode(str, "latin1")
MAX_WALK = 2_000_000


class _Refused(Exception):
    pass


def _xgboost_payloads(state: dict) -> list[bytes]:
    handle = state.get("handle")
    if handle is None:
        return []
    return [_bytearray(handle)]


def _latin1(args) -> bytes | None:
    if isinstance(args, tuple) and len(args) == 2 and type(args[0]) is str and args[1] in ("latin1", "latin-1"):
        try:
            return args[0].encode("latin-1")
        except UnicodeEncodeError:
            raise _Refused("a str latin-1 cannot encode") from None
    return None


def _bytearray(handle) -> bytes:
    """The bytes of a bytearray as pickle writes one: BYTEARRAY8 (protocol 5),
    bytearray(bytes) (3 and 4), bytearray(_codecs.encode(str, 'latin1')) (2) or
    bytearray(str, 'latin-1') (0 and 1)."""
    if isinstance(handle, bytearray):
        return bytes(handle)
    if isinstance(handle, Obj) and handle.how == "reduce" and isinstance(handle.func, Global) \
            and handle.func.pair in BYTEARRAY and isinstance(handle.args, tuple):
        args = handle.args
        if len(args) == 1 and type(args[0]) is bytes:
            return args[0]
        inner = args[0] if len(args) == 1 else None
        if isinstance(inner, Obj) and inner.how == "reduce" and isinstance(inner.func, Global) \
                and inner.func.pair == CODECS_ENCODE and _latin1(inner.args) is not None:
            return _latin1(inner.args)
        if _latin1(args) is not None:
            return _latin1(args)
    raise _Refused(f"handle is a {type(handle).__name__} xgboost never writes")


def _lightgbm_payloads(state: dict) -> list[bytes]:
    # LightGBM 4.x: state.get("_handle", state.get("handle", None)); 3.x: state.get("handle").
    # Which key a loader reads depends on its version, so every model string present is checked.
    out = []
    for key in ("_handle", "handle"):
        model = state.get(key)
        if model is None:
            continue
        if type(model) is not str:
            raise _Refused(f"{key} is a {type(model).__name__}, not the model string")
        try:
            out.append(model.encode("utf-8"))  # _c_str / c_str: model_str.encode("utf-8")
        except UnicodeEncodeError:
            raise _Refused(f"{key} cannot be encoded as UTF-8") from None
    return out


def _numbers(value, depth: int = 0) -> bool:
    if isinstance(value, (list, tuple)) and depth < 4:
        return all(_numbers(v, depth + 1) for v in value)
    return type(value) in (int, float)


def _catboost_payloads(state: dict) -> list[bytes]:
    for key in ("_test_eval", "_test_evals"):
        if key in state and not _numbers(state[key]):
            raise _Refused(f"{key} is not plain numbers")
    if "__model" not in state:
        return []
    model = state["__model"]
    if type(model) is not bytes:
        raise _Refused(f"__model is a {type(model).__name__}")
    return [model]


_PAYLOADS = {"xgboost": _xgboost_payloads, "lightgbm": _lightgbm_payloads, "catboost": _catboost_payloads}


def _occurrences(value, targets: set[int], steps: list[int]) -> bool:
    """Whether any of the objects with ids ``targets`` is reachable in ``value``."""
    todo, seen = [value], set()
    while todo:
        item = todo.pop()
        steps[0] += 1
        if steps[0] > MAX_WALK:
            return True  # undecided counts as used
        if id(item) in targets:
            return True
        if id(item) in seen:
            continue
        if isinstance(item, Obj):
            seen.add(id(item))
            todo += [item.func, item.args, item.state]
        elif isinstance(item, (tuple, list, set, frozenset)):
            seen.add(id(item))
            todo.extend(item)
        elif isinstance(item, dict):
            seen.add(id(item))
            todo.extend(v for kv in item.items() for v in kv)
    return False


class _Recorder:
    """Appends each call to ``calls`` and keeps a copy of each Booster's BUILD state as it
    was at that BUILD: ``__setstate__`` runs then, and the pickle may change the same dict
    afterwards (SETITEM through the memo), which the walk's final values would show instead."""

    def __init__(self, calls: list):
        self.calls = calls
        self.states: dict[int, dict] = {}

    def __call__(self, call: tuple) -> None:
        how, func, args, _pos = call
        if how == "build" and class_of(func) in BOOSTERS and isinstance(args, tuple) and len(args) == 1 \
                and isinstance(args[0], dict) and id(func) not in self.states:
            self.states[id(func)] = dict(args[0])
        self.calls.append(call)


def recorder(calls: list) -> _Recorder:
    """The on_call recorder parse_pickle uses with --validate-boosters."""
    return _Recorder(calls)


def find(report: dict, calls: list[tuple], uses: list[tuple], globals_at: dict,
         states: dict) -> tuple[dict, dict]:
    """({pair: [(library, payload bytes), ...]}, {pair: reason}) for the Booster classes the
    stream imports: the payloads to validate when every use is the expected one, or why not."""
    pairs = {(i["module"], i["symbol"]) for i in report.get("imports") or [] if i.get("resolved")}
    wanted = {p for p in pairs if p in BOOSTERS}
    if not wanted:
        return {}, {}
    refused: dict = {}
    payloads: dict = {p: [] for p in wanted}
    instances: dict[int, Obj] = {}
    builds: dict[int, int] = {}
    # Every stand-in the stream's imports produced, used or not: a class that reaches a
    # call only as an argument (copyreg._reconstructor(cls, object, None)) is caught below.
    class_globals = {id(g) for g in globals_at.values() if isinstance(g, Global) and g.pair in wanted}
    for how, func, args, pos in calls:
        if isinstance(func, Global) and func.pair in wanted:
            class_globals.add(id(func))
            if how != "newobj" or args != ():
                refused.setdefault(func.pair, f"{func.module}.{func.name} is used through {how.upper()} "
                                              f"with {type(args).__name__} arguments at {pos}, not NEWOBJ cls ()")
        elif isinstance(func, Obj) and class_of(func) in wanted and func.how == "newobj":
            pair = class_of(func)
            instances[id(func)] = func
            if how != "build":
                refused.setdefault(pair, f"an instance of {pair[0]}.{pair[1]} is called ({how.upper()}) at {pos}")
                continue
            builds[id(func)] = builds.get(id(func), 0) + 1
            state = args[0] if isinstance(args, tuple) and len(args) == 1 else None
            if isinstance(state, dict) and states.get(id(func)) != state:
                refused.setdefault(pair, f"the BUILD state of {pair[0]}.{pair[1]} at {pos} is changed after the BUILD")
                continue
            if builds[id(func)] > 1 or not isinstance(state, dict) or not all(type(k) is str for k in state):
                refused.setdefault(pair, f"an instance of {pair[0]}.{pair[1]} gets a BUILD state its library "
                                         f"never writes at {pos}")
                continue
            library = BOOSTERS[pair]
            try:
                found = _PAYLOADS[library](state)
            except _Refused as exc:
                refused.setdefault(pair, f"{pair[0]}.{pair[1]} at {pos}: {exc}")
                continue
            payloads[pair].extend((library, payload) for payload in found)
    for obj_id, obj in instances.items():
        if obj_id not in builds:
            pair = class_of(obj)
            refused.setdefault(pair, f"an instance of {pair[0]}.{pair[1]} is never given its state")
    # The class may reach nothing but its own NEWOBJ; an instance may only be stored, as a
    # value in another object's BUILD state (XGBClassifier._Booster, an ensemble's list).
    # As a call argument or an item set on an object it could reach code nobody checked.
    steps = [0]
    instance_ids = set(instances)
    everything = class_globals | instance_ids
    for how, func, args, pos in calls:
        own = isinstance(func, Global) and id(func) in class_globals
        if own and args == ():
            continue
        if how == "build":
            values, watch = ((args,) if id(func) in instance_ids else (func, args)), class_globals
        else:
            values, watch = (func, args), everything
        if _occurrences(values, watch, steps):
            for pair in wanted:
                refused.setdefault(pair, f"the class or an instance reaches a {how.upper()} call at {pos}; "
                                         "it may only be instantiated and stored")
    for kind, items, target, pos in uses:
        if id(target) in instance_ids:
            pair = class_of(target)
            refused.setdefault(pair, f"an item is {kind}-ed on an instance of {pair[0]}.{pair[1]} at {pos}")
        if class_of(target) in PLAIN_CONTAINERS and kind in ("setitem", "append"):
            items = items[0::2] if kind == "setitem" else ()  # values are stored; keys are hashed
        if _occurrences(items, everything, steps):
            for pair in wanted:
                refused.setdefault(pair, f"the class or an instance is used as an item ({kind}) at {pos}")
    return {p: v for p, v in payloads.items() if p not in refused}, refused


def clear(report: dict, calls: list[tuple], uses: list[tuple], globals_at: dict, extra: dict,
          states: dict) -> None:
    """Validate the stream's Booster payloads in the sandbox and add each pair whose every
    payload is valid to ``extra`` (mechanism ``validated-booster``). Records the outcome
    under ``report["boosters"]``."""
    candidates, refused = find(report, calls, uses, globals_at, states)
    record = report.setdefault("boosters", [])
    for pair, why in sorted(refused.items()):
        record.append({"item": ".".join(pair), "validated": False, "reason": why})
    items = [(pair, lib, payload) for pair, entries in sorted(candidates.items()) for lib, payload in entries]
    results: list[dict] = []
    if items:
        from ..sandbox import validate_boosters

        outcome = validate_boosters([(lib, payload) for _, lib, payload in items])
        if "failed" not in outcome and len(outcome.get("results") or []) != len(items):
            outcome = {"failed": f"{len(outcome.get('results') or [])} results for {len(items)} payloads"}
        if "failed" in outcome:
            for pair in sorted(candidates):
                record.append({"item": ".".join(pair), "validated": False,
                               "reason": "the validator did not finish: " + str(outcome["failed"])[:300]})
            return
        results = outcome["results"]
    for pair in sorted(candidates):
        mine = [r for (p, _, _), r in zip(items, results, strict=True) if p == pair]
        bad = [r["invalid"] for r in mine if "invalid" in r]
        if bad:
            record.append({"item": ".".join(pair), "validated": False, "reason": "model bytes refused: " + bad[0]})
            continue
        summaries = [r["summary"] for r in mine]
        detail = "; ".join(f"{s['library']} {s['encoding']} model {s['version']}, {s['booster']}, {s['trees']} trees"
                           for s in summaries[:3]) or "no model bytes (handle is None)"
        record.append({"item": ".".join(pair), "validated": True, "models": summaries})
        extra.setdefault(pair, (MECHANISM, f"--validate-boosters: {detail} passed the structural validator"))
