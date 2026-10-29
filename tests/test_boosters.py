"""--validate-boosters (0.10.0): pickled XGBoost, LightGBM and CatBoost Boosters whose model
bytes pass the strict structural validator (shared/booster_check.py, run in the WASI
sandbox) are accepted; by default they stay UNVERIFIABLE (owner decision A2).

The valid payloads were written by the libraries themselves (tools/make_booster_fixtures.py);
every malformed variant is made from their bytes here. The pickles use stand-in classes
registered under the libraries' module names only while pickling; nothing imports
xgboost, lightgbm or catboost and nothing is unpickled."""
from __future__ import annotations

import contextlib
import json
import os
import pickle
import random
import struct
import sys
import types

import pytest

from safeloadai import Verdict, scan
from safeloadai.shared import booster_check as bc
from safeloadai.static import boosters

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures", "boosters")
MARKER = "SAFELOADAI_TEST_MARKER"


def fixture(name: str) -> bytes:
    with open(os.path.join(FIXTURES, name), "rb") as fh:
        return fh.read()


def lgb(name: str = "lgb.txt") -> str:
    return fixture(name).decode("utf-8")


def invalid(library: str, payload, match: str | None = None) -> None:
    with pytest.raises(bc.Invalid, match=match):
        bc.check(library, payload)


# --- a UBJSON writer (the subset libxgboost writes), for the variants ------------------------

def ubj(value) -> bytes:
    if isinstance(value, dict):
        out = b"{"
        for key, item in value.items():
            raw = key.encode()
            out += b"L" + struct.pack(">q", len(raw)) + raw + ubj(item)
        return out + b"}"
    if isinstance(value, bc.Typed):
        fmt = bc._UBJ_SCALARS[value.code]
        return (b"[$" + value.code.encode() + b"#L" + struct.pack(">q", len(value))
                + struct.pack(f">{len(value)}{fmt[1]}", *value.values))
    if isinstance(value, list):
        return b"[#L" + struct.pack(">q", len(value)) + b"".join(ubj(v) for v in value)
    if isinstance(value, str):
        raw = value.encode()
        return b"SL" + struct.pack(">q", len(raw)) + raw
    if value is True or value is False:
        return b"T" if value else b"F"
    if value is None:
        return b"Z"
    if isinstance(value, int):
        return b"L" + struct.pack(">q", value)
    if isinstance(value, float):
        return b"D" + struct.pack(">d", value)
    raise TypeError(type(value))


def xgb_doc(name: str = "xgb.ubj") -> dict:
    return bc._load_ubjson(fixture(name))


def first_tree(doc: dict) -> dict:
    return doc["Model"]["learner"]["gradient_booster"]["model"]["trees"][0]


def set_typed(tree: dict, key: str, index: int, value) -> None:
    arr = tree[key]
    values = list(arr.values)
    values[index] = value
    tree[key] = bc.Typed(arr.code, tuple(values))


def to_json(value):
    if isinstance(value, bc.Typed):
        return list(value.values)
    if isinstance(value, dict):
        return {k: to_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_json(v) for v in value]
    return value


# --- the fixtures the libraries wrote ---------------------------------------------------------

@pytest.mark.parametrize("name", ["xgb.ubj", "xgb_dart.ubj", "xgb_multi.ubj"])
def test_xgboost_serializations_validate(name):
    summary = bc.check("xgboost", fixture(name))
    assert summary["library"] == "xgboost" and summary["encoding"] == "ubjson" and summary["trees"] > 0


def test_xgboost_json_serialization_validates():
    # xgboost before 2.0 stored the serialization as JSON text ('{"Config": ...').
    text = json.dumps(to_json(xgb_doc()), separators=(",", ":")).encode()
    assert bc.check("xgboost", text)["encoding"] == "json"


def test_xgboost_categorical_container_stays_unverifiable():
    invalid("xgboost", fixture("xgb_cat.ubj"), "category container")


@pytest.mark.parametrize("name", ["lgb.txt", "lgb_multi.txt", "lgb_linear.txt", "lgb_cat.txt"])
def test_lightgbm_models_validate(name):
    summary = bc.check("lightgbm", lgb(name))
    assert summary["library"] == "lightgbm" and summary["trees"] > 0


@pytest.mark.parametrize("name", ["cb.cbm", "cb_onehot.cbm"])
def test_catboost_models_validate(name):
    assert bc.check("catboost", fixture(name))["booster"] == "oblivious"


def test_catboost_ctr_model_stays_unverifiable():
    # CTR tables are a model part after the flatbuffer core: not validated.
    invalid("catboost", fixture("cb_ctr.cbm"), "model parts")


# --- XGBoost: malformed variants ----------------------------------------------------------------

def _xgb_variant(change, name: str = "xgb.ubj") -> bytes:
    doc = xgb_doc(name)
    change(doc)
    return ubj(doc)


def test_xgboost_round_trip_of_the_writer_is_valid():
    assert bc.check("xgboost", _xgb_variant(lambda doc: None))


@pytest.mark.parametrize("change, match", [
    (lambda d: set_typed(first_tree(d), "parents", 1, 10_000), "inconsistent"),  # self[parent] unchecked
    (lambda d: set_typed(first_tree(d), "left_children", 0, 10_000), "inconsistent"),
    (lambda d: set_typed(first_tree(d), "left_children", 0, 0), "inconsistent"),  # a cycle to the root
    (lambda d: set_typed(first_tree(d), "right_children", 0, first_tree(d)["left_children"].values[0]),
     "inconsistent"),
    (lambda d: set_typed(first_tree(d), "split_indices", 0, 4), "inconsistent"),  # 4 features: 0..3
    (lambda d: set_typed(first_tree(d), "parents", 0, 5), "root has a parent"),
    (lambda d: first_tree(d).__setitem__("id", 3), "has id"),
    (lambda d: first_tree(d)["tree_param"].__setitem__("num_nodes", "999"), "entries, expected"),
    (lambda d: first_tree(d)["tree_param"].__setitem__("num_deleted", "1"), "deleted"),
    (lambda d: first_tree(d)["tree_param"].__setitem__("size_leaf_vector", "3"), "multi-target"),
    (lambda d: first_tree(d).__setitem__("extra", 1), "does not write"),
    (lambda d: first_tree(d).__setitem__("parents", bc.Typed("L", first_tree(d)["parents"].values)), "typed array"),
    (lambda d: d["Model"]["learner"]["gradient_booster"]["model"]["tree_info"].__setitem__(0, 7), "output group"),
    (lambda d: d["Model"]["learner"]["gradient_booster"]["model"]["iteration_indptr"].__setitem__(-1, 99), "indptr"),
    (lambda d: d["Model"]["learner"]["gradient_booster"]["model"]["trees"].pop(), "disagree"),
    (lambda d: d["Model"]["learner"]["gradient_booster"].__setitem__("name", "gblinear"), "not validated"),
    (lambda d: d["Model"]["learner"]["learner_model_param"].__setitem__("num_feature", "-1"), "decimal"),
    (lambda d: d["Config"].__setitem__("version", [1, 0, 0]), "versions differ"),
    (lambda d: d.__setitem__("Extra", {}), "does not write"),
    (lambda d: d["Model"]["learner"]["attributes"].__setitem__("x", 1), "not strings"),
])
def test_xgboost_inconsistencies_are_refused(change, match):
    invalid("xgboost", _xgb_variant(change), match)


def _categorical_tree(doc: dict, segments=(0,), sizes=(2,), cats=(1, 3), nodes=(0,)) -> None:
    """Turn the first tree's root into a categorical split, the way RegTree::SaveCategoricalSplit
    writes one (no category container: xgboost 1.5 to 3.0 models)."""
    tree = first_tree(doc)
    n = len(tree["parents"])
    kinds = [0] * n
    for node in nodes:
        if 0 <= node < n:
            kinds[node] = 1
    tree.update(split_type=bc.Typed("U", tuple(kinds)), categories=bc.Typed("l", tuple(cats)),
                categories_nodes=bc.Typed("l", tuple(nodes)), categories_segments=bc.Typed("L", tuple(segments)),
                categories_sizes=bc.Typed("L", tuple(sizes)))
    doc["Model"]["learner"]["gradient_booster"]["model"].pop("cats", None)


def test_xgboost_categorical_split_without_container_validates():
    assert bc.check("xgboost", _xgb_variant(_categorical_tree))


@pytest.mark.parametrize("kwargs, match", [
    ({"segments": (1,), "sizes": (2,)}, "out of range"),  # categories[j] read unchecked
    ({"sizes": (0,)}, "out of range"),
    ({"cats": (1, -5)}, "out of range"),
    ({"cats": (1, 1 << 30)}, "out of range"),  # a bit field of max_cat + 1 bits
    ({"nodes": (500,)}, "disagree"),
    ({"nodes": (0, 0), "segments": (0, 0), "sizes": (1, 1)}, "increasing"),
])
def test_xgboost_categorical_inconsistencies_are_refused(kwargs, match):
    invalid("xgboost", _xgb_variant(lambda d: _categorical_tree(d, **kwargs)), match)


def test_xgboost_ubjson_lengths_are_bounded():
    data = fixture("xgb.ubj")
    start = data.index(b"{L") + 2  # the first key's length: UBJReader::DecodeStr copies it unchecked
    patched = data[:start] + struct.pack(">q", len(data) * 4) + data[start + 8:]
    invalid("xgboost", patched, "past the end")
    invalid("xgboost", data + b"Z", "after the UBJSON document")
    invalid("xgboost", data[:-1], "ends early")
    typed = data.index(b"[$d#L") + 5
    invalid("xgboost", data[:typed] + struct.pack(">q", 1 << 40) + data[typed + 8:], "past the end")


def test_xgboost_ubjson_duplicate_key_and_unknown_marker():
    one = ubj({"a": 1})
    invalid("xgboost", b"{" + one[1:-1] + one[1:-1] + b"}", None)
    invalid("xgboost", b"{L" + struct.pack(">q", 1) + b"aH" + b"}", None)


@pytest.mark.parametrize("text, match", [
    (b'{"Config":{},"Config":{}}', "duplicate"),
    (b'{"Config":NaN}', "constant"),
    (b'{"Config":"\\u0041"}', "escapes"),
    (b'{"Config":"\xc3\xa9"}', "escapes"),
    (b'{"Config": [1,', "not valid JSON"),
])
def test_xgboost_json_text_is_strict(text, match):
    invalid("xgboost", text, match)


def test_xgboost_old_binary_serialization_stays_unverifiable():
    invalid("xgboost", b"binf" + bytes(100), "not a JSON or UBJSON")
    invalid("xgboost", b"CONFIG-offset:" + bytes(20), "not a JSON or UBJSON")


# --- LightGBM: malformed variants -------------------------------------------------------------

def _replace_once(text: str, old: str, new: str) -> str:
    assert old in text, old
    return text.replace(old, new, 1)


def _tree_line(text: str, key: str, tree: int = 0) -> str:
    start = text.index(f"Tree={tree}\n")
    line_start = text.index(f"\n{key}=", start) + 1
    return text[line_start:text.index("\n", line_start)]


def _set_tree_line(text: str, key: str, value: str, tree: int = 0) -> str:
    """Replace one field of one tree and keep tree_sizes exact, so the check under test is
    the one that fires."""
    old = _tree_line(text, key, tree)
    new = f"{key}={value}"
    out = _replace_once(text, old, new)
    line = next(x for x in out.split("\n") if x.startswith("tree_sizes="))
    sizes = [int(v) for v in line[len("tree_sizes="):].split(" ")]
    sizes[tree] += len(new) - len(old)
    return _replace_once(out, line, "tree_sizes=" + " ".join(map(str, sizes)))


def test_lightgbm_edit_helper_keeps_the_model_valid():
    text = lgb()
    same = _set_tree_line(text, "shrinkage", _tree_line(text, "shrinkage")[len("shrinkage="):] + "0")
    assert bc.check("lightgbm", same)


def _n_inner(text: str) -> int:
    return len(_tree_line(text, "left_child")[len("left_child="):].split(" "))


@pytest.mark.parametrize("key, values, match", [
    ("left_child", lambda n: [99] + [-(i + 1) for i in range(n - 1)], "out of range"),
    ("left_child", lambda n: [-1] * n, "reached twice"),
    ("split_feature", lambda n: [9] + [0] * (n - 1), "out of range"),
    ("leaf_value", lambda n: [1, 2], "values, expected"),
    ("decision_type", lambda n: [15] + [2] * (n - 1), "out of range"),
    ("decision_type", lambda n: [1] * n, "num_cat=0"),
    ("num_cat", lambda n: [1], "categories"),
    ("threshold", lambda n: ["0x10"] * n, "does not write"),
])
def test_lightgbm_tree_inconsistencies_are_refused(key, values, match):
    text = lgb()
    value = " ".join(map(str, values(_n_inner(text))))
    invalid("lightgbm", _set_tree_line(text, key, value), match)


def test_lightgbm_tree_sizes_must_match_exactly():
    text = lgb()
    line = next(x for x in text.split("\n") if x.startswith("tree_sizes="))
    values = [int(v) for v in line[len("tree_sizes="):].split(" ")]
    for delta in (-1, 1, 1000):
        bad = values.copy()
        bad[0] += delta
        invalid("lightgbm", _replace_once(text, line, "tree_sizes=" + " ".join(map(str, bad))))
    invalid("lightgbm", _replace_once(text, line, "tree_sizes=" + " ".join(map(str, values[:-1]))))
    invalid("lightgbm", _replace_once(text, line + "\n", ""), "lacks tree_sizes")


@pytest.mark.parametrize("old, new, match", [
    ("num_class=1", "num_class=2", "num_tree_per_iteration"),
    ("objective=binary sigmoid:1", "objective=binary sigmoid:1 num_class:2", "num_class"),
    ("objective=binary sigmoid:1", "objective=evil", "objective"),
    ("version=v4", "version=v9", "model version"),
    ("max_feature_idx=3", "max_feature_idx=7", "feature_names"),
    ("end of parameters", "end of parameters\n\nparser:\n{}\nend of parser", "after the parameters"),
    ("\nparameters:", "\nbogus\nparameters:", None),
    ("tree\nversion", "tree\nunknown=1\nversion", "header line"),
])
def test_lightgbm_header_and_sections_are_refused(old, new, match):
    invalid("lightgbm", _replace_once(lgb(), old, new), match)


def test_lightgbm_multiclass_objective_must_match_num_class():
    text = lgb("lgb_multi.txt")
    assert "num_class:3" in text
    invalid("lightgbm", _replace_once(text, "num_class:3", "num_class:9"), "num_class")


@pytest.mark.parametrize("change", [
    lambda t: t.replace("\n", "\r\n"),
    lambda t: t.replace("num_cat=0", "num_cat=0\x00", 1),
    lambda t: t[:len(t) // 2],
    lambda t: "garbage\n" + t,
    lambda t: t.replace("is_linear=0\n", "is_linear=0\nleaf_const=1\n", 1),
])
def test_lightgbm_text_variants_are_refused(change):
    invalid("lightgbm", change(lgb()))


def test_lightgbm_repeated_tree_key_is_refused():
    text = lgb()
    line = _tree_line(text, "shrinkage")
    invalid("lightgbm", _set_tree_line(text, "shrinkage", line[len("shrinkage="):] + "\n" + line), "repeats")


# --- CatBoost: malformed variants ------------------------------------------------------------

def _cb_vector(data: bytes, slot: int) -> tuple[int, int]:
    """(absolute start, length) of a TModelTrees vector field, read with the validator's reader."""
    fb = bc._Fb(data[8:])
    core = fb.root()
    trees = fb._target(fb.fields(core, 4)[1])
    start, n = fb.vector(fb.fields(trees, 19)[slot], 4)
    return start + 8, n


def test_catboost_split_index_out_of_range_is_refused():
    data = bytearray(fixture("cb.cbm"))
    start, n = _cb_vector(bytes(data), 1)  # TreeSplits
    assert n > 0
    struct.pack_into("<i", data, start, 1 << 20)
    invalid("catboost", bytes(data), "bin feature")


def test_catboost_tree_sizes_must_cover_the_splits():
    data = bytearray(fixture("cb.cbm"))
    start, n = _cb_vector(bytes(data), 2)  # TreeSizes
    struct.pack_into("<i", data, start, struct.unpack_from("<i", data, start)[0] + 1)
    invalid("catboost", bytes(data))


@pytest.mark.parametrize("change, match", [
    (lambda d: d[:-1], "core does not end"),
    (lambda d: d + b"\x00", "core does not end"),
    (lambda d: b"CBM2" + d[4:], "descriptor"),
    (lambda d: d[:4] + struct.pack("<I", 0xFFFFFFFF) + d[8:], "64-bit"),
    (lambda d: d[:8] + struct.pack("<I", len(d)) + d[12:], "reference out of range"),
])
def test_catboost_container_variants_are_refused(change, match):
    invalid("catboost", change(fixture("cb.cbm")), match)


# --- fuzzing: the validators only ever accept or raise Invalid ------------------------------

FUZZ = [("xgboost", "xgb.ubj"), ("xgboost", "xgb_dart.ubj"), ("lightgbm", "lgb.txt"), ("lightgbm", "lgb_cat.txt"),
        ("lightgbm", "lgb_linear.txt"), ("catboost", "cb.cbm"), ("catboost", "cb_onehot.cbm")]


@pytest.mark.parametrize("library, name", FUZZ)
def test_random_mutations_never_crash_the_validator(library, name):
    rng = random.Random(f"{library}-{name}")
    data = fixture(name)
    accepted = 0
    for _ in range(400):
        mutated = bytearray(data)
        for _ in range(rng.randint(1, 6)):
            op = rng.random()
            pos = rng.randrange(len(mutated))
            if op < 0.6:
                mutated[pos] = rng.randrange(256)
            elif op < 0.8:
                del mutated[pos:pos + rng.randint(1, 16)]
            else:
                mutated[pos:pos] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
        payload = bytes(mutated)
        if library == "lightgbm":
            try:
                payload = payload.decode("utf-8")
            except UnicodeDecodeError:
                continue
        try:
            bc.check(library, payload)
            accepted += 1
        except bc.Invalid:
            pass
    # A mutation that keeps every structure consistent (a changed leaf value or threshold
    # digit) may pass; most must not.
    assert accepted < 400


@pytest.mark.parametrize("library, name", FUZZ)
def test_truncations_are_refused(library, name):
    data = fixture(name)
    # LightGBM ignores what follows its parameters (Python's pandas_categorical line), so a
    # cut there changes nothing the native parser reads; every earlier cut must be refused.
    end = data.index(b"end of parameters") + 17 if library == "lightgbm" else len(data)
    for cut in sorted({1, 2, 7, end // 3, end // 2, end - 9, end - 1}):
        payload = data[:cut]
        if library == "lightgbm":
            payload = payload.decode("utf-8", "ignore")
        with pytest.raises(bc.Invalid):
            bc.check(library, payload)


def test_structural_mutations_of_xgboost_trees_never_pass_unless_consistent():
    """Random index changes in every tree array: anything accepted must still be a tree
    the reviewed loader reads in bounds (re-checked here independently)."""
    rng = random.Random(7)
    for _ in range(300):
        doc = xgb_doc()
        tree = rng.choice(doc["Model"]["learner"]["gradient_booster"]["model"]["trees"])
        key = rng.choice(["left_children", "right_children", "parents", "split_indices"])
        set_typed(tree, key, rng.randrange(len(tree[key])), rng.choice([-2, -1, 0, 1, 2, 3, 4, 5, 2 ** 31 - 1]))
        try:
            bc.check("xgboost", ubj(doc))
        except bc.Invalid:
            continue
        n = len(tree["parents"])
        for i in range(n):
            lc, rc = tree["left_children"].values[i], tree["right_children"].values[i]
            assert (lc, rc) == (-1, -1) or (0 < lc < n and 0 < rc < n)
            assert i == 0 or 0 <= tree["parents"].values[i] < n


# --- the pickle side: which uses of a Booster class are cleared ------------------------------

@contextlib.contextmanager
def stand_in(module: str, name: str, reduce=None):
    """A class registered as ``module.name`` while pickling; ``reduce`` overrides __reduce_ex__."""
    cls = type(name, (), {})
    cls.__module__, cls.__qualname__ = module, name
    if reduce is not None:
        cls.__reduce_ex__ = lambda self, proto: reduce(cls, self)
    saved = {k: sys.modules.get(k) for k in (module, module.split(".")[0])}
    mod = types.ModuleType(module)
    setattr(mod, name, cls)
    sys.modules[module] = mod
    sys.modules.setdefault(module.split(".")[0], types.ModuleType(module.split(".")[0]))
    try:
        yield cls
    finally:
        for key, value in saved.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value


def booster_pickle(tmp_path, library: str, state: dict, name: str = "model.pkl", reduce=None, wrap=None) -> str:
    module, cls_name = {"xgboost": ("xgboost.core", "Booster"), "lightgbm": ("lightgbm.basic", "Booster"),
                        "catboost": ("catboost.core", "CatBoostClassifier")}[library]
    with stand_in(module, cls_name, reduce) as cls:
        obj = cls()
        obj.__dict__.update(state)
        data = pickle.dumps(wrap(obj) if wrap else obj, protocol=4)
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


STATES = {
    "xgboost": lambda: {"handle": bytearray(fixture("xgb.ubj")), "booster": "gbtree"},
    "lightgbm": lambda: {"_handle": lgb(), "_network": False, "best_iteration": 0},
    "catboost": lambda: {"iterations": 5, "__model": fixture("cb.cbm")},
}


@pytest.mark.parametrize("library", sorted(STATES))
def test_default_keeps_boosters_unverifiable(tmp_path, library):
    report = scan(booster_pickle(tmp_path, library, STATES[library]()))
    assert report.verdict is Verdict.SUSPICIOUS
    assert report.unverifiable_only
    assert not any(c["mechanism"] == boosters.MECHANISM for c in report.cleared)


@pytest.mark.parametrize("library", sorted(STATES))
def test_valid_boosters_are_clean_with_the_option(tmp_path, library):
    report = scan(booster_pickle(tmp_path, library, STATES[library]()), validate_boosters=True)
    assert report.verdict is Verdict.CLEAN, report.reasons
    entry = next(c for c in report.cleared if c["mechanism"] == boosters.MECHANISM)
    assert "--validate-boosters" in entry["detail"] and library in entry["detail"]
    assert {"name": "validate_boosters", "value": True, "source": "argument", "direction": "looser"} in report.options


def test_protocol_2_bytearray_handle(tmp_path):
    path = tmp_path / "p2.pkl"
    with stand_in("xgboost.core", "Booster") as cls:
        obj = cls()
        obj.__dict__.update(STATES["xgboost"]())
        path.write_bytes(pickle.dumps(obj, protocol=2))
    assert scan(str(path), validate_boosters=True).verdict is Verdict.CLEAN


def test_protocol_5_bytearray_handle(tmp_path):
    path = tmp_path / "p5.pkl"
    with stand_in("xgboost.core", "Booster") as cls:
        obj = cls()
        obj.__dict__.update(STATES["xgboost"]())
        path.write_bytes(pickle.dumps(obj, protocol=5))
    assert scan(str(path), validate_boosters=True).verdict is Verdict.CLEAN


def test_booster_stored_in_a_container(tmp_path):
    # XGBClassifier keeps its Booster in _Booster; whatever holds it is judged on its own.
    def wrap(obj):
        return {"_Booster": obj, "n_estimators": 5, "ensemble": [obj]}

    report = scan(booster_pickle(tmp_path, "xgboost", STATES["xgboost"](), wrap=wrap), validate_boosters=True)
    assert report.verdict is Verdict.CLEAN, report.reasons


def test_booster_in_the_state_of_its_sklearn_wrapper(tmp_path):
    # XGBClassifier is rebuilt with NEWOBJ () and BUILD {"_Booster": <Booster>, ...}: the Booster
    # instance is stored, and the class global inside it is not a second use of the class.
    path = tmp_path / "model.pkl"
    with stand_in("xgboost.core", "Booster") as booster, stand_in("xgboost.sklearn", "XGBClassifier") as cls:
        inner = booster()
        inner.__dict__.update(STATES["xgboost"]())
        outer = cls()
        outer.__dict__.update(_Booster=inner, n_estimators=5)
        path.write_bytes(pickle.dumps(outer, protocol=4))
    assert scan(str(path)).verdict is Verdict.SUSPICIOUS
    report = scan(str(path), validate_boosters=True)
    assert report.verdict is Verdict.CLEAN, report.reasons


def test_booster_class_as_a_value_in_a_wrapper_state_is_not_cleared(tmp_path):
    # the class global itself (not an instance) in another object's state stays a use
    path = tmp_path / "model.pkl"
    with stand_in("xgboost.core", "Booster") as booster, stand_in("xgboost.sklearn", "XGBClassifier") as cls:
        inner = booster()
        inner.__dict__.update(STATES["xgboost"]())
        outer = cls()
        outer.__dict__.update(_Booster=inner, factory=booster)
        path.write_bytes(pickle.dumps(outer, protocol=4))
    _assert_not_cleared(scan(str(path), validate_boosters=True), "reaches a BUILD call")


def _assert_not_cleared(report, why: str | None = None):
    assert report.verdict is not Verdict.CLEAN
    assert not any(c["mechanism"] == boosters.MECHANISM for c in report.cleared)
    if why:
        details = json.dumps(report.layers[0].details.get("boosters") or [])
        assert why in details, details


@pytest.mark.parametrize("library, change, why", [
    ("xgboost", lambda s: s.update(handle=bytearray(fixture("xgb.ubj")[:-1])), "refused"),
    ("xgboost", lambda s: s.update(handle=bytes(fixture("xgb.ubj"))), "never writes"),
    ("xgboost", lambda s: s.update(handle="text"), "never writes"),
    ("lightgbm", lambda s: s.update(_handle=lgb().replace("num_class=1", "num_class=2")), "refused"),
    ("lightgbm", lambda s: s.update(_handle=b"tree\n"), "not the model string"),
    # 3.x reads "handle", 4.x "_handle": a bad model under either key is not cleared
    ("lightgbm", lambda s: s.update(handle="tree\nnot a model"), "refused"),
    ("catboost", lambda s: s.update(__model=fixture("cb_ctr.cbm")), "model parts"),
    ("catboost", lambda s: s.update(__model=bytearray(fixture("cb.cbm"))), "__model is a"),
])
def test_invalid_payloads_stay_unverifiable(tmp_path, library, change, why):
    state = STATES[library]()
    change(state)
    report = scan(booster_pickle(tmp_path, library, state), validate_boosters=True)
    _assert_not_cleared(report, why)
    assert report.verdict is Verdict.SUSPICIOUS and report.unverifiable_only


def test_catboost_test_evals_must_be_numbers(tmp_path):
    state = STATES["catboost"]()
    state["_test_evals"] = [[[1.0, 2.0]], [["x"]]]
    _assert_not_cleared(scan(booster_pickle(tmp_path, "catboost", state), validate_boosters=True), "plain numbers")


def test_booster_called_with_arguments_is_not_cleared(tmp_path):
    def reduce(cls, self):
        return (cls, (b"model bytes",), dict(self.__dict__))

    path = booster_pickle(tmp_path, "xgboost", STATES["xgboost"](), reduce=reduce)
    _assert_not_cleared(scan(path, validate_boosters=True), "not NEWOBJ")


def test_booster_class_passed_to_a_call_is_not_cleared(tmp_path):
    import copyreg

    def reduce(cls, self):  # how protocols 0 and 1 rebuild an object: the class is an argument
        return (copyreg._reconstructor, (cls, object, None), dict(self.__dict__))

    path = booster_pickle(tmp_path, "xgboost", STATES["xgboost"](), reduce=reduce)
    _assert_not_cleared(scan(path, validate_boosters=True), "only be instantiated")


def test_booster_with_a_slot_state_is_not_cleared(tmp_path):
    import copyreg

    def reduce(cls, self):
        return (copyreg.__newobj__, (cls,), (dict(self.__dict__), {"handle": bytearray(b"x")}))

    path = booster_pickle(tmp_path, "xgboost", STATES["xgboost"](), reduce=reduce)
    _assert_not_cleared(scan(path, validate_boosters=True), "BUILD state")


def test_malicious_file_with_a_valid_booster_stays_malicious(tmp_path):
    # posix.system(MARKER) stored next to a valid handle, written as raw opcodes (protocol 0)
    path = booster_pickle(tmp_path, "xgboost", STATES["xgboost"]())
    data = open(path, "rb").read()
    payload = b"cposix\nsystem\n(S'echo " + MARKER.encode() + b"'\ntR"
    stop = data.rindex(b".")
    with open(path, "wb") as fh:  # the payload's result replaces the Booster on the stack
        fh.write(data[:stop] + b"0" + payload + b".")
    report = scan(path, validate_boosters=True)
    assert report.verdict is Verdict.MALICIOUS


def test_option_is_off_by_default_and_has_no_environment_switch(tmp_path, monkeypatch):
    from safeloadai import options

    assert options.BY_NAME["validate_boosters"].default is False
    assert options.BY_NAME["validate_boosters"].direction == "looser"
    assert options.BY_NAME["validate_boosters"].env is None
    monkeypatch.setenv("SAFELOADAI_VALIDATE_BOOSTERS", "1")
    report = scan(booster_pickle(tmp_path, "xgboost", STATES["xgboost"]()))
    assert report.verdict is Verdict.SUSPICIOUS and not report.options


def test_option_rejects_non_bool(tmp_path):
    report = scan(booster_pickle(tmp_path, "xgboost", STATES["xgboost"]()), validate_boosters="yes")
    assert report.status == "error" and report.error["code"] == "E501"


def test_cli_flag_and_config_key(tmp_path):
    from safeloadai.__main__ import main

    path = booster_pickle(tmp_path, "lightgbm", STATES["lightgbm"]())
    assert main(["scan", path, "--no-input"]) != 0
    assert main(["scan", path, "--validate-boosters", "--no-input"]) == 0
    config = tmp_path / "safeloadai.toml"
    config.write_text("[scan]\nvalidate_boosters = true\n")
    assert main(["scan", path, "--config", str(config), "--no-input"]) == 0


def test_validator_failure_never_clears(tmp_path, monkeypatch):
    import safeloadai.sandbox as sandbox

    monkeypatch.setattr(sandbox, "validate_boosters", lambda items, **kw: {"failed": "simulated fuel exhaustion"})
    report = scan(booster_pickle(tmp_path, "xgboost", STATES["xgboost"]()), validate_boosters=True)
    _assert_not_cleared(report, "did not finish")


def test_missing_validator_results_never_clear(tmp_path, monkeypatch):
    # fewer results than payloads (a cut-off guest answer) is a failed run, not a pass
    import safeloadai.sandbox as sandbox

    monkeypatch.setattr(sandbox, "validate_boosters", lambda items, **kw: {"results": []})
    report = scan(booster_pickle(tmp_path, "xgboost", STATES["xgboost"]()), validate_boosters=True)
    _assert_not_cleared(report, "did not finish")


@pytest.mark.wasi
def test_model_data_above_the_validator_limit_is_not_cleared(tmp_path, monkeypatch):
    from safeloadai.sandbox import emulate

    monkeypatch.setattr(emulate, "MAX_BOOSTER_BYTES", 16)
    report = scan(booster_pickle(tmp_path, "xgboost", STATES["xgboost"]()), validate_boosters=True)
    _assert_not_cleared(report, "more than the validator reads")


def _text(value: str) -> bytes:
    raw = value.encode("utf-8")
    return b"X" + struct.pack("<I", len(raw)) + raw


def test_state_changed_after_the_build_is_not_cleared(tmp_path):
    """__setstate__ sees the state as it is at BUILD; a SETITEM through the memo afterwards
    must not swap a bad model string for a good one in the scanner's view."""
    data = (b"\x80\x02clightgbm.basic\nBooster\n)\x81}q\x01" + _text("_handle") + _text("tree\nbad model")
            + b"sb" + b"h\x01" + _text("_handle") + _text(lgb()) + b"s0.")
    path = tmp_path / "swap.pkl"
    path.write_bytes(data)
    _assert_not_cleared(scan(str(path), validate_boosters=True), "changed after the BUILD")
    # the same stream without the late SETITEM, the good model at BUILD time, is cleared
    good = (b"\x80\x02clightgbm.basic\nBooster\n)\x81}q\x01" + _text("_handle") + _text(lgb()) + b"sb.")
    path.write_bytes(good)
    assert scan(str(path), validate_boosters=True).verdict is Verdict.CLEAN
