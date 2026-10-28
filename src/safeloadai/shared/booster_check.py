"""Strict structural validators for the model bytes a gradient-boosting Booster hands to its
native parser when it is unpickled (``--validate-boosters``, off by default).

``xgboost.core.Booster.__setstate__`` passes its ``handle`` bytes to libxgboost
(``XGBoosterUnserializeFromBuffer``: a JSON or UBJSON document ``{"Config": ..., "Model": ...}``),
``lightgbm.basic.Booster.__setstate__`` passes its ``_handle`` string to LightGBM
(``LGBM_BoosterLoadModelFromString``: the text model) and CatBoost's ``__setstate__`` passes
``__model`` to ``_deserialize_model`` (a CBM file). Those parsers are C++ and trust their input
in places (an UBJSON string length is copied without a bounds check, a tree's parent index and
LightGBM's ``tree_sizes`` are used without one). The validators here accept only documents
whose every length, index and reference is consistent, in the exact shape the libraries
write, so the bytes that reach the native parser are bytes it is known to read as data.
They do not prove the native parser free of bugs; docs/OPTIONS.md states that residual risk.

Runs INSIDE the WASI sandbox (guest task ``booster_check``). Stdlib only, shared with the
host for the tests. Everything it does not recognise raises ``Invalid``: the Booster then
stays UNVERIFIABLE exactly as without the option.

Sources reviewed (read only): xgboost 3.1.1 (src/learner.cc LearnerIO::Load / LoadModel /
LoadConfig, src/common/json.cc UBJReader, src/tree/tree_model.cc RegTree::LoadModel,
src/gbm/gbtree_model.cc, src/gbm/gbtree.cc Dart), lightgbm 4.6.0
(src/boosting/gbdt_model_text.cpp GBDT::LoadModelFromString, src/io/tree.cpp Tree::Tree(const
char*, size_t*) and Tree::ToString), catboost 1.2.8 (see ``check_catboost``).
"""
from __future__ import annotations

import json
import math
import re
import struct

MAX_DEPTH = 32
MAX_STRING = 1 << 20  # a feature name, an attribute value
MAX_TREES = 1_000_000
MAX_NODES = 50_000_000  # over all trees
MAX_FEATURES = 10_000_000
MAX_CLASSES = 100_000
MAX_CATEGORY = 1 << 24  # one categorical split's largest category


class Invalid(ValueError):
    """The bytes are not a model document the validator accepts."""


def _need(condition, message: str) -> None:
    if not condition:
        raise Invalid(message)


# --- XGBoost: UBJSON and JSON readers --------------------------------------------------


class Typed:
    """A UBJSON typed array: ``code`` is the element marker, ``values`` the decoded numbers."""

    __slots__ = ("code", "values")

    def __init__(self, code: str, values):
        self.code = code
        self.values = values

    def __len__(self):
        return len(self.values)


_UBJ_SCALARS = {"i": ">b", "U": ">B", "I": ">h", "l": ">i", "L": ">q", "d": ">f", "D": ">d"}
_UBJ_TYPED = {"d", "D", "i", "U", "I", "l", "L"}


class _Ubj:
    """The subset of UBJSON libxgboost's UBJReader reads (json.cc), with every length
    checked against the bytes left. Duplicate object keys and trailing bytes are refused."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def byte(self) -> str:
        _need(self.pos < len(self.data), "UBJSON ends early")
        c = chr(self.data[self.pos])
        self.pos += 1
        return c

    def peek(self) -> str:
        _need(self.pos < len(self.data), "UBJSON ends early")
        return chr(self.data[self.pos])

    def scalar(self, code: str):
        fmt = _UBJ_SCALARS[code]
        size = struct.calcsize(fmt)
        _need(self.pos + size <= len(self.data), "UBJSON number runs past the end")
        (value,) = struct.unpack_from(fmt, self.data, self.pos)
        self.pos += size
        return value

    def length(self) -> int:
        _need(self.byte() == "L", "UBJSON length is not an int64 ('L')")
        n = self.scalar("L")
        _need(0 <= n <= len(self.data) - self.pos, f"UBJSON length {n} runs past the end")
        return n

    def string(self) -> str:
        n = self.length()
        _need(n <= MAX_STRING, "UBJSON string too long")
        raw = self.data[self.pos:self.pos + n]
        self.pos += n
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise Invalid("UBJSON string is not UTF-8") from None

    def value(self, depth: int = 0):
        _need(depth <= MAX_DEPTH, "UBJSON nested too deep")
        c = self.byte()
        if c == "{":
            out: dict = {}
            while self.peek() != "}":
                key = self.string()
                _need(key not in out, f"duplicate key {key[:40]!r}")
                out[key] = self.value(depth + 1)
            self.pos += 1
            return out
        if c == "[":
            return self.array(depth)
        if c == "S":
            return self.string()
        if c == "Z":
            return None
        if c in "TF":
            return c == "T"
        if c in _UBJ_SCALARS:
            value = self.scalar(c)
            if c in "dD":
                _need(math.isfinite(value), "non-finite number outside an array")
            return value
        raise Invalid(f"UBJSON marker {c!r} libxgboost does not write")

    def array(self, depth: int):
        if self.peek() == "$":
            self.pos += 1
            code = self.byte()
            _need(code in _UBJ_TYPED, f"typed array of {code!r}")
            _need(self.byte() == "#", "typed array without a count")
            n = self.length()
            size = struct.calcsize(_UBJ_SCALARS[code])
            _need(n * size <= len(self.data) - self.pos, "typed array runs past the end")
            values = struct.unpack_from(f">{n}{_UBJ_SCALARS[code][1]}", self.data, self.pos)
            self.pos += n * size
            return Typed(code, values)
        if self.peek() == "#":
            self.pos += 1
            n = self.length()  # each element is at least one byte
            return [self.value(depth + 1) for _ in range(n)]
        out = []
        while self.peek() != "]":
            out.append(self.value(depth + 1))
        self.pos += 1
        return out


def _load_ubjson(data: bytes):
    reader = _Ubj(data)
    value = reader.value()
    _need(reader.pos == len(data), f"{len(data) - reader.pos} bytes after the UBJSON document")
    return value


_JSON_TEXT = re.compile(rb"[\x20-\x5b\x5d-\x7e\t\n\r]*")  # printable ASCII, no backslash


def _load_json(data: bytes):
    """A JSON text the way Python and libxgboost's JsonReader read it alike: ASCII without
    escapes, no duplicate keys, no NaN or Infinity. Number ranges are checked where the
    model uses them (_ints, _floats); the schema checks bound the nesting."""
    _need(_JSON_TEXT.fullmatch(data) is not None, "JSON text with escapes or non-ASCII bytes")

    def pairs(items):
        out = dict(items)
        _need(len(out) == len(items), "duplicate key in a JSON object")
        return out

    def constant(name):
        raise Invalid(f"JSON constant {name}")

    try:
        return json.loads(data.decode("ascii"), object_pairs_hook=pairs, parse_constant=constant)
    except Invalid:
        raise
    except (ValueError, RecursionError) as exc:
        raise Invalid(f"not valid JSON: {str(exc)[:120]}") from None


# --- XGBoost: the model document -------------------------------------------------------

_INT = (int,)
_DEC = re.compile(r"(0|[1-9][0-9]{0,9})")
_FLOAT = re.compile(r"-?(\d+(\.\d*)?|\.\d+)([eE][-+]?\d+)?")
_NAME = re.compile(r"[A-Za-z0-9_:@.\-]{1,64}")


def _obj(value, what: str, required=(), optional=()) -> dict:
    _need(isinstance(value, dict), f"{what} is not an object")
    keys = set(value)
    missing = set(required) - keys
    _need(not missing, f"{what} lacks {sorted(missing)}")
    unknown = keys - set(required) - set(optional)
    _need(not unknown, f"{what} has keys libxgboost does not write: {sorted(unknown)[:5]}")
    return value


def _dec(value, what: str, low: int = 0, high: int = 1 << 31) -> int:
    _need(isinstance(value, str) and _DEC.fullmatch(value) is not None, f"{what} is not a decimal string")
    number = int(value)
    _need(low <= number <= high, f"{what} = {number} out of range")
    return number


def _float_text(value, what: str) -> None:
    _need(isinstance(value, str), f"{what} is not a string")
    text = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    parts = text.split(",") if text else []
    _need(parts and len(parts) <= MAX_CLASSES, f"{what} is empty")
    for part in parts:
        _need(_FLOAT.fullmatch(part.strip()) is not None, f"{what} is not a number")


def _str_map(value, what: str, depth: int = 0) -> None:
    """A parameter object: string values, or nested parameter objects (objective params)."""
    _need(isinstance(value, dict) and depth <= 4, f"{what} is not an object of strings")
    for key, item in value.items():
        _need(len(key) <= 256, f"{what} key too long")
        if isinstance(item, dict):
            _str_map(item, what, depth + 1)
        else:
            _need(isinstance(item, str) and len(item) <= MAX_STRING, f"{what}.{key[:40]} is not a string")


_INT_BITS = {"i": 8, "U": 8, "I": 16, "l": 32, "L": 64}


def _ints(value, what: str, n: int | None, codes: tuple[str, ...]) -> tuple:
    """An integer array: a typed UBJSON array with one of ``codes``, or a JSON list of ints
    in the range of the widest of ``codes``."""
    if isinstance(value, Typed):
        _need(value.code in codes, f"{what} is a typed array of {value.code!r}")
        out = value.values
    else:
        _need(isinstance(value, list) and set(map(type, value)) <= {int}, f"{what} is not an integer array")
        bits = max(_INT_BITS[c] for c in codes)
        _need(not value or (min(value) >= -(1 << (bits - 1)) and max(value) < (1 << (bits - 1))),
              f"{what} out of range")
        out = tuple(value)
    _need(n is None or len(out) == n, f"{what} has {len(out)} entries, expected {n}")
    return out


def _floats(value, what: str, n: int | None) -> None:
    """A number array; libxgboost's reader takes any finite number (NaN and infinity are
    written only as non-JSON tokens, which _load_json refuses)."""
    if isinstance(value, Typed):
        _need(value.code == "d", f"{what} is a typed array of {value.code!r}")
    else:
        _need(isinstance(value, list) and set(map(type, value)) <= {int, float}, f"{what} is not a number array")
        _need(all(map(math.isfinite, value)), f"{what} has a non-finite number")
    _need(n is None or len(value) == n, f"{what} has {len(value)} entries, expected {n}")


def _bools(value, what: str, n: int, allowed=(0, 1)) -> tuple:
    if isinstance(value, Typed):
        _need(value.code == "U", f"{what} is a typed array of {value.code!r}")
        out = value.values
    else:
        _need(isinstance(value, list) and set(map(type, value)) <= {int, bool}, f"{what} is not 0/1")
        out = tuple(map(int, value))
    _need(len(out) == n, f"{what} has {len(out)} entries, expected {n}")
    _need(set(out) <= set(allowed), f"{what} has values outside {allowed}")
    return out


_TREE_KEYS = ("tree_param", "id", "loss_changes", "sum_hessian", "base_weights", "left_children",
              "right_children", "parents", "split_indices", "split_conditions", "default_left")
_CAT_KEYS = ("split_type", "categories", "categories_nodes", "categories_segments", "categories_sizes")


def _check_tree(tree, index: int, num_feature: int) -> int:
    _obj(tree, f"tree {index}", _TREE_KEYS, _CAT_KEYS)
    param = _obj(tree["tree_param"], f"tree {index} tree_param",
                 ("num_deleted", "num_feature", "num_nodes", "size_leaf_vector"))
    n = _dec(param["num_nodes"], "num_nodes", 1, MAX_NODES)
    deleted = _dec(param["num_deleted"], "num_deleted", 0, n)
    _dec(param["num_feature"], "tree num_feature", 0, MAX_FEATURES)
    # A vector-leaf (multi-target) tree has a loader of its own (MultiTargetTree::LoadModel).
    _need(_dec(param["size_leaf_vector"], "size_leaf_vector", 0, MAX_CLASSES) <= 1,
          "multi-target trees are not validated")
    _need(type(tree["id"]) is int and tree["id"] == index, f"tree {index} has id {tree['id']!r}")
    for key in ("loss_changes", "sum_hessian", "base_weights", "split_conditions"):
        _floats(tree[key], f"tree {index} {key}", n)
    left = _ints(tree["left_children"], "left_children", n, ("l",))
    right = _ints(tree["right_children"], "right_children", n, ("l",))
    parents = _ints(tree["parents"], "parents", n, ("l",))
    split = _ints(tree["split_indices"], "split_indices", n, ("l", "L"))
    _bools(tree["default_left"], "default_left", n)
    # Typed or not, every array of one tree is written the same way (RegTree::LoadModel
    # picks the reader from the type of "parents").
    typed = isinstance(tree["parents"], Typed)
    _need(all(isinstance(tree[k], Typed) == typed for k in (*_TREE_KEYS[2:], *(k for k in _CAT_KEYS if k in tree))),
          "a tree mixes typed and untyped arrays")

    # The tree: node 0 is the root; every other node has one parent whose child it is.
    _need(parents[0] in (-1, 0x7FFFFFFF), "the root has a parent")
    seen = bytearray(n)
    seen[0] = 1
    stack = [0]
    while stack:
        node = stack.pop()
        lc, rc = left[node], right[node]
        if lc == -1 and rc == -1:
            continue  # a leaf
        if not (0 < lc < n and 0 < rc < n and lc != rc and not seen[lc] and not seen[rc]
                and parents[lc] == node and parents[rc] == node and (split[node] & 0x7FFFFFFF) < num_feature):
            raise Invalid(f"tree {index} node {node}: children ({lc}, {rc}), their parents or its split feature "
                          f"{split[node]} (of {num_feature}) are inconsistent")
        seen[lc] = seen[rc] = 1
        stack.append(lc)
        stack.append(rc)
    gone = n - sum(seen)
    _need(gone == deleted, f"tree {index} has {gone} unreachable nodes, says {deleted} deleted")
    if gone:
        default_left = _bools(tree["default_left"], "default_left", n)
        for node in range(n):
            if not seen[node]:
                # A pruned node: MarkDelete makes it a leaf with sindex_ 0xFFFFFFFF, saved as
                # split index 0x7FFFFFFF with default_left set (RegTree::Node::IsDeleted); it
                # keeps its slot and a parent inside the tree, which RegTree::LoadModel reads.
                _need(split[node] == 0x7FFFFFFF and default_left[node] == 1 and left[node] == -1
                      and right[node] == -1 and 0 <= parents[node] < n, f"node {node} is not reachable from the root")

    if "split_type" in tree:
        _need(all(k in tree for k in _CAT_KEYS), "a tree with some of the categorical keys")
        kinds = _bools(tree["split_type"], "split_type", n)
        nodes = _ints(tree["categories_nodes"], "categories_nodes", None, ("l",))
        segments = _ints(tree["categories_segments"], "categories_segments", len(nodes), ("L",))
        sizes = _ints(tree["categories_sizes"], "categories_sizes", len(nodes), ("L",))
        cats = _ints(tree["categories"], "categories", None, ("l",))
        _need(list(nodes) == sorted(set(nodes)), "categories_nodes not strictly increasing")
        _need([i for i in range(n) if kinds[i] == 1] == list(nodes), "split_type and categories_nodes disagree")
        for node, begin, size in zip(nodes, segments, sizes):
            _need(0 <= node < n and seen[node] and left[node] != -1, f"categorical node {node} is not a split")
            _need(size > 0 and 0 <= begin and begin + size <= len(cats), f"categories of node {node} out of range")
            _need(all(0 <= c < MAX_CATEGORY for c in cats[begin:begin + size]), f"category of node {node} out of range")
    return n


def _check_gbtree(model, num_feature: int, groups: int) -> tuple[int, int]:
    _obj(model, "gbtree model", ("gbtree_model_param", "trees", "tree_info"), ("iteration_indptr", "cats"))
    if "cats" in model:
        # xgboost 3.1 writes its category container (CatContainer::Save) into every model;
        # only the empty one, from training without categorical features, is accepted.
        cats = _obj(model["cats"], "cats", ("enc", "feature_segments", "sorted_idx"))
        _need(cats["enc"] == [] and all(isinstance(cats[k], (Typed, list)) and len(cats[k]) == 0
                                        for k in ("feature_segments", "sorted_idx")),
              "a non-empty category container is not validated")
    param = _obj(model["gbtree_model_param"], "gbtree_model_param", ("num_trees",),
                 ("num_parallel_tree", "size_leaf_vector"))
    num_trees = _dec(param["num_trees"], "num_trees", 0, MAX_TREES)
    if "size_leaf_vector" in param:
        _need(_dec(param["size_leaf_vector"], "size_leaf_vector", 0, MAX_CLASSES) <= 1,
              "multi-target models are not validated")
    if "num_parallel_tree" in param:
        _dec(param["num_parallel_tree"], "num_parallel_tree", 0, MAX_TREES)
    trees = model["trees"]
    _need(isinstance(trees, list) and len(trees) == num_trees, "trees and num_trees disagree")
    info = _ints(model["tree_info"], "tree_info", num_trees, ("l", "L", "i", "U", "I"))
    _need(all(0 <= g < groups for g in info), "tree_info names an output group out of range")
    if "iteration_indptr" in model:
        indptr = _ints(model["iteration_indptr"], "iteration_indptr", None, ("l", "L", "i", "U", "I"))
        _need(indptr and indptr[0] == 0 and indptr[-1] == num_trees
              and all(a <= b for a, b in zip(indptr, indptr[1:])), "iteration_indptr is not 0..num_trees")
    nodes = 0
    for index, tree in enumerate(trees):
        nodes += _check_tree(tree, index, num_feature)
        _need(nodes <= MAX_NODES, "too many nodes")
    return num_trees, nodes


# xgboost 3.4 writes dart_train_param for gbtree too (GBTree::SaveConfig).
_GBM_CONFIG_KEYS = {"gbtree": ("gbtree_model_param", "gbtree_train_param", "process_type", "specified_updater",
                               "tree_method", "tree_train_param", "updater", "name", "dart_train_param"),
                    "dart": ("name", "gbtree", "dart_train_param")}


def _check_config_value(value, what: str, depth: int = 0) -> None:
    """The Config half: parameter objects of strings, booleans, and lists of such objects
    (metrics, updaters). It is read by LearnerConfiguration::LoadConfig through the
    parameter parsers, which reject what they do not know."""
    _need(depth <= 8, f"{what} nested too deep")
    if isinstance(value, dict):
        for key, item in value.items():
            _need(len(key) <= 256, f"{what} key too long")
            _check_config_value(item, what, depth + 1)
    elif isinstance(value, list):
        _need(len(value) <= 10_000, f"{what} list too long")
        for item in value:
            _check_config_value(item, what, depth + 1)
    else:
        _need(isinstance(value, (str, bool)) or type(value) is int, f"{what} holds a {type(value).__name__}")
        _need(not isinstance(value, str) or len(value) <= MAX_STRING, f"{what} string too long")


def _version(value, what: str) -> tuple:
    _need(isinstance(value, (list, Typed)) and len(value) == 3, f"{what} is not [major, minor, patch]")
    parts = tuple(value.values if isinstance(value, Typed) else value)
    _need(all(type(p) is int and 0 <= p < 1000 for p in parts) and 1 <= parts[0] <= 3, f"{what} = {parts}")
    return parts


def check_xgboost(data: bytes) -> dict:
    """The serialization ``Booster.__getstate__`` stores (``save_raw``), as libxgboost's
    LearnerIO::Load reads it: '{' then a letter is UBJSON, '{"' is JSON (before 2.0)."""
    _need(len(data) >= 2 and data[:1] == b"{", "not a JSON or UBJSON document")
    if data[1:2] == b'"' or data[1:2].isspace():
        doc, encoding = _load_json(data), "json"
    else:
        _need(data[1:2] == b"L", "not a JSON or UBJSON document")
        doc, encoding = _load_ubjson(data), "ubjson"
    _obj(doc, "document", ("Config", "Model"))
    model = _obj(doc["Model"], "Model", ("learner", "version"))
    version = _version(model["version"], "Model version")
    learner = _obj(model["learner"], "learner", ("attributes", "gradient_booster", "learner_model_param", "objective"),
                   ("feature_names", "feature_types"))
    attrs = learner["attributes"]
    _need(isinstance(attrs, dict) and all(isinstance(v, str) and len(v) <= MAX_STRING for v in attrs.values()),
          "attributes are not strings")
    for key in ("feature_names", "feature_types"):
        if key in learner:
            names = learner[key]
            _need(isinstance(names, list) and len(names) <= MAX_FEATURES
                  and all(isinstance(v, str) and len(v) <= 4096 for v in names), f"{key} are not strings")
    mparam = _obj(learner["learner_model_param"], "learner_model_param", ("base_score", "num_feature"),
                  ("num_class", "num_target", "boost_from_average"))
    _float_text(mparam["base_score"], "base_score")
    num_feature = _dec(mparam["num_feature"], "num_feature", 0, MAX_FEATURES)
    num_class = _dec(mparam.get("num_class", "0"), "num_class", 0, MAX_CLASSES)
    num_target = _dec(mparam.get("num_target", "1"), "num_target", 1, MAX_CLASSES)
    if "boost_from_average" in mparam:
        _dec(mparam["boost_from_average"], "boost_from_average", 0, 1)
    objective = learner["objective"]
    _need(isinstance(objective, dict) and isinstance(objective.get("name"), str)
          and _NAME.fullmatch(objective["name"]) is not None, "objective has no name")
    _str_map(objective, "objective")
    groups = max(num_class, num_target, 1)

    booster = learner["gradient_booster"]
    _need(isinstance(booster, dict), "gradient_booster is not an object")
    name = booster.get("name")
    if name == "gbtree":
        _obj(booster, "gradient_booster", ("name", "model"))
        trees, nodes = _check_gbtree(booster["model"], num_feature, groups)
    elif name == "dart":
        _obj(booster, "gradient_booster", ("name", "gbtree", "weight_drop"))
        inner = _obj(booster["gbtree"], "dart gbtree", ("name", "model"))
        _need(inner["name"] == "gbtree", "dart wraps something other than gbtree")
        trees, nodes = _check_gbtree(inner["model"], num_feature, groups)
        _floats(booster["weight_drop"], "weight_drop", trees)
    else:
        raise Invalid(f"gradient booster {str(name)[:40]!r} is not validated (gbtree and dart are)")

    config = _obj(doc["Config"], "Config", ("learner", "version"))
    _need(_version(config["version"], "Config version") == version, "Config and Model versions differ")
    learner_config = _obj(config["learner"], "Config learner",
                          ("generic_param", "gradient_booster", "learner_train_param", "metrics", "objective"),
                          ("learner_model_param",))
    _need(isinstance(learner_config["metrics"], list), "metrics is not a list")
    gbm_config = learner_config["gradient_booster"]
    _need(isinstance(gbm_config, dict) and gbm_config.get("name") == name, "Config names another booster")
    _need(set(gbm_config) <= set(_GBM_CONFIG_KEYS[name]), "gradient_booster config has unknown keys")
    _check_config_value(config, "Config")
    return {"library": "xgboost", "encoding": encoding, "version": ".".join(map(str, version)),
            "booster": name, "trees": trees, "nodes": nodes}


# --- LightGBM: the text model ------------------------------------------------------------

_LGB_HEADER = {"version", "num_class", "num_tree_per_iteration", "label_index", "max_feature_idx", "objective",
               "average_output", "feature_names", "feature_infos", "monotone_constraints", "tree_sizes"}
_LGB_TREE = {"num_leaves", "num_cat", "split_feature", "split_gain", "threshold", "decision_type", "left_child",
             "right_child", "leaf_value", "leaf_weight", "leaf_count", "internal_value", "internal_weight",
             "internal_count", "cat_boundaries", "cat_threshold", "is_linear", "shrinkage", "leaf_const",
             "num_features", "leaf_features", "leaf_coeff"}
_LGB_MAX_TREE_LINES = 22  # Tree::Tree(const char*, size_t*) reads at most this many lines
# Objectives whose ConvertOutput writes one value per class (multiclass.hpp): their own
# num_class must be the model's, which sizes the output buffer.
_LGB_PER_CLASS = {"multiclass", "multiclassova"}
_LGB_OBJECTIVES = {"regression", "regression_l1", "huber", "fair", "poisson", "quantile", "mape", "gamma",
                   "tweedie", "binary", "multiclass", "multiclassova", "cross_entropy", "cross_entropy_lambda",
                   "lambdarank", "rank_xendcg", "custom"}
_LGB_INT = re.compile(r"-?[0-9]{1,10}")
_LGB_FLOAT = re.compile(r"-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]{1,3})?|-?inf|nan")
_LGB_NAME = re.compile(r"[^\s=]{1,4096}")
_LGB_PARAM = re.compile(r"\[[a-z0-9_]{1,64}: [^\[\]\n]{0,65536}\]")
_LGB_PANDAS = re.compile(r"pandas_categorical:[^\n]*")


def _lgb_numbers(text: str, n: int, pattern, what: str) -> list[str]:
    """``n`` numbers separated by spaces. ArrayToString writes one space between them (two
    between the leaves of a linear tree's leaf_features and leaf_coeff); LightGBM's
    StringToArray drops empty pieces between spaces and StringToArrayFast skips spaces
    before each number and reads exactly ``n`` of them without looking for the end."""
    parts = [p for p in text.split(" ") if p]
    _need(len(parts) == n, f"{what} has {len(parts)} values, expected {n}")
    _need(all(pattern.fullmatch(p) for p in parts), f"{what} has a value LightGBM does not write")
    return parts


def _lgb_ints(text: str, n: int, what: str, low: int, high: int) -> list[int]:
    values = [int(p) for p in _lgb_numbers(text, n, _LGB_INT, what)]
    _need(all(low <= v <= high for v in values), f"{what} out of range")
    return values


def _lgb_int(text: str, what: str, low: int, high: int) -> int:
    return _lgb_ints(text, 1, what, low, high)[0]


def _lgb_tree(lines: list[str], index: int, num_features: int) -> int:
    _need(len(lines) <= _LGB_MAX_TREE_LINES, f"tree {index} has more lines than LightGBM reads")
    kv: dict[str, str] = {}
    for line in lines:
        key, sep, value = line.partition("=")
        _need(sep and key in _LGB_TREE, f"tree {index} has a line LightGBM does not write: {line[:40]!r}")
        _need(key not in kv, f"tree {index} repeats {key}")
        kv[key] = value
    _need("num_leaves" in kv and "num_cat" in kv and "leaf_value" in kv, f"tree {index} lacks a required field")
    leaves = _lgb_int(kv["num_leaves"], "num_leaves", 1, 1 << 24)
    num_cat = _lgb_int(kv["num_cat"], "num_cat", 0, max(leaves - 1, 0))
    linear = _lgb_int(kv.get("is_linear", "0"), "is_linear", 0, 1)
    _lgb_numbers(kv["leaf_value"], leaves, _LGB_FLOAT, "leaf_value")
    for key in ("leaf_weight",):
        if key in kv:
            _lgb_numbers(kv[key], leaves, _LGB_FLOAT, key)
    if "leaf_count" in kv:
        _lgb_ints(kv["leaf_count"], leaves, "leaf_count", 0, (1 << 31) - 1)
    if "shrinkage" in kv:
        _lgb_numbers(kv["shrinkage"], 1, _LGB_FLOAT, "shrinkage")
    inner = leaves - 1
    if leaves > 1:
        for key in ("left_child", "right_child", "split_feature", "threshold"):
            _need(key in kv, f"tree {index} lacks {key}")
    if leaves > 1 or linear:
        left = _lgb_ints(kv.get("left_child", ""), inner, "left_child", -leaves, inner - 1)
        right = _lgb_ints(kv.get("right_child", ""), inner, "right_child", -leaves, inner - 1)
        _lgb_ints(kv.get("split_feature", ""), inner, "split_feature", 0, num_features - 1)
        thresholds = _lgb_numbers(kv.get("threshold", ""), inner, _LGB_FLOAT, "threshold")
        for key in ("split_gain", "internal_value", "internal_weight"):
            if key in kv:
                _lgb_numbers(kv[key], inner, _LGB_FLOAT, key)
        if "internal_count" in kv:
            _lgb_ints(kv["internal_count"], inner, "internal_count", 0, (1 << 31) - 1)
        # decision_type bits (tree.h): 1 categorical, 2 default left, bits 2-3 the missing type (0..2)
        kinds = _lgb_ints(kv["decision_type"], inner, "decision_type", 0, 11) if "decision_type" in kv else [0] * inner
        _need(all((k >> 2) <= 2 for k in kinds), "decision_type has a missing type LightGBM does not write")
        # One binary tree: every internal node but the root and every leaf is a child exactly once.
        seen_inner, seen_leaf = [False] * max(inner, 1), [False] * leaves
        if inner:
            seen_inner[0] = True
        for node in range(inner):
            for child in (left[node], right[node]):
                if child >= 0:
                    _need(child > 0 and not seen_inner[child], f"tree {index} node {child} is reached twice")
                    seen_inner[child] = True
                else:
                    leaf = ~child
                    _need(not seen_leaf[leaf], f"tree {index} leaf {leaf} is reached twice")
                    seen_leaf[leaf] = True
        _need(all(seen_inner[:inner]) and all(seen_leaf), f"tree {index} is not one binary tree")
        _need(all(left[n] > n or left[n] < 0 for n in range(inner)) and all(right[n] > n or right[n] < 0
                                                                            for n in range(inner)),
              f"tree {index} has a child before its parent")
        categorical = [n for n in range(inner) if kinds[n] & 1]
        if num_cat:
            _need("cat_boundaries" in kv and "cat_threshold" in kv, f"tree {index} lacks its categories")
            bounds = _lgb_ints(kv["cat_boundaries"], num_cat + 1, "cat_boundaries", 0, 1 << 30)
            _need(bounds[0] == 0 and all(a <= b for a, b in zip(bounds, bounds[1:])),
                  "cat_boundaries are not increasing from 0")
            _lgb_ints(kv["cat_threshold"], bounds[-1], "cat_threshold", 0, (1 << 32) - 1)
            # A categorical split's threshold is the index of its category set (Tree::CategoricalDecision).
            for node in categorical:
                cat = thresholds[node]
                _need(_LGB_INT.fullmatch(cat) is not None and 0 <= int(cat) < num_cat,
                      f"tree {index} categorical node {node} names category set {cat}")
        else:
            _need(not categorical and "cat_boundaries" not in kv and "cat_threshold" not in kv,
                  f"tree {index} has categorical splits but num_cat=0")
    else:
        _need(not set(kv) & {"cat_boundaries", "cat_threshold"}, f"tree {index} has categories but no split")
    if linear:
        if "leaf_const" in kv:
            _lgb_numbers(kv["leaf_const"], leaves, _LGB_FLOAT, "leaf_const")
        counts = _lgb_ints(kv["num_features"], leaves, "num_features", 0, num_features) if "num_features" in kv else []
        total = sum(counts)
        if "leaf_features" in kv or "leaf_coeff" in kv:
            _need(counts, f"tree {index} has linear features without num_features")
        if "leaf_features" in kv:
            _lgb_ints(kv["leaf_features"], total, "leaf_features", 0, num_features - 1)
        if "leaf_coeff" in kv:
            _lgb_numbers(kv["leaf_coeff"], total, _LGB_FLOAT, "leaf_coeff")
    else:
        _need(not set(kv) & {"leaf_const", "num_features", "leaf_features", "leaf_coeff"},
              f"tree {index} has linear fields but is_linear=0")
    return leaves


def check_lightgbm(text) -> dict:
    """The model string ``Booster.__getstate__`` stores (``model_to_string``), as
    GBDT::LoadModelFromString reads it. It reaches LightGBM as a NUL-terminated C string."""
    _need(isinstance(text, str), "the LightGBM model is not a str")
    _need("\x00" not in text and "\r" not in text, "NUL or CR in the model string")
    _need(text.startswith("tree\n"), "the model string does not start with 'tree'")
    lines = text.split("\n")
    first_tree = next((i for i, line in enumerate(lines) if line.startswith("Tree=")), None)
    _need(first_tree is not None, "no trees")
    header: dict[str, str] = {}
    for line in lines[1:first_tree]:
        if not line:
            continue
        key, sep, value = line.partition("=")
        _need(key in _LGB_HEADER, f"header line LightGBM does not write: {line[:40]!r}")
        _need(key not in header, f"header repeats {key}")
        _need("=" not in value or key in ("feature_names", "monotone_constraints"), f"{key} has more than one '='")
        _need(sep or key == "average_output", f"{key} has no value")
        header[key] = value
    for key in ("version", "num_class", "label_index", "max_feature_idx", "feature_names", "feature_infos",
                "tree_sizes"):
        _need(key in header, f"the header lacks {key}")
    _need(header["version"] in ("v2", "v3", "v4"), f"model version {header['version'][:10]!r}")
    num_class = _lgb_int(header["num_class"], "num_class", 1, MAX_CLASSES)
    per_iteration = _lgb_int(header.get("num_tree_per_iteration", header["num_class"]), "num_tree_per_iteration",
                             1, MAX_CLASSES)
    _need(per_iteration == num_class, "num_tree_per_iteration differs from num_class")
    _lgb_int(header["label_index"], "label_index", 0, MAX_FEATURES)
    num_features = _lgb_int(header["max_feature_idx"], "max_feature_idx", -1, MAX_FEATURES - 1) + 1
    names = header["feature_names"].split(" ")
    _need(len(names) == num_features and all(_LGB_NAME.fullmatch(n) for n in names), "feature_names")
    _need(len(header["feature_infos"].split(" ")) == num_features, "feature_infos count")
    if "monotone_constraints" in header:
        _lgb_ints(header["monotone_constraints"], num_features, "monotone_constraints", -1, 1)
    if "objective" in header:
        parts = header["objective"].split(" ")
        _need(parts[0] in _LGB_OBJECTIVES, f"objective {parts[0][:40]!r}")
        options = {}
        for part in parts[1:]:
            key, sep, value = part.partition(":")
            _need(sep and re.fullmatch(r"[a-z_]{1,32}", key) and _LGB_FLOAT.fullmatch(value) and key not in options,
                  f"objective option {part[:40]!r}")
            options[key] = value
        if parts[0] in _LGB_PER_CLASS:
            _need(options.get("num_class") == str(num_class), "the objective's num_class differs from the model's")
        else:
            _need(num_class == 1 and "num_class" not in options, "a single-output objective with num_class > 1")

    # The trees: tree_sizes gives each tree's exact byte length (LoadModelFromString uses the
    # offsets unchecked), each block is "Tree=i\n", the fields, and two newlines.
    sizes = _lgb_ints(header["tree_sizes"], len(header["tree_sizes"].split(" ")), "tree_sizes", 1, 1 << 40)
    _need(len(sizes) <= MAX_TREES and len(sizes) % per_iteration == 0, "the tree count is not whole iterations")
    pos = sum(len(line) + 1 for line in lines[:first_tree])
    leaves = 0
    for index, size in enumerate(sizes):
        block = text[pos:pos + size]
        _need(len(block) == size, f"tree {index} runs past the end")
        head = f"Tree={index}\n"
        _need(block.startswith(head) and block.endswith("\n\n\n"), f"tree {index} is not one tree block")
        body = block[len(head):-3].split("\n")
        _need(all(body), f"tree {index} has an empty line inside")
        leaves += _lgb_tree(body, index, num_features)
        _need(leaves <= MAX_NODES, "too many leaves")
        pos += size
    rest = text[pos:].split("\n")
    _need(rest[:2] == ["end of trees", ""], "the trees are not followed by 'end of trees'")
    i = 2
    if i < len(rest) and rest[i] in ("feature_importances:", "feature importances:"):  # v4, v3
        i += 1
        while i < len(rest) and rest[i]:
            key, sep, value = rest[i].rpartition("=")
            _need(sep and _LGB_INT.fullmatch(value), "feature_importances line")
            i += 1
        i += 1
    _need(rest[i:i + 1] == ["parameters:"], "no parameters section")
    i += 1
    while i < len(rest) and rest[i] != "end of parameters":
        _need(rest[i] == "" or _LGB_PARAM.fullmatch(rest[i]), f"parameter line {rest[i][:40]!r}")
        i += 1
    _need(i < len(rest), "parameters section without its end")
    tail = rest[i + 1:]
    # Python adds the pandas_categorical line (basic.py _dump_pandas_categorical); no 'parser:'
    # section (a custom parser config) is accepted.
    while tail and tail[-1] == "":
        tail.pop()
    _need(all(line == "" or _LGB_PANDAS.fullmatch(line) for line in tail) and len([t for t in tail if t]) <= 1,
          "unexpected text after the parameters")
    return {"library": "lightgbm", "encoding": "text", "version": header["version"], "booster": "gbdt",
            "trees": len(sizes), "nodes": leaves}


# --- CatBoost: the CBM model --------------------------------------------------------------


class _Fb:
    """A bounds-checked flatbuffer table reader for the TModelCore schema (catboost
    libs/model/flatbuffers/*.fbs). Every offset is checked; tables may not overlap their
    vtable with the buffer's ends; unknown fields (a vtable longer than the schema) are refused."""

    def __init__(self, data: bytes):
        self.data = data

    def _u(self, fmt: str, pos: int):
        size = struct.calcsize(fmt)
        _need(0 <= pos and pos + size <= len(self.data), "flatbuffer offset out of range")
        return struct.unpack_from(fmt, self.data, pos)[0]

    def root(self) -> int:
        return self._target(0)

    def _target(self, pos: int) -> int:
        offset = self._u("<I", pos)
        target = pos + offset
        _need(offset > 0 and target < len(self.data) and target % 4 == 0, "flatbuffer reference out of range")
        return target

    def fields(self, table: int, count: int) -> list[int | None]:
        """The position of each of the table's ``count`` schema fields, or None when absent."""
        vtable = table - self._u("<i", table)
        _need(vtable % 2 == 0, "flatbuffer vtable misaligned")
        vsize, tsize = self._u("<H", vtable), self._u("<H", vtable + 2)
        _need(vsize >= 4 and vsize % 2 == 0 and table + tsize <= len(self.data) and tsize >= 4,
              "flatbuffer vtable size")
        slots = (vsize - 4) // 2
        _need(slots <= count or all(self._u("<H", vtable + 4 + 2 * i) == 0 for i in range(count, slots)),
              "flatbuffer table has fields the schema does not have")
        out: list[int | None] = []
        for i in range(count):
            off = self._u("<H", vtable + 4 + 2 * i) if i < slots else 0
            _need(off == 0 or 4 <= off < tsize, "flatbuffer field outside its table")
            out.append(table + off if off else None)
        return out

    def scalar(self, pos: int | None, fmt: str, default):
        return default if pos is None else self._u(fmt, pos)

    def vector(self, pos: int | None, elem: int, align: int = 4) -> tuple[int, int]:
        """(start, length) of the vector the field at ``pos`` refers to; (0, 0) when absent."""
        if pos is None:
            return 0, 0
        start = self._target(pos)
        n = self._u("<I", start)
        _need(start + 4 + n * elem <= len(self.data), "flatbuffer vector runs past the end")
        _need((start + 4) % align == 0, "flatbuffer vector misaligned")
        return start + 4, n

    def numbers(self, pos: int | None, fmt: str) -> tuple:
        size = struct.calcsize("<" + fmt)
        start, n = self.vector(pos, size, min(size, 8))
        return struct.unpack_from(f"<{n}{fmt}", self.data, start) if n else ()

    def string(self, pos: int | None) -> str | None:
        if pos is None:
            return None
        start, n = self.vector(pos, 1)
        _need(n <= MAX_STRING and self._u("<B", start + n) == 0, "flatbuffer string not NUL-terminated")
        try:
            return self.data[start:start + n].decode("utf-8")
        except UnicodeDecodeError:
            raise Invalid("flatbuffer string is not UTF-8") from None

    def tables(self, pos: int | None) -> list[int]:
        start, n = self.vector(pos, 4)
        return [self._target(start + 4 * i) for i in range(n)]


_CB_DESCRIPTOR = b"CBM1"
_CB_CORE_FORMAT = "FlabuffersModel_v1"  # sic, CURRENT_CORE_FORMAT_STRING in model.cpp
_CB_MAX_DEPTH = 16  # oblivious trees: 2**depth leaves


def check_catboost(data: bytes) -> dict:
    """A CBM model as TFullModel::Load reads it (catboost 1.2.8 libs/model/model.cpp): the
    'CBM1' descriptor, the core size, the TModelCore flatbuffer, then one part per
    ModelPartIds entry. Only oblivious-tree models of float and one-hot features with no
    model parts (no CTR tables, text or embedding processing) are accepted."""
    data = bytes(data)
    _need(data[:4] == _CB_DESCRIPTOR, "no CBM1 descriptor")
    _need(len(data) >= 8, "CBM file ends early")
    size = struct.unpack_from("<I", data, 4)[0]
    _need(size != 0xFFFFFFFF, "64-bit core sizes are not validated")
    _need(8 + size == len(data), "the flatbuffer core does not end the model (model parts or trailing bytes)")
    fb = _Fb(data[8:])
    core = fb.root()
    version, trees_pos, info, parts = fb.fields(core, 4)
    _need(fb.string(version) == _CB_CORE_FORMAT, "unknown core format version")
    _need(not fb.tables(parts), "model parts (CTR, text or embedding data) are not validated")
    for kv in fb.tables(info):
        key, value = fb.fields(kv, 2)
        _need(fb.string(key) is not None and fb.string(value) is not None, "InfoMap entry without key or value")
    _need(trees_pos is not None, "no ModelTrees")
    trees = fb._target(trees_pos)
    (approx, splits, sizes, offsets, cat_features, float_features, one_hot, ctr, leaf_values, leaf_weights,
     step_nodes, node_to_leaf, text, estimated, scale, bias, multi_bias, repacked, embedding) = fb.fields(trees, 19)
    dimension = fb.scalar(approx, "<i", 0)
    _need(1 <= dimension <= MAX_CLASSES, f"ApproxDimension {dimension}")
    for name, pos in (("CtrFeatures", ctr), ("TextFeatures", text), ("EstimatedFeatures", estimated),
                      ("EmbeddingFeatures", embedding), ("NonSymmetricStepNodes", step_nodes),
                      ("NonSymmetricNodeIdToLeafId", node_to_leaf)):
        _need(fb.vector(pos, 1)[1] == 0, f"{name} are not validated (oblivious float/one-hot models only)")
    for value in (fb.scalar(scale, "<d", 1.0), fb.scalar(bias, "<d", 0.0), *fb.numbers(multi_bias, "d")):
        _need(math.isfinite(value), "scale or bias is not finite")
    _need(len(fb.numbers(multi_bias, "d")) in (0, dimension), "MultiBias length")

    # Features, in the order CalcBinFeatures numbers their splits.
    bins = 0
    last = -1
    for table in fb.tables(float_features):
        has_nans, index, flat, borders, name, nan_mode = fb.fields(table, 6)
        position = fb.scalar(index, "<i", -1)
        _need(position > last and 0 <= fb.scalar(flat, "<i", -1) < MAX_FEATURES and position < MAX_FEATURES,
              "float feature positions")
        last = position
        _need(fb.scalar(nan_mode, "<b", 0) in (0, 1, 2) and fb.scalar(has_nans, "<B", 0) in (0, 1), "float feature flags")
        values = fb.numbers(borders, "f")
        _need(all(math.isfinite(v) for v in values) and all(a < b for a, b in zip(values, values[1:])),
              "float feature borders are not increasing")
        fb.string(name)
        bins += len(values)
    cats = set()
    for table in fb.tables(cat_features):
        index, flat, name, used = fb.fields(table, 4)
        position = fb.scalar(index, "<i", -1)
        _need(0 <= position < MAX_FEATURES and 0 <= fb.scalar(flat, "<i", -1) < MAX_FEATURES
              and position not in cats, "categorical feature positions")
        cats.add(position)
        fb.string(name)
        _need(fb.scalar(used, "<B", 1) in (0, 1), "categorical feature flag")
    for table in fb.tables(one_hot):
        index, values, strings = fb.fields(table, 3)
        _need(fb.scalar(index, "<i", -1) in cats, "a one-hot feature names no categorical feature")
        count = len(fb.numbers(values, "i"))
        names = fb.tables(strings)
        _need(not names or len(names) == count, "one-hot value names")
        for pos in range(len(names)):
            start, _ = fb.vector(strings, 4)
            fb.string(start + 4 * pos)
        bins += count

    # Oblivious trees: TreeSplits holds sum(TreeSizes) bin-feature indexes; leaves are
    # 2**depth per tree, ApproxDimension values each (CalcFirstLeafOffsets).
    tree_sizes = fb.numbers(sizes, "i")
    tree_splits = fb.numbers(splits, "i")
    _need(len(tree_sizes) <= MAX_TREES and all(0 <= s <= _CB_MAX_DEPTH for s in tree_sizes), "tree depths")
    _need(sum(tree_sizes) == len(tree_splits), "TreeSplits and TreeSizes disagree")
    _need(all(0 <= s < bins for s in tree_splits), "a split names a bin feature that does not exist")
    starts = fb.numbers(offsets, "i")
    expected, total = [], 0
    for depth in tree_sizes:
        expected.append(total)
        total += depth
    _need(not starts or list(starts) == expected, "TreeStartOffsets are not the prefix sums of TreeSizes")
    leaves = sum(1 << d for d in tree_sizes)
    _need(fb.vector(leaf_values, 8, 8)[1] == leaves * dimension, "LeafValues length")
    _need(fb.vector(leaf_weights, 8, 8)[1] in (0, leaves), "LeafWeights length")
    _need(fb.vector(repacked, 4)[1] in (0, len(tree_splits)), "RepackedBins length")
    return {"library": "catboost", "encoding": "cbm", "version": _CB_CORE_FORMAT, "booster": "oblivious",
            "trees": len(tree_sizes), "nodes": leaves}


CHECKS = {"xgboost": check_xgboost, "lightgbm": check_lightgbm, "catboost": check_catboost}


def check(library: str, payload) -> dict:
    """Validate one Booster payload; raises Invalid for anything not accepted."""
    _need(library in CHECKS, f"no validator for {library!r}")
    return CHECKS[library](payload)
