"""Facts about Python libraries derived from their source code with ``ast``. Nothing here
imports, runs or loads any of the code it reads.

Two questions are answered, both for the pinned library versions at development time
(``tools/gen_policies.py`` writes the results into ``static/upstream/``) and, on
request, for the versions installed where the scan runs (``trust_inert_from``):

* **Is a module inert?** Its top level only defines things: imports, ``def``, ``class``,
  assignments, docstrings, and ``if``/``try`` blocks made of the same. A top-level
  expression (``main()``, ``webbrowser.open(...)``, ``print(...)``), a loop or a ``with``
  block is "more than definitions". Importing an inert module runs no code of its own
  beyond defining names (its imports run the top level of other modules of the
  library, which is the library's normal import graph). ``if __name__ == "__main__":``
  and ``if TYPE_CHECKING:`` bodies never run on import and are not counted.
* **Is a class state-only?** Rebuilding an instance from saved state (``NEWOBJ ()`` then
  ``BUILD`` with a dict) runs no code of the class when nothing in its MRO defines
  ``__reduce__``, ``__reduce_ex__``, ``__setstate__``, ``__new__``, ``__setattr__``,
  ``__getattr__``, ``__getattribute__`` or ``__delattr__``, no property has a setter, no
  ``__slots__`` replaces the ``__dict__``, the metaclass is ``type`` or ``abc.ABCMeta``,
  and no class decorator outside a reviewed set rewrites the class. A hook whose exact
  source was reviewed as benign (``REVIEWED_HOOKS``, keyed by its sha256) does not
  count. Every base must resolve to Python source the index can read, or to
  ``object``, ``abc.ABC`` or ``typing.Generic``; anything else (a C extension type, a
  base from a library that is not indexed) makes the class not state-only.
"""
from __future__ import annotations

import ast
import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

# Modules whose import does something by itself, whatever any analysis says.
DENIED_MODULES = frozenset({
    "antigravity", "this", "webbrowser", "turtle", "turtledemo", "idlelib", "tkinter", "__main__",
    "__phello__", "__hello__", "pydoc", "pdb", "code", "codeop", "site", "sitecustomize", "usercustomize",
})
# Path parts that mark test, benchmark or command-line modules: never eligible.
NON_LIBRARY_PARTS = frozenset({"tests", "test", "testing", "_testing", "conftest", "benchmarks", "__main__",
                               "setup", "_pytest", "examples"})

HOOKS = ("__reduce__", "__reduce_ex__", "__setstate__", "__new__", "__setattr__", "__getattr__",
         "__getattribute__", "__delattr__")
# Bases outside the indexed libraries that add nothing to unpickling (no pickling hooks,
# no __setattr__/__getattr__; ABC's metaclass ABCMeta only adds isinstance machinery).
NEUTRAL_BASES = frozenset({("builtins", "object"), ("abc", "ABC"), ("typing", "Generic")})
NEUTRAL_METACLASSES = frozenset({("builtins", "type"), ("abc", "ABCMeta")})
# Class decorators that leave pickling alone. dataclass is accepted only without
# frozen=True (which generates __setattr__) or slots=True (which removes __dict__).
NEUTRAL_DECORATORS = frozenset({("dataclasses", "dataclass"), ("functools", "total_ordering"),
                                ("typing", "final"), ("typing", "runtime_checkable"),
                                ("typing_extensions", "final")})

# Hook implementations read and judged benign for a dict-state BUILD (they only update
# __dict__ and set defaults, or only run when an attribute is missing and then raise).
# (module, class, hook) -> (sha256 of the function's source text with LF line endings,
# note); a property
# setter or deleter is keyed "<name>.setter" / "<name>.deleter". A different
# source (another library version) is not covered: the class is then not state-only.
REVIEWED_HOOKS: dict[tuple[str, str, str], tuple[str, str]] = {
    ("sklearn.base", "BaseEstimator", "__setstate__"): (
        "b761516c2ddf957fe8d52e783ed4aca73d2e542f58c9e7ab04df1361ee83fda6",
        "scikit-learn 1.9.1: pops _sklearn_version, may warn, then super().__setstate__ or __dict__.update"),
    ("torch.nn.modules.module", "Module", "__setstate__"): (
        "a47fd547bead07282b750a37be3d6dd4633a28b1a4ed928eff960bf242df3cbd",
        "torch 2.14.1: __dict__.update, then empty OrderedDict/set/None defaults for missing hook dicts"),
    ("torch.nn.modules.module", "Module", "__getattr__"): (
        "b96dcce0f3bc98e0bb84c7516c51875e20a3298f71a90955f5f23d557f1640e3",
        "torch 2.14.1: looks the name up in _parameters/_buffers/_modules, else AttributeError"),
    ("torch.nn.modules.module", "Module", "__setattr__"): (
        "45473fc67957988b485a3c2943278de89433811215270916509c03c6299d2387",
        "torch 2.14.1: files Parameter/Module/buffer values into their dicts; on load only reached by "
        "Module.__setstate__ assigning empty defaults (no registration hook runs for those values)"),
    ("torch.nn.modules.module", "Module", "__delattr__"): (
        "344e0be907b337c0212d9b0d1c47af91f06154daaf90d4a4ba448430e1597910",
        "torch 2.14.1: removes from _parameters/_buffers/_modules; unpickling never deletes attributes"),
    ("torch.nn.modules.conv", "_ConvNd", "__setstate__"): (
        "481146e1a95578962c8171f4be07690ad8c9082549712e6f788512c8246bccce",
        "torch 2.14.1: super().__setstate__, then padding_mode = 'zeros' if missing"),
    ("torch.nn.modules.upsampling", "Upsample", "__setstate__"): (
        "f28eabf1cc56ca66cab561c0f4826e85754e1e400a3f3d3739153fa979fdb80c",
        "torch 2.14.1: sets recompute_scale_factor in the state dict if missing, then super().__setstate__"),
    ("sklearn.utils._repr_html.base", "_HTMLDocumentationLinkMixin", "_doc_link_template.setter"): (
        "bd2e19fa5efc7035e8235fe5bd1b92a9c3d0bc12b2115be26d789c7f3c0e4250",
        "scikit-learn 1.9.1: setattr(self, '__doc_link_template', value), a plain attribute"),
    ("ultralytics.utils", "SimpleClass", "__getattr__"): (
        "6ffd01d179f611273ddd45d8caf06e43c7a7c817294bbba4681d9816067092ec",
        "ultralytics 8.4.182: raises AttributeError with a help text"),
    # 0.9.0 tune / tune-2 review (evaluation/results/source-review-4-20261023.md)
    ("sklearn.isotonic", "IsotonicRegression", "__setstate__"): (
        "679d16aa2ff2d2a733f09e31b00a3e40b6801e287ae8c6df0cb5d47e6e8e5d1c",
        "scikit-learn 1.9.1: BaseEstimator.__setstate__, then when X_thresholds_ and y_thresholds_ are set "
        "_build_f: compares out_of_bounds with 'raise', stores a lambda over y (not called) or "
        "scipy.interpolate.interp1d(X, y, kind='linear') as f_; computation on state values only"),
    ("ultralytics.nn.modules.block", "AAttn", "__setstate__"): (
        "7e1355f657a1a8aa152cd7aeac5fb60eeae1069235cfee9573521c04ba2528ab",
        "ultralytics 8.4.182: Module.__setstate__, then all_head_dim = head_dim * num_heads if missing"),
    ("accelerate.utils.dataclasses", "DeepSpeedPlugin", "selected.setter"): (
        "9a1f3cc36667f8a01ee87f881a5a829109acfa7abb4e03dcb5ca10a12cdf3572",
        "accelerate 1.15.0: raises NotImplementedError; sets nothing"),
}
# Hooks of older library releases, read and judged benign for a dict-state BUILD by the same
# rule (0.9.0, tools/gen_historical_paths.py): (module, class, hook) -> {sha256: note}. They
# only let an old module path of a reviewed class be accepted (upstream/historical_paths.json)
# and let trust_inert_from accept the same class in an installed old release.
REVIEWED_OLD_HOOKS: dict[tuple[str, str, str], dict[str, str]] = {
    # Each pops "_sklearn_version", may warn (the popped value is compared with __version__
    # and formatted into the message, as in the reviewed 1.9.1 hook), then
    # super().__setstate__ or a plain __dict__ update. Same behaviour as the reviewed one.
    ("sklearn.base", "BaseEstimator", "__setstate__"): {
        "53df01a877e185359278432e8fb1e04c15ab87c89694982280f47cc031cb37d8":
            "scikit-learn 0.18 to 0.18.2: version warning, then __dict__.update",
        "37d9581ea77618edcd46143b3e0ff09bc5e98dcea409dd661c95352859211d72":
            "scikit-learn 0.19.0 to 0.20.4: version warning, then super(BaseEstimator, self).__setstate__ "
            "or __dict__.update",
        "a6176b9474b9d989e0e526b8b27c6fc1c4d75366aa924b0b07f23fc9b170eda9":
            "scikit-learn 0.21.0 to 0.24.2: version warning, then super().__setstate__ or __dict__.update",
        "d1a1490e41b866e2f4c3305a0f08127229abe3a73ce425aa09c88d19fe9504bc":
            "scikit-learn 1.0 to 1.1.0: as 0.21, longer warning text",
        "5b042d64998c26484d726caf588da9efe909946ff2e7d9bed268cd4146c0ceee":
            "scikit-learn 1.1.1 to 1.2.2: as 1.0, another documentation link",
    },
    # the same source as the reviewed 1.9.1 setter, under the module it had before
    ("sklearn.utils._estimator_html_repr", "_HTMLDocumentationLinkMixin", "_doc_link_template.setter"): {
        "bd2e19fa5efc7035e8235fe5bd1b92a9c3d0bc12b2115be26d789c7f3c0e4250":
            "scikit-learn 1.4.0 to 1.6.1: setattr(self, '__doc_link_template', value), a plain attribute",
    },
}
# Read and left unreviewed on purpose (2026-10-19): torch.nn.modules.rnn.RNNBase.__setstate__
# indexes and calls into objects from the state (_all_weights[0][0], weakref.ref) and
# ultralytics.engine.model.Model.__getattr__ forwards every lookup to self.model.


def module_name(path: str) -> str | None:
    """'a/b/c.py' -> 'a.b.c', 'a/b/__init__.py' -> 'a.b'; None for anything that is not a module."""
    if not path.endswith(".py") or ".dist-info/" in path or ".data/" in path:
        return None
    parts = path[:-3].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts or not all(p.isidentifier() for p in parts):
        return None
    return ".".join(parts)


def library_module(name: str) -> bool:
    parts = name.split(".")
    return parts[0] not in DENIED_MODULES and not (NON_LIBRARY_PARTS & set(parts))


# --- module top level -------------------------------------------------------------------

# Builtins a module's top level may call: they only build or inspect values in the process.
SAFE_BUILTINS = frozenset({
    "setattr", "getattr", "hasattr", "delattr", "isinstance", "issubclass", "len", "dict", "list", "set",
    "frozenset", "tuple", "sorted", "reversed", "range", "enumerate", "zip", "str", "int", "float", "complex",
    "bool", "bytes", "bytearray", "type", "object", "property", "staticmethod", "classmethod", "super", "min",
    "max", "sum", "abs", "any", "all", "map", "filter", "repr", "format", "vars", "globals", "locals", "id",
    "hash", "iter", "next", "callable", "slice", "chr", "ord", "round", "divmod", "pow", "NotImplemented",
    "memoryview", "dir",
})
# Attributes a top-level store may set on any object: naming metadata only.
METADATA_ATTRS = frozenset({"__module__", "__doc__", "__qualname__", "__name__", "__signature__"})
# Standard-library modules (and dotted prefixes) whose functions only work inside the
# process: no files, processes, network, imports by name or environment changes.
SAFE_STDLIB = frozenset({
    "logging", "warnings", "typing", "typing_extensions", "re", "collections", "functools", "dataclasses", "enum",
    "abc", "math", "cmath", "itertools", "operator", "types", "weakref", "numbers", "copy", "string", "decimal",
    "fractions", "contextlib", "textwrap", "keyword", "datetime", "struct", "array", "bisect", "heapq",
    "os.path", "os.environ.get", "os.getenv", "importlib.metadata", "importlib_metadata", "sys.version_info",
    "sys.platform", "sys.maxsize", "sys.byteorder", "sys.float_info", "sys.getrecursionlimit", "inspect",
    "threading.Lock", "threading.RLock", "threading.local", "packaging.version", "string.Template",
})


def _plain_target(node: ast.expr) -> bool:
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, (ast.Tuple, ast.List)):
        return all(_plain_target(item) for item in node.elts)
    return isinstance(node, ast.Starred) and _plain_target(node.value)


def _targets(node: ast.expr, out: set[str]) -> None:
    if isinstance(node, ast.Name):
        out.add(node.id)
    elif isinstance(node, (ast.Tuple, ast.List)):
        for item in node.elts:
            _targets(item, out)
    elif isinstance(node, ast.Starred):
        _targets(node.value, out)


def _root(node: ast.expr) -> tuple[str | None, list[str]]:
    """(root name, attribute chain) of a.b.c, a[i].b, a().b; root None for anything else."""
    attrs: list[str] = []
    while True:
        if isinstance(node, ast.Attribute):
            attrs.append(node.attr)
            node = node.value
        elif isinstance(node, (ast.Subscript, ast.Call)):
            attrs.clear()  # a value of the root, not an attribute path of it
            node = node.value if isinstance(node, ast.Subscript) else node.func
        elif isinstance(node, ast.Name):
            return node.id, attrs[::-1]
        else:
            return None, []


def _is_type_checking(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")


def _is_main_guard(test: ast.expr) -> bool:
    return (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and test.left.id == "__name__"
            and len(test.comparators) == 1 and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value == "__main__")


@dataclass
class ModuleFacts:
    name: str
    is_package: bool
    inert: bool = True  # structurally: no loop-forever, no store into imported objects, no denied import
    why: str | None = None
    names: set[str] = field(default_factory=set)
    imported: set[str] = field(default_factory=set)  # names bound by import statements
    star_from: list[str] = field(default_factory=list)  # modules of "from x import *" (resolved later)
    calls: list[ast.expr] = field(default_factory=list)  # callees evaluated on import (not in function bodies)
    stores: list[ast.expr] = field(default_factory=list)  # roots of a[...] = ... / a.b = ... at top level
    local_names: set[str] = field(default_factory=set)  # comprehension variables
    tree: ast.Module | None = None
    source: str = ""

    def refuse(self, node: ast.AST, why: str) -> None:
        self.inert = False
        self.why = self.why or f"line {getattr(node, 'lineno', '?')}: {why}"


class _ImportTimeCalls(ast.NodeVisitor):
    """Callees of every call evaluated when a statement runs at import time: function
    bodies and lambdas are skipped (they run when called), their decorators, default
    values and annotations are not."""

    def __init__(self, out: list[ast.expr], local: set[str] | None = None):
        self.out = out
        self.local = local if local is not None else set()

    def visit_Call(self, node: ast.Call) -> None:
        self.out.append(node.func)
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        _targets(node.target, self.local)  # comprehension variables: local to the expression
        self.generic_visit(node)

    def visit_FunctionDef(self, node) -> None:
        for item in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults]:
            if item is not None:
                self.visit(item)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for item in [*node.args.defaults, *node.args.kw_defaults]:
            if item is not None:
                self.visit(item)


def _walk_top(stmts: list[ast.stmt], facts: ModuleFacts, package: str = "") -> None:  # noqa: C901 - one table
    calls = _ImportTimeCalls(facts.calls, facts.local_names)
    for node in stmts:
        if isinstance(node, ast.Expr):
            calls.visit(node)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in DENIED_MODULES:
                    facts.refuse(node, f"imports {alias.name}")
                bound = alias.asname or alias.name.split(".", 1)[0]
                facts.names.add(bound)
                facts.imported.add(bound)
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in DENIED_MODULES and not node.level:
                facts.refuse(node, f"imports from {node.module}")
            for alias in node.names:
                if alias.name == "*":
                    facts.star_from.append(_absolute(node, package))
                else:
                    facts.names.add(alias.asname or alias.name)
                    facts.imported.add(alias.asname or alias.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            facts.names.add(node.name)
            calls.visit(node)
        elif isinstance(node, ast.ClassDef):
            facts.names.add(node.name)
            for item in [*node.decorator_list, *node.bases, *(k.value for k in node.keywords)]:
                calls.visit(item)
            _class_body(node.body, calls)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if _plain_target(target):
                    if not isinstance(node, ast.AnnAssign) or node.value is not None:
                        _targets(target, facts.names)
                else:
                    facts.stores.append(target)
                    calls.visit(target)
            if node.value is not None:
                calls.visit(node.value)
        elif isinstance(node, ast.If):
            calls.visit(node.test)
            if _is_type_checking(node.test) or _is_main_guard(node.test):
                _walk_top(node.orelse, facts, package)  # the body never runs on import
            else:
                _walk_top(node.body, facts, package)
                _walk_top(node.orelse, facts, package)
        elif isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            _walk_top(node.body, facts, package)
            for handler in node.handlers:
                if handler.type is not None:
                    calls.visit(handler.type)
                if handler.name:
                    facts.names.add(handler.name)
                _walk_top(handler.body, facts, package)
            _walk_top(node.orelse, facts, package)
            _walk_top(node.finalbody, facts, package)
        elif isinstance(node, ast.For):
            _targets(node.target, facts.names)
            if not _plain_target(node.target):
                facts.refuse(node, "top-level for loop storing into another object")
            calls.visit(node.iter)
            _walk_top(node.body, facts, package)
            _walk_top(node.orelse, facts, package)
        elif isinstance(node, ast.With):
            for item in node.items:
                calls.visit(item.context_expr)
                if item.optional_vars is not None:
                    _targets(item.optional_vars, facts.names)
            _walk_top(node.body, facts, package)
        elif isinstance(node, (ast.Pass, ast.Global, ast.Nonlocal, ast.Assert, ast.Raise, ast.Delete)):
            calls.visit(node)
        elif type(node).__name__ == "TypeAlias":  # type X = ... (3.12) binds a lazily evaluated alias
            facts.names.add(node.name.id)
        else:
            facts.refuse(node, f"top-level {type(node).__name__.lower()} statement")


_DISPLAYS = (ast.Dict, ast.List, ast.Tuple, ast.Set)


def _plain_data(node: ast.expr, data: set[str]) -> bool:
    """A constant, a name in ``data``, or a display of them (a dict display's values may be
    anything: building it is checked as usual, and no method reads them)."""
    if isinstance(node, ast.Constant) or (isinstance(node, ast.Name) and node.id in data):
        return True
    if isinstance(node, ast.Dict):
        return all(k is not None and _plain_data(k, data) for k in node.keys)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_plain_data(e, data) for e in node.elts)
    return False


def _class_body(stmts: list[ast.stmt], calls: _ImportTimeCalls) -> None:
    # A method call on a dict, list, set, tuple or constant that the class body itself
    # made, with plain data as arguments (``_parameter_constraints.pop("l1_ratio")`` on a
    # dict display two lines above), runs only a builtin method, so it is not counted as a
    # call. Any other call still is, and so are calls inside the display.
    data: set[str] = set()  # names whose current value is such a display or constant
    for stmt in stmts:
        if isinstance(stmt, ast.ClassDef):
            for item in [*stmt.decorator_list, *stmt.bases, *(k.value for k in stmt.keywords)]:
                calls.visit(item)
            _class_body(stmt.body, calls)  # a nested class body does not see this one's names
            data.discard(stmt.name)
            continue
        loop = set()
        if isinstance(stmt, ast.For) and isinstance(stmt.iter, (ast.Tuple, ast.List)) and all(
                isinstance(e, ast.Constant) for e in stmt.iter.elts):
            _targets(stmt.target, loop)  # for name in ("a", "b"): ... binds constants
        builtin = {id(node.func) for node in ast.walk(stmt) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                   and node.func.value.id in data and node.func.value.id not in loop
                   and all(_plain_data(a.value if isinstance(a, ast.Starred) else a, data | loop)
                           for a in node.args)
                   and all(k.arg is not None and _plain_data(k.value, data | loop) for k in node.keywords)}
        begin = len(calls.out)
        calls.visit(stmt)
        calls.out[begin:] = [c for c in calls.out[begin:] if id(c) not in builtin]
        bound: set[str] = set()
        if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            for target in stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]:
                _targets(target, bound)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.For, ast.With, ast.If, ast.Try)):
            for node in ast.walk(stmt):  # any name these bind is no longer known data
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                    bound.add(node.id)
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                bound.add(stmt.name)
        data -= bound
        value = getattr(stmt, "value", None)
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and isinstance(value, (*_DISPLAYS, ast.Constant)):
            data |= {t.id for t in (stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target])
                     if isinstance(t, ast.Name)}


def _absolute(node: ast.ImportFrom, package: str) -> str:
    base = node.module or ""
    if not node.level:
        return base
    parts = package.split(".")
    parts = parts[:len(parts) - (node.level - 1)] if node.level > 1 else parts
    return ".".join(p for p in [*parts, *(base.split(".") if base else [])] if p)


def module_facts(name: str, source: str, is_package: bool) -> ModuleFacts:
    facts = ModuleFacts(name=name, is_package=is_package, source=source)
    try:
        facts.tree = ast.parse(source)
    except (SyntaxError, ValueError) as exc:
        facts.refuse(facts, f"does not parse: {exc}")
        return facts
    _walk_top(facts.tree.body, facts, name if is_package else name.rpartition(".")[0])
    if not library_module(name):
        facts.inert, facts.why = False, "test, command-line or denied module"
    return facts


# --- classes ----------------------------------------------------------------------------

@dataclass
class ClassFacts:
    module: str
    name: str
    node: ast.ClassDef
    pickled_module: str  # __module__ as pickle records it (a class-body __module__ = "x" wins)


@dataclass
class Verdict:
    state_only: bool
    reasons: list[str] = field(default_factory=list)
    mro: list[tuple[str, str]] = field(default_factory=list)
    reviewed_hooks: list[str] = field(default_factory=list)


def source_sha256(text: str) -> str:
    """sha256 of source text with line endings normalised: a Windows wheel ships the same
    file with CRLF, and a review of a function covers it whatever the platform."""
    return hashlib.sha256(text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")).hexdigest()


class SourceIndex:
    """Modules read on demand through ``read(module) -> (source, is_package) | None``."""

    def __init__(self, read: Callable[[str], tuple[str, bool] | None], reviewed_hooks=None,
                 known_tops: Iterable[str] = ()):
        self._read = read
        self.known_tops = frozenset(known_tops)
        self._inert: dict[tuple[str, bool], str | None] = {}
        self._modules: dict[str, ModuleFacts | None] = {}
        self._namespaces: dict[str, dict[str, tuple]] = {}
        self._verdicts: dict[tuple[str, str], Verdict] = {}
        self.reviewed_hooks = REVIEWED_HOOKS if reviewed_hooks is None else reviewed_hooks

    def module(self, name: str) -> ModuleFacts | None:
        if name not in self._modules:
            found = self._read(name)
            self._modules[name] = module_facts(name, found[0], found[1]) if found else None
        return self._modules[name]

    # namespace: local name -> ("module", m) | ("attr", m, n) | ("class", node) | ("alias", expr)
    def namespace(self, name: str) -> dict[str, tuple]:
        if name in self._namespaces:
            return self._namespaces[name]
        facts = self.module(name)
        ns: dict[str, tuple] = {}
        if facts and facts.tree:
            package = name if facts.is_package else name.rpartition(".")[0]
            self._collect(facts.tree.body, ns, package)
        self._namespaces[name] = ns
        return ns

    def _collect(self, stmts, ns, package):
        for node in stmts:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        ns[alias.asname] = ("module", alias.name)
                    else:
                        top = alias.name.split(".", 1)[0]
                        ns[top] = ("module", top)
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    parts = package.split(".")
                    parts = parts[:len(parts) - (node.level - 1)] if node.level > 1 else parts
                    base = ".".join(p for p in [*parts, *(base.split(".") if base else [])] if p)
                for alias in node.names:
                    if alias.name != "*":
                        ns[alias.asname or alias.name] = ("attr", base, alias.name)
            elif isinstance(node, ast.ClassDef):
                ns[node.name] = ("class", node)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ns[node.name] = ("def", node)
            elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                ns[node.targets[0].id] = ("alias", node.value)
            elif isinstance(node, ast.If) and not _is_main_guard(node.test):
                self._collect(node.body, ns, package)
                self._collect(node.orelse, ns, package)
            elif isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                self._collect(node.body, ns, package)
                for handler in node.handlers:
                    self._collect(handler.body, ns, package)
                self._collect(node.orelse, ns, package)

    def lookup(self, module: str, name: str, depth: int = 0):
        """What ``module.name`` is: ("class", ClassFacts) | ("module", m) | ("external", m, n) | None."""
        if depth > 16:
            return None
        if self.module(module) is None:
            if self.module(f"{module}.{name}") is not None:
                return ("module", f"{module}.{name}")
            return ("external", module, name)
        entry = self.namespace(module).get(name)
        if entry is None:
            if self.module(f"{module}.{name}") is not None:
                return ("module", f"{module}.{name}")
            for star in reversed(self.module(module).star_from):  # the last star import binds last
                if self.module(star) is not None and name in self.exported(star):
                    return self.lookup(star, name, depth + 1)
            return None
        kind = entry[0]
        if kind == "class":
            return ("class", self._class_facts(module, entry[1]))
        if kind == "module":
            return ("module", entry[1])
        if kind == "attr":
            if self.module(f"{entry[1]}.{entry[2]}") is not None:
                return ("module", f"{entry[1]}.{entry[2]}")
            return self.lookup(entry[1], entry[2], depth + 1)
        if kind == "alias":
            return self.resolve(module, entry[1], depth + 1)
        return None

    def exported(self, module: str) -> set[str]:
        """Names ``from module import *`` binds: a literal __all__, else the public names."""
        facts = self.module(module)
        if facts is None or facts.tree is None:
            return set()
        for node in facts.tree.body:
            if (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__"
                                                     for t in node.targets)
                    and isinstance(node.value, (ast.List, ast.Tuple))
                    and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.value.elts)):
                return {e.value for e in node.value.elts}
        names = {n for n in facts.names if not n.startswith("_")}
        for star in facts.star_from:
            if star != module:
                names |= {n for n in self.exported(star) if not n.startswith("_")}
        return names

    # --- inert modules -----------------------------------------------------------------

    def inert(self, module: str, lazy: bool = False) -> str | None:
        """None when importing ``module`` (its own top level) runs only definitions and
        calls into in-process code: the module itself, the libraries in ``known_tops`` or
        SAFE_STDLIB; otherwise why not. Parent packages are judged separately. ``lazy``
        also accepts the lazy-module store (``_lazy_store``)."""
        if (module, lazy) in self._inert:
            return self._inert[(module, lazy)]
        facts = self.module(module)
        why = None
        if facts is None:
            why = "no source"
        elif not facts.inert:
            why = facts.why
        else:
            for callee in facts.calls:
                if not self._safe_callee(module, facts, callee):
                    why = f"line {callee.lineno}: top level calls {ast.unparse(callee)[:80]}"
                    break
            for target in facts.stores if why is None else ():
                root, _ = _root(target)
                if isinstance(target, ast.Attribute) and target.attr in METADATA_ATTRS:
                    continue
                if lazy and self._lazy_store(module, target):
                    continue
                if root is None or root not in facts.names or root in facts.imported:
                    why = f"line {target.lineno}: top level stores into {ast.unparse(target)[:80]}"
                    break
        self._inert[(module, lazy)] = why
        return why

    def _lazy_store(self, module: str, target: ast.expr) -> bool:
        """``sys.modules[__name__] = ...``: the lazy-module idiom (transformers, trl), where a
        package replaces its own entry with a library object that imports submodules on
        attribute access. The value's calls are checked like any other top-level call. Only
        the import chains of state-only policy classes accept it (tools/gen_policies.py);
        such a package never makes a module inert for the referenced-only rule."""
        if not (isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Name)
                and target.slice.id == "__name__" and isinstance(target.value, ast.Attribute)
                and target.value.attr == "modules" and isinstance(target.value.value, ast.Name)):
            return False
        entry = self.namespace(module).get(target.value.value.id)
        return entry is not None and entry[0] == "module" and entry[1] == "sys"

    def _safe_callee(self, module: str, facts: ModuleFacts, callee: ast.expr) -> bool:
        root, attrs = _root(callee)
        if root is None:
            # a method of a literal ("".join, [..].index) or of a call result, which is checked itself
            node = callee.value if isinstance(callee, ast.Attribute) else None
            return isinstance(node, (ast.Constant, ast.JoinedStr, ast.List, ast.Tuple, ast.Dict, ast.Set,
                                     ast.Call, ast.Subscript))
        if (root in facts.names and root not in facts.imported) or root in facts.local_names:
            return True  # this module's own function, class or value
        if root in facts.imported:
            entry = self.namespace(module).get(root)
            if entry is None:
                return False
            dotted = entry[1] if entry[0] == "module" else f"{entry[1]}.{entry[2]}" if entry[0] == "attr" else ""
            return self._safe_dotted(".".join([dotted, *attrs]))
        if root in SAFE_BUILTINS:
            return True
        import builtins

        value = getattr(builtins, root, None)
        if isinstance(value, type) and issubclass(value, BaseException):
            return True
        return any(star.split(".")[0] in self.known_tops and root in self.exported(star)
                   for star in facts.star_from)

    def _safe_dotted(self, dotted: str) -> bool:
        if dotted.split(".")[0] in self.known_tops:
            return True
        return any(dotted == p or dotted.startswith(p + ".") for p in SAFE_STDLIB)

    def resolve(self, module: str, expr: ast.expr, depth: int = 0):
        """A base, metaclass or decorator expression of ``module`` -> what lookup returns."""
        if depth > 16:
            return None
        if isinstance(expr, ast.Subscript):  # Generic[T], SomeBase[X]
            return self.resolve(module, expr.value, depth + 1)
        if isinstance(expr, ast.Call):  # dataclass(...), a class factory: judged by the caller
            return self.resolve(module, expr.func, depth + 1)
        if isinstance(expr, ast.Name):
            entry = self.namespace(module).get(expr.id)
            if entry is None:
                import builtins

                return ("external", "builtins", expr.id) if hasattr(builtins, expr.id) else None
            return self.lookup(module, expr.id, depth + 1)
        if isinstance(expr, ast.Attribute):
            owner = self.resolve(module, expr.value, depth + 1)
            if owner and owner[0] == "module":
                return self.lookup(owner[1], expr.attr, depth + 1)
            if owner and owner[0] == "external":
                return ("external", f"{owner[1]}.{owner[2]}", expr.attr)
            return None
        return None

    def _class_facts(self, module: str, node: ast.ClassDef) -> ClassFacts:
        pickled = module
        for stmt in node.body:
            if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__module__"
                                                    for t in stmt.targets):
                if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                    pickled = stmt.value.value
        return ClassFacts(module=module, name=node.name, node=node, pickled_module=pickled)

    def classes(self, module: str) -> list[ClassFacts]:
        facts = self.module(module)
        if not facts or not facts.tree:
            return []
        return [self._class_facts(module, n) for n in facts.tree.body if isinstance(n, ast.ClassDef)]

    # --- state-only ----------------------------------------------------------------

    def state_only(self, module: str, name: str) -> Verdict:
        key = (module, name)
        if key in self._verdicts:
            return self._verdicts[key]
        self._verdicts[key] = Verdict(False, ["recursive class hierarchy"])  # cycle guard
        found = self.lookup(module, name)
        if not found or found[0] != "class":
            verdict = Verdict(False, [f"{module}.{name} is not a class defined in readable source"])
        else:
            verdict = self._judge(found[1])
        self._verdicts[key] = verdict
        return verdict

    def _judge(self, cls: ClassFacts) -> Verdict:
        verdict = Verdict(True)
        own = (cls.module, cls.name)
        verdict.mro.append(own)
        self._own_checks(cls, verdict)
        for base in cls.node.bases:
            found = self.resolve(cls.module, base)
            if not found:
                verdict.state_only = False
                verdict.reasons.append(f"base {ast.unparse(base)} of {cls.name} does not resolve to readable source")
                continue
            if found[0] == "external":
                pair = (found[1], found[2])
                if pair not in NEUTRAL_BASES:
                    verdict.state_only = False
                    verdict.reasons.append(f"base {found[1]}.{found[2]} of {cls.name} is not Python source the "
                                           "index reads (a C type or another library)")
                continue
            if found[0] != "class":
                verdict.state_only = False
                verdict.reasons.append(f"base {ast.unparse(base)} of {cls.name} is not a class")
                continue
            parent = self.state_only(found[1].module, found[1].name)
            verdict.mro += [p for p in parent.mro if p not in verdict.mro]
            verdict.reviewed_hooks += [h for h in parent.reviewed_hooks if h not in verdict.reviewed_hooks]
            if not parent.state_only:
                verdict.state_only = False
                verdict.reasons += [r for r in parent.reasons if r not in verdict.reasons]
        return verdict

    def _own_checks(self, cls: ClassFacts, verdict: Verdict) -> None:
        facts = self.module(cls.module)
        source = facts.source if facts else ""
        for keyword in cls.node.keywords:
            if keyword.arg != "metaclass":
                continue
            found = self.resolve(cls.module, keyword.value)
            pair = (found[1], found[2]) if found and found[0] == "external" else (
                (found[1].module, found[1].name) if found and found[0] == "class" else None)
            if pair not in NEUTRAL_METACLASSES:
                verdict.state_only = False
                verdict.reasons.append(f"{cls.name} has the metaclass {ast.unparse(keyword.value)}")
        for decorator in cls.node.decorator_list:
            found = self.resolve(cls.module, decorator)
            pair = (found[1], found[2]) if found and found[0] == "external" else None
            if pair not in NEUTRAL_DECORATORS or (pair == ("dataclasses", "dataclass") and _rewrites(decorator)):
                verdict.state_only = False
                verdict.reasons.append(f"{cls.name} is decorated with {ast.unparse(decorator)[:60]}")
        for stmt in cls.node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if stmt.name in HOOKS:
                    self._hook(cls, stmt.name, ast.get_source_segment(source, stmt) or ast.unparse(stmt), verdict)
                for decorator in stmt.decorator_list:
                    if isinstance(decorator, ast.Attribute) and decorator.attr in ("setter", "deleter"):
                        # only setattr reaches it (a slot state, or a hook assigning that name);
                        # a reviewed implementation does not count
                        self._hook(cls, f"{stmt.name}.{decorator.attr}",
                                   ast.get_source_segment(source, stmt) or ast.unparse(stmt), verdict)
            elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                names = {t.id for t in targets if isinstance(t, ast.Name)}
                for hook in names & set(HOOKS):
                    verdict.state_only = False
                    verdict.reasons.append(f"{cls.name}.{hook} is assigned, not defined (cannot be reviewed)")
                if "__slots__" in names and stmt.value is not None and not _empty(stmt.value):
                    verdict.state_only = False
                    verdict.reasons.append(f"{cls.name} defines __slots__")
                value = stmt.value
                if isinstance(value, ast.Call) and _call_name(value.func) == "property" and (
                        len(value.args) >= 2 or any(k.arg in ("fset", "fdel") for k in value.keywords)):
                    verdict.state_only = False
                    verdict.reasons.append(f"{cls.name}.{', '.join(sorted(names))} is a property with a setter")

    def _hook(self, cls: ClassFacts, hook: str, text: str, verdict: Verdict) -> None:
        key = (cls.module, cls.name, hook)
        reviewed = self.reviewed_hooks.get(key)
        digest = source_sha256(text)
        if (reviewed and reviewed[0] == digest) or digest in REVIEWED_OLD_HOOKS.get(key, {}):
            verdict.reviewed_hooks.append(f"{cls.module}.{cls.name}.{hook}")
            return
        verdict.state_only = False
        if reviewed:
            verdict.reasons.append(f"{cls.module}.{cls.name}.{hook} differs from the reviewed source "
                                   f"(sha256 {digest[:12]}, reviewed {reviewed[0][:12]})")
        elif hook.endswith((".setter", ".deleter")):
            verdict.reasons.append(f"{cls.module}.{cls.name} defines the property {hook} "
                                   f"(sha256 {digest[:12]}, not reviewed)")
        else:
            verdict.reasons.append(f"{cls.module}.{cls.name} defines {hook} (sha256 {digest[:12]}, not reviewed)")


def _empty(value: ast.expr) -> bool:
    return isinstance(value, (ast.Tuple, ast.List, ast.Set)) and not value.elts or (
        isinstance(value, ast.Constant) and value.value in ((), "", None))


def _call_name(func: ast.expr) -> str | None:
    return func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None


def _rewrites(decorator: ast.expr) -> bool:
    """dataclass(frozen=True) generates __setattr__; dataclass(slots=True) removes __dict__."""
    if not isinstance(decorator, ast.Call):
        return False
    return any(k.arg in ("frozen", "slots") and not (isinstance(k.value, ast.Constant) and k.value.value is False)
               for k in decorator.keywords)


# --- readers ------------------------------------------------------------------------------

def wheel_reader(paths: Iterable[str]) -> tuple[Callable[[str], tuple[str, bool] | None], dict[str, str]]:
    """A reader over the .py members of wheel files (zip archives, read, never extracted or
    imported), and module -> wheel file name."""
    import zipfile

    sources: dict[str, tuple[str, bool]] = {}
    owner: dict[str, str] = {}
    for path in paths:
        with zipfile.ZipFile(path) as zf:
            for member in zf.namelist():
                name = module_name(member)
                if name is None:
                    continue
                text = zf.read(member).decode("utf-8", errors="replace")
                sources[name] = (text, member.endswith("/__init__.py"))
                owner[name] = path
    return sources.get, owner


def installed_reader(distribution: str):
    """A reader over the .py files an installed distribution lists in its RECORD
    (importlib.metadata; the package is never imported). Returns (reader, version, modules)."""
    from importlib import metadata

    dist = metadata.distribution(distribution)
    files: dict[str, tuple[object, bool]] = {}
    for entry in dist.files or ():
        name = module_name(str(entry).replace("\\", "/"))
        if name is not None:
            files[name] = (entry, str(entry).endswith("__init__.py"))

    def read(module: str):
        found = files.get(module)
        if not found:
            return None
        try:
            with open(dist.locate_file(found[0]), encoding="utf-8", errors="replace") as fh:
                return fh.read(), found[1]
        except OSError:
            return None

    return read, dist.version, sorted(files)
