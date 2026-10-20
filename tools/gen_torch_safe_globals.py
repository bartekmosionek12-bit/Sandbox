"""Generate src/safeloadai/static/upstream/torch_weights_only.py from torch's own
weights-only unpickler (development time only).

    python tools/gen_torch_safe_globals.py [--wheels DIR] [--check]

Reads ``torch/_weights_only_unpickler.py``, ``torch/storage.py`` and ``torch/__init__.py``
from the torch wheel pinned in tools/upstream_pins.json, with ``ast`` (the wheel is a
zip archive; nothing is installed or imported), and writes:

* the full paths torch's ``_get_allowed_globals()`` accepts by default (``module.name``
  joined with a dot, which is what torch compares);
* the opcodes its ``Unpickler.load`` implements (anything else raises);
* the blocked modules.

What torch computes at run time is derived from the same source: dtypes are written as
``str(dtype)``, so the aliases in ``_dtype_to_storage_type_map`` (``torch.double`` ...)
are mapped to their canonical names (``DTYPE_ALIASES`` below, from c10's ScalarType
names); storage classes come from the ``_storage_classes`` literal in ``torch/__init__.py``.
``torch._tensor_classes`` is filled by C code at import time and cannot be read from
source, so legacy tensor-type globals (``torch.FloatTensor``) are left out: stricter
than torch.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import gen_policies  # noqa: E402

OUT = os.path.join(ROOT, "src", "safeloadai", "static", "upstream", "torch_weights_only.py")
# str(torch.<alias>) for the alias attribute names torch/storage.py uses.
DTYPE_ALIASES = {"double": "float64", "float": "float32", "half": "float16", "long": "int64", "int": "int32",
                 "short": "int16", "cdouble": "complex128", "cfloat": "complex64", "chalf": "complex32"}


def _function(tree: ast.AST, name: str) -> ast.FunctionDef:
    return next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)


def _torch_attr(node: ast.expr) -> str:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "torch":
        return node.attr
    raise ValueError(f"unexpected expression {ast.unparse(node)}")


def derive(sources: dict[str, str]) -> dict:
    wou = ast.parse(sources["torch/_weights_only_unpickler.py"])
    storage = ast.parse(sources["torch/storage.py"])
    init = ast.parse(sources["torch/__init__.py"])
    allowed: set[str] = set()

    allowed_fn = _function(wou, "_get_allowed_globals")
    for node in ast.walk(allowed_fn):
        if isinstance(node, ast.Dict):
            allowed |= {k.value for k in node.keys if isinstance(k, ast.Constant)}
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) \
                and isinstance(node.slice.value, str):
            allowed.add(node.slice.value)  # rc["torch._tensor._rebuild_from_type_v2"] = ...
        if isinstance(node, ast.List) and all(isinstance(e, ast.Attribute) for e in node.elts) and node.elts:
            allowed |= {f"torch.{_torch_attr(e)}" for e in node.elts}  # quantization schemes
        if isinstance(node, ast.ListComp) and "range(1, 8)" in ast.unparse(node):
            fstring = next(n for n in ast.walk(node) if isinstance(n, ast.JoinedStr))
            prefix = next(v.value for v in fstring.values if isinstance(v, ast.Constant))  # "uint" / "int"
            allowed |= {f"torch.{prefix}{i}" for i in range(1, 8)}
    rebuild = _function(wou, "_tensor_rebuild_functions")
    allowed |= {f"torch._utils.{n.attr}" for n in ast.walk(rebuild) if isinstance(n, ast.Attribute)
                and n.attr.startswith("_rebuild")}

    dtypes = set()
    for name in ("_dtype_to_storage_type_map", "_new_dtypes"):
        fn = _function(storage, name)
        ret = next(n for n in ast.walk(fn) if isinstance(n, ast.Return)).value
        elts = ret.keys if isinstance(ret, ast.Dict) else ret.elts
        dtypes |= {DTYPE_ALIASES.get(_torch_attr(e), _torch_attr(e)) for e in elts}
    allowed |= {f"torch.{d}" for d in dtypes}

    legacy = {n.name for n in init.body if isinstance(n, ast.ClassDef)}
    imported = {a.asname or a.name: f"{n.module}.{a.name}" for n in ast.walk(init)
                if isinstance(n, ast.ImportFrom) and n.module and n.module.startswith("torch")
                for a in n.names}
    storage_set = next(n for n in init.body if isinstance(n, ast.AnnAssign)
                       and isinstance(n.target, ast.Name) and n.target.id == "_storage_classes")
    for elt in storage_set.value.elts:
        allowed.add(f"torch.{elt.id}" if elt.id in legacy else imported[elt.id])

    blocked = next(n for n in wou.body if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == "_blocklisted_modules" for t in n.targets))
    opcodes = {a.name for n in wou.body if isinstance(n, ast.ImportFrom) and n.module == "pickle"
               for a in n.names if a.name.isupper() and a.name != "UnpicklingError"}
    unpickler = next(n for n in wou.body if isinstance(n, ast.ClassDef) and n.name == "Unpickler")
    load = _function(unpickler, "load")
    handled = {n.value.id for n in ast.walk(load) if isinstance(n, ast.Subscript)
               and isinstance(n.value, ast.Name) and n.value.id.isupper()}  # key[0] == BUILD[0]
    return {"allowed": sorted(allowed), "blocked": sorted(e.value for e in blocked.value.elts),
            "opcodes": sorted(opcodes & handled)}


def render(data: dict, version: str, sha: str) -> str:
    def block(name: str, items: list[str]) -> str:
        body = "".join(f"    {item!r},\n" for item in items)
        return f"{name} = frozenset({{\n{body}}})\n"

    return ('"""Generated by tools/gen_torch_safe_globals.py from torch/_weights_only_unpickler.py; do not edit.\n\n'
            "What torch.load(weights_only=True) accepts by default, read from the pinned torch source\n"
            "with ast (static/clearance.weights_only_ok replicates how it uses them).\n"
            '"""\n\n'
            f"TORCH_VERSION = {version!r}\n"
            f"SOURCE_SHA256 = {sha!r}  # torch/_weights_only_unpickler.py\n\n"
            "# full paths (module + '.' + name), as torch compares them\n"
            + block("ALLOWED", data["allowed"]) + "\n"
            + block("BLOCKED_MODULES", data["blocked"]) + "\n"
            + "# pickletools names of the opcodes torch's weights-only Unpickler.load implements\n"
            + block("OPCODES", [_pickletools_name(o) for o in data["opcodes"]]))


def _pickletools_name(pickle_name: str) -> str:
    return pickle_name  # pickle's constant names equal pickletools' opcode names for these


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--wheels", default=gen_policies.DEFAULT_CACHE)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    pins = gen_policies.load_pins()
    torch_pin = pins["distributions"]["torch"]
    wheel = gen_policies.fetch({"distributions": {"torch": torch_pin}}, args.wheels)["torch"]
    names = ("torch/_weights_only_unpickler.py", "torch/storage.py", "torch/__init__.py")
    with zipfile.ZipFile(wheel) as zf:
        raw = {n: zf.read(n) for n in names}
    sources = {n: b.decode("utf-8") for n, b in raw.items()}
    text = render(derive(sources), torch_pin["version"],
                  hashlib.sha256(raw["torch/_weights_only_unpickler.py"]).hexdigest())
    old = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else None
    if old == text:
        print("unchanged", file=sys.stderr)
        return 0
    if args.check:
        print(f"{OUT} differs from the pinned torch source; run tools/gen_torch_safe_globals.py and review",
              file=sys.stderr)
        return 1
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print(f"wrote {OUT}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
