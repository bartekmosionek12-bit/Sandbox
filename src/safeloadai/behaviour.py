"""Turn validated emulation records into a layer verdict (host side).

The guest only records; this module decides. Rules, all fail-closed:

* tampering with the evidence channel -> MALICIOUS;
* emulation unavailable, crashed, timed out or out of fuel -> a tool error (errors.py,
  E301-E304), never a verdict; evidence recorded before that still counts;
* a guest that ends normally without finishing its work -> SUSPICIOUS;
* any anomaly record (marshal error, foreign bytecode, missing stub, emulation
  exception, introspection, tensor values read, sleep) -> SUSPICIOUS;
* a call to a known sink -> MALICIOUS or SUSPICIOUS by sink category;
* any other call that is neither a framework tensor operation nor a method of
  an allowlisted global -> SUSPICIOUS;
* an import of a global outside the allowlist -> SUSPICIOUS.

An import outside the allowlist that is not a known sink, and an unexpected call to
it or through it, are UNVERIFIABLE (the scanner cannot see that code); everything
else stays RISKY or MALICIOUS.
"""
from __future__ import annotations

from . import errors, override
from .report import Category, LayerResult, Verdict
from .sandbox.host import GuestRun
from .static.allowlists import (
    ARRAY_RECONSTRUCTORS,
    CLOUDPICKLE_CODE,
    CLOUDPICKLE_DATA,
    CLOUDPICKLE_IMPORT,
    CLOUDPICKLE_MODULES,
    CLOUDPICKLE_TYPES,
    DANGEROUS_SYMBOLS,
    DILL_ARRAY,
    DILL_CODE,
    DILL_DATA,
    DILL_MODULES,
    GETATTR,
    KNOWN_GADGETS,
    PATH_CLASSES,
    PICKLE_GLOBALS,
    SCORER_FUNCTIONS,
    TORCH_GLOBALS,
)
from .static.lookalike import imitates
from .static.pickle_static import is_dangerous_import

M, S = Verdict.MALICIOUS, Verdict.SUSPICIOUS

# (prefix, category, severity). A prefix matches the call target itself, its
# attributes ("prefix.x") and results of calling it ("prefix().x").
SINKS: tuple[tuple[str, str, Verdict], ...] = tuple(
    (prefix, category, severity)
    for category, severity, prefixes in (
        ("process", M, ("os.system", "posix.system", "nt.system", "os.popen", "posix.popen", "nt.popen",
                        "os.fork", "os.forkpty", "os.posix_spawn", "os.posix_spawnp", "os.kill",
                        "os.killpg", "subprocess", "pty", "commands", "platform.popen",
                        "multiprocessing", "asyncio.create_subprocess_exec",
                        "asyncio.create_subprocess_shell")
         + tuple(f"{mod}.{fn}" for mod in ("os", "posix", "nt")
                 for fn in ("execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp",
                            "execvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve",
                            "spawnvp", "spawnvpe", "startfile"))),
        ("network", M, ("socket", "urllib", "http", "requests", "httpx", "webbrowser", "ftplib",
                        "smtplib", "telnetlib", "ssl", "xmlrpc")),
        ("file_write", M, ("file.write", "shutil", "tempfile", "pathlib", "tf.io.write_file",
                           "tf.io.gfile", "tf.gfile", "tf.compat.v1.gfile", "tf.keras.utils.get_file",
                           "keras.utils.get_file", "torch.save", "numpy.save", "numpy.savez",
                           "numpy.tofile")
         + tuple(f"{mod}.{fn}" for mod in ("os", "posix", "nt")
                 for fn in ("remove", "unlink", "rmdir", "removedirs", "rename", "renames", "replace",
                            "chmod", "chown", "lchown", "mkdir", "makedirs", "symlink", "link",
                            "truncate", "ftruncate", "write", "open", "mkfifo", "utime"))),
        ("code_exec", M, ("builtins.exec", "builtins.eval", "builtins.compile", "runpy", "code",
                          "codeop", "importlib", "marshal", "pickle", "_pickle", "dill", "cloudpickle",
                          "types.FunctionType", "types.CodeType", "tf.py_function", "tf.numpy_function",
                          "tf.compat.v1.py_func", "tf.load_op_library", "tf.load_library",
                          "torch.ops.load_library")),
        ("native", M, ("ctypes", "cffi", "_ctypes")),
        ("file_read", S, ("tf.io.read_file", "tf.io.matching_files", "numpy.load", "numpy.fromfile",
                          "numpy.memmap")),
        ("model_loading", S, ("torch.load", "torch.hub", "torch.jit.load", "tf.saved_model",
                              "keras.models.load_model", "keras.saving.load_model",
                              "tf.keras.models.load_model", "tf.raw_ops")),
        ("environment_probe", S, ("os.environ", "os.getenv", "posix.environ", "os.path.exists",
                                  "os.path.isfile", "os.path.isdir", "os.listdir", "os.scandir",
                                  "os.walk", "os.stat", "os.getlogin", "os.uname", "platform",
                                  "getpass", "sys", "socket.gethostname")),
        ("process_control", S, ("signal", "threading", "atexit", "builtins.exit", "gc", "inspect")),
        ("introspection", S, ("builtins.getattr",)),
    )
    for prefix in prefixes
)

FRAMEWORK_PREFIXES = ("tf.", "keras.", "K.", "ops.", "torch.", "numpy.", "np.", "Tensor.")
SAFE_IMPORTS = frozenset({"math", "functools", "itertools", "operator", "collections", "re", "string",
                          "json", "base64", "binascii", "struct", "typing", "abc", "enum", "copy",
                          "numbers", "random", "hashlib", "zlib", "tensorflow", "tf", "keras", "torch",
                          "numpy", "np"})
WRITE_MODES = set("wax+")
MAX_EVIDENCE = 200


PATH_CLASS_CALLS = frozenset(f"{m}.{n}{suffix}" for m, n in PATH_CLASSES for suffix in ("", ".__new__"))


def _matches(target: str, prefix: str) -> bool:
    return target == prefix or target.startswith((prefix + ".", prefix + "(", prefix + "["))


def sink_for(target: str) -> tuple[str, Verdict] | None:
    for prefix, category, severity in SINKS:
        if _matches(target, prefix):
            return category, severity
    return None


def _unquote(text: str) -> str:
    return text[1:-1] if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"" else text


def _fake_name(text) -> str:
    """The name inside the guest's ``<fake class numpy._core.multiarray._reconstruct>``."""
    text = str(text)
    for prefix in ("<fake class ", "<fake "):
        if text.startswith(prefix) and text.endswith(">"):
            return text[len(prefix):-1]
    return text


def _classify_call(event: dict, allowed_names: frozenset[str], framework: bool) -> tuple[str, Verdict] | None:
    target = str(event.get("target", ""))
    args = event.get("args") or []
    if target == "builtins.open":
        mode = _unquote(str(args[1])) if len(args) > 1 else _unquote(str((event.get("kwargs") or {}).get("mode", "r")))
        return ("file_write", M) if WRITE_MODES & set(mode) else ("file_read", S)
    if target == "builtins.getattr":
        # How pickle writes a bound method. The static layer judges the object and whether
        # the result is called; here a public, non-sink constant name is no finding.
        name = _unquote(str(args[1])) if len(args) > 1 else ""
        if name and not name.startswith("_") and name not in DANGEROUS_SYMBOLS:
            return None
        return "introspection", S
    if target == "builtins.__import__":
        module = _unquote(str(args[0])) if args else ""
        if module.split(".")[0] in SAFE_IMPORTS:
            return None
        return "import", S
    if any(target == f"{module}.{DILL_ARRAY}" for module in DILL_MODULES):
        # f(*args) with f the first argument: numpy's array reconstructor rebuilds an array;
        # anything else is a call of that argument, judged by its name.
        f = _fake_name(args[0]) if args else ""
        if tuple(f.rsplit(".", 1)) in ARRAY_RECONSTRUCTORS:
            return "dill", S
        return sink_for(f) or ("unexpected_call", S)
    for module in CLOUDPICKLE_MODULES:
        if target == f"{module}._builtin_type":
            name = _unquote(str(args[0])) if args else ""
            return ("cloudpickle", S) if name in CLOUDPICKLE_TYPES else ("introspection", S)
        if target == f"{module}.{CLOUDPICKLE_IMPORT}":
            name = _unquote(str(args[0])) if args else ""
            return None if name.split(".")[0] in SAFE_IMPORTS else ("import", S)
        if any(_matches(target, f"{module}.{name}") for name in CLOUDPICKLE_CODE | CLOUDPICKLE_DATA):
            # Reviewed cloudpickle helpers (allowlists.CLOUDPICKLE_CODE, CLOUDPICKLE_DATA): the
            # code object, function and class a pickle is rebuilt with, whose bytecode the static
            # layer and the code emulation judge, and cells and dict views.
            return "cloudpickle", S
    if any(_matches(target, f"{module}.{name}") for module in DILL_MODULES for name in DILL_DATA | DILL_CODE):
        # Reviewed dill helpers (allowlists.DILL_CODE, DILL_DATA): a type lookup, cells, dict
        # copies and the code a function is rebuilt from, whose bytecode the static layer
        # and the dill code emulation judge. Other dill helpers stay code_exec sinks.
        return "dill", S
    if target in PATH_CLASS_CALLS:
        # building a path object parses strings only (allowlists.PATH_CLASSES); a method
        # called on it is "pathlib.X().name" and still matches the pathlib sink below
        return "unexpected_call", S
    found = sink_for(target)
    if found:
        return found
    if framework and target.startswith(FRAMEWORK_PREFIXES):
        return None
    if any(_matches(target, name) for name in allowed_names):
        return None
    return "unexpected_call", S


def allowed_names(extra_allowed: frozenset = frozenset(), torch: bool = False) -> frozenset[str]:
    """Call targets that are no finding. A scorer's score function may be imported and stored
    (allowlists.SCORER_FUNCTIONS) but is never called while loading, so a call to it is."""
    pairs = (PICKLE_GLOBALS - SCORER_FUNCTIONS) | frozenset(extra_allowed) | (TORCH_GLOBALS if torch else frozenset())
    return frozenset(f"{module}.{name}" for module, name in pairs)


def classify(run: GuestRun, *, name: str = "emulation", torch: bool = False,
             extra_allowed: frozenset = frozenset(), framework: bool = True,
             referenced: frozenset = frozenset()) -> LayerResult:
    """``framework=False`` (pickle streams): only methods of allowlisted globals are
    benign calls; a tensor-library name alone (``numpy.testing...``) is not.

    ``referenced``: pairs the static layer found only referenced from an inert library
    module (static/clearance.py). Their import is no finding; any call to or through
    them stays RISKY (they are not allowlisted, and not UNVERIFIABLE either)."""
    layer = LayerResult(name=name, verdict=Verdict.CLEAN, timings_ms=dict(run.timings_ms),
                        details={"status": run.status, "completed": run.completed, "runtime": run.runtime,
                                 "problems": run.problems[:50]})
    failure = errors.guest_error(run.status, run.problems, layer=name)
    if run.status == "unavailable":
        layer.ran = False
        layer.errors.append(failure)
        return layer
    if run.tampered:
        layer.raise_to(M, "write to the evidence channel that did not come from the recorder")
    if failure is not None:
        # The sandbox crashed or ran out of time: a tool error, never a verdict. What the
        # guest recorded before that still counts (MALICIOUS evidence decides).
        layer.errors.append(failure)
    elif not run.completed:
        layer.raise_to(S, f"emulation did not complete (status {run.status}): " + "; ".join(run.problems[:5]))

    allow_pairs = PICKLE_GLOBALS | frozenset(extra_allowed) | (TORCH_GLOBALS if torch else frozenset())
    names = allowed_names(extra_allowed, torch)
    unknown: dict[str, tuple[str, str]] = {}  # "module.name" -> pair, for imports that are not sinks
    for event in run.events:
        if event.get("kind") == "import":
            pair = (str(event.get("module")), str(event.get("name")))
            if (event.get("resolved") != "real" and pair not in allow_pairs and pair not in KNOWN_GADGETS
                    and pair not in GETATTR and pair not in referenced
                    and not is_dangerous_import(*pair) and not imitates(pair[0])):
                unknown[f"{pair[0]}.{pair[1]}"] = pair
    for event in run.events:
        kind = event.get("kind")
        if kind == "anomaly":
            layer.raise_to(S, f"anomaly: {event.get('what')}")
            _evidence(layer, event, "anomaly", S)
        elif kind == "call":
            found = _classify_call(event, names, framework)
            if found:
                category, severity = found
                target = str(event.get("target"))
                owner = _unknown_owner(target, unknown) if category == "unexpected_call" else None
                if owner:
                    layer.raise_to(severity, f"{category}: {target}", category=Category.UNVERIFIABLE,
                                   item=owner, pair=unknown[owner],
                                   explanation=override.pickle_global(*unknown[owner]))
                else:
                    layer.raise_to(severity, f"{category}: {target}")
                _evidence(layer, event, category, severity)
        elif kind == "import":
            pair = (event.get("module"), event.get("name"))
            if (event.get("resolved") != "real" and pair not in allow_pairs and pair not in GETATTR
                    and pair not in referenced):
                dotted = f"{pair[0]}.{pair[1]}"
                if dotted in unknown:
                    layer.raise_to(S, f"import outside the allowlist: {dotted}", category=Category.UNVERIFIABLE,
                                   item=dotted, pair=unknown[dotted],
                                   explanation=override.pickle_global(*unknown[dotted]))
                else:
                    layer.raise_to(S, f"import outside the allowlist: {dotted}")
                _evidence(layer, event, "import", S)
        elif kind == "persistent_id" and not torch:
            layer.raise_to(S, "persistent id outside a torch checkpoint")
            _evidence(layer, event, "persistent_id", S)
    return layer


def _unknown_owner(target: str, unknown: dict[str, tuple[str, str]]) -> str | None:
    """The unknown import a call target is (``m.n``), is an attribute of (``m.n.x``) or was
    returned by (``m.n().x``). Longest match wins."""
    matches = [name for name in unknown if _matches(target, name)]
    return max(matches, key=len) if matches else None


def _evidence(layer: LayerResult, event: dict, category: str, severity: Verdict) -> None:
    if len(layer.evidence) >= MAX_EVIDENCE:
        return
    item = {k: event[k] for k in ("kind", "target", "args", "kwargs", "what", "module", "name", "path",
                                   "error", "detail", "stack") if k in event}
    item.update(category=category, severity=severity.value)
    layer.evidence.append(item)
