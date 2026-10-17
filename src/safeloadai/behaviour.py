"""Turn validated emulation records into a layer verdict (host side).

The guest only records; this module decides. Rules, all fail-closed:

* tampering with the evidence channel -> MALICIOUS;
* emulation unavailable, incomplete, timed out or out of fuel -> SUSPICIOUS;
* any anomaly record (marshal error, foreign bytecode, missing stub, emulation
  exception, introspection, tensor values read, sleep) -> SUSPICIOUS;
* a call to a known sink -> MALICIOUS or SUSPICIOUS by sink category;
* any other call that is neither a framework tensor operation nor a method of
  an allowlisted global -> SUSPICIOUS;
* an import of a global outside the allowlist -> SUSPICIOUS.
"""
from __future__ import annotations

from .report import LayerResult, Verdict
from .sandbox.host import GuestRun
from .static.allowlists import PICKLE_GLOBALS, TORCH_GLOBALS

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


def _matches(target: str, prefix: str) -> bool:
    return target == prefix or target.startswith((prefix + ".", prefix + "(", prefix + "["))


def sink_for(target: str) -> tuple[str, Verdict] | None:
    for prefix, category, severity in SINKS:
        if _matches(target, prefix):
            return category, severity
    return None


def _unquote(text: str) -> str:
    return text[1:-1] if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"" else text


def _classify_call(event: dict, allowed_names: frozenset[str]) -> tuple[str, Verdict] | None:
    target = str(event.get("target", ""))
    args = event.get("args") or []
    if target == "builtins.open":
        mode = _unquote(str(args[1])) if len(args) > 1 else _unquote(str((event.get("kwargs") or {}).get("mode", "r")))
        return ("file_write", M) if WRITE_MODES & set(mode) else ("file_read", S)
    if target == "builtins.__import__":
        module = _unquote(str(args[0])) if args else ""
        if module.split(".")[0] in SAFE_IMPORTS:
            return None
        return "import", S
    found = sink_for(target)
    if found:
        return found
    if target.startswith(FRAMEWORK_PREFIXES):
        return None
    if any(_matches(target, name) for name in allowed_names):
        return None
    return "unexpected_call", S


def allowed_names(extra_allowed: frozenset = frozenset(), torch: bool = False) -> frozenset[str]:
    pairs = PICKLE_GLOBALS | frozenset(extra_allowed) | (TORCH_GLOBALS if torch else frozenset())
    return frozenset(f"{module}.{name}" for module, name in pairs)


def classify(run: GuestRun, *, name: str = "emulation", torch: bool = False,
             extra_allowed: frozenset = frozenset()) -> LayerResult:
    layer = LayerResult(name=name, verdict=Verdict.CLEAN, timings_ms=dict(run.timings_ms),
                        details={"status": run.status, "completed": run.completed, "runtime": run.runtime,
                                 "problems": run.problems[:50]})
    if run.status == "unavailable":
        layer.ran = False
        layer.raise_to(S, "emulation layer could not run: " + "; ".join(run.problems))
        return layer
    if run.tampered:
        layer.raise_to(M, "write to the evidence channel that did not come from the recorder")
    if not run.completed:
        layer.raise_to(S, f"emulation did not complete (status {run.status}): " + "; ".join(run.problems[:5]))

    allow_pairs = PICKLE_GLOBALS | frozenset(extra_allowed) | (TORCH_GLOBALS if torch else frozenset())
    names = allowed_names(extra_allowed, torch)
    for event in run.events:
        kind = event.get("kind")
        if kind == "anomaly":
            layer.raise_to(S, f"anomaly: {event.get('what')}")
            _evidence(layer, event, "anomaly", S)
        elif kind == "call":
            found = _classify_call(event, names)
            if found:
                category, severity = found
                layer.raise_to(severity, f"{category}: {event.get('target')}")
                _evidence(layer, event, category, severity)
        elif kind == "import":
            pair = (event.get("module"), event.get("name"))
            if event.get("resolved") != "real" and pair not in allow_pairs:
                layer.raise_to(S, f"import outside the allowlist: {pair[0]}.{pair[1]}")
                _evidence(layer, event, "import", S)
        elif kind == "persistent_id" and not torch:
            layer.raise_to(S, "persistent id outside a torch checkpoint")
            _evidence(layer, event, "persistent_id", S)
    return layer


def _evidence(layer: LayerResult, event: dict, category: str, severity: Verdict) -> None:
    if len(layer.evidence) >= MAX_EVIDENCE:
        return
    item = {k: event[k] for k in ("kind", "target", "args", "kwargs", "what", "module", "name", "path",
                                   "error", "detail", "stack") if k in event}
    item.update(category=category, severity=severity.value)
    layer.evidence.append(item)
