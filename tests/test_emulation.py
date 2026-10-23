"""Fake-API emulation inside the WASI sandbox (M4).

Payloads are harmless markers (echo MARKER, /tmp/safeloadai_marker, 127.0.0.1)
built as raw bytes or compiled inside the guest. None of them is ever loaded,
unmarshalled or called on the host.
"""
from __future__ import annotations

import base64
import marshal
import sys

import pytest

from safeloadai.sandbox import emulate_keras_lambdas, emulate_pickle, run_guest

pytestmark = pytest.mark.wasi


def _calls(run):
    return [e for e in run.events if e["kind"] == "call"]


def _targets(run):
    return [e["target"] for e in _calls(run)]


def _anomalies(run):
    return [e["what"] for e in run.events if e["kind"] == "anomaly"]


def _imports(run):
    return [(e["module"], e["name"], e["resolved"]) for e in run.events if e["kind"] == "import"]


# --- pickle ---------------------------------------------------------------------

def test_benign_pickle_records_no_calls():
    data = b"(dp0\nS'a'\np1\n(lp2\nI1\naI2\nas."
    run = emulate_pickle([data])
    assert run.completed and not run.tampered
    assert _calls(run) == [] and _anomalies(run) == []


def test_allowlisted_real_type_is_recorded_as_import():
    run = emulate_pickle([b"ccollections\nOrderedDict\n)R."])
    assert _imports(run) == [("collections", "OrderedDict", "real")]
    assert _calls(run) == []


def test_posix_system_marker_is_recorded_not_run():
    run = emulate_pickle([b"cposix\nsystem\n(S'echo MARKER'\ntR."])
    assert run.completed
    assert _imports(run) == [("posix", "system", "fake")]
    (call,) = _calls(run)
    assert call["target"] == "posix.system" and call["args"] == ["'echo MARKER'"]


def test_getattr_chain_is_followed():
    data = (b"cbuiltins\ngetattr\n(cbuiltins\n__import__\n(S'os'\ntRS'system'\ntR"
            b"(S'echo MARKER'\ntR.")
    run = emulate_pickle([data])
    assert "os.system" in _targets(run)
    assert "builtins.getattr" in _targets(run)


def test_nested_exec_is_emulated_under_fakes():
    data = b"cbuiltins\nexec\n(S\"import os; os.system('echo MARKER')\"\ntR."
    run = emulate_pickle([data])
    assert _targets(run)[0] == "builtins.exec"
    assert "os.system" in _targets(run)


def test_second_pickle_in_stream_is_emulated():
    benign = b"(dp0\n."
    evil = b"cposix\nsystem\n(S'echo MARKER'\ntR."
    run = emulate_pickle([benign + evil], max_pickles=2)
    assert "posix.system" in _targets(run)


def test_truncated_pickle_is_an_anomaly():
    run = emulate_pickle([b"cposix\nsystem\n(S'echo MAR"])
    assert "unpickling raised" in _anomalies(run)


def test_dunder_getattr_is_an_anomaly():
    data = b"cbuiltins\ngetattr\n(cbuiltins\ndict\nS'__subclasses__'\ntR."
    run = emulate_pickle([data])
    assert "introspection via getattr" in _anomalies(run)


# --- keras Lambda -------------------------------------------------------------------

def _guest_marshal(source: str) -> str:
    """Compile a lambda inside the guest so the bytecode matches its interpreter."""
    code = ("import marshal, base64\n"
            f"print(base64.b64encode(marshal.dumps(({source}).__code__)).decode())\n")
    run = run_guest({"kind": "python", "code": code}, {})
    assert run.completed, run.problems
    return run.guest_stdout.strip()


def _lambda(source: str, **extra):
    entry = {"path": "layers[0]", "code_b64": _guest_marshal(source), "input_shape": [None, 4]}
    entry.update(extra)
    return emulate_keras_lambdas([entry])


def test_benign_lambda_runs_clean():
    run = _lambda("lambda x: tf.nn.relu(x * 2.0 + 1.0)")
    assert run.completed and _anomalies(run) == []
    assert any(e.get("category") == "lambda" for e in run.events)
    assert _targets(run) == ["tf.nn.relu"]


def test_lambda_arguments_are_passed():
    run = _lambda("lambda x, scale: x * scale", arguments={"scale": 2.0})
    assert run.completed and _anomalies(run) == []


def test_lambda_os_system_marker():
    run = _lambda("lambda x: (__import__('os').system('echo MARKER'), x)[1]")
    assert "os.system" in _targets(run)


def test_lambda_string_built_getattr():
    run = _lambda("lambda x: getattr(__import__('o' + 's'), 'sys' + 'tem')('echo MARKER')")
    assert "os.system" in _targets(run)


def test_lambda_tf_io_write_file_marker():
    run = _lambda("lambda x: (tf.io.write_file('/tmp/safeloadai_marker', 'MARKER'), x)[1]")
    call = next(c for c in _calls(run) if c["target"] == "tf.io.write_file")
    assert "/tmp/safeloadai_marker" in call["args"][0]


def test_lambda_py_function_is_recorded():
    run = _lambda("lambda x: tf.py_function(lambda y: y, [x], tf.float32)")
    assert "tf.py_function" in _targets(run)


def test_lambda_environment_probe_is_recorded():
    run = _lambda("lambda x: x if __import__('os').environ.get('CI') else x * 2")
    assert "os.environ.get" in _targets(run)


def test_lambda_gated_on_weights_reads_tensor_values():
    run = _lambda(
        "lambda x: x if __import__('hashlib').sha256(str(x.numpy()).encode()).hexdigest() != 'ab'"
        " else __import__('os').system('echo MARKER')"
    )
    assert "tensor value read" in _anomalies(run)


def test_lambda_introspection_is_an_anomaly():
    run = _lambda("lambda x: ().__class__.__bases__[0].__subclasses__()")
    assert "introspection names in Lambda" in _anomalies(run)


def test_lambda_unknown_global_is_a_missing_stub():
    run = _lambda("lambda x: mystery_helper(x)")
    assert "missing stub for global" in _anomalies(run)


def test_lambda_garbage_bytecode_is_a_marshal_error():
    run = emulate_keras_lambdas([{"path": "l", "code_b64": base64.b64encode(b"not marshal").decode()}])
    assert "marshal error" in _anomalies(run)


@pytest.mark.skipif(sys.version_info[:2] == (3, 12), reason="needs host bytecode from another Python version")
def test_lambda_from_other_python_version_is_not_executed():
    # marshal.dumps of our own benign code object; nothing is unmarshalled on the host.
    # A trivial body (RESUME, LOAD_FAST, RETURN_VALUE) is byte-identical between
    # 3.11 and 3.12; a call is not, so use one.
    blob = marshal.dumps(compile("lambda x: tf.nn.relu(x * 2.0)", "<lambda>", "eval").co_consts[0])
    run = emulate_keras_lambdas([{"path": "l", "code_b64": base64.b64encode(blob).decode(),
                                  "input_shape": [None, 4]}])
    assert _anomalies(run), "foreign bytecode must be an anomaly"
    assert not any(e.get("category") == "lambda" for e in run.events)


def test_newobj_and_build_on_allowlisted_class_run_through_fakes():
    # Protocol 2 object as sklearn writes it: NEWOBJ then BUILD with a state dict.
    data = b"\x80\x02csklearn.linear_model._logistic\nLogisticRegression\n)\x81}X\x01\x00\x00\x00CK\x01sb."
    run = emulate_pickle([data])
    assert run.completed and _anomalies(run) == []
    assert _targets(run) == ["sklearn.linear_model._logistic.LogisticRegression.__new__",
                             "sklearn.linear_model._logistic.LogisticRegression.__setstate__"]


def test_lambda_closure_values_from_config_are_used():
    code = ("import marshal, base64\n"
            "def outer(cmd):\n"
            "    return lambda x: (__import__('os').system(cmd), x)[1]\n"
            "print(base64.b64encode(marshal.dumps(outer('').__code__)).decode())\n")
    blob = run_guest({"kind": "python", "code": code}, {}).guest_stdout.strip()
    run = emulate_keras_lambdas([{"path": "l", "code_b64": blob, "closure": ["echo MARKER"],
                                  "input_shape": [None, 4]}])
    call = next(c for c in _calls(run) if c["target"] == "os.system")
    assert call["args"] == ["'echo MARKER'"]


def test_sample_lambda_from_another_python_is_rejected_before_execution():
    # tests/fixtures/poc/evil_lambda.keras carries bytecode from another CPython version
    # that starts with RESUME too; it must be rejected, not run until it traps.
    import os

    from safeloadai.static import keras_static

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report = keras_static.parse_file(os.path.join(root, "tests", "fixtures", "poc", "evil_lambda.keras"))
    run = emulate_keras_lambdas(report["lambdas"])
    assert run.completed
    assert any("layout invalid" in a for a in _anomalies(run))
    assert not any(e.get("category") == "lambda" for e in run.events)


def test_reduce_result_accepts_tuple_state_like_numpy_arrays():
    # REDUCE(numpy._core.multiarray._reconstruct, (numpy.ndarray, (0,), b'b')) then BUILD
    # with a tuple state, as every numpy array pickle does.
    data = (b"\x80\x02cnumpy._core.multiarray\n_reconstruct\ncnumpy\nndarray\nK\x00\x85C\x01b\x87R"
            b"(K\x01K\x02\x86tb.")
    run = emulate_pickle([data])
    assert run.completed and _anomalies(run) == []
    assert "numpy._core.multiarray._reconstruct().__setstate__" in _targets(run)


# --- the emulation's budget grows with the file (0.8.0 held-out, E304) -------------------

def test_scaled_limits_grow_with_the_file_up_to_a_ceiling():
    from safeloadai.sandbox import host

    base = host.Limits()
    assert host.scaled_limits(0, 0) == base
    grown = host.scaled_limits(100 << 20, 1_000_000)
    assert base.fuel < grown.fuel <= host.MAX_FUEL
    assert base.wall_seconds < grown.wall_seconds <= host.MAX_WALL_SECONDS
    assert base.memory_bytes < grown.memory_bytes <= host.MAX_GUEST_MEMORY
    top = host.scaled_limits(1 << 40, 10 ** 9)
    assert (top.fuel, top.wall_seconds, top.memory_bytes) == (host.MAX_FUEL, host.MAX_WALL_SECONDS,
                                                              host.MAX_GUEST_MEMORY)


def test_a_large_pickle_gets_a_larger_budget_by_default(tmp_path, monkeypatch):
    import functools
    import pickle

    from safeloadai import pipeline, scan
    from safeloadai.sandbox import host

    # A base budget that starting the guest just fits in, so the file's own opcodes decide.
    small = host.Limits(fuel=1_150_000_000)
    path = tmp_path / "many.pkl"
    path.write_bytes(pickle.dumps(list(range(400_000)), protocol=2))
    fixed = scan(path, limits=small)
    assert fixed.status == "error" and fixed.error["code"] == "E304", fixed.error
    monkeypatch.setattr(pipeline, "scaled_limits", functools.partial(host.scaled_limits, base=small))
    grown = scan(path)
    assert grown.status == "ok" and grown.verdict is not None, grown.error


def test_over_the_ceiling_is_still_an_error(tmp_path, monkeypatch):
    import functools
    import pickle

    from safeloadai import pipeline, scan
    from safeloadai.sandbox import host

    small = host.Limits(fuel=1_150_000_000)
    monkeypatch.setattr(host, "MAX_FUEL", small.fuel)  # the ceiling: no room to grow
    monkeypatch.setattr(pipeline, "scaled_limits", functools.partial(host.scaled_limits, base=small))
    path = tmp_path / "many.pkl"
    path.write_bytes(pickle.dumps(list(range(400_000)), protocol=2))
    report = scan(path)
    assert report.status == "error" and report.error["code"] == "E304", report.error
