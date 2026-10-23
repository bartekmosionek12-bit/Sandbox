"""The bundled WASI runtime: resolution, pinned-hash checks, failure modes, doctor."""
from __future__ import annotations

import pickle
import shutil
import sys

import pytest

from safeloadai import RuntimeIntegrityError, scan
from safeloadai.__main__ import EXIT_INTEGRITY, main
from safeloadai.sandbox import host, run_guest, runtime


@pytest.fixture(autouse=True)
def _fresh_hash_cache():
    runtime.clear_cache()
    yield
    runtime.clear_cache()


def _pickle(tmp_path):
    path = tmp_path / "m.pkl"
    path.write_bytes(pickle.dumps({"a": 1}))
    return path


def _right_size_wrong_bytes(tmp_path):
    fake = tmp_path / runtime.PINNED.file_name
    fake.write_bytes(b"\0" * runtime.PINNED.size)
    return fake


def test_env_override_is_still_verified(tmp_path, monkeypatch):
    monkeypatch.setenv(runtime.RUNTIME_ENV, str(_right_size_wrong_bytes(tmp_path)))
    with pytest.raises(RuntimeIntegrityError, match="sha256"):
        runtime.locate()


def test_tampered_runtime_refuses_the_scan(tmp_path, monkeypatch):
    monkeypatch.setenv(runtime.RUNTIME_ENV, str(_right_size_wrong_bytes(tmp_path)))
    report = scan(_pickle(tmp_path))
    assert report.status == "error" and report.verdict is None and not report.clean
    assert report.error["code"] == "E401" and "sha256" in report.error["message"]


def test_cli_exit_code_on_integrity_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(runtime.RUNTIME_ENV, str(_right_size_wrong_bytes(tmp_path)))
    assert main(["scan", str(_pickle(tmp_path))]) == EXIT_INTEGRITY
    assert "sha256" in capsys.readouterr().err


@pytest.mark.wasi
def test_one_flipped_byte_is_refused(tmp_path, monkeypatch):
    original = runtime.locate()
    tampered = tmp_path / runtime.PINNED.file_name
    shutil.copyfile(original, tampered)
    with open(tampered, "r+b") as fh:
        fh.seek(runtime.PINNED.size // 2)
        byte = fh.read(1)
        fh.seek(-1, 1)
        fh.write(bytes([byte[0] ^ 0x01]))
    monkeypatch.setenv(runtime.RUNTIME_ENV, str(tampered))
    with pytest.raises(RuntimeIntegrityError, match="sha256"):
        runtime.locate()
    with pytest.raises(RuntimeIntegrityError):
        run_guest({"kind": "selftest"}, {})


def test_runner_rechecks_the_bytes_it_compiles(tmp_path, monkeypatch):
    # The host check is bypassed here, as if the file were swapped right after it.
    fake = _right_size_wrong_bytes(tmp_path)
    monkeypatch.setattr(runtime, "locate", lambda spec=runtime.PINNED: fake)
    with pytest.raises(RuntimeIntegrityError, match="expected"):
        run_guest({"kind": "selftest"}, {})


def test_missing_runtime_is_an_error_with_reason(tmp_path, monkeypatch):
    monkeypatch.setenv(runtime.RUNTIME_ENV, str(tmp_path / "absent.wasm"))
    report = scan(_pickle(tmp_path))
    assert report.status == "error" and report.verdict is None
    emulation = report.layer("emulation")
    assert emulation.ran is False
    assert report.error["code"] == "E301"
    assert "no WASI runtime" in report.error["message"] and "safeloadai doctor" in report.error["message"]


def test_missing_runtime_package_is_an_error(tmp_path, monkeypatch):
    monkeypatch.delenv(runtime.RUNTIME_ENV, raising=False)
    monkeypatch.setitem(sys.modules, runtime.RUNTIME_MODULE, None)  # import fails
    with pytest.raises(runtime.RuntimeUnavailable, match="not installed"):
        runtime.locate()
    report = scan(_pickle(tmp_path))
    assert report.status == "error" and report.error["code"] == "E301"
    assert "safeloadai-runtime package is not installed" in report.error["message"]


def test_package_file_missing_is_suspicious(tmp_path, monkeypatch):
    import types

    monkeypatch.delenv(runtime.RUNTIME_ENV, raising=False)
    broken = types.SimpleNamespace(path=lambda: tmp_path / "gone.wasm")
    monkeypatch.setitem(sys.modules, runtime.RUNTIME_MODULE, broken)
    with pytest.raises(runtime.RuntimeUnavailable, match="safeloadai-runtime package"):
        runtime.locate()


def test_verified_hash_is_cached_until_the_file_changes(tmp_path, monkeypatch):
    fake = tmp_path / "rt.wasm"
    fake.write_bytes(b"x" * 64)
    spec = runtime.RuntimeSpec(name="t", python_version="3.12.0", file_name="rt.wasm",
                               sha256=runtime.sha256_file(fake), size=64, source_url="", package_version="0")
    calls = []
    real = runtime.sha256_file
    monkeypatch.setattr(runtime, "sha256_file", lambda p: calls.append(p) or real(p))
    runtime.verify(fake, spec)
    runtime.verify(fake, spec)
    assert len(calls) == 1
    fake.write_bytes(b"y" * 64)  # same size, new content and mtime
    import os

    os.utime(fake, ns=(1, 1))
    with pytest.raises(RuntimeIntegrityError):
        runtime.verify(fake, spec)
    assert len(calls) == 2


def test_runtime_package_pins_the_same_hash():
    safeloadai_runtime = pytest.importorskip(runtime.RUNTIME_MODULE)
    assert safeloadai_runtime.SHA256 == runtime.PINNED.sha256
    assert safeloadai_runtime.SIZE == runtime.PINNED.size
    assert safeloadai_runtime.FILE_NAME == runtime.PINNED.file_name
    assert safeloadai_runtime.__version__ == runtime.PINNED.package_version


def test_job_carries_the_pinned_hash(monkeypatch, tmp_path):
    seen = {}

    class Proc:
        returncode = 0

        def communicate(self, data, timeout=None):
            import json

            seen.update(json.loads(data))
            return b'{"status": "runner_error", "error": "stop here"}', b""

    monkeypatch.setattr(runtime, "locate", lambda spec=runtime.PINNED: tmp_path / "x.wasm")
    monkeypatch.setattr(host.subprocess, "Popen", lambda *a, **k: Proc())
    run_guest({"kind": "selftest"}, {})
    assert seen["wasm_sha256"] == runtime.PINNED.sha256


def test_doctor_explains_a_missing_runtime(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(runtime.RUNTIME_ENV, str(tmp_path / "absent.wasm"))
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "FAIL  runtime file" in out and "fix:" in out


def test_doctor_reports_tampering(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(runtime.RUNTIME_ENV, str(_right_size_wrong_bytes(tmp_path)))
    assert main(["doctor", "--json"]) == 1
    import json

    doc = json.loads(capsys.readouterr().out)
    file_check = next(c for c in doc["checks"] if c["name"] == "runtime file")
    assert "INTEGRITY FAILURE" in file_check["detail"] and file_check["fix"]


@pytest.mark.wasi
def test_doctor_passes_with_the_pinned_runtime(capsys):
    assert main(["doctor"]) == 0
    assert "all checks passed" in capsys.readouterr().out
