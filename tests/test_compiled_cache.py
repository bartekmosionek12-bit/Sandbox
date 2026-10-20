"""Where compiled modules are cached: platform defaults, fallbacks, errors, doctor."""
from __future__ import annotations

import os
import pickle
from pathlib import Path

import pytest

from safeloadai import doctor, scan
from safeloadai.sandbox import host, run_guest, runtime

PLATFORM_VARS = ("SAFELOADAI_HOME", "XDG_CACHE_HOME", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP")


@pytest.fixture
def clean_env(monkeypatch):
    for var in PLATFORM_VARS:
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


def _blocked(tmp_path, name="blocked"):
    """A candidate whose directory cannot be created: its parent is a regular file."""
    marker = tmp_path / f"{name}-file"
    marker.write_bytes(b"")
    return marker / "safeloadai"


def _candidates(monkeypatch, *paths):
    monkeypatch.setattr(runtime, "cache_candidates", lambda platform=None: list(paths))


def test_safeloadai_home_overrides_everything(tmp_path, clean_env):
    clean_env.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    clean_env.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    clean_env.setenv(runtime.HOME_ENV, str(tmp_path / "home"))
    for platform in ("win32", "darwin", "linux"):
        assert runtime.cache_candidates(platform) == [tmp_path / "home"]
    cache = runtime.compiled_cache_dir()
    assert cache.path == tmp_path / "home" / "compiled" and cache.attempts == ()


def test_safeloadai_home_is_not_replaced_when_it_fails(tmp_path, clean_env):
    clean_env.setenv(runtime.HOME_ENV, str(_blocked(tmp_path)))
    cache = runtime.compiled_cache_dir()
    assert cache.path is None and len(cache.attempts) == 1


def test_windows_candidates(tmp_path, clean_env):
    clean_env.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    clean_env.setenv("APPDATA", str(tmp_path / "Roaming"))
    clean_env.setenv("TEMP", str(tmp_path / "Temp"))
    clean_env.setattr(runtime.getpass, "getuser", lambda: "Jan Kowalski")
    assert runtime.cache_candidates("win32") == [
        tmp_path / "Local" / "safeloadai",
        tmp_path / "Roaming" / "safeloadai",
        tmp_path / "Temp" / "safeloadai-Jan_Kowalski",
    ]


def test_windows_skips_unset_variables(tmp_path, clean_env):
    clean_env.setenv("TMP", str(tmp_path / "Temp"))
    clean_env.setattr(runtime.getpass, "getuser", lambda: "")
    assert runtime.cache_candidates("win32") == [tmp_path / "Temp" / "safeloadai-user"]


def test_macos_candidate(tmp_path, clean_env):
    clean_env.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert runtime.cache_candidates("darwin") == [tmp_path / "Library" / "Caches" / "safeloadai"]


def test_linux_candidates_never_use_a_shared_temp_dir(tmp_path, clean_env):
    clean_env.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    clean_env.setenv("TEMP", "/tmp")
    assert runtime.cache_candidates("linux") == [tmp_path / ".cache" / "safeloadai"]
    xdg = tmp_path / "xdg"
    clean_env.setenv("XDG_CACHE_HOME", str(xdg))
    assert runtime.cache_candidates("linux") == [xdg / "safeloadai", tmp_path / ".cache" / "safeloadai"]
    clean_env.setenv("XDG_CACHE_HOME", "relative/path")  # ignored, as the XDG spec says
    assert runtime.cache_candidates("linux") == [tmp_path / ".cache" / "safeloadai"]


def test_unwritable_default_falls_back_to_the_next_candidate(tmp_path, monkeypatch):
    blocked, good = _blocked(tmp_path), tmp_path / "good"
    _candidates(monkeypatch, blocked, good)
    cache = runtime.compiled_cache_dir()
    assert cache.path == good / "compiled" and cache.path.is_dir()
    assert [a.path for a in cache.attempts] == [blocked / "compiled"]
    assert "Error" in cache.attempts[0].error


def test_permission_error_is_kept(tmp_path, monkeypatch):
    denied = tmp_path / "denied"
    real_mkdir = Path.mkdir

    def mkdir(self, *args, **kwargs):
        if denied in (self, *self.parents):
            raise PermissionError(13, "Access is denied", str(self))
        return real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", mkdir)
    _candidates(monkeypatch, denied, tmp_path / "ok")
    cache = runtime.compiled_cache_dir()
    assert cache.path == tmp_path / "ok" / "compiled"
    assert cache.attempts[0].error.startswith("PermissionError [Errno 13] Access is denied")


def test_unwritable_directory_is_skipped(tmp_path, monkeypatch):
    def no_write(*args, **kwargs):
        raise PermissionError(13, "Access is denied")

    _candidates(monkeypatch, tmp_path / "ro")
    monkeypatch.setattr(runtime.tempfile, "mkstemp", no_write)
    cache = runtime.compiled_cache_dir()
    assert cache.path is None and "PermissionError" in cache.attempts[0].error


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_posix_privacy_rules_are_unchanged(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    (shared / "compiled").mkdir(parents=True)
    os.chmod(shared, 0o777)
    _candidates(monkeypatch, shared, tmp_path / "private")
    cache = runtime.compiled_cache_dir()
    assert cache.path == tmp_path / "private" / "compiled"
    assert "not private" in cache.attempts[0].error


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_fresh_cache_is_private_under_a_group_writable_umask(tmp_path, monkeypatch):
    _candidates(monkeypatch, tmp_path / "fresh" / "safeloadai")
    old = os.umask(0o002)
    try:
        cache = runtime.compiled_cache_dir()
    finally:
        os.umask(old)
    assert cache.path == tmp_path / "fresh" / "safeloadai" / "compiled" and cache.attempts == ()


def test_no_usable_candidate_compiles_in_memory(tmp_path, monkeypatch):
    _candidates(monkeypatch, _blocked(tmp_path, "a"), _blocked(tmp_path, "b"))
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
    assert seen["compiled_cache_dir"] is None


def test_doctor_warns_with_the_real_errors(tmp_path, monkeypatch, capsys):
    first, second = _blocked(tmp_path, "a"), _blocked(tmp_path, "b")
    _candidates(monkeypatch, first, second)
    monkeypatch.setattr(doctor, "run_checks", lambda: [doctor._cache()])
    assert doctor.main() == 0
    out = capsys.readouterr().out
    assert out.startswith("warn  compiled cache: no usable directory")
    assert "FAIL" not in out and "all checks passed" in out
    for path in (first, second):
        assert f"- {path / 'compiled'}: " in out
    assert out.count("Error [") == 2  # e.g. "NotADirectoryError [Errno 20]" or "...Error [WinError 3]"


def test_doctor_names_the_fallback(tmp_path, monkeypatch):
    _candidates(monkeypatch, _blocked(tmp_path), tmp_path / "good")
    check = doctor._cache()
    assert check.ok and check.status == "ok"
    assert check.detail.startswith(str(tmp_path / "good" / "compiled")) and "fallback" in check.detail


@pytest.mark.wasi
def test_cache_location_never_changes_the_verdict(tmp_path, monkeypatch):
    model = tmp_path / "m.pkl"
    model.write_bytes(pickle.dumps({"a": [1, 2.0, "x"]}))
    _candidates(monkeypatch, tmp_path / "cache")
    cached = scan(model).to_dict()
    _candidates(monkeypatch, _blocked(tmp_path))
    in_memory = scan(model).to_dict()
    assert cached["verdict"] == in_memory["verdict"]
    assert cached["reasons"] == in_memory["reasons"]
