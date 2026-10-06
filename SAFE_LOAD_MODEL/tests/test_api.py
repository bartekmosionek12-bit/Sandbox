import os
import pickle
import shutil

import pytest

from conftest import SAMPLES, sandbox_report
from sandbox_rce import SecurityException, api, safe_load_model


def _write(path, obj):
    with open(path, "wb") as fh:
        pickle.dump(obj, fh)
    return str(path)


def test_clean_file_loads(tmp_path, fake_detonation):
    path = _write(tmp_path / "m.pkl", {"w": [1, 2, 3]})
    assert safe_load_model(path, verbose=False) == {"w": [1, 2, 3]}


def test_pathlib_path_accepted(tmp_path, fake_detonation):
    path = tmp_path / "m.pkl"
    _write(path, [1])
    assert safe_load_model(path, verbose=False) == [1]


def test_evil_file_blocked_before_load(tmp_path, fake_detonation, forbid_pickle_load):
    fake_detonation.result = sandbox_report(events=[{"type": "os_system", "detail": "touch /tmp/pwned"}])
    target = tmp_path / "evil.pkl"
    shutil.copy(os.path.join(SAMPLES, "evil_os_system.pkl"), target)
    with pytest.raises(SecurityException) as info:
        safe_load_model(str(target), verbose=False)
    assert info.value.verdict == "malicious"
    assert info.value.code == api.BLOCKED_VERDICT


def test_scan_then_swap_loads_scanned_copy(tmp_path, fake_detonation):
    # Okno TOCTOU: w trakcie skanu ktoś podmienia plik pod oryginalną ścieżką.
    original = tmp_path / "m.pkl"
    _write(original, "zeskanowany")

    def swap(_staged):
        _write(original, "podmieniony")

    fake_detonation.side_effect = swap
    assert safe_load_model(str(original), verbose=False) == "zeskanowany"


def test_timeout_blocks(tmp_path, fake_detonation, forbid_pickle_load):
    fake_detonation.result = sandbox_report(timed_out=True, load_succeeded=None)
    path = _write(tmp_path / "m.pkl", {"a": 1})
    with pytest.raises(SecurityException) as info:
        safe_load_model(path, verbose=False)
    assert info.value.code == api.DETONATION_TIMEOUT


def test_cache_skips_second_detonation(tmp_path, fake_detonation):
    path = _write(tmp_path / "m.pkl", {"a": 1})
    cache = tmp_path / "cache"
    first = api.scan_model(path, cache_dir=cache)
    second = api.scan_model(path, cache_dir=cache)
    assert len(fake_detonation.calls) == 1
    assert first["cache"]["hit"] is False and second["cache"]["hit"] is True
    assert second["gate"]["allowed"]


def test_cache_ignores_incomplete_scan(tmp_path, fake_detonation):
    fake_detonation.result = sandbox_report(detonated=False, skipped_reason="Brak Dockera.")
    path = _write(tmp_path / "m.pkl", {"a": 1})
    api.scan_model(path, cache_dir=tmp_path / "cache")
    api.scan_model(path, cache_dir=tmp_path / "cache")
    assert len(fake_detonation.calls) == 2


def test_unsupported_extension():
    with pytest.raises(ValueError):
        safe_load_model("model.bin")
