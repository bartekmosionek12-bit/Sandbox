import os
import pickle
import shutil

from conftest import SAMPLES, sandbox_report
from sandbox_rce.__main__ import main


def _clean(tmp_path, name="m.pkl"):
    path = tmp_path / name
    with open(path, "wb") as fh:
        pickle.dump({"a": 1}, fh)
    return str(path)


def test_scan_subcommand_ok(tmp_path, fake_detonation):
    assert main(["scan", "-q", _clean(tmp_path)]) == 0


def test_legacy_form_without_subcommand(tmp_path, fake_detonation):
    assert main(["-q", _clean(tmp_path)]) == 0


def test_blocked_exit_1(tmp_path, fake_detonation):
    fake_detonation.result = sandbox_report(events=[{"type": "os_system", "detail": "x"}])
    target = tmp_path / "evil.pkl"
    shutil.copy(os.path.join(SAMPLES, "evil_os_system.pkl"), target)
    assert main(["scan", "-q", str(target)]) == 1


def test_no_detonation_exit_3(tmp_path, fake_detonation):
    fake_detonation.result = sandbox_report(detonated=False, skipped_reason="Brak Dockera.")
    assert main(["scan", "-q", _clean(tmp_path)]) == 3


def test_directory_and_report(tmp_path, fake_detonation):
    _clean(tmp_path, "a.pkl")
    _clean(tmp_path, "b.pickle")
    (tmp_path / "notes.txt").write_text("x")
    out = tmp_path / "raport.json"
    assert main(["scan", "-q", str(tmp_path), "--report", str(out)]) == 0
    assert len(fake_detonation.calls) == 2 and out.exists()


def test_missing_path_exit_2(tmp_path):
    assert main(["scan", str(tmp_path / "nie-ma")]) == 2
