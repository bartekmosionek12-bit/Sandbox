import json
import os
import pickle
import shutil

from conftest import SAMPLES

from safeloadai.__main__ import main
from safeloadai.report import Verdict


def _clean(tmp_path, name="m.pkl"):
    path = tmp_path / name
    path.write_bytes(pickle.dumps({"a": 1}))
    return str(path)


def test_clean_exit_0(tmp_path, fake_emulation):
    assert main(["scan", "-q", _clean(tmp_path)]) == 0


def test_malicious_exit_1(tmp_path, fake_emulation):
    target = tmp_path / "evil.pkl"
    shutil.copy(os.path.join(SAMPLES, "evil_os_system.pkl"), target)
    assert main(["scan", "-q", str(target)]) == 1


def test_suspicious_exit_3(tmp_path, fake_emulation):
    fake_emulation.verdict = Verdict.SUSPICIOUS
    assert main(["scan", "-q", _clean(tmp_path)]) == 3


def test_json_output(tmp_path, fake_emulation, capsys):
    assert main(["scan", "--json", _clean(tmp_path)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == "CLEAN" and data["layers"][0]["name"] == "static"


def test_directory_and_report(tmp_path, fake_emulation):
    _clean(tmp_path, "a.pkl")
    _clean(tmp_path, "b.pickle")
    (tmp_path / "notes.txt").write_text("x")
    out = tmp_path / "report.json"
    assert main(["scan", "-q", str(tmp_path), "--report", str(out)]) == 0
    assert len(fake_emulation.calls) == 2 and len(json.loads(out.read_text())) == 2


def test_missing_path_exit_2(tmp_path):
    assert main(["scan", str(tmp_path / "missing")]) == 2


def test_bad_allow_exit_2(tmp_path):
    assert main(["scan", "--allow", "nocolon", _clean(tmp_path)]) == 2
