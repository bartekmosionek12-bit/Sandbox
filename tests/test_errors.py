"""Tool errors (ERROR) are kept apart from verdicts about the file (docs/ERRORS.md)."""
from __future__ import annotations

import json
import pickle
import random

import pytest
from corpus.build_corpus import MARKER_CMD, P2, STOP, call, g, s

from safeloadai import errors, pipeline, safe_load, scan
from safeloadai import static as static_mod
from safeloadai.__main__ import EXIT_ERROR, EXIT_INTEGRITY, exit_code, main
from safeloadai.api import UnsafeModelError
from safeloadai.report import LayerResult, Report, Verdict
from safeloadai.sandbox import emulate as sandbox_emulate
from safeloadai.sandbox.host import GuestRun
from safeloadai.static import keras_static, pickle_static, pickle_vm


def _clean(tmp_path, name="m.pkl"):
    path = tmp_path / name
    path.write_bytes(pickle.dumps({"a": 1}))
    return path


def _evil(tmp_path, name="evil.pkl"):
    path = tmp_path / name
    path.write_bytes(P2 + call(g("posix", "system"), s(MARKER_CMD)) + STOP)
    return path


def _is_error(report, code):
    assert report.status == "error", (report.status, report.verdict, report.reasons)
    assert report.verdict is None and report.outcome == "ERROR"
    assert not report.clean and not report.accepted
    assert report.error["code"] == code, report.error
    assert set(report.error) == {"code", "message", "layer"}
    assert report.to_dict()["verdict"] is None


def test_every_code_is_documented():
    from pathlib import Path

    text = (Path(__file__).resolve().parents[1] / "docs" / "ERRORS.md").read_text(encoding="utf-8")
    for code in errors.CODES:
        assert f"`{code}`" in text, code


# --- I/O (E1xx) ---------------------------------------------------------------------------

def test_missing_file(tmp_path):
    _is_error(scan(tmp_path / "absent.pkl"), "E101")


def test_directory_is_not_a_regular_file(tmp_path):
    _is_error(scan(tmp_path), "E104")


def test_unreadable_file(tmp_path, monkeypatch):
    path = _clean(tmp_path)
    real_open = open

    def refuse(file, *args, **kwargs):
        if str(file) == str(path):
            raise PermissionError(13, "Permission denied", str(file))
        return real_open(file, *args, **kwargs)

    # root reads any file regardless of its mode, so the refusal is simulated
    monkeypatch.setattr(pipeline, "open", refuse, raising=False)
    report = scan(path)
    _is_error(report, "E102")
    assert "Permission denied" in report.error["message"] and report.error["layer"] == "io"


def test_file_too_large_to_read(tmp_path, monkeypatch):
    monkeypatch.setattr(static_mod, "MAX_FILE_BYTES", 8)
    _is_error(scan(_clean(tmp_path)), "E103")


def test_safe_load_of_a_missing_file_is_refused_with_the_error(tmp_path):
    with pytest.raises(UnsafeModelError) as info:
        safe_load(tmp_path / "absent.pkl")
    assert info.value.report.error["code"] == "E101" and info.value.verdict is None


# --- file problems stay verdicts --------------------------------------------------------

@pytest.mark.wasi
def test_truncated_pickle_is_suspicious_in_plain_words(tmp_path):
    path = tmp_path / "t.pkl"
    path.write_bytes(pickle.dumps({"weights": list(range(50))}, protocol=4)[:-7])
    report = scan(path)
    assert report.ok and report.verdict is Verdict.SUSPICIOUS
    assert any("pickle is not readable: it is truncated" in r for r in report.reasons), report.reasons


@pytest.mark.wasi
def test_missing_memo_entry_is_suspicious_in_plain_words(tmp_path):
    path = tmp_path / "memo.pkl"
    path.write_bytes(b"\x80\x04" + b"h\x65" + b".")  # BINGET 101: never stored
    report = scan(path)
    assert report.ok and report.verdict is Verdict.SUSPICIOUS
    assert any("refers to stored object 101 that it never stored" in r for r in report.reasons), report.reasons
    assert not report.errors


@pytest.mark.wasi
def test_random_bytes_are_a_verdict_not_an_error(tmp_path):
    path = tmp_path / "noise.bin"
    path.write_bytes(random.Random(8).randbytes(4096))
    report = scan(path)
    assert report.ok and report.verdict is Verdict.UNSUPPORTED and not report.errors


@pytest.mark.parametrize("exc, words", [
    (pickle_vm.VMError("memo key 101 not found"), "never stored"),
    (pickle_vm.VMError("unpickling stack underflow"), "off its stack"),
    (ValueError("not enough data in stream to read uint4"), "truncated"),
    (ValueError("at position 36, opcode b'\\xff' unknown"), "no pickle opcode"),
    (pickle_vm.VMError("GLOBAL at 114 crosses the end of its frame at 115"), "framing"),
    (pickle_vm.VMError("NumpyArrayWrapper at 756: unexpected numpy.dtype arguments"), "joblib array"),
])
def test_walk_problems_about_the_file(exc, words):
    text = pickle_static.walk_problem(exc)
    assert text.startswith("pickle is not readable: ") and words in text


@pytest.mark.parametrize("exc", [pickle_vm.VMUnmodelled("opcode X is not modelled"), KeyError("x"),
                                 AttributeError("y"), RecursionError("deep"), TypeError("z")])
def test_walk_failures_of_the_tool(exc):
    assert pickle_static.walk_problem(exc) is None


# --- parser bugs (E2xx) -------------------------------------------------------------------

def _boom(*args, **kwargs):
    raise KeyError("injected")


def test_internal_exception_in_the_pickle_walker(tmp_path, monkeypatch, fake_emulation):
    monkeypatch.setattr(pickle_static.Machine, "run_one", _boom)
    report = scan(_clean(tmp_path))
    _is_error(report, "E201")
    assert "KeyError" in report.error["message"] and report.error["layer"] == "static"


def test_unmodelled_opcode_is_a_tool_error():
    report = pickle_static.parse_pickle(pickle.dumps(1))
    assert not report["tool_errors"]
    real = pickle_vm.Machine._step

    def unmodelled(self, name, *args):
        if name == "BININT1":
            raise pickle_vm.VMUnmodelled(f"opcode {name} is not modelled")
        return real(self, name, *args)

    pickle_vm.Machine._step, saved = unmodelled, pickle_vm.Machine._step
    try:
        report = pickle_static.parse_pickle(pickle.dumps(1))
    finally:
        pickle_vm.Machine._step = saved
    assert [e["code"] for e in report["tool_errors"]] == ["E201"]
    assert report["static_risk"] != "clean"


def test_internal_exception_in_a_format_reader(tmp_path, monkeypatch, fake_emulation):
    import zipfile

    path = tmp_path / "m.keras"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
        zf.writestr("model.weights.h5", b"")
    monkeypatch.setattr(static_mod, "parse_keras", _boom)
    _is_error(scan(path), "E202")
    assert keras_static  # the reader module itself is untouched


def test_internal_exception_outside_the_readers(tmp_path, monkeypatch, fake_emulation):
    monkeypatch.setattr(static_mod.views_mod, "find_views", _boom)
    _is_error(scan(_clean(tmp_path)), "E200")


def test_internal_exception_in_the_emulation_layer(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "emulation_layer", _boom)
    _is_error(scan(_clean(tmp_path)), "E300")


def test_tool_error_report_is_refused_by_safe_load(tmp_path, monkeypatch, fake_emulation):
    monkeypatch.setattr(pickle_static.Machine, "run_one", _boom)
    with pytest.raises(UnsafeModelError) as info:
        safe_load(_clean(tmp_path), accept_unverified=["anything"])
    assert info.value.error["code"] == "E201" and "ERROR" in str(info.value)


# --- sandbox (E3xx) -----------------------------------------------------------------------

@pytest.mark.parametrize("status, code", [("trap", "E302"), ("runner_error", "E302"), ("timeout", "E303"),
                                          ("fuel_exhausted", "E304"), ("unavailable", "E301")])
def test_simulated_sandbox_crash_and_timeout(tmp_path, monkeypatch, status, code):
    monkeypatch.setattr(sandbox_emulate, "run_guest",
                        lambda *a, **k: GuestRun(status=status, problems=[f"simulated {status}"]))
    report = scan(_clean(tmp_path))
    _is_error(report, code)
    assert f"simulated {status}" in report.error["message"]


def test_malicious_evidence_decides_despite_a_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox_emulate, "run_guest",
                        lambda *a, **k: GuestRun(status="trap", problems=["simulated trap"]))
    report = scan(_evil(tmp_path))  # the static layer already found the sink call
    assert report.ok and report.verdict is Verdict.MALICIOUS
    assert [e["code"] for e in report.errors] == ["E302"] and report.error is None


def test_h5_reader_crash_is_a_tool_error(monkeypatch):
    monkeypatch.setattr(sandbox_emulate, "run_guest", lambda *a, **k: GuestRun(
        status="ok", completed=True, events=[{"kind": "anomaly", "what": "guest task raised",
                                              "error": "IndexError", "detail": "boom"}]))
    meta = sandbox_emulate.read_h5_metadata(b"\x89HDF\r\n\x1a\n")
    assert meta["tool_error"]["code"] == "E203"
    report = static_mod.parse_h5_metadata(meta)
    assert [e["code"] for e in report["tool_errors"]] == ["E203"] and not report["reasons"]


def test_h5_structure_refused_is_a_file_problem(monkeypatch):
    monkeypatch.setattr(sandbox_emulate, "run_guest", lambda *a, **k: GuestRun(
        status="ok", completed=True, events=[{"kind": "h5_meta", "refused": "superblock checksum mismatch"}]))
    report = static_mod.parse_h5_metadata(sandbox_emulate.read_h5_metadata(b"\x89HDF\r\n\x1a\n"))
    assert not report["tool_errors"] and report["static_risk"] == "suspicious"


# --- options (E5xx) -----------------------------------------------------------------------

def test_invalid_option_is_an_error_report(tmp_path, fake_emulation):
    report = scan(_clean(tmp_path), allow=[("builtins", "exec")])
    _is_error(report, "E501")
    assert report.error["layer"] == "options"


# --- CLI ----------------------------------------------------------------------------------

def test_missing_file_in_a_batch_does_not_abort_the_scan(tmp_path, fake_emulation, capsys):
    clean = _clean(tmp_path)
    missing = tmp_path / "gone.pkl"
    assert main(["scan", "--json", str(clean), str(missing), str(_clean(tmp_path, "b.pkl"))]) == EXIT_ERROR
    results = json.loads(capsys.readouterr().out)
    assert [r["status"] for r in results] == ["ok", "error", "ok"]
    assert [r["verdict"] for r in results] == ["CLEAN", None, "CLEAN"]
    assert results[1]["error"]["code"] == "E101" and len(fake_emulation.calls) == 2


def test_text_output_names_the_error(tmp_path, capsys):
    main(["scan", str(tmp_path / "gone.pkl")])
    out = capsys.readouterr().out
    assert out.startswith("ERROR") and "E101" in out


def test_malicious_wins_over_error(tmp_path, fake_emulation):
    assert main(["scan", "-q", str(_evil(tmp_path)), str(tmp_path / "gone.pkl")]) == 1


def test_error_wins_over_suspicious(tmp_path, fake_emulation):
    fake_emulation.verdict = Verdict.SUSPICIOUS
    assert main(["scan", "-q", str(_clean(tmp_path)), str(tmp_path / "gone.pkl")]) == EXIT_ERROR


def _report(verdict=None, code=None):
    report = Report(path="p", file_name="p", sha256="", size=0, file_format="pickle", verdict=verdict,
                    reasons=[], layers=[LayerResult("static", Verdict.CLEAN)], timings_ms={}, version="0")
    if code:
        report.status, report.error = "error", errors.error(code, "x")
    return report


@pytest.mark.parametrize("reports, expected", [
    ([_report(Verdict.MALICIOUS), _report(code="E101")], 1),
    ([_report(code="E302"), _report(code="E401")], EXIT_INTEGRITY),
    ([_report(code="E302"), _report(Verdict.SUSPICIOUS)], EXIT_ERROR),
    ([_report(Verdict.SUSPICIOUS), _report(Verdict.UNSUPPORTED)], 3),
    ([_report(Verdict.UNSUPPORTED), _report(Verdict.CLEAN)], 5),
    ([_report(Verdict.CLEAN)], 0),
])
def test_exit_code_precedence(reports, expected):
    assert exit_code(reports) == expected
