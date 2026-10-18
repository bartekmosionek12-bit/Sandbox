"""UNVERIFIABLE reasons and the informed, per-file override (API and CLI).

The override-able files here are a Keras 2 .h5 fixture with a bare custom class and
custom loss (tests/fixtures/h5/k2_custom_objects.h5) and pickles of
``fractions.Fraction``: a stdlib class outside the allowlist that is not a sink, so
loading it after an accepted override only builds a fraction.
"""
from __future__ import annotations

import io
import json
import pickle
from fractions import Fraction
from pathlib import Path

import pytest
from corpus.build_corpus import P2, STOP, call, g, s

from safeloadai import UnsafeModelError, Verdict, override, safe_load, scan
from safeloadai import __main__ as cli

pytestmark = pytest.mark.wasi
H5 = Path(__file__).with_name("fixtures") / "h5" / "k2_custom_objects.h5"


@pytest.fixture
def fraction_a(tmp_path) -> Path:
    path = tmp_path / "a.pkl"
    path.write_bytes(pickle.dumps(Fraction(1, 3), protocol=4))
    return path


@pytest.fixture
def fraction_b(tmp_path) -> Path:
    path = tmp_path / "b.pkl"
    path.write_bytes(pickle.dumps(Fraction(2, 3), protocol=4))
    return path


def _write(tmp_path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


FRACTION = call(g("fractions", "Fraction"), s("1/3"))


def test_bare_class_in_h5_is_unverifiable_with_an_explanation():
    report = scan(H5)
    assert report.verdict is Verdict.SUSPICIOUS
    assert report.category == "UNVERIFIABLE" and report.unverifiable_only
    assert report.unverifiable_items == ["MyDense", "my_custom_loss"]
    for finding in report.findings:
        assert finding["category"] == "UNVERIFIABLE"
        assert finding["item"] in finding["explanation"]
    bare = next(f for f in report.findings if f["item"] == "MyDense")
    assert "without its module" in bare["explanation"] and ".keras" in bare["explanation"]


def test_every_reason_has_a_category(fraction_a, tmp_path):
    evil = scan(_write(tmp_path, "evil.pkl", P2 + call(g("posix", "system"), s("echo MARKER")) + STOP))
    assert evil.verdict is Verdict.MALICIOUS and evil.category == "MALICIOUS"
    assert len(evil.findings) == len(evil.reasons)
    assert {f["category"] for f in evil.findings} <= {"MALICIOUS", "RISKY"}
    report = scan(fraction_a)
    assert report.unverifiable_items == ["fractions.Fraction"]
    assert scan(Path(__file__).parent.parent / "poc" / "samples" / "clean_model.pkl").category is None


def test_override_accepts_unverifiable_only_file_and_records_it():
    report = scan(H5)
    assert override.apply(report, ["MyDense", "my_custom_loss"], how="api")
    assert report.accepted and report.verdict is Verdict.SUSPICIOUS  # the verdict never changes
    record = report.to_dict()["override"]
    assert record["accepted"] is True and record["items"] == ["MyDense", "my_custom_loss"]
    assert record["sha256"] == report.sha256 and record["how"] == "api" and record["time"]


def test_override_must_name_every_item():
    report = scan(H5)
    assert not override.apply(report, ["MyDense"], how="api")
    assert not report.accepted
    assert "my_custom_loss" in report.override["refused_because"]


def test_safe_load_refuses_by_default_and_loads_with_named_items(fraction_a):
    with pytest.raises(UnsafeModelError) as exc:
        safe_load(fraction_a)
    assert exc.value.report.unverifiable_only and exc.value.report.override is None
    assert safe_load(fraction_a, accept_unverified=["fractions.Fraction"]) == Fraction(1, 3)


def test_safe_load_has_no_accept_all_switch(fraction_a):
    with pytest.raises(TypeError):
        safe_load(fraction_a, accept_unverified="fractions.Fraction")
    for wrong in (["*"], ["fractions"], ["fractions.*"], [True]):
        with pytest.raises(UnsafeModelError):
            safe_load(fraction_a, accept_unverified=wrong)


def test_acceptance_for_file_a_does_not_apply_to_file_b(fraction_a, fraction_b):
    sha_a = scan(fraction_a).sha256
    assert safe_load(fraction_a, accept_unverified={sha_a: ["fractions.Fraction"]}) == Fraction(1, 3)
    with pytest.raises(UnsafeModelError) as exc:
        safe_load(fraction_b, accept_unverified={sha_a: ["fractions.Fraction"]})
    assert exc.value.report.override is None


@pytest.mark.parametrize("data, category", [
    (P2 + b"(" + FRACTION + call(g("posix", "system"), s("echo MARKER")) + b"l" + STOP, "MALICIOUS"),
    (P2 + b"(" + FRACTION + b"\x82\x01" + b"l" + STOP, "RISKY"),  # EXT1 import through copyreg
    (P2 + b"(" + FRACTION + call(g("numpy.testing._private.utils", "runstring"), s("pass"), b"}") + b"l" + STOP,
     "RISKY"),  # a known gadget is never UNVERIFIABLE
])
def test_override_is_impossible_with_any_other_reason(tmp_path, data, category):
    path = _write(tmp_path, "mixed.pkl", data)
    report = scan(path)
    assert report.category == category and not report.unverifiable_only
    assert any(f["category"] == "UNVERIFIABLE" for f in report.findings)  # the Fraction is still there
    with pytest.raises(UnsafeModelError, match="override refused") as exc:
        safe_load(path, accept_unverified=report.unverifiable_items + ["fractions.Fraction"])
    assert exc.value.report.override["accepted"] is False


# --- CLI ---------------------------------------------------------------------------------


@pytest.fixture
def no_tty(monkeypatch):
    monkeypatch.setattr(cli, "_interactive", lambda: False)
    monkeypatch.setattr(cli, "_prompt", lambda report: pytest.fail("prompted without a terminal"))


def _json(capsys) -> dict | list:
    return json.loads(capsys.readouterr().out)


def test_cli_non_interactive_refuses_by_default(no_tty, capsys):
    assert cli.main(["scan", str(H5)]) == cli.EXIT_SUSPICIOUS
    out = capsys.readouterr().out
    assert "[UNVERIFIABLE]" in out and "--accept-unverified" in out


def test_cli_flag_names_items(no_tty, capsys):
    argv = ["scan", str(H5), "--json", "--accept-unverified", "MyDense"]
    assert cli.main(argv) == cli.EXIT_SUSPICIOUS
    assert _json(capsys)["override"]["accepted"] is False
    assert cli.main(argv + ["--accept-unverified", "my_custom_loss"]) == cli.EXIT_CLEAN
    record = _json(capsys)["override"]
    assert record["accepted"] is True and record["how"] == "cli-flag"


def test_cli_prompt_defaults_to_no(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    monkeypatch.setattr("sys.stdin", io.StringIO("\n"))
    assert cli.main(["scan", str(H5)]) == cli.EXIT_SUSPICIOUS
    captured = capsys.readouterr()
    assert "[y/N]" in captured.err and "without its module" in captured.err


def test_cli_prompt_yes_is_recorded(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))
    out = tmp_path / "report.json"
    assert cli.main(["scan", str(H5), "--report", str(out)]) == cli.EXIT_CLEAN
    record = json.loads(out.read_text())["override"]
    assert record["accepted"] is True and record["how"] == "cli-prompt"
    assert record["items"] == ["MyDense", "my_custom_loss"]


def test_cli_no_input_never_prompts(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    monkeypatch.setattr(cli, "_prompt", lambda report: pytest.fail("prompted with --no-input"))
    assert cli.main(["scan", str(H5), "--no-input"]) == cli.EXIT_SUSPICIOUS


def test_cli_scopes_acceptance_to_one_file(no_tty, fraction_a, fraction_b, capsys):
    assert cli.main(["scan", str(fraction_a), str(fraction_b), "--accept-unverified",
                     "fractions.Fraction"]) == cli.EXIT_USAGE
    capsys.readouterr()
    sha_a = scan(fraction_a).sha256
    assert cli.main(["scan", str(fraction_a), str(fraction_b), "--json", "--accept-unverified",
                     f"{sha_a}:fractions.Fraction"]) == cli.EXIT_SUSPICIOUS
    a, b = _json(capsys)
    assert a["override"]["accepted"] is True and b["override"] is None


def test_cli_refuses_override_with_a_risky_reason(no_tty, tmp_path, capsys):
    path = _write(tmp_path, "risky.pkl", P2 + b"(" + FRACTION + b"\x82\x01" + b"l" + STOP)
    assert cli.main(["scan", str(path), "--json", "--accept-unverified", "fractions.Fraction"]) == cli.EXIT_SUSPICIOUS
    assert "RISKY" in _json(capsys)["override"]["refused_because"]
