"""Secure defaults and option records (owner's rule of 2026-10-19, docs/OPTIONS.md)."""
from __future__ import annotations

import inspect
import json
import pickle

import pytest

from safeloadai import api, options, pipeline
from safeloadai.__main__ import _build_parser, main
from safeloadai.sandbox.host import Limits

UNKNOWN = b"\x80\x02cmypkg.models\nNet\n)\x81}b."  # one global outside the allowlist


def _clean(tmp_path, name="m.pkl"):
    path = tmp_path / name
    path.write_bytes(pickle.dumps({"a": 1}))
    return str(path)


# --- every default is the safe one -------------------------------------------------------

SAFE_API_DEFAULTS = {"judge": False, "deep": False, "allow": (), "limits": None, "progress": None,
                     "option_sources": None, "accept_unverified": None,
                     # off: no installed distribution is trusted; on: the shipped reviewed-hash list
                     # (turning it off is the stricter setting, docs/OPTIONS.md)
                     "trust_inert_from": (), "known_good": True}


@pytest.mark.parametrize("func", [pipeline.scan, api.safe_load])
def test_every_api_option_defaults_to_the_safe_value(func):
    params = {n: p.default for n, p in inspect.signature(func).parameters.items()
              if p.kind is inspect.Parameter.KEYWORD_ONLY}
    assert params, func
    for name, default in params.items():
        assert name in SAFE_API_DEFAULTS, f"new option {name} needs a safe default and docs/OPTIONS.md"
        assert default == SAFE_API_DEFAULTS[name], name


def test_every_cli_option_defaults_to_the_safe_value():
    args = _build_parser().parse_args(["scan", "x.pkl"])
    assert args.allow == [] and args.accept_unverified == [] and args.trust_inert_from == []
    assert args.no_known_good is False
    assert args.judge is False and args.deep is False
    assert args.config is None  # no config file is read unless named
    assert args.no_input is False  # the prompt's default answer is No (test_override)


def test_registry_defaults_are_safe_and_looser_options_never_come_from_the_environment():
    for option in options.OPTIONS:
        if option.direction == "looser":
            assert option.env is None, option.name
            assert not option.default, option.name
    assert options.BY_NAME["deep"].default is False and options.BY_NAME["judge"].default is False
    assert options.is_default("limits", Limits()) and options.is_default("limits", None)


def test_every_option_is_documented():
    import pathlib

    doc = (pathlib.Path(__file__).parent.parent / "docs" / "OPTIONS.md").read_text()
    for option in options.OPTIONS:
        assert f"## `{option.name}`" in doc, option.name
        section = doc.split(f"## `{option.name}`", 1)[1].split("\n## ", 1)[0]
        for heading in ("What it does", "Risk you accept", "When to use it", "How to use it",
                        "How to check it in the report", "Safer alternative"):
            assert heading in section, (option.name, heading)


def test_plain_scan_records_no_options(tmp_path, fake_emulation):
    report = pipeline.scan(_clean(tmp_path))
    assert report.options == []
    assert report.to_dict()["options"] == []


# --- options are explicit and narrow -----------------------------------------------------

@pytest.mark.parametrize("pair", [("builtins", "exec"), ("posix", "system"), ("os", "system"),
                                  ("builtins", "getattr"), ("functools", "partial"), ("*", "*"),
                                  ("mypkg", "*"), ("", "x"), ("subprocess", "Popen")])
def test_allow_refuses_sinks_gadgets_and_wildcards(pair, tmp_path, fake_emulation):
    with pytest.raises(options.OptionError):
        pipeline.scan(_clean(tmp_path), allow=[pair])


def test_no_allow_all_switch_exists():
    flags = {a for action in _build_parser()._subparsers._group_actions[0].choices["scan"]._actions
             for a in action.option_strings}
    words = {"all", "disable", "skip", "unsafe", "trust", "insecure", "everything", "any"}
    # --trust-inert-from is the owner's name for an option that names exact distributions
    # (DECISIONS F6); it is no blanket switch
    flags -= {"--trust-inert-from"}
    assert not any(words & set(flag.strip("-").split("-")) for flag in flags), flags


# --- non-default options are recorded and announced --------------------------------------

def test_allow_is_recorded_with_its_source(tmp_path, fake_emulation):
    path = tmp_path / "u.pkl"
    path.write_bytes(UNKNOWN)
    report = pipeline.scan(str(path), allow=[("mypkg.models", "Net")])
    assert report.options == [{"name": "allow", "value": ["mypkg.models:Net"], "source": "argument",
                               "direction": "looser"}]


def test_safe_load_records_accept_unverified(tmp_path, fake_emulation):
    from safeloadai import override

    path = tmp_path / "u.pkl"
    path.write_bytes(UNKNOWN)
    report = pipeline.scan(str(path))
    override.apply(report, ["mypkg.models.Net"], how="api")
    assert {"name": "accept_unverified", "value": ["mypkg.models.Net"], "source": "argument",
            "direction": "looser"} in report.options


def test_cli_warns_and_marks_the_verdict_line(tmp_path, fake_emulation, capsys):
    assert main(["scan", _clean(tmp_path), "--allow", "mypkg.models:Net"]) == 0
    out, err = capsys.readouterr()
    assert "warning: non-default option allow=['mypkg.models:Net'] (from CLI flag --allow" in err
    assert out.startswith("CLEAN (with options: allow)")


def test_cli_plain_scan_prints_no_warning(tmp_path, fake_emulation, capsys):
    assert main(["scan", _clean(tmp_path)]) == 0
    out, err = capsys.readouterr()
    assert err == ""
    assert out.startswith("CLEAN ") and "with options" not in out


def test_config_file_is_used_only_when_named(tmp_path, fake_emulation, capsys, monkeypatch):
    config = tmp_path / "safeloadai.toml"
    config.write_text('[scan]\nallow = ["mypkg.models:Net"]\n')
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "u.pkl"
    target.write_bytes(UNKNOWN)
    assert main(["scan", "--json", str(target)]) == 3  # sitting in the directory: not read
    assert json.loads(capsys.readouterr().out)["options"] == []
    assert main(["scan", "--json", "--config", str(config), str(target)]) == 0
    out, err = capsys.readouterr()
    assert f"reading options from config file {config}" in err
    assert f"(from config file {config}" in err
    assert json.loads(out)["options"] == [{"name": "allow", "value": ["mypkg.models:Net"],
                                           "source": f"config file {config}", "direction": "looser"}]


def test_config_file_accept_unverified_is_recorded(tmp_path, fake_emulation, capsys):
    target = tmp_path / "u.pkl"
    target.write_bytes(UNKNOWN)
    config = tmp_path / "c.toml"
    config.write_text('[scan]\naccept_unverified = ["mypkg.models.Net"]\n')
    assert main(["scan", "--json", "--config", str(config), str(target)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["override"]["accepted"] is True and data["override"]["how"] == "config"
    assert data["options"][0]["source"] == f"config file {config}"


@pytest.mark.parametrize("text", ['[scan]\nallow_all = true\n', '[scan]\ndeep = "yes"\n', '[other]\nx = 1\n',
                                  '[scan]\nallow = ["builtins:exec"]\n'])
def test_bad_config_is_a_usage_error(tmp_path, text, fake_emulation):
    config = tmp_path / "c.toml"
    config.write_text(text)
    assert main(["scan", "--config", str(config), _clean(tmp_path)]) == 2


def test_environment_never_enables_a_looser_option(tmp_path, fake_emulation, monkeypatch):
    for option in options.OPTIONS:
        if option.env:
            monkeypatch.setenv(option.env, "x")
    for name in ("SAFELOADAI_ALLOW", "SAFELOADAI_ACCEPT_UNVERIFIED", "SAFELOADAI_DEEP", "SAFELOADAI_JUDGE"):
        monkeypatch.setenv(name, "1")
    monkeypatch.delenv("SAFELOADAI_WASI_PYTHON")  # a bogus runtime path would refuse the scan
    path = tmp_path / "u.pkl"
    path.write_bytes(UNKNOWN)
    report = pipeline.scan(str(path))
    assert report.verdict.value == "SUSPICIOUS"
    assert [o["name"] for o in report.options] == []  # deep/judge are off, so their env settings do not apply


def test_options_command_prints_table_and_found_config(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "safeloadai.toml").write_text("[scan]\ndeep = true\n")
    assert main(["options"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0].split() == ["option", "default", "stricter", "or", "looser", "risk"]
    for option in options.OPTIONS:
        assert option.name in out
    assert "It is NOT used" in out
