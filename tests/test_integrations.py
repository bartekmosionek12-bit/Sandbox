"""The shipped integrations (GitHub Action, pre-commit hook) stay in step with the CLI."""
import os
import re

import yaml

from safeloadai.parsing.detect import SCAN_EXTENSIONS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _yaml(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_pre_commit_hook_covers_every_supported_extension():
    (hook,) = _yaml(".pre-commit-hooks.yaml")
    pattern = re.compile(hook["files"])
    # what a directory scan picks up (an OpenVINO .xml is checked with its .bin)
    assert all(pattern.search(f"model{ext}") for ext in SCAN_EXTENSIONS)
    assert not pattern.search("notes.txt")
    assert hook["entry"].startswith("safeloadai scan") and "--no-input" in hook["entry"]


def test_action_pins_its_actions_and_never_masks_errors():
    action = _yaml("action.yml")
    assert action["runs"]["using"] == "composite"
    for step in action["runs"]["steps"]:
        if "uses" in step:
            assert re.search(r"@[0-9a-f]{40}$", step["uses"]), step["uses"]
    verdict = next(step for step in action["runs"]["steps"] if step.get("name") == "Verdict")
    # "malicious" lets only SUSPICIOUS (3) and UNSUPPORTED (5) through; ERROR (4, 6) always fails
    assert "malicious) case \"$CODE\" in 0|3|5) exit 0" in verdict["run"]
    scan = next(step for step in action["runs"]["steps"] if step.get("id") == "scan")
    assert "--sarif" in scan["run"] and "--no-input" in scan["run"]


def test_hf_example_refuses_a_moving_revision(capsys):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "hf_example", os.path.join(ROOT, "examples", "huggingface_safe_download.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        module.main(["org/repo", "model.bin", "--revision", "main"])
    except SystemExit as exc:
        assert exc.code == 2
    assert "40-character commit sha" in capsys.readouterr().err
