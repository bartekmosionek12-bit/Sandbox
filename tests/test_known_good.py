"""0.7.0 Part 4: reviewed benign files by exact sha256 (tune split only)."""
from __future__ import annotations

import hashlib
import os
import pickle
from fractions import Fraction

import pytest

from safeloadai import api, known_good
from safeloadai.pipeline import scan
from safeloadai.report import Verdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UNKNOWN = pickle.dumps(Fraction(1, 3), protocol=2)  # fractions.Fraction: outside the allowlist
SINK = b"\x80\x02cposix\nsystem\nX\x0b\x00\x00\x00echo MARKER\x85R."


@pytest.fixture
def listed(monkeypatch):
    """Put the given bytes' sha256 on the list for the duration of a test."""
    table: dict[str, dict] = {}

    def add(data: bytes, repo="org/model", file="model.pkl"):
        sha = hashlib.sha256(data).hexdigest()
        table[sha] = {"sha256": sha, "repo": repo, "revision": "0" * 40, "file": file, "note": "test entry"}

    monkeypatch.setattr(known_good, "entries", lambda: table)
    return add


def write(tmp_path, data: bytes, name="model.pkl"):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_listed_file_is_clean_with_the_reason(tmp_path, listed, fake_emulation):
    listed(UNKNOWN)
    report = scan(write(tmp_path, UNKNOWN))
    assert report.verdict is Verdict.CLEAN
    assert report.reasons == ["known reviewed file org/model/model.pkl"]
    entry = report.cleared[-1]
    assert entry["mechanism"] == "known-file" and entry["pairs"] == [["fractions", "Fraction"]]
    assert entry["category"] == "UNVERIFIABLE"  # what it was without the list


def test_one_byte_different_gets_no_benefit(tmp_path, listed, fake_emulation):
    listed(UNKNOWN)
    changed = UNKNOWN[:-2] + bytes([UNKNOWN[-2] ^ 1]) + UNKNOWN[-1:]  # the memo index byte
    report = scan(write(tmp_path, changed))
    assert report.verdict is not Verdict.CLEAN
    assert not [c for c in report.cleared if c["mechanism"] == "known-file"]


def test_malicious_is_never_cleared(tmp_path, listed, fake_emulation):
    listed(SINK)
    assert scan(write(tmp_path, SINK)).verdict is Verdict.MALICIOUS


def test_unsupported_is_never_cleared(tmp_path, listed, fake_emulation):
    data = b"\x00\x01OpenVINO-ish weights" * 8
    listed(data)
    assert scan(write(tmp_path, data, "model.bin")).verdict is Verdict.UNSUPPORTED


def test_turned_off_is_recorded_and_clears_nothing(tmp_path, listed, fake_emulation):
    listed(UNKNOWN)
    report = scan(write(tmp_path, UNKNOWN), known_good=False)
    assert report.verdict is Verdict.SUSPICIOUS
    assert [o["name"] for o in report.options] == ["known_good"]
    assert report.options[0]["direction"] == "stricter"


def test_safe_load_resolves_the_listed_files_pairs(tmp_path, listed, fake_emulation):
    listed(UNKNOWN)
    assert api.safe_load(write(tmp_path, UNKNOWN)) == Fraction(1, 3)
    with pytest.raises(api.UnsafeModelError):
        api.safe_load(write(tmp_path, UNKNOWN, "other.pkl"), known_good=False)


# --- the shipped list -------------------------------------------------------------------

def _rows(path):
    with open(path, encoding="utf-8") as fh:
        return [line for line in fh if line.strip() and not line.startswith("#")]


def test_shipped_list_equals_the_reviewed_evaluation_list():
    with open(os.path.join(ROOT, "evaluation", "known_good", "known_good.tsv"), encoding="utf-8") as fh:
        reviewed = fh.read()
    with open(known_good.PATH, encoding="utf-8") as fh:
        assert fh.read() == reviewed


def test_shipped_list_holds_tune_files_only():
    with open(os.path.join(ROOT, "evaluation", "splits", "hf-tune.txt"), encoding="utf-8") as fh:
        tune = {line.strip() for line in fh if line.strip() and not line.startswith("#")}
    entries = known_good.entries()
    assert len(entries) == len(_rows(known_good.PATH))  # no duplicate sha256
    for entry in entries.values():
        assert entry["repo"] in tune, entry
        assert len(entry["revision"]) == 40 and entry["note"].strip(), entry
