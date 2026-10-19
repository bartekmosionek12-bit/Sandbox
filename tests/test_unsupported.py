"""UNSUPPORTED: files in no format safeloadai reads get a verdict of their own (Part 5).

It is never CLEAN, never loadable by safe_load, never overridable, and has its own CLI
exit code. Files that parse but look odd stay RISKY (SUSPICIOUS)."""
import pickle
import random

import pytest

from safeloadai import override, safe_load, scan
from safeloadai.__main__ import EXIT_SUSPICIOUS, EXIT_UNSUPPORTED, main
from safeloadai.api import UnsafeModelError
from safeloadai.report import Category, Verdict

# Bytes no supported loader reads: not a pickle opcode at offset 0, no archive, no HDF5.
OPAQUE = bytes([0xFF, 0x13, 0x37]) + random.Random(7).randbytes(4000).replace(b"PK", b"pk")


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


@pytest.mark.parametrize("name", ["openvino_model.bin", "weights.pt", "model.pkl", "empty.bin"])
def test_opaque_bytes_are_unsupported(tmp_path, name):
    report = scan(_write(tmp_path, name, b"" if name == "empty.bin" else OPAQUE))
    assert report.verdict is Verdict.UNSUPPORTED
    assert report.category == Category.UNSUPPORTED
    assert not report.clean and not report.accepted and not report.unverifiable_only
    assert [f["category"] for f in report.findings] == ["UNSUPPORTED"]
    # nothing to emulate is not an emulation failure, and the extension mismatch is implied
    assert not any("no emulator" in r or "does not match its content" in r for r in report.reasons)


def test_unsupported_is_never_loadable(tmp_path):
    path = _write(tmp_path, "openvino_model.bin", OPAQUE)
    with pytest.raises(UnsafeModelError) as info:
        safe_load(path)
    assert info.value.verdict is Verdict.UNSUPPORTED


def test_unsupported_is_never_overridable(tmp_path):
    report = scan(_write(tmp_path, "openvino_model.bin", OPAQUE))
    assert override.apply(report, ["anything"], how="api") is False
    assert not report.accepted


def test_cli_exit_code_is_distinct(tmp_path):
    path = _write(tmp_path, "openvino_model.bin", OPAQUE)
    assert main(["scan", "-q", path]) == EXIT_UNSUPPORTED == 5


def test_cli_suspicious_wins_over_unsupported(tmp_path, fake_emulation):
    opaque = _write(tmp_path, "openvino_model.bin", OPAQUE)
    trailing = _write(tmp_path, "m.pkl", pickle.dumps({"a": 1}) + b"\x00garbage")
    assert main(["scan", "-q", opaque, trailing]) == EXIT_SUSPICIOUS


@pytest.mark.parametrize("data", [
    b"PK\x03\x04garbage",  # looks like an archive the reader refuses: a laxer reader may open it
    b"\x89HDF\r\n\x1a\n" + b"\0" * 40,  # HDF5 superblock that does not parse
], ids=["refused-zip", "broken-hdf5"])
def test_unparseable_known_containers_stay_risky(tmp_path, data):
    report = scan(_write(tmp_path, "model.bin", data))
    assert report.verdict is Verdict.SUSPICIOUS
    assert "UNSUPPORTED" not in {f["category"] for f in report.findings}


def test_parsing_but_odd_files_stay_risky(tmp_path, fake_emulation):
    # a pickle followed by bytes that are not a pickle: it parses, so it is RISKY, not UNSUPPORTED
    report = scan(_write(tmp_path, "m.pkl", pickle.dumps({"a": 1}) + b"\x00garbage"))
    assert report.verdict is Verdict.SUSPICIOUS
    assert report.category == Category.RISKY


def test_pickle_that_calls_before_failing_is_not_unsupported(tmp_path, fake_emulation):
    report = scan(_write(tmp_path, "m.pkl", b"cposix\nsystem\n(S'echo MARKER'\ntR\xff"))
    assert report.verdict is Verdict.MALICIOUS


def test_unsupported_reason_next_to_another_finding_is_risky():
    from safeloadai import verdict
    from safeloadai.static import UNSUPPORTED_REASON

    layer = verdict.static_layer({"static_risk": "unsupported", "reasons": [UNSUPPORTED_REASON, "other"]})
    assert layer.verdict is Verdict.SUSPICIOUS
    assert [f["category"] for f in layer.findings] == ["UNSUPPORTED", "RISKY"]


def test_verdict_order():
    assert Verdict.CLEAN.rank < Verdict.UNSUPPORTED.rank < Verdict.SUSPICIOUS.rank < Verdict.MALICIOUS.rank
