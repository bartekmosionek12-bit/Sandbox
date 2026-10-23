"""Polyglot files: every reading a loader could make of the bytes is analysed."""
from __future__ import annotations

import pickle

import pytest
from corpus.build_corpus import MALICIOUS, polyglot_payloads

from safeloadai import Verdict, scan
from safeloadai.parsing import views

PAYLOADS = {name: (expected, data) for name, _category, expected, data in polyglot_payloads()}


def _fmts(data: bytes) -> list[tuple[str, int]]:
    return [(v.fmt, v.start) for v in views.find_views(data)]


def test_pickle_then_zip_has_two_readings():
    data = PAYLOADS["poly_pickle_then_torch_zip.pt"][1]
    zip_start = data.index(b"PK\x03\x04")
    assert _fmts(data) == [("pickle", 0), ("torch", zip_start)]
    joblib_zip = PAYLOADS["poly_joblib_zlib_then_zip.joblib"][1]
    joblib_view = views.find_views(joblib_zip)[0]
    assert joblib_view.end == joblib_zip.index(b"PK\x03\x04")  # one compressed stream, then the archive


def test_extension_picks_the_loader_reading():
    data = PAYLOADS["poly_pickle_then_keras.keras"][1]
    found = views.find_views(data)
    assert views.primary_view(found, "model.keras").fmt == "keras"
    assert views.primary_view(found, "model.pkl").fmt == "pickle"
    # torch.load takes the zip branch only for a local header at offset 0.
    assert views.primary_view(views.find_views(PAYLOADS["poly_pickle_then_torch_zip.pt"][1]), "m.pt").fmt == "pickle"
    assert views.primary_view(views.find_views(PAYLOADS["b_torch_zip.pt"][1]), "m.pt").fmt == "torch"


def test_h5_after_user_block_and_compressed_joblib_are_found():
    assert _fmts(PAYLOADS["poly_h5_userblock_pickle.h5"][1]) == [("pickle", 0), ("h5", 512)]
    joblib_zip = PAYLOADS["poly_joblib_zlib_then_zip.joblib"][1]
    assert [f for f, _ in _fmts(joblib_zip)] == ["joblib", "keras"]


@pytest.mark.parametrize("data", [
    pickle.dumps({"a": 1}, protocol=0), pickle.dumps([1, 2], protocol=1), pickle.dumps(None, protocol=5),
    b"N.",
])
def test_plain_pickles_are_one_reading(data):
    assert _fmts(data) == [("pickle", 0)]


@pytest.mark.parametrize("data", [b"\x89HDF\r\n\x1a\n" + b"\0" * 40, b"PK\x03\x04garbage", b"(garbage\xff", b""])
def test_non_pickles_are_no_pickle_reading(data):
    assert not views.pickle_at_start(data)


def test_a_pickle_that_calls_before_failing_is_a_reading():
    # pickle.load runs REDUCE before it reaches the broken byte: that reading must exist.
    assert views.pickle_at_start(b"cposix\nsystem\n(S'echo MARKER'\ntR\xff")


@pytest.mark.wasi
@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_polyglot_corpus(tmp_path, name):
    expected, data = PAYLOADS[name]
    path = tmp_path / name
    path.write_bytes(data)
    report = scan(path)
    assert report.verdict is Verdict(expected), report.reasons
    if expected == MALICIOUS:
        assert not report.unverifiable_only


@pytest.mark.wasi
def test_unexplained_bytes_before_an_archive_are_risky(tmp_path):
    data = b"\xffJUNK" * 20 + PAYLOADS["b_torch_zip.pt"][1]
    path = tmp_path / "junk_then_zip.pt"
    path.write_bytes(data)
    report = scan(path)
    assert report.verdict is Verdict.SUSPICIOUS
    assert report.category == "RISKY"
    assert any("before the first ZIP entry" in r for r in report.reasons), report.reasons


@pytest.mark.parametrize("data", [
    # No PROTO header, first opcode SHORT_BINUNICODE / FRAME / BINUNICODE8: pickle.load accepts all of them.
    b"\x8c\x05posix\x8c\x06system\x93(\x8c\x0becho MARKERtR.",
    b"\x95\x05\x00\x00\x00\x00\x00\x00\x00N.",
    b"\x8d\x01\x00\x00\x00\x00\x00\x00\x00a0N.",
])
def test_headerless_pickles_with_newer_opcodes_are_a_reading(data):
    assert views.pickle_at_start(data)


@pytest.mark.wasi
def test_headerless_short_binunicode_pickle_is_malicious(tmp_path):
    path = tmp_path / "m.pkl"
    path.write_bytes(b"\x8c\x05posix\x8c\x06system\x93(\x8c\x0becho MARKERtR.")
    assert scan(path).verdict is Verdict.MALICIOUS


# --- a pickle reading ends at its STOP (owner's rule, 2026-10-19) --------------------------

EVIL = b"\x80\x02cposix\nsystem\n(X\x0b\x00\x00\x00echo MARKERtR."


@pytest.mark.wasi
def test_pickle_then_benign_zip_reports_the_sink_first(tmp_path):
    zip_part = PAYLOADS["b_torch_zip.pt"][1]
    data = EVIL + zip_part
    path = tmp_path / "evil_then_zip.pt"
    path.write_bytes(data)
    report = scan(path)
    assert report.verdict is Verdict.MALICIOUS
    assert "known sink" in report.reasons[0], report.reasons
    assert report.findings[0]["category"] == "MALICIOUS"
    # the zip is trailing data of the pickle reading, not a walker error
    static = report.layer("static").details
    assert static["error"] is None
    assert static["trailing"]["start"] == len(EVIL)
    pickle_view = next(v for v in static["views"] if v["format"] == "pickle")
    assert pickle_view["end"] == len(EVIL)
    assert not any("pickle is not readable" in r for r in report.reasons), report.reasons


@pytest.mark.wasi
def test_benign_pickle_then_evil_pickle_is_a_second_reading(tmp_path):
    benign = pickle.dumps({"a": 1}, protocol=2)
    path = tmp_path / "two.pkl"
    path.write_bytes(benign + EVIL)
    report = scan(path)
    assert report.verdict is Verdict.MALICIOUS
    assert "known sink" in report.reasons[0], report.reasons
    assert any(layer.name == f"static[pickle@{len(benign)}]" for layer in report.layers)


def test_trailing_garbage_is_risky_not_a_walker_error():
    from safeloadai.static.pickle_static import parse_pickle

    report = parse_pickle(pickle.dumps([1, 2], protocol=2) + b"\xff\xfe junk", trailing="view")
    assert report["error"] is None
    assert report["static_risk"] == "suspicious"
    assert any("trailing data" in r for r in report["reasons"])


def test_trailing_pickle_inside_a_container_is_analysed():
    from safeloadai.static.pickle_static import parse_pickle

    report = parse_pickle(pickle.dumps([1, 2], protocol=2) + EVIL)
    assert report["static_risk"] == "malicious"
    assert any(r.startswith("trailing data at offset") and "known sink" in r for r in report["reasons"])


def _benign_zip() -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("notes.txt", "hello")
    return buf.getvalue()


def _texts(report, category):
    return [f["text"] for f in report.findings if f["category"] == category]


@pytest.mark.wasi
def test_benign_pickle_plus_benign_zip_is_risky_not_malicious(tmp_path):
    path = tmp_path / "poly.pkl"
    path.write_bytes(pickle.dumps({"a": 1}, protocol=2) + _benign_zip())
    report = scan(path)
    assert report.verdict is Verdict.SUSPICIOUS and report.category == "RISKY", report.reasons
    assert any("more than one format" in t for t in _texts(report, "RISKY"))
    assert any("trailing data" in t for t in _texts(report, "RISKY"))
    assert not _texts(report, "MALICIOUS")


@pytest.mark.wasi
def test_polyglot_with_a_sink_is_malicious_from_the_sink_evidence(tmp_path):
    from corpus.build_corpus import MARKER_CMD, P2, STOP, call, g, s

    path = tmp_path / "poly.pkl"
    path.write_bytes(P2 + call(g("posix", "system"), s(MARKER_CMD)) + STOP + _benign_zip())
    report = scan(path)
    assert report.verdict is Verdict.MALICIOUS
    malicious = _texts(report, "MALICIOUS")
    assert malicious and all("posix.system" in t for t in malicious), malicious
    # the polyglot itself is no evidence: it stays a RISKY finding next to the sink
    assert any("more than one format" in t for t in _texts(report, "RISKY"))
    assert any("trailing data" in t for t in _texts(report, "RISKY"))
