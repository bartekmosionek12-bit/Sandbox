"""Sandbox host logic that needs no WASI runtime."""
from __future__ import annotations

import pytest

from safeloadai.sandbox import run_guest, runtime
from safeloadai.sandbox.host import validate_records


def test_validate_rejects_gaps_and_duplicates():
    nonce = "ab" * 16
    rec = lambda seq, kind: b"SLAI1 " + nonce.encode() + b" " + (  # noqa: E731
        b'{"kind": "%s", "seq": %d}' % (kind.encode(), seq))
    events, problems, tampered, completed = validate_records([rec(0, "start"), rec(2, "done")], nonce)
    assert not completed and not tampered
    events, problems, tampered, completed = validate_records(
        [rec(0, "start"), rec(1, "done"), rec(2, "done")], nonce)
    assert not completed


def test_runtime_hash_mismatch_is_refused(tmp_path, monkeypatch):
    fake = tmp_path / "python.wasm"
    fake.write_bytes(b"\0asm not the pinned runtime")
    monkeypatch.setenv(runtime.RUNTIME_ENV, str(fake))
    with pytest.raises(runtime.RuntimeUnavailable, match="sha256"):
        runtime.locate()


def test_missing_runtime_is_reported_not_faked(tmp_path, monkeypatch):
    monkeypatch.delenv(runtime.RUNTIME_ENV, raising=False)
    monkeypatch.setenv(runtime.HOME_ENV, str(tmp_path))
    run = run_guest({"kind": "selftest"}, {})
    assert run.status == "unavailable" and not run.completed
