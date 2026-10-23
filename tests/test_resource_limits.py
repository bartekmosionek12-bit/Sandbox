"""The scanner's own availability: a file that asks for more host memory than a scan may
hold ends in a tool error (E105), never in a crash of the process (docs/THREAT_MODEL.md)."""
from __future__ import annotations

import pickle
import struct
import time
import tracemalloc

import pytest
from corpus.build_corpus import P2, STOP

from safeloadai import scan
from safeloadai import static as static_mod
from safeloadai.static import budget, pickle_static


def _bytes_flood(count: int, size: int) -> bytes:
    """A synthetic pickle that pushes ``count`` distinct byte strings of ``size`` bytes onto
    one list: everything it builds stays alive until STOP."""
    body = bytearray(P2 + b"]" + b"(")
    for i in range(count):
        chunk = i.to_bytes(4, "little") * (size // 4)
        body += b"B" + struct.pack("<I", len(chunk)) + chunk
    return bytes(body + b"e" + STOP)


def test_budget_charges_and_runs_out():
    b = budget.Budget(100)
    b.charge(60)
    with pytest.raises(budget.ResourceLimit, match="host memory"):
        b.charge(41)


def test_limit_grows_with_the_file_and_has_a_ceiling():
    assert budget.limit_for(0) == budget.BASE_BYTES
    assert budget.limit_for(10 << 20) == budget.BASE_BYTES + (20 << 20)
    assert budget.limit_for(1 << 40) == budget.MAX_HOST_BYTES


def test_ordinary_pickle_stays_within_the_budget():
    report = static_mod.analyze_bytes(pickle.dumps({"weights": list(range(1000))}), "m.pkl")
    assert not report["tool_errors"], report["tool_errors"]


def test_memory_exhaustion_is_a_resource_limit_error(tmp_path, monkeypatch, fake_emulation):
    # 64 KiB of budget for a pickle that holds 400 KiB of byte strings at once.
    monkeypatch.setattr(budget, "BASE_BYTES", 64 << 10)
    monkeypatch.setattr(budget, "limit_for", lambda size: budget.BASE_BYTES)
    path = tmp_path / "flood.pkl"
    path.write_bytes(_bytes_flood(100, 4096))
    report = scan(path)
    assert report.status == "error" and report.verdict is None and not report.clean
    assert report.error["code"] == "E105", report.error
    assert "host memory" in report.error["message"]


def test_resource_limit_in_static_analysis_does_not_escape(monkeypatch):
    def boom(*args, **kwargs):
        raise MemoryError

    monkeypatch.setattr(static_mod, "_analyze_bytes", boom)
    report = static_mod.analyze_bytes(pickle.dumps([1, 2, 3]), "m.pkl")
    assert [e["code"] for e in report["tool_errors"]] == ["E105"]
    assert report["static_risk"] == "suspicious"


def test_large_pickle_is_walked_in_memory_bounded_by_its_size():
    """The 0.8.0 held-out run met a 211 MB pickle that took more than 13 GB of host memory:
    the listing for the dashboard and one record per opcode grew with the file. Both are
    bounded now; a pickle of many small opcodes stays within a small multiple of its size."""
    data = pickle.dumps([i * 7 for i in range(400_000)], protocol=2)
    tracemalloc.start()
    t = time.perf_counter()
    try:
        report = static_mod.analyze_bytes(data, "big.pkl")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert time.perf_counter() - t < 120
    assert not report["tool_errors"], report["tool_errors"]
    assert len(report["opcodes"]) <= pickle_static.MAX_OPCODE_RECORDS
    assert peak < (64 << 20) + 20 * len(data), (peak, len(data))


def test_listing_of_a_large_pickle_is_capped_while_written():
    data = pickle.dumps(list(range(300_000)), protocol=2)
    tracemalloc.start()
    try:
        listing = pickle_static._disasm(data)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(listing) <= pickle_static.MAX_DISASM_CHARS
    assert peak < 20 * pickle_static.MAX_DISASM_CHARS, peak


def test_opcode_records_are_bounded_but_every_opcode_is_counted(monkeypatch):
    monkeypatch.setattr(pickle_static, "MAX_OPCODE_RECORDS", 50)
    report = pickle_static.parse_pickle(pickle.dumps(list(range(500)), protocol=2), "m.pkl")
    assert len(report["opcodes"]) == 50
    assert sum(report["opcode_counts"].values()) > 50


def test_memory_error_in_the_walker_is_a_resource_limit_not_a_walker_bug(monkeypatch):
    from safeloadai.static import pickle_vm

    def boom(self, *args, **kwargs):
        raise MemoryError

    monkeypatch.setattr(pickle_vm.Machine, "run_one", boom)
    report = static_mod.analyze_bytes(pickle.dumps([1, 2, 3]), "m.pkl")
    assert [e["code"] for e in report["tool_errors"]] == ["E105"]
    assert "no pickle found" not in report["reasons"]
