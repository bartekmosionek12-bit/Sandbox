"""0.7.0 Part 2: a torch stream that torch.load(weights_only=True) of the pinned torch
version would accept is CLEAN; anything its unpickler refuses keeps the usual rules."""
from __future__ import annotations

import json
import os

import pytest

from safeloadai.static.pickle_static import parse_pickle
from safeloadai.static.upstream import torch_weights_only as wo

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P2, STOP = b"\x80\x02", b"."


def glob(module: str, name: str) -> bytes:
    return b"c" + module.encode() + b"\n" + name.encode() + b"\n"


def u(text: str) -> bytes:
    raw = text.encode()
    return b"X" + len(raw).to_bytes(4, "little") + raw


INT4 = glob("torch", "int4")  # a torch dtype outside the hand-written TORCH_GLOBALS
STORAGE_PID = b"(" + u("storage") + glob("torch", "FloatStorage") + u("0") + u("cpu") + b"K\x04tQ"
TENSOR = (glob("torch._utils", "_rebuild_tensor_v2") + b"(" + STORAGE_PID + b"K\x00K\x02K\x02\x86K\x02K\x01\x86"
          + b"\x89" + glob("collections", "OrderedDict") + b")RtR")


def torch_stream(body: bytes) -> dict:
    return parse_pickle(P2 + body + STOP, torch=True, file_format="torch")


def test_generated_data_matches_the_pin():
    with open(os.path.join(ROOT, "tools", "upstream_pins.json"), encoding="utf-8") as fh:
        assert wo.TORCH_VERSION == json.load(fh)["distributions"]["torch"]["version"]
    assert "torch._utils._rebuild_tensor_v2" in wo.ALLOWED and "os" in wo.BLOCKED_MODULES
    assert {"GLOBAL", "REDUCE", "BUILD", "BINPERSID"} <= wo.OPCODES and "STACK_GLOBAL" not in wo.OPCODES


def test_weights_only_stream_is_clean():
    report = torch_stream(b"}(" + u("w") + TENSOR + u("dtype") + INT4 + b"u")
    assert report["static_risk"] == "clean", report["reasons"]
    assert report["weights_only"] == "accepted"
    assert {c["item"]: c["mechanism"] for c in report["cleared"]} == {"torch.int4": "torch-weights-only"}


def test_outside_a_torch_reading_the_rule_does_not_apply():
    report = parse_pickle(P2 + b"}(" + u("dtype") + INT4 + b"u" + STOP)
    assert report["static_risk"] != "clean"


@pytest.mark.parametrize("extra, why", [
    (glob("sklearn.linear_model._base", "LinearRegression") + b")\x81", "not a torch weights-only global"),
    (glob("collections", "OrderedDict") + b")R]b", None),  # BUILD on OrderedDict is fine in torch ...
    (glob("torch", "Size") + b")R" + INT4 + b"a", "APPEND"),  # ... APPEND into a non-list is not
    (b"(" + u("module") + u("x") + b"tQ", "persistent id"),
    (glob("builtins", "getattr") + glob("torch", "Size") + u("x") + b"\x86R", "not a torch weights-only global"),
    (b"\x8c\x05torch\x8c\x04int4\x93", "opcodes torch does not implement"),  # protocol 4 STACK_GLOBAL
])
def test_refused_by_weights_only(extra, why):
    report = torch_stream(b"}(" + u("dtype") + INT4 + u("x") + extra + b"u")
    if why is None:
        assert report["weights_only"] == "accepted"
        return
    assert why in report["weights_only"], report["weights_only"]
    assert "torch.int4" not in {c["item"] for c in report["cleared"]}
    assert report["static_risk"] != "clean"


def test_a_sink_stays_malicious():
    report = torch_stream(b"}(" + u("x") + glob("posix", "system") + u("echo MARKER") + b"\x85Ru")
    assert report["static_risk"] == "malicious"
