"""Python 3 pickles int, str and range at protocol 0-2 under their Python 2 names
(held-out-4 review, 0.11.1: a benign pyannote checkpoint was MALICIOUS for it)."""
from __future__ import annotations

import _compat_pickle
import pickle

import pytest

from safeloadai.static.pickle_static import parse_pickle


@pytest.mark.parametrize("value", [int, str, range, {"key_type": int, "element_type": str}])
@pytest.mark.parametrize("protocol", [0, 1, 2])
def test_types_written_under_python2_names_are_clean(value, protocol):
    data = pickle.dumps(value, protocol=protocol)
    assert b"__builtin__" in data
    for name in (b"long", b"unicode", b"xrange"):  # the real Unpickler maps them back (fix_imports)
        if b"__builtin__\n" + name in data:
            assert _compat_pickle.NAME_MAPPING[("__builtin__", name.decode())][0] == "builtins"
    report = parse_pickle(data)
    assert report["static_risk"] == "clean", report["reasons"]


@pytest.mark.parametrize("name", ["reduce", "intern", "eval", "exec", "getattr", "__import__", "open"])
def test_other_python2_builtin_names_stay_flagged(name):
    data = b"\x80\x02c__builtin__\n" + name.encode() + b"\nq\x00."
    assert parse_pickle(data)["static_risk"] != "clean"


def test_a_python2_type_name_does_not_launder_a_sink():
    # int(...) is harmless; the eval next to it is still a sink
    data = (b"\x80\x02c__builtin__\nlong\nq\x00c__builtin__\neval\nq\x01X\x01\x00\x00\x001q\x02\x85q\x03Rq\x04"
            b"\x86q\x05.")
    report = parse_pickle(data)
    assert report["static_risk"] == "malicious", report["reasons"]
