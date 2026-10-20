"""trust_inert_from / --trust-inert-from: state-only analysis of the INSTALLED version of
named distributions (0.7.0 Part 2). The fake distributions below are only written to
disk and found through importlib.metadata; nothing is imported."""
from __future__ import annotations

import sys

import pytest

from safeloadai import Verdict, scan
from safeloadai.__main__ import main
from safeloadai.options import OptionError
from safeloadai.static import clearance
from safeloadai.static.pickle_static import parse_pickle

P4, STOP = b"\x80\x04", b"."

FAKELIB = {
    "fakelib/__init__.py": "",
    "fakelib/models.py": (
        "from otherlib.base import Reducer\n"
        "from ._native import NativeBase\n"
        "class Plain:\n    x = 1\n"
        "class WithState:\n    def __setstate__(self, state):\n        self.__dict__.update(state)\n"
        "class ChildOfState(WithState):\n    pass\n"
        "class ChildOfReducer(Reducer):\n    pass\n"
        "class ChildOfNative(NativeBase):\n    pass\n"
        "class WithSetter:\n    @property\n    def a(self):\n        return 1\n"
        "    @a.setter\n    def a(self, v):\n        pass\n"
    ),
    "fakelib/noisy.py": "import os\nos.system('echo MARKER')\nclass Plain:\n    pass\n",
    "fakelib/_native.cpython-312-x86_64-linux-gnu.so": "",
}
OTHERLIB = {
    "otherlib/__init__.py": "",
    "otherlib/base.py": ("class Reducer:\n    def __reduce__(self):\n        return (print, ('x',))\n"
                         "class Plain:\n    pass\n"),
}


def _install(root, name: str, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    info = root / f"{name}-1.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n")
    (info / "RECORD").write_text("".join(f"{rel},,\n" for rel in files) + f"{name}-1.0.dist-info/METADATA,,\n")


@pytest.fixture
def fake_dists(tmp_path, monkeypatch):
    _install(tmp_path, "fakelib", FAKELIB)
    _install(tmp_path, "otherlib", OTHERLIB)
    monkeypatch.syspath_prepend(str(tmp_path))
    yield tmp_path
    for name in [m for m in sys.modules if m.split(".")[0] in ("fakelib", "otherlib")]:
        raise AssertionError(f"{name} was imported")


def s(text: str) -> bytes:
    raw = text.encode()
    return b"\x8c" + bytes([len(raw)]) + raw


def rebuilt(module: str, name: str) -> bytes:
    return P4 + s(module) + s(name) + b"\x93)\x81}" + s("x") + b"K\x02sb" + STOP


def check(data: bytes, names: tuple[str, ...]) -> dict:
    with clearance.active(clearance.for_distributions(names)):
        return parse_pickle(data)


def test_plain_class_is_accepted_only_when_its_distribution_is_named(fake_dists):
    data = rebuilt("fakelib.models", "Plain")
    assert parse_pickle(data)["static_risk"] == "suspicious"  # default: unknown package
    report = check(data, ("fakelib",))
    assert report["static_risk"] == "clean", report["reasons"]
    assert report["cleared"][0]["detail"] == "CLEAN by inert-class rule (fakelib 1.0)"
    assert report["cleared"][0]["mechanism"] == "inert-class"


@pytest.mark.parametrize("name", [
    "WithState",  # __setstate__ in the class
    "ChildOfState",  # __setstate__ in a base class
    "ChildOfReducer",  # __reduce__ in a parent from another (named) distribution
    "ChildOfNative",  # a base with no Python source (C extension)
    "WithSetter",  # a property setter
])
def test_classes_with_hooks_or_unreadable_bases_are_not_accepted(fake_dists, name):
    report = check(rebuilt("fakelib.models", name), ("fakelib", "otherlib"))
    assert report["static_risk"] != "clean", report["reasons"]
    assert not report["cleared"]


def test_side_effect_module_is_not_accepted(fake_dists):
    assert check(rebuilt("fakelib.noisy", "Plain"), ("fakelib",))["static_risk"] != "clean"


def test_unnamed_distribution_is_not_accepted(fake_dists):
    assert check(rebuilt("otherlib.base", "Plain"), ("fakelib",))["static_risk"] != "clean"
    assert check(rebuilt("otherlib.base", "Plain"), ("fakelib", "otherlib"))["static_risk"] == "clean"


@pytest.mark.parametrize("body", [
    s("fakelib.models") + s("Plain") + b"\x93)\x81N}" + s("x") + b"K\x02s\x86b",  # slot state: setattr
    s("fakelib.models") + s("Plain") + b"\x93" + s("arg") + b"\x85R",  # REDUCE with arguments
    s("fakelib.models") + s("Plain") + b"\x93)R",  # REDUCE without arguments still runs __init__
    s("fakelib.models") + s("Plain") + b"\x93)\x81}b)R",  # the rebuilt instance is called
])
def test_accepted_class_used_otherwise_stays_flagged(fake_dists, body):
    report = check(P4 + body + STOP, ("fakelib",))
    assert report["static_risk"] != "clean", report["reasons"]


def test_unknown_distribution_is_an_option_error(fake_dists, tmp_path):
    path = tmp_path / "m.pkl"
    path.write_bytes(rebuilt("fakelib.models", "Plain"))
    with pytest.raises(OptionError):
        scan(path, trust_inert_from=["no-such-distribution-xyz"])
    with pytest.raises(OptionError):
        scan(path, trust_inert_from=["fake*"])


@pytest.mark.wasi
def test_scan_records_the_option_and_the_rule(fake_dists, tmp_path, capsys):
    path = tmp_path / "m.pkl"
    path.write_bytes(rebuilt("fakelib.models", "Plain"))
    assert scan(path).verdict is not Verdict.CLEAN
    report = scan(path, trust_inert_from=["fakelib"])
    assert report.verdict is Verdict.CLEAN, report.reasons
    assert report.options == [{"name": "trust_inert_from", "value": ["fakelib"], "source": "argument",
                               "direction": "looser"}]
    assert report.cleared[0]["detail"] == "CLEAN by inert-class rule (fakelib 1.0)"
    assert main(["scan", "--no-input", "--trust-inert-from", "fakelib", str(path)]) == 0
    out, err = capsys.readouterr()
    assert "non-default option trust_inert_from=['fakelib']" in err
    assert "CLEAN by inert-class rule (fakelib 1.0)" in out
