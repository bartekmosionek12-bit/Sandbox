"""trust_inert_from / --trust-inert-from: state-only analysis of the INSTALLED version of
named distributions (0.7.0 Part 2). The fake distributions below are only written to
disk and found through importlib.metadata; nothing is imported."""
from __future__ import annotations

import sys

import pytest

from safeloadai import Verdict, scan
from safeloadai.__main__ import main
from safeloadai.options import OptionError, validate_trust_inert_from
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
    for names in (["no-such-distribution-xyz"], ["fake*"]):
        with pytest.raises(OptionError):
            validate_trust_inert_from(names)
        report = scan(path, trust_inert_from=names)
        assert report.status == "error" and report.error["code"] == "E501" and not report.clean


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



def test_owner_excluded_classes_stay_out_of_the_installed_analysis(fake_dists, monkeypatch):
    # FunctionTransformer is state-only by its source, but decision A1 keeps it out; naming
    # its distribution must not bring it back (static/upstream policies.json "excluded").
    from safeloadai.static import upstream

    assert upstream.excluded(("sklearn.preprocessing._function_transformer", "FunctionTransformer"))
    monkeypatch.setattr(upstream, "excluded", lambda pair: "test" if pair == ("fakelib.models", "Plain") else None)
    report = check(rebuilt("fakelib.models", "Plain"), ("fakelib",))
    assert report["static_risk"] != "clean" and not report["cleared"]


@pytest.mark.wasi
def test_option_changes_the_verdict_on_a_lab_file_from_a_real_installed_package(tmp_path):
    # threadpoolctl is installed with scikit-learn (a test dependency) and is not among the
    # pinned distributions, so by default its classes are outside the allowlist. A lab
    # pickle that rebuilds its state-only ThreadpoolController from a dict state:
    pytest.importorskip("threadpoolctl")  # the installed metadata is what is read; the module is not used
    path = tmp_path / "lab_threadpoolctl.pkl"
    path.write_bytes(rebuilt("threadpoolctl", "ThreadpoolController"))
    default = scan(path)
    assert default.verdict is Verdict.SUSPICIOUS and default.category == "UNVERIFIABLE", default.reasons
    trusted = scan(path, trust_inert_from=["threadpoolctl"])
    assert trusted.verdict is Verdict.CLEAN, trusted.reasons
    assert trusted.cleared[0]["mechanism"] == "inert-class"
    assert trusted.cleared[0]["detail"].startswith("CLEAN by inert-class rule (threadpoolctl ")
    # naming another distribution does not clear it
    assert scan(path, trust_inert_from=["scikit-learn"]).verdict is Verdict.SUSPICIOUS


@pytest.mark.wasi
def test_option_never_clears_a_hook_class_or_a_sink(tmp_path):
    # a class of an installed package built on a C type (ctypes.Structure) stays out, and a
    # sink stays MALICIOUS
    pytest.importorskip("threadpoolctl")
    path = tmp_path / "lab_ctypes.pkl"
    path.write_bytes(rebuilt("threadpoolctl", "_dl_phdr_info"))
    assert scan(path, trust_inert_from=["threadpoolctl"]).verdict is not Verdict.CLEAN
    sink = tmp_path / "lab_sink.pkl"
    sink.write_bytes(P4 + s("posix") + s("system") + b"\x93" + s("echo MARKER") + b"\x85R" + STOP)
    assert scan(sink, trust_inert_from=["threadpoolctl"]).verdict is Verdict.MALICIOUS


# --- 0.11.0: the option only adds (DECISIONS.md T1, T2) ----------------------------------

@pytest.mark.parametrize("pair", [
    ("sklearn.utils.parallel", "Parallel"),  # a base (joblib.Parallel) outside the named distribution
    ("sklearn.ensemble.forest", "RandomForestClassifier"),  # an old module path (historical_paths.json)
    ("sklearn.tree.tree", "DecisionTreeClassifier"),
])
def test_naming_a_distribution_never_removes_a_pinned_policy_class(pair):
    # Until 0.11.0 the installed analysis replaced the pinned policies for a named
    # distribution, so these, CLEAN by default, were UNVERIFIABLE with the "looser" option:
    # it cannot read joblib's source, and an old module path does not exist in the
    # installed release. The evaluation never scanned a file CLEAN by default again, which
    # hid it. Named or not, a pinned policy class stays accepted.
    pytest.importorskip("sklearn")  # its installed metadata is read; nothing is imported
    from safeloadai.static import upstream

    assert upstream.state_only(pair), pair
    data = rebuilt(*pair)
    assert parse_pickle(data)["static_risk"] == "clean"
    report = check(data, ("scikit-learn",))
    assert report["static_risk"] == "clean", report["reasons"]
    assert report["cleared"][0]["mechanism"] == "policy"


def test_every_pinned_policy_class_of_a_named_distribution_stays_accepted():
    pytest.importorskip("sklearn")
    from safeloadai.static import upstream

    trust = clearance.for_distributions(("scikit-learn",))
    pinned = [pair for pair, entry in upstream._state_only().items() if entry["distribution"] == "scikit-learn"]
    old = [pair for pair in upstream._historical() if upstream.state_only(pair)
           and upstream.state_only(pair)["distribution"] == "scikit-learn"]
    assert len(pinned) > 400 and len(old) > 200
    lost = [pair for pair in pinned + old if trust.state_only(pair) is None]
    assert not lost, lost[:5]


def test_installed_analysis_still_adds_a_class_the_pins_lack(fake_dists):
    # the other half: a state-only class outside the pinned policies is what the option is for
    report = check(rebuilt("fakelib.models", "Plain"), ("fakelib",))
    assert report["static_risk"] == "clean" and report["cleared"][0]["mechanism"] == "inert-class"


def test_a_hook_in_the_installed_version_still_removes_a_pinned_class(fake_dists, monkeypatch):
    # What the option keeps from replacing: when the installed source gives a pinned class
    # code of its own that runs on load (here __setstate__, as if a newer release added it),
    # the class is not state-only for that scan. Only a hook does this, never a limit of the
    # installed analysis (an old path it lacks, a base it cannot read).
    from safeloadai.static import upstream

    real = upstream.state_only
    pinned = {("fakelib.models", "WithState"), ("fakelib.models", "ChildOfNative")}
    monkeypatch.setattr(upstream, "state_only",
                        lambda pair: {"distribution": "fakelib"} if pair in pinned else real(pair))
    monkeypatch.setattr(upstream, "label", lambda dist: dist)
    hooked = rebuilt("fakelib.models", "WithState")
    assert parse_pickle(hooked)["static_risk"] == "clean"  # the pinned policy, option off
    report = check(hooked, ("fakelib",))
    assert report["static_risk"] != "clean" and not report["cleared"]
    native = check(rebuilt("fakelib.models", "ChildOfNative"), ("fakelib",))
    assert native["static_risk"] == "clean" and native["cleared"][0]["mechanism"] == "policy"
