"""Old module paths of reviewed classes (0.9.0, static/upstream/historical_paths.json).

An old path is accepted only under the rule of the class it became, and only as the exact
pair the generator found in an older release; anything else stays flagged.
Nothing here is loaded: every stream is assembled opcode by opcode and only scanned.
"""
from __future__ import annotations

import pytest
from corpus.build_corpus import MARKER_CMD, call, g, s, tup

from safeloadai.static import allowlists, upstream
from safeloadai.static.pickle_static import parse_pickle

P2, STOP = b"\x80\x02", b"."
EMPTY_TUPLE, EMPTY_DICT, NEWOBJ, BUILD = b")", b"}", b"\x81", b"b"
DATA = upstream._load("historical_paths.json")
PATHS = {tuple(k.split(":", 1)): v for k, v in DATA["paths"].items()}
POLICY_ALIASES = sorted(p for p, v in PATHS.items() if v["form"] == "policy")


def _rebuilt(pair, state: bytes = EMPTY_DICT + b"(" + s("n_estimators") + b"K\x05u") -> bytes:
    return P2 + g(*pair) + EMPTY_TUPLE + NEWOBJ + state + BUILD + STOP


def _risk(data: bytes):
    report = parse_pickle(data)
    return report["static_risk"], report["reasons"], report.get("cleared") or []


def test_generated_file_is_consistent():
    forms = {**{tuple(k.split(":", 1)): "policy" for k in upstream._load("policies.json")["state_only"]}}
    for pair, entry in PATHS.items():
        current = tuple(entry["current"].split(":", 1))
        assert pair != current and entry["versions"], pair
        assert pair not in forms, f"{pair} is a reviewed pair of its own"
        if entry["form"] == "policy":
            assert current in forms, f"{pair}: {current} is not a policy class"
            assert pair[1] == current[1]  # the same class: only its module path changed
        elif entry["form"] == "state-only":
            # an allowlisted class's old path is accepted only in the stricter state-only form
            assert current in allowlists.STATE_ONLY_CLASSES or current in allowlists.PICKLE_GLOBALS
        elif entry["form"] == "allowlist":
            assert current in allowlists.PICKLE_GLOBALS
        assert not upstream.excluded(current)


@pytest.mark.skipif(not POLICY_ALIASES, reason="no policy aliases generated")
def test_policy_alias_rebuilt_from_state_is_clean():
    pair = next((p for p in POLICY_ALIASES if p == ("sklearn.ensemble.forest", "RandomForestClassifier")),
                POLICY_ALIASES[0])
    risk, reasons, cleared = _risk(_rebuilt(pair))
    assert risk == "clean", reasons
    assert any("old module path of" in c["detail"] for c in cleared)


@pytest.mark.parametrize("pair", POLICY_ALIASES[:40])
def test_policy_alias_called_with_arguments_is_refused(pair):
    data = P2 + g(*pair) + tup(s(MARKER_CMD)) + NEWOBJ + STOP
    risk, reasons, _ = _risk(data)
    assert risk != "clean", pair
    reduce = P2 + call(g(*pair), s(MARKER_CMD)) + STOP
    assert _risk(reduce)[0] != "clean", pair


def test_near_miss_paths_are_not_accepted():
    for pair in [("sklearn.ensemble.forestx", "RandomForestClassifier"),
                 ("sklearn.ensemble.forest", "RandomForestClassifierX"),
                 ("sklearn.ensemble", "forest"),
                 ("sklearn.ensemble.forest.sub", "RandomForestClassifier")]:
        assert upstream.state_only(pair) is None
        assert _risk(_rebuilt(pair))[0] != "clean", pair


def test_alias_does_not_rescue_a_marker_in_its_state():
    pair = POLICY_ALIASES[0] if POLICY_ALIASES else ("sklearn.ensemble.forest", "RandomForestClassifier")
    payload = call(g("posix", "system"), s(MARKER_CMD))
    risk, _, _ = _risk(_rebuilt(pair, EMPTY_DICT + b"(" + s("x") + payload + b"u"))
    assert risk == "malicious"


def test_compiled_aliases_keep_the_current_form():
    for pair, entry in PATHS.items():
        if entry["kind"] == "compiled":
            current = tuple(entry["current"].split(":", 1))
            assert pair in allowlists.PICKLE_GLOBALS
            assert (pair in allowlists.STATE_ONLY_CLASSES) == (current in allowlists.STATE_ONLY_CLASSES)
