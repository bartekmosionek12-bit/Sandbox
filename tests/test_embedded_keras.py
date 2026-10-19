"""Keras 3 models pickled as an embedded .keras archive (owner's decision of 2026-10-19).

KerasSaveable.__reduce__ (keras/src/saving/keras_saveable.py, Keras 3.3.3 to 3.15.1)
pickles a model as ``getattr(cls, "_unpickle_model")(BytesIO(<.keras bytes>))``. The form
is not evidence by itself: the bytes are analysed as a Keras file of their own and the
pickle keeps a RISKY reason, because the loader runs with safe_mode=False.

Pickles are assembled opcode by opcode; nothing is unpickled or loaded.
"""
from __future__ import annotations

import pickle
import struct

import pytest
from corpus.build_corpus import (
    LAMBDAS,
    MARKER_CMD,
    P2,
    STOP,
    _keras_zip,
    _lambda_layer,
    _model,
    call,
    compile_lambdas,
    g,
    s,
    sg,
)

from safeloadai import Verdict, scan
from safeloadai.static.pickle_static import parse_pickle

FUNCTIONAL = ("keras.src.models.functional", "Functional")
EMBEDDED = "pickle invokes the Keras loader on embedded bytes"
P4 = b"\x80\x04"


def _binbytes(data: bytes) -> bytes:
    return b"B" + struct.pack("<I", len(data)) + data


def _bytes_io(blob: bytes, *, latin1: bool = False) -> bytes:
    value = call(g("_codecs", "encode"), s(blob.decode("latin-1")), s("latin1")) if latin1 else _binbytes(blob)
    state = b"(" + value + b"J" + struct.pack("<i", len(blob)) + b"Nt"
    return sg("_io", "BytesIO") + b")\x81" + state + b"b"


def _method(cls=FUNCTIONAL, name: str = "_unpickle_model") -> bytes:
    return call(sg("builtins", "getattr"), sg(*cls), s(name))


def embedded(blob: bytes, *, latin1: bool = False, cls=FUNCTIONAL, name: str = "_unpickle_model") -> bytes:
    """What pickle.dumps(keras_model) writes, in a dict like a wrapper object would hold it."""
    model = call(_method(cls, name), _bytes_io(blob, latin1=latin1))
    return (P2 if latin1 else P4) + b"}(" + s("model") + model + b"u" + STOP


def _scan(tmp_path, data: bytes, name: str = "model.pkl"):
    path = tmp_path / name
    path.write_bytes(data)
    return scan(str(path))


def _is_risky(result) -> bool:
    return result.verdict is Verdict.SUSPICIOUS and not result.unverifiable_only


BENIGN = _keras_zip(_model())


@pytest.mark.parametrize("latin1", [False, True], ids=["protocol4-bytes", "protocol2-codecs"])
def test_benign_embedded_keras_is_risky(latin1, tmp_path):
    data = embedded(BENIGN, latin1=latin1)
    report = parse_pickle(data)
    assert report["static_risk"] == "suspicious", report["reasons"]
    assert any(EMBEDDED in r for r in report["reasons"])
    assert report["embedded_keras"][0]["length"] == len(BENIGN)
    # the form itself is not evidence, and its globals are not findings
    assert not any("is called" in r or "known sink" in r or "outside the allowlist" in r
                   or "private attribute" in r for r in report["reasons"]), report["reasons"]
    result = _scan(tmp_path, data)
    assert _is_risky(result), result.findings
    assert any(EMBEDDED in r for r in result.reasons)
    names = [layer.name for layer in result.layers]
    assert any(n.startswith("static[embedded keras@") for n in names)
    assert any(n.startswith("emulation[embedded keras@") for n in names)


def test_embedded_reason_cannot_be_overridden(tmp_path):
    result = _scan(tmp_path, embedded(BENIGN))
    assert not result.unverifiable_only


def test_embedded_keras_with_os_system_lambda_is_malicious(tmp_path):
    code = compile_lambdas({"x": LAMBDAS["k_lambda_os_system.keras"][2]})["x"]
    blob = _keras_zip(_model(_lambda_layer(code)))
    result = _scan(tmp_path, embedded(blob))
    assert result.verdict is Verdict.MALICIOUS
    assert any(layer.name.startswith("emulation[embedded keras@") and layer.verdict is Verdict.MALICIOUS
               for layer in result.layers), [(la.name, la.verdict) for la in result.layers]


def test_embedded_keras_with_sink_function_config_is_malicious(tmp_path):
    from corpus.build_corpus import _layer

    blob = _keras_zip(_model(_layer("keras.layers", "Activation", {
        "name": "act", "activation": {"module": "posix", "class_name": "function", "config": "system",
                                      "registered_name": "function"}})))
    assert _scan(tmp_path, embedded(blob)).verdict is Verdict.MALICIOUS


def test_embedded_pickle_instead_of_keras_is_judged_as_what_it_is(tmp_path):
    evil = P2 + call(g("posix", "system"), s(MARKER_CMD)) + STOP
    assert _scan(tmp_path, embedded(evil)).verdict is Verdict.MALICIOUS
    result = _scan(tmp_path, embedded(pickle.dumps({"a": 1})))
    assert _is_risky(result)
    assert any("not a Keras archive" in r for r in result.reasons)


# --- anything else than exactly the Keras form is judged as before -------------------------

def test_other_class_or_name_stays_malicious():
    assert parse_pickle(embedded(BENIGN, cls=("mypkg.models", "Functional")))["static_risk"] == "malicious"
    assert parse_pickle(embedded(BENIGN, name="_unpickle"))["static_risk"] == "malicious"


def test_bytes_io_used_elsewhere_stays_malicious():
    # the BytesIO class fetched again from the memo and called with a payload argument
    state = b"(" + _binbytes(BENIGN) + b"J" + struct.pack("<i", 0) + b"Nt"
    model = call(_method(), sg("_io", "BytesIO") + b"\x94)\x81" + state + b"b")
    other = call(b"h\x00", s(MARKER_CMD))  # BINGET 0: _io.BytesIO again
    data = P4 + b"(" + model + other + b"l" + STOP
    report = parse_pickle(data)
    assert report["static_risk"] == "malicious", report["reasons"]
    assert any("known sink: _io.BytesIO" in r for r in report["reasons"])


def test_method_called_twice_stays_malicious():
    method = _method() + b"\x94"  # MEMOIZE as 0
    first = method + b"(" + _bytes_io(BENIGN) + b"tR"
    second = b"h\x00(" + s(MARKER_CMD) + b"tR"  # the same bound method, called again
    report = parse_pickle(P4 + b"(" + first + second + b"l" + STOP)
    assert report["static_risk"] == "malicious"
    assert any("is called" in r for r in report["reasons"])


def test_state_with_extra_dict_entries_is_not_the_keras_form():
    blob = _binbytes(BENIGN)
    bio = sg("_io", "BytesIO") + b")\x81(" + blob + b"J\x00\x00\x00\x00}(" + s("x") + s("y") + b"ut" + b"b"
    report = parse_pickle(P4 + call(_method(), bio) + STOP)
    assert report["static_risk"] == "malicious"
    assert not report["embedded_keras"]
