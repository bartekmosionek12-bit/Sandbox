import pickle

import pytest

from conftest import SAMPLES
from sandbox_rce import parser, parser_keras


def _su(text):
    raw = text.encode()
    return b"\x8c" + bytes([len(raw)]) + raw


@pytest.mark.parametrize(
    "name, risk",
    [
        ("evil_os_system.pkl", "malicious"),
        ("evil_file_write.pkl", "malicious"),
        ("evil_network_beacon.pkl", "malicious"),
        ("clean_model.pkl", "clean"),
    ],
)
def test_poc_pickles(name, risk):
    assert parser.parse_file(f"{SAMPLES}/{name}")["static_risk"] == risk


@pytest.mark.parametrize(
    "name, risk",
    [
        ("evil_lambda.keras", "malicious"),
        ("evil_custom_object.keras", "suspicious"),
        ("clean_model.keras", "clean"),
    ],
)
def test_poc_keras(name, risk):
    assert parser_keras.parse_file(f"{SAMPLES}/{name}")["static_risk"] == risk


def test_stack_global_through_memo_is_resolved():
    # posix i system odkładane do memo, na stos idą wabiki, BINGET wyjmuje
    # prawdziwe nazwy tuż przed STACK_GLOBAL. Plik tylko parsujemy.
    data = (
        b"\x80\x04" + _su("posix") + b"\x94" + _su("system") + b"\x94"
        + _su("a") + _su("b") + b"00" + b"h\x00h\x01\x93" + _su("id") + b"\x85R."
    )
    report = parser.parse_pickle(data)
    assert {"module": "posix", "symbol": "system"} in [
        {"module": i["module"], "symbol": i["symbol"]} for i in report["suspicious_imports"]
    ]
    assert report["static_risk"] == "malicious"


def test_obj_opcode_counts_as_call():
    # OBJ wywołuje dowolny callable, tak jak REDUCE. Wcześniej wynik był "clean".
    data = b"\x80\x04(" + b"ctimeit\ntimeit\n" + _su("print(1)") + b"o."
    assert parser.parse_pickle(data)["static_risk"] == "malicious"


def test_unparseable_file_is_not_clean():
    report = parser.parse_pickle(b"to nie jest pickle")
    assert report["error"]
    assert report["static_risk"] == "suspicious"


def test_protocol2_set_is_not_malicious():
    report = parser.parse_pickle(pickle.dumps({1, 2}, protocol=2))
    assert report["suspicious_imports"] == []
    assert report["static_risk"] != "malicious"


def test_dotted_symbol_flagged():
    data = b"\x80\x02cos\npath.join\nq\x00."
    assert parser.parse_pickle(data)["suspicious_imports"]
