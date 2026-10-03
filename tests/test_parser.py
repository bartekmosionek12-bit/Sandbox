"""Testy parsera statycznego."""

from __future__ import annotations

import os
import pickle
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from poc import build_poc  # noqa: E402
from sandbox_rce import parser  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "poc", "samples")


@pytest.fixture(scope="module", autouse=True)
def _samples():
    build_poc.build(SAMPLES)


def _parse(name: str) -> dict:
    return parser.parse_file(os.path.join(SAMPLES, name))


@pytest.mark.parametrize(
    "name",
    ["evil_os_system.pkl", "evil_file_write.pkl", "evil_network_beacon.pkl"],
)
def test_evil_samples_are_flagged_malicious(name):
    report = _parse(name)
    assert report["static_risk"] == "malicious"
    assert report["suspicious_imports"], "oczekiwano wykrytego niebezpiecznego importu"
    assert any(o["name"] == "REDUCE" for o in report["flagged_opcodes"])


def test_clean_sample_is_clean():
    report = _parse("clean_model.pkl")
    assert report["static_risk"] == "clean"
    assert report["flagged_opcodes"] == []
    assert report["suspicious_imports"] == []


def test_stack_global_import_is_resolved():
    """STACK_GLOBAL (protokół 4) nie ma argumentu — moduł i symbol są
    osobnymi stringami na stosie. Bez ich śledzenia os.system w pliku
    proto-4 przechodziłby niewykryty."""
    report = _parse("evil_os_system.pkl")
    pairs = {(i["module"], i["symbol"]) for i in report["suspicious_imports"]}
    assert ("posix", "system") in pairs


def test_global_proto2_import_is_resolved():
    """Stary GLOBAL (protokół <= 3) ma argument 'moduł symbol'."""

    class Legacy:
        def __reduce__(self):
            return (os.system, ("true",))

    data = pickle.dumps(Legacy(), protocol=2)
    report = parser.parse_pickle(data, "legacy.pkl")
    assert report["static_risk"] == "malicious"
    pairs = {(i["module"], i["symbol"]) for i in report["suspicious_imports"]}
    # Ten pickle powstaje w locie, więc niesie nazwę modułu z bieżącego
    # systemu: os.system to posix.system na POSIX-ie i nt.system na Windows.
    assert (os.system.__module__, "system") in pairs


def test_contract_shape():
    report = _parse("clean_model.pkl")
    for key in (
        "schema_version", "file_name", "file_format", "opcodes",
        "flagged_opcodes", "suspicious_imports", "raw_disasm", "static_risk",
    ):
        assert key in report, f"brak klucza kontraktu: {key}"
    assert report["schema_version"] == "1.0"


def test_truncated_file_does_not_crash():
    """Celowo uszkodzony plik ma dać raport z błędem, nie wyjątek."""
    with open(os.path.join(SAMPLES, "evil_os_system.pkl"), "rb") as fh:
        data = fh.read()
    report = parser.parse_pickle(data[: len(data) // 2], "truncated.pkl")
    assert report["error"] or report["notes"]


def test_parser_never_executes_payload(tmp_path):
    """Parser czyta opcody, więc NIE może uruchomić payloadu.

    Payload tworzy plik-znacznik; po analizie statycznej znacznik nie
    może istnieć.
    """
    marker = tmp_path / "parser_must_not_run_this"

    script = f"""
import pickle, sys
sys.path.insert(0, {os.path.dirname(os.path.dirname(os.path.abspath(__file__)))!r})
import os
class P:
    def __reduce__(self):
        return (os.system, ("touch " + {str(marker)!r},))
data = pickle.dumps(P(), protocol=4)
from sandbox_rce import parser
r = parser.parse_pickle(data, "x.pkl")
assert r["static_risk"] == "malicious", r["static_risk"]
print("OK")
"""
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert not marker.exists(), "parser statyczny wykonał payload — to poważny błąd"
