"""Testy detonera i kontraktu sandboksa.

Detoner uruchamiamy jako podproces (nigdy w procesie testów — instaluje
globalne monkey-patche), na własnych, nieszkodliwych fixture'ach.
To są testy, które pilnują najważniejszej rzeczy: że instrumentacja
faktycznie przechwytuje zachowanie. Pusty log podczas demo jest gorszy
niż brak detonacji, bo wygląda na dowód niewinności.
"""

from __future__ import annotations

import json
import pickle
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from poc import build_poc  # noqa: E402
from sandbox_rce import sandbox  # noqa: E402

SAMPLES = os.path.join(ROOT, "poc", "samples")
DETONATE = os.path.join(ROOT, "sandbox_rce", "detonate.py")


@pytest.fixture(scope="module", autouse=True)
def _samples():
    build_poc.build(SAMPLES)


def _run_detoner(name: str, env_extra: dict | None = None) -> dict:
    return _run_detoner_path(os.path.join(SAMPLES, name), env_extra)


def _run_detoner_path(path: str, env_extra: dict | None = None) -> dict:
    env = dict(os.environ)
    env.update(env_extra or {})
    proc = subprocess.run(
        [sys.executable, "-I", "-u", DETONATE, path],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    result = None
    for line in proc.stdout.splitlines():
        if line.startswith("@@RESULT@@"):
            result = json.loads(line[len("@@RESULT@@") :])
    assert result is not None, f"detoner nie zwrócił wyniku. stdout={proc.stdout!r} stderr={proc.stderr!r}"
    return result


# Fixture'y celują w posix.system (tak jak kontener detonera), więc poza
# POSIX-em pickle.load() kończy się na imporcie i nie ma czego przechwycić.
posix_only = pytest.mark.skipif(
    os.name != "posix",
    reason="fixture'y odwołują się do posix.system — detonacja tylko na POSIX/w kontenerze",
)


@posix_only
def test_os_system_payload_is_logged(tmp_path):
    result = _run_detoner("evil_os_system.pkl")
    types = [e["type"] for e in result["events"]]
    assert "os_system" in types, f"nie przechwycono os.system: {types}"
    detail = next(e["detail"] for e in result["events"] if e["type"] == "os_system")
    assert "touch" in detail


@posix_only
def test_posix_system_is_patched_not_only_os():
    """os.system to w istocie posix.system, a pickle importuje posix.system
    wprost. Ten test pilnuje, że patch obejmuje moduł posix — bez tego
    detoner pokazywałby pusty log dla najbardziej typowego payloadu."""
    result = _run_detoner("evil_os_system.pkl")
    assert any(e["type"] == "os_system" for e in result["events"])


def _build_unroutable_beacon(tmp_path) -> str:
    """Fixture sieciowy celujący w 192.0.2.1 (TEST-NET-1, RFC 5737).

    Demo'wy ``evil_network_beacon.pkl`` celuje w example.com, bo tak czytelniej
    wygląda na dashboardzie — ale on jest uruchamiany WYŁĄCZNIE w kontenerze
    z ``--network=none``. Testy odpalają detoner bezpośrednio na hoście, więc
    tamten fixture wysyłałby z maszyny dewelopera prawdziwy pakiet. TEST-NET-1
    jest zarezerwowany do dokumentacji i nietrasowalny, więc próba zostaje
    zalogowana, a nic nie opuszcza maszyny.
    """
    import socket

    class UnroutableBeacon:
        def __reduce__(self):
            return (socket.create_connection, (("192.0.2.1", 80), 1))

    path = os.path.join(str(tmp_path), "beacon_testnet.pkl")
    with open(path, "wb") as fh:
        pickle.dump(UnroutableBeacon(), fh, protocol=4)
    return path


def test_network_attempt_is_logged(tmp_path):
    result = _run_detoner_path(_build_unroutable_beacon(tmp_path))
    assert any(e["type"] == "network" for e in result["events"])


def test_clean_model_produces_no_events():
    result = _run_detoner("clean_model.pkl")
    assert result["load_succeeded"] is True
    assert result["events"] == [], f"czysty model nie powinien nic robić: {result['events']}"


def test_import_machinery_does_not_pollute_log(tmp_path):
    """Maszyneria importów woła exec() na obiektach code. Logujemy tylko
    kod podany jako źródło (str/bytes), więc zwykłe importy nie mogą
    generować zdarzeń code_exec."""
    result = _run_detoner_path(_build_unroutable_beacon(tmp_path))
    code_events = [e for e in result["events"] if e["type"] == "code_exec"]
    assert code_events == [], f"log zaśmiecony przez importy: {code_events}"


def test_sandbox_contract_shape_when_docker_missing():
    """Bez Dockera kontrakt musi być uczciwy: detonated=False i powód."""
    report = sandbox._empty_report("x.pkl", "Docker niedostępny.")
    for key in ("schema_version", "file_name", "detonated", "events", "raw_log"):
        assert key in report
    assert report["detonated"] is False
    assert report["skipped_reason"]
    assert report["events"] == []
    assert report["raw_log"] == ""


def test_docker_status_never_raises():
    available, message = sandbox.docker_status()
    assert isinstance(available, bool)
    assert isinstance(message, str) and message
