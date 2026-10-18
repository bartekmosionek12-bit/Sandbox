"""Testy działają bez Dockera i bez klucza API.

Detonacja jest podmieniana na atrapę zwracającą gotowy raport. Żaden test
nie wczytuje plików PoC przez pickle.load — zasada projektu: ładunków nie
detonujemy poza kontenerem. Testy, które sprawdzają, że złośliwy plik NIE
został wczytany, podmieniają pickle.load na funkcję, która oblewa test.
"""
import os
import pickle
import socket
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SAMPLES = os.path.join(ROOT, "poc", "samples")


@pytest.fixture(autouse=True)
def _no_judge_no_cache(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("SAFELOADAI_CACHE_DIR", raising=False)


def sandbox_report(**overrides):
    report = {
        "schema_version": "1.0",
        "file_name": "sample",
        "detonated": True,
        "detonation_backend": "docker",
        "skipped_reason": None,
        "load_succeeded": True,
        "duration_ms": 10,
        "timed_out": False,
        "events": [],
        "raw_log": "[detoner] /tmp: payload nie utworzył ani nie zmienił żadnego pliku",
        "error": None,
    }
    report.update(overrides)
    return report


@pytest.fixture
def fake_detonation(monkeypatch):
    """Podmienia detonację. Zwraca listę wywołań; raport ustawia się przez .result."""
    from safeloadai import docker_sandbox as sandbox

    class Fake:
        calls = []
        result = sandbox_report()
        side_effect = None

    def fake(path, timeout_s=None, profile="pickle"):
        Fake.calls.append((path, profile))
        if Fake.side_effect:
            Fake.side_effect(path)
        return dict(Fake.result, file_name=os.path.basename(path))

    monkeypatch.setattr(sandbox, "detonate_in_docker", fake)
    return Fake


@pytest.fixture
def fake_emulation(monkeypatch):
    """Replaces the WASI emulation layer. Set .verdict / .reasons; .calls lists scanned formats."""
    from safeloadai import pipeline
    from safeloadai.report import LayerResult, Verdict

    class Fake:
        calls = []
        verdict = Verdict.CLEAN
        reasons = []
        side_effect = None

    def fake(data, parser_report, extra_allowed, limits=None):
        Fake.calls.append(parser_report.get("file_format"))
        if Fake.side_effect:
            Fake.side_effect(data)
        layer = LayerResult(name="emulation", verdict=Verdict.CLEAN)
        for reason in Fake.reasons or (["fake"] if Fake.verdict is not Verdict.CLEAN else []):
            layer.raise_to(Fake.verdict, reason)
        return layer

    monkeypatch.setattr(pipeline, "emulation_layer", fake)
    return Fake


# --- host-execution guard (audit S13) ----------------------------------------
#
# Sample payloads must never run on the host. During every test, process
# execution, non-loopback network connections and unrestricted unpickling are
# replaced with functions that fail the test. A test that legitimately needs one
# of them must say so with a marker, so the exception is visible in review.

class HostExecutionError(AssertionError):
    """Raised when a test tries to execute something on the host."""


def _refuse(what):
    def refuse(*args, **kwargs):
        raise HostExecutionError(f"host execution attempted during tests: {what} {args[:1]!r}")

    return refuse


def pytest_configure(config):
    config.addinivalue_line("markers", "wasi: needs the pinned WASI runtime (skipped if absent)")


def pytest_collection_modifyitems(config, items):
    import safeloadai
    from safeloadai.sandbox import runtime

    if os.environ.get("SAFELOADAI_EXPECT_INSTALLED"):
        # CI runs the suite against the built wheels: refuse to test the source tree.
        source_tree = os.path.join(ROOT, "src")
        if os.path.abspath(safeloadai.__file__).startswith(source_tree + os.sep):
            raise pytest.UsageError(f"testing {safeloadai.__file__}, not the installed wheel")
    try:
        runtime.locate()
        return
    except runtime.RuntimeIntegrityError as exc:
        raise pytest.UsageError(f"WASI runtime failed its integrity check: {exc}") from exc
    except runtime.RuntimeUnavailable as exc:
        if os.environ.get("SAFELOADAI_REQUIRE_WASI"):
            raise pytest.UsageError(f"SAFELOADAI_REQUIRE_WASI is set but {exc}") from exc
        reason = f"WASI runtime unavailable: {exc}"
    for item in items:
        if item.get_closest_marker("wasi"):
            item.add_marker(pytest.mark.skip(reason=reason))


@pytest.fixture(autouse=True)
def _host_execution_guard(request, monkeypatch):
    native = sys.modules.get("posix") or sys.modules.get("nt")
    for mod in (os, native):
        for name in ("system", "popen", "execv", "execve", "execvp", "execvpe", "execl",
                     "execlp", "spawnv", "spawnve", "spawnl", "posix_spawn", "posix_spawnp",
                     "fork", "forkpty"):
            if hasattr(mod, name):
                monkeypatch.setattr(mod, name, _refuse(f"{mod.__name__}.{name}"))
    # The only process tests may start is the sandbox runner (wasmtime child).
    from safeloadai.sandbox.host import RUNNER_ARGV

    real_popen = subprocess.Popen

    def popen(args, *a, **kw):
        if list(args) != RUNNER_ARGV:
            raise HostExecutionError(f"host execution attempted during tests: subprocess {args!r}")
        return real_popen(args, *a, **kw)

    monkeypatch.setattr(subprocess, "Popen", popen)
    # Unrestricted unpickling is never allowed; loaders use RestrictedUnpickler.
    monkeypatch.setattr(pickle, "load", _refuse("pickle.load"))
    monkeypatch.setattr(pickle, "loads", _refuse("pickle.loads"))

    real_connect = socket.socket.connect

    def connect(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise HostExecutionError(f"non-loopback connection attempted during tests: {address!r}")
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", connect)
