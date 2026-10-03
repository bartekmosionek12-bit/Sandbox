"""Warstwa 2 — orkiestracja detonacji w kontenerze Docker.

Host buduje (raz) obraz, a potem uruchamia detoner w kontenerze z twardo
zakręconą izolacją. Jeśli Docker jest niedostępny, zwracamy kontrakt
z ``detonated: false`` i czytelnym powodem — **nigdy nie udajemy logu
i nie podmieniamy detonacji na symulację**.

Output to kontrakt zgodny ze ``schemas/sandbox.schema.json``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

SCHEMA_VERSION = "1.0"
IMAGE_TAG = "pickle-sandbox-detoner:latest"
DEFAULT_TIMEOUT_S = 30

EVENT_PREFIX = "@@EVENT@@"
RESULT_PREFIX = "@@RESULT@@"

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DOCKERFILE_DIR = os.path.join(_REPO_ROOT, "docker")


class DockerUnavailable(RuntimeError):
    """Docker nie jest dostępny — detonacja nie może się odbyć."""


def _empty_report(file_name: str, reason: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "file_name": file_name,
        "detonated": False,
        "detonation_backend": None,
        "skipped_reason": reason,
        "load_succeeded": None,
        "duration_ms": None,
        "events": [],
        "raw_log": "",
        "error": None,
    }


def docker_status() -> tuple[bool, str]:
    """Zwraca (dostępny, komunikat). Nie rzuca wyjątkami."""
    if shutil.which("docker") is None:
        return False, "Nie znaleziono binarki 'docker' w PATH."
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        return False, "Polecenie 'docker info' przekroczyło limit czasu."
    except Exception as exc:  # noqa: BLE001
        return False, f"Nie udało się wykonać 'docker info': {exc}"

    if proc.returncode != 0:
        raw = (proc.stderr or proc.stdout or "").strip()
        # Komunikat trafia do UI, więc skracamy go do jednej czytelnej frazy
        # zamiast wylewać na stronę całą ścieżkę gniazda i podpowiedzi Dockera.
        if "docker.sock" in raw or "Cannot connect" in raw or "daemon" in raw.lower():
            detail = "demon nie jest uruchomiony"
        else:
            first = raw.splitlines()[0] if raw else "nieznany błąd"
            detail = first[:120]
        return False, f"Demon Dockera nie odpowiada ({detail})."
    return True, f"Docker {proc.stdout.strip()}"


def ensure_image(force_rebuild: bool = False) -> None:
    """Buduje obraz detonera, jeśli jeszcze nie istnieje."""
    available, message = docker_status()
    if not available:
        raise DockerUnavailable(message)

    if not force_rebuild:
        probe = subprocess.run(
            ["docker", "image", "inspect", IMAGE_TAG],
            capture_output=True,
            text=True,
        )
        if probe.returncode == 0:
            return

    build = subprocess.run(
        [
            "docker", "build", "-q",
            "-t", IMAGE_TAG,
            "-f", os.path.join(_DOCKERFILE_DIR, "Dockerfile"),
            _REPO_ROOT,
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if build.returncode != 0:
        raise DockerUnavailable(
            f"Budowa obrazu detonera nie powiodła się: {build.stderr.strip()[:500]}"
        )


def _parse_detoner_output(stdout: str) -> tuple[list[dict], dict | None]:
    events: list[dict] = []
    result: dict | None = None
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith(EVENT_PREFIX):
            try:
                events.append(json.loads(stripped[len(EVENT_PREFIX) :].strip()))
            except json.JSONDecodeError:
                continue
        elif stripped.startswith(RESULT_PREFIX):
            try:
                result = json.loads(stripped[len(RESULT_PREFIX) :].strip())
            except json.JSONDecodeError:
                continue
    return events, result


def detonate_in_docker(
    path: str,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> dict:
    """Odpala plik w kontenerze i zwraca kontrakt sandboksa."""
    file_name = os.path.basename(path)

    available, message = docker_status()
    if not available:
        return _empty_report(file_name, message)

    try:
        ensure_image()
    except DockerUnavailable as exc:
        return _empty_report(file_name, str(exc))

    report = _empty_report(file_name, "")
    report["skipped_reason"] = None

    # Plik kopiujemy do katalogu tymczasowego i montujemy read-only pod
    # stałą nazwą, żeby nazwa pliku z uploadu nie trafiła do argv kontenera.
    with tempfile.TemporaryDirectory() as staging:
        staged = os.path.join(staging, "sample.pkl")
        shutil.copyfile(path, staged)
        os.chmod(staged, 0o444)

        cmd = [
            "docker", "run", "--rm",
            "--network=none",              # brak jakiegokolwiek wyjścia na sieć
            "--read-only",                 # cały filesystem ro...
            "--tmpfs", "/tmp:rw,size=16m", # ...poza /tmp, gdzie payload może pisać
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--memory=256m",
            "--pids-limit=128",
            "--cpus=1",
            "-v", f"{staging}:/target:ro",
            # ENTRYPOINT obrazu to już sam detoner, więc dokładamy tylko
            # ścieżkę pliku jako jego argument.
            IMAGE_TAG,
            "/target/sample.pkl",
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
            stdout, stderr, returncode = proc.stdout, proc.stderr, proc.returncode
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            returncode = -1
            timed_out = True

    events, result = _parse_detoner_output(stdout)

    # Surowy log do pokazania na dashboardzie — bez linii kontrolnych.
    log_lines = [
        line
        for line in (stdout or "").splitlines()
        if not line.strip().startswith((EVENT_PREFIX, RESULT_PREFIX))
    ]
    if stderr:
        log_lines.append("--- stderr ---")
        log_lines.extend(stderr.splitlines())

    report["detonated"] = result is not None or bool(events)
    report["detonation_backend"] = "docker"
    report["events"] = result["events"] if result else events
    report["raw_log"] = "\n".join(log_lines).strip()

    if result:
        report["load_succeeded"] = result.get("load_succeeded")
        report["duration_ms"] = result.get("duration_ms")
        report["error"] = result.get("error")

    if timed_out:
        report["error"] = (
            f"Detonacja przerwana po {timeout_s}s (limit czasu) — kontener zabity."
        )
        report["detonated"] = True
    elif not report["detonated"]:
        report["skipped_reason"] = (
            f"Kontener zakończył się kodem {returncode}, bez wyniku detonacji."
        )
        report["error"] = (stderr or stdout or "").strip()[:1000] or None

    return report


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("usage: python -m sandbox_rce.sandbox <plik.pkl>", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(detonate_in_docker(sys.argv[1]), indent=2, ensure_ascii=False))
