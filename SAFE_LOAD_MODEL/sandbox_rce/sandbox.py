"""Warstwa 2 — orkiestracja detonacji w kontenerze Docker.

Host buduje (raz) obraz, a potem uruchamia detoner w kontenerze z twardo
zakręconą izolacją. Jeśli Docker jest niedostępny, zwracamy kontrakt
z ``detonated: false`` i czytelnym powodem — **nigdy nie udajemy logu
i nie podmieniamy detonacji na symulację**.

Output to kontrakt zgodny ze ``schemas/sandbox.schema.json``.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import uuid

SCHEMA_VERSION = "1.0"
IMAGE_TAG = "pickle-sandbox-detoner:latest"
DEFAULT_TIMEOUT_S = 30

EVENT_PREFIX = "@@EVENT@@"
RESULT_PREFIX = "@@RESULT@@"

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DOCKERFILE_DIR = os.path.join(_REPO_ROOT, "docker")

# Profile detonacji. Pickle jedzie na minimalnym obrazie (sam Python); keras
# potrzebuje TensorFlow, więc dostaje więcej pamięci, większy /tmp i dłuższy
# limit czasu (sam import TF to kilkanaście sekund). Flagi izolacji
# (--network=none, --read-only, --cap-drop=ALL, no-new-privileges, --ipc=none)
# są identyczne dla obu — różnią się tylko rozmiary i limity.
_PROFILES = {
    "pickle": {
        "image_tag": IMAGE_TAG,
        "dockerfile": "Dockerfile",
        # Pliki, które trafiają do obrazu. Ich skrót jest etykietą obrazu:
        # zmiana detonera po pullu wymusza przebudowę sama, bez pamiętania
        # o "docker build" (kod detonera jest zapieczony w obrazie).
        "sources": [
            "docker/Dockerfile",
            "docker/requirements-pickle.txt",
            "sandbox_rce/detonate.py",
        ],
        "sample_name": "sample.pkl",
        "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=16m",
        # 512 MB, bo w obrazie jest teraz numpy i scikit-learn (import samego
        # sklearn ze scipy to ~150 MB). Za niski limit = kod 137 i odmowa.
        "memory": "512m",
        "pids": "128",
        "nofile": "256:256",
        "timeout_s": DEFAULT_TIMEOUT_S,
        "build_timeout_s": 600,
    },
    "keras": {
        "image_tag": "pickle-sandbox-detoner-keras:latest",
        "dockerfile": "Dockerfile.keras",
        "sources": [
            "docker/Dockerfile.keras",
            "docker/requirements-keras.txt",
            "sandbox_rce/detonate.py",
            "sandbox_rce/detonate_keras.py",
        ],
        "sample_name": "sample.keras",
        # TF zapisuje do /tmp przy starcie — 16 MB to za mało.
        "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=512m",
        "memory": "2g",
        "pids": "512",
        "nofile": "4096:4096",
        # Import TF + load_model + przebieg w przód potrafi zająć ~minutę.
        "timeout_s": 120,
        "build_timeout_s": 1800,
    },
}


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
        "timed_out": False,
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
            # Krotki limit celowo. To wywolanie stoi na drodze zadania HTTP
            # (dashboard pyta o stan Dockera przy wejsciu na strone), a gdy
            # Docker Desktop sie restartuje, "docker info" potrafi wisiec.
            # Przy dlugim limicie strona i upload czekaly razem z nim.
            timeout=6,
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


IMAGE_LABEL = "safeloadai.sources"


def image_fingerprint(profile: str = "pickle") -> str:
    """Skrót SHA-256 plików, z których budowany jest obraz danego profilu."""
    digest = hashlib.sha256()
    for relative in _PROFILES[profile]["sources"]:
        full = os.path.join(_REPO_ROOT, relative)
        digest.update(relative.encode())
        with open(full, "rb") as fh:
            digest.update(fh.read())
    return digest.hexdigest()[:16]


def ensure_image(force_rebuild: bool = False, profile: str = "pickle") -> None:
    """Buduje obraz detonera, jeśli go nie ma albo jest z innej wersji kodu.

    Wersję rozpoznajemy po etykiecie ze skrótem plików źródłowych. Wcześniej
    sprawdzaliśmy tylko, czy obraz o danej nazwie istnieje — po pullu, który
    zmieniał detoner, kontener dalej uruchamiał STARY kod i trzeba było
    pamiętać o ręcznym "docker build".
    """
    cfg = _PROFILES[profile]
    available, message = docker_status()
    if not available:
        raise DockerUnavailable(message)

    missing = [
        rel for rel in cfg["sources"]
        if not os.path.isfile(os.path.join(_REPO_ROOT, rel))
    ]
    if missing:
        raise DockerUnavailable(
            "Brak plików potrzebnych do zbudowania obrazu detonera: "
            f"{', '.join(missing)}. Biblioteka musi być zainstalowana z katalogu "
            "repozytorium (pip install -e .), bo obraz buduje się z katalogu docker/."
        )
    fingerprint = image_fingerprint(profile)

    if not force_rebuild:
        try:
            probe = subprocess.run(
                [
                    "docker", "image", "inspect",
                    "--format", "{{ index .Config.Labels \"%s\" }}" % IMAGE_LABEL,
                    cfg["image_tag"],
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired as exc:
            raise DockerUnavailable("'docker image inspect' przekroczyło limit czasu.") from exc
        if probe.returncode == 0 and probe.stdout.strip() == fingerprint:
            return

    try:
        build = subprocess.run(
            [
                "docker", "build", "-q",
                "--label", f"{IMAGE_LABEL}={fingerprint}",
                "-t", cfg["image_tag"],
                "-f", os.path.join(_DOCKERFILE_DIR, cfg["dockerfile"]),
                _REPO_ROOT,
            ],
            capture_output=True,
            text=True,
            timeout=cfg["build_timeout_s"],
        )
    except subprocess.TimeoutExpired as exc:
        raise DockerUnavailable(
            f"Budowa obrazu detonera ({profile}) przekroczyła "
            f"{cfg['build_timeout_s']} s."
        ) from exc
    if build.returncode != 0:
        raise DockerUnavailable(
            f"Budowa obrazu detonera ({profile}) nie powiodła się: "
            f"{build.stderr.strip()[:500]}"
        )


def _kill_container(name: str) -> None:
    """Zabija kontener po nazwie. Błąd (np. kontener już skończył) łykamy."""
    try:
        subprocess.run(
            ["docker", "kill", name], capture_output=True, text=True, timeout=30
        )
    except Exception:  # noqa: BLE001
        pass


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
    timeout_s: int | None = None,
    profile: str = "pickle",
) -> dict:
    """Odpala plik w kontenerze i zwraca kontrakt sandboksa.

    ``profile`` wybiera obraz i limity: ``pickle`` (lekki) albo ``keras``
    (z TensorFlow). Flagi izolacji są dla obu takie same.
    """
    cfg = _PROFILES[profile]
    if timeout_s is None:
        timeout_s = cfg["timeout_s"]
    file_name = os.path.basename(path)

    available, message = docker_status()
    if not available:
        return _empty_report(file_name, message)

    try:
        ensure_image(profile=profile)
    except DockerUnavailable as exc:
        return _empty_report(file_name, str(exc))

    report = _empty_report(file_name, "")
    report["skipped_reason"] = None

    # Plik kopiujemy do katalogu tymczasowego i montujemy read-only pod
    # stałą nazwą, żeby nazwa pliku z uploadu nie trafiła do argv kontenera.
    container_name = f"safeloadai-{uuid.uuid4().hex[:12]}"
    with tempfile.TemporaryDirectory() as staging:
        staged = os.path.join(staging, cfg["sample_name"])
        shutil.copyfile(path, staged)
        os.chmod(staged, 0o444)

        cmd = [
            "docker", "run", "--rm",
            # Nazwa, żeby po przekroczeniu limitu czasu dało się kontener
            # zabić. Zabicie samego klienta "docker run" (to robi
            # subprocess.run przy timeoucie) kontenera NIE zatrzymuje.
            "--name", container_name,
            # --- odcięcie od sieci ---
            # Brak interfejsu poza loopbackiem — DNS i hosty są bezprzedmiotowe,
            # a Docker i tak odrzuca --dns/--add-host razem z network=none.
            "--network=none",
            # --- filesystem ---
            "--read-only",                 # cały filesystem ro...
            # ...poza /tmp. noexec: payload nie uruchomi binarki, którą zrzuci.
            # nosuid/nodev: nie podniesie uprawnień i nie stworzy urządzenia.
            "--tmpfs", cfg["tmpfs"],
            # --- uprawnienia ---
            "--cap-drop=ALL",              # zero capabilities
            "--security-opt=no-new-privileges",
            # --- izolacja przestrzeni nazw ---
            "--ipc=none",                  # brak współdzielonej pamięci
            # --- limity zasobów (ochrona przed fork bombą i zajeżdżeniem hosta) ---
            f"--memory={cfg['memory']}",
            f"--memory-swap={cfg['memory']}",  # bez tego swap jest nielimitowany
            f"--pids-limit={cfg['pids']}",
            "--cpus=1",
            "--ulimit", f"nofile={cfg['nofile']}",
            "--ulimit", "fsize=16777216",  # 16 MB, limit rozmiaru pliku
            "-v", f"{staging}:/target:ro",
            # ENTRYPOINT obrazu to już sam detoner, więc dokładamy tylko
            # ścieżkę pliku jako jego argument.
            cfg["image_tag"],
            f"/target/{cfg['sample_name']}",
        ]

        # Opcjonalnie: gVisor (runsc) albo inny runtime z własnym jądrem.
        # Zwykły kontener dzieli jądro z hostem, więc dopiero to daje
        # izolację, przy której "w pełni odcięty" jest uczciwym określeniem.
        runtime = os.environ.get("SANDBOX_RUNTIME")
        if runtime:
            cmd.insert(2, f"--runtime={runtime}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                # Detoner pisze UTF-8; bez tego Windows dekoduje log stroną
                # kodową systemu i zdarzenia wychodzą jako krzaki.
                encoding="utf-8",
                errors="replace",
                timeout=timeout_s,
            )
            stdout, stderr, returncode = proc.stdout, proc.stderr, proc.returncode
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            returncode = -1
            timed_out = True
            _kill_container(container_name)

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
            f"Detonacja przerwana po {timeout_s}s (limit czasu) — kontener zabity. "
            "Ładunek mógł czekać dłużej niż limit, więc brak zdarzeń nic tu nie dowodzi."
        )
        report["detonated"] = True
        report["timed_out"] = True
    elif not report["detonated"]:
        # Dwa kody wychodza tu czesto i oba znacza cos konkretnego. Bez nazwania
        # ich wprost raport mowi tylko "brak wyniku", czyli dokladnie to samo,
        # co powiedzialby o pliku nieszkodliwym — a to jest najgorszy mozliwy
        # komunikat w detektorze zlosliwego kodu.
        _KILLED = {
            137: (
                "kod 137 = proces zabity (SIGKILL), prawie zawsze przez limit "
                f"pamieci kontenera (--memory={cfg['memory']}). Podnies limit "
                "w profilu detonacji i sprobuj ponownie"
            ),
            139: (
                "kod 139 = naruszenie ochrony pamieci (SIGSEGV) wewnatrz "
                "kontenera — biblioteka wywalila sie przed zapisaniem wyniku"
            ),
        }
        detail = _KILLED.get(returncode)
        report["skipped_reason"] = (
            f"Kontener zakończył się kodem {returncode}, bez wyniku detonacji."
            + (f" {detail}. To NIE znaczy, że plik jest nieszkodliwy." if detail else "")
        )
        report["error"] = (stderr or stdout or "").strip()[:1000] or None

    return report


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("usage: python -m sandbox_rce.sandbox <plik.pkl|.keras>", file=sys.stderr)
        raise SystemExit(2)
    target = sys.argv[1]
    prof = "keras" if os.path.splitext(target)[1].lower() == ".keras" else "pickle"
    print(json.dumps(detonate_in_docker(target, profile=prof), indent=2, ensure_ascii=False))
