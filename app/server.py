"""Serwer dashboardu — jedna strona, jeden przepływ.

Upload → status → wynik parsera → log z sandboksa → werdykt.
Bez kont, bez historii, bez dodatkowych ekranów.
"""

from __future__ import annotations

import os
import tempfile
import threading
import uuid

from flask import Flask, jsonify, render_template, request

from sandbox_rce import pipeline, sandbox

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB

ALLOWED_EXTENSIONS = {".pkl", ".pickle", ".keras", ".npy", ".npz"}

# Stan zadań trzymany w pamięci procesu — zgodnie z założeniem "zero historii".
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def _set_job(job_id: str, **fields) -> None:
    with _jobs_lock:
        _jobs.setdefault(job_id, {}).update(fields)


def _get_job(job_id: str) -> dict | None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        return dict(job) if job else None


def _run_analysis(job_id: str, path: str, display_name: str) -> None:
    try:
        def progress(message: str) -> None:
            _set_job(job_id, status="running", step=message)

        result = pipeline.analyze(path, progress=progress)
        result["file_name"] = display_name
        result["parser"]["file_name"] = display_name
        result["sandbox"]["file_name"] = display_name
        _set_job(job_id, status="done", step="Gotowe", result=result)
    except Exception as exc:  # noqa: BLE001 — błąd ma dotrzeć do UI, nie do logu
        _set_job(
            job_id,
            status="error",
            step="Błąd",
            error=f"{type(exc).__name__}: {exc}",
        )
    finally:
        try:
            os.unlink(path)
            os.rmdir(os.path.dirname(path))
        except OSError:
            pass


@app.get("/")
def index():
    docker_ok, docker_message = sandbox.docker_status()
    return render_template(
        "index.html",
        docker_ok=docker_ok,
        docker_message=docker_message,
        judge_ok=bool(os.environ.get("ANTHROPIC_API_KEY")),
    )


@app.post("/api/analyze")
def analyze():
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "Nie wybrano pliku."}), 400

    display_name = os.path.basename(uploaded.filename)
    extension = os.path.splitext(display_name)[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        return (
            jsonify(
                {
                    "error": (
                        f"Obsługiwane rozszerzenia: {', '.join(sorted(ALLOWED_EXTENSIONS))}. "
                        f"Otrzymano: {extension or 'brak'}."
                    )
                }
            ),
            400,
        )

    # Nazwa pliku z uploadu nigdy nie trafia na dysk — zapisujemy pod stałą
    # nazwą w świeżym katalogu tymczasowym.
    staging = tempfile.mkdtemp(prefix="pickle-sandbox-")
    path = os.path.join(staging, "upload" + extension)
    uploaded.save(path)

    job_id = uuid.uuid4().hex
    _set_job(job_id, status="queued", step="W kolejce", result=None, error=None)

    thread = threading.Thread(
        target=_run_analysis, args=(job_id, path, display_name), daemon=True
    )
    thread.start()

    return jsonify({"job_id": job_id})


@app.get("/api/status/<job_id>")
def status(job_id: str):
    job = _get_job(job_id)
    if job is None:
        return jsonify({"error": "Nieznane zadanie."}), 404
    return jsonify(job)


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "Plik jest za duży (limit 32 MB)."}), 413


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=False)
