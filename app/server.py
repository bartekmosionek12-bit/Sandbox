"""Dashboard: a viewer for Report JSON produced by ``safeloadai scan --json``.

It never scans or loads model files. Paste or upload a report (or a list of
reports) and it renders verdict, reasons, per-layer results and evidence. All
report text is attacker-influenced, so templates rely on Jinja autoescaping.

    pip install 'safeloadai[dashboard]'
    flask --app app.server run --host 127.0.0.1
"""
from __future__ import annotations

import json

from flask import Flask, render_template, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

REQUIRED_KEYS = ("verdict", "layers", "file_name")


def parse_reports(text: str) -> list[dict]:
    data = json.loads(text)
    reports = data if isinstance(data, list) else [data]
    for report in reports:
        if not isinstance(report, dict) or any(k not in report for k in REQUIRED_KEYS):
            raise ValueError("not a safeloadai Report (needs verdict, layers, file_name)")
    return reports


@app.route("/", methods=["GET", "POST"])
def index():
    reports, error = [], None
    if request.method == "POST":
        upload = request.files.get("report")
        text = upload.read().decode("utf-8", "replace") if upload and upload.filename else request.form.get("text", "")
        try:
            reports = parse_reports(text)
        except (ValueError, json.JSONDecodeError) as exc:
            error = str(exc)
    return render_template("index.html", reports=reports, error=error)


@app.errorhandler(413)
def too_large(_error):
    return render_template("index.html", reports=[], error="report larger than 16 MB"), 413
