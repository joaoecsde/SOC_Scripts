"""Local Flask web UI for the email, IP / hash and PDF tools.

Run from the web folder:
    python3 app.py
"""
from __future__ import annotations

import io
import json
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file
from werkzeug.serving import make_server
from werkzeug.utils import secure_filename

import tools
from jobs import Job, JobStore, remove_stale_workdirs
from keys import keys_from_form
from tools import ToolError

HOST = "127.0.0.1"
PORT = 8765
MAX_UPLOAD_MB = 25
TOOLS = ("email", "ioc", "pdf")
DEFAULT_DELAY = "15"
MAX_DELAY = 300
DELAY_ERROR = "Delay must be a number of seconds from 0 to 300."
DEFAULT_MAX_AGE = "90"
EXPIRED = "This result has expired or never existed. Run the analysis again."


def utc_date(epoch) -> str:
    """Format a Unix timestamp (as VirusTotal returns it) for display.

    Args:
        epoch: Seconds since 1970, or None.

    Returns:
        ``YYYY-MM-DD HH:MM UTC``, or "Unknown" when missing or invalid.
    """
    try:
        return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        return "Unknown"


def create_app(store: Optional[JobStore] = None) -> Flask:
    """Build the Flask app.

    Args:
        store: Job store to use; a new one when omitted.

    Returns:
        The configured app.
    """
    store = store or JobStore()
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
    app.jinja_env.filters["defang"] = tools.defang
    app.jinja_env.filters["utc"] = utc_date

    def form_page(tab: str, errors: Dict[str, str], status: int = 400):
        """Re-render the landing page with messages; keys are never passed back."""
        values = {name: request.form.get(name, "")
                  for name in ("delay", "indicators", "max_age")}
        values["online"] = "online" in request.form
        values["extract"] = "extract" in request.form
        return render_template("index.html", tab=tab, errors=errors, form=values), status

    def read_upload():
        """Return (safe_name, bytes) of the uploaded file, or None if missing/empty."""
        upload = request.files.get("file")
        if upload is None or not upload.filename:
            return None
        data = upload.read()
        if not data:
            return None
        return upload.filename, data

    def parse_delay():
        text = request.form.get("delay", "").strip() or DEFAULT_DELAY
        try:
            value = float(text)
        except ValueError:
            return None
        return value if 0 <= value <= MAX_DELAY else None

    def save_upload(job: Job, name: str, data: bytes, fallback: str) -> str:
        path = job.workdir / (secure_filename(name) or fallback)
        path.write_bytes(data)
        return str(path)

    @app.errorhandler(413)
    def too_large(_exc):
        tab = request.path.rsplit("/", 1)[-1]
        return render_template("index.html", tab=tab if tab in TOOLS else "email",
                               errors={"file": f"This file is larger than {MAX_UPLOAD_MB} MB."},
                               form={"delay": "", "indicators": "", "max_age": "",
                                     "online": False, "extract": False}), 413

    @app.get("/")
    def index():
        tab = request.args.get("tool", "email")
        return render_template("index.html", tab=tab if tab in TOOLS else "email",
                               errors={}, form={"delay": "", "indicators": "", "max_age": "",
                                                "online": False, "extract": False})

    @app.post("/analyse/email")
    def analyse_email():
        upload = read_upload()
        if upload is None:
            return form_page("email", {"file": "Choose a file to analyse."})
        online = "online" in request.form
        keys = keys_from_form(request.form) if online else None
        if online:
            try:
                tools.check_online_keys(keys)
            except ToolError as e:
                return form_page("email", {"online": str(e)})
        delay = parse_delay() if online else float(DEFAULT_DELAY)
        if delay is None:
            return form_page("email", {"delay": DELAY_ERROR})
        name, data = upload

        def work(job: Job):
            path = save_upload(job, name, data, "upload.eml")
            return tools.run_email(path, name, keys, delay, store.progress_callback(job))

        return redirect(f"/job/{store.start('email', work).id}", 303)

    @app.post("/analyse/ioc")
    def analyse_ioc():
        indicators = tools.parse_indicators(request.form.get("indicators", ""))
        if not indicators:
            return form_page("ioc", {"indicators": "Paste at least one IP or hash."})
        keys = keys_from_form(request.form)
        needed = tools.needed_keys(indicators)
        if "abuseipdb" in needed and not tools.usable_key(keys["abuseipdb"]):
            return form_page("ioc", {"abuseipdb_key": "Add an AbuseIPDB key to check IPs."})
        if "virustotal" in needed and not tools.usable_key(keys["virustotal"]):
            return form_page("ioc", {"virustotal_key": "Add a VirusTotal key to check hashes."})
        delay = parse_delay()
        if delay is None:
            return form_page("ioc", {"delay": DELAY_ERROR})
        age_text = request.form.get("max_age", "").strip() or DEFAULT_MAX_AGE
        try:
            max_age = int(age_text)
        except ValueError:
            max_age = 0
        if not 1 <= max_age <= 365:
            return form_page("ioc", {"max_age": "Report window must be between 1 and 365 days."})

        def work(job: Job):
            return tools.run_ioc(indicators, keys, max_age, delay, store.progress_callback(job))

        return redirect(f"/job/{store.start('ioc', work).id}", 303)

    @app.post("/analyse/pdf")
    def analyse_pdf():
        upload = read_upload()
        if upload is None:
            return form_page("pdf", {"file": "Choose a file to analyse."})
        extract = "extract" in request.form
        name, data = upload

        def work(job: Job):
            path = save_upload(job, name, data, "upload.pdf")
            try:
                result = tools.run_pdf(path, name, extract, job.workdir)
            finally:
                Path(path).unlink(missing_ok=True)
                (job.workdir / "report.txt").unlink(missing_ok=True)
            zip_path = result.pop("payloads_zip", None)
            if zip_path:
                job.downloads["payloads"] = Path(zip_path)
            return result

        return redirect(f"/job/{store.start('pdf', work).id}", 303)

    def expired_page():
        return render_template("message.html", title="Result not found", message=EXPIRED,
                               tab="email"), 404

    @app.get("/job/<job_id>")
    def job_page(job_id: str):
        job = store.get(job_id)
        if job is None:
            return expired_page()
        if job.status == "running":
            return render_template("progress.html", job=job, status=store.status(job))
        if job.status == "error":
            return render_template("message.html", title="The analysis could not run",
                                   message=job.error, tab=job.tool)
        return render_template(f"result_{job.tool}.html", job=job, result=job.result)

    @app.get("/job/<job_id>/status")
    def job_status(job_id: str):
        job = store.get(job_id)
        if job is None:
            return jsonify({"status": "expired"}), 404
        return jsonify(store.status(job))

    @app.get("/job/<job_id>/json")
    def job_json(job_id: str):
        job = store.get(job_id)
        if job is None:
            return expired_page()
        if job.status != "done":
            abort(404)
        body = json.dumps(job.result, indent=2, default=str).encode("utf-8")
        return send_file(io.BytesIO(body), mimetype="application/json", as_attachment=True,
                         download_name=f"{job.tool}-result.json")

    @app.get("/job/<job_id>/payloads")
    def job_payloads(job_id: str):
        job = store.get(job_id)
        zip_path = job.downloads.get("payloads") if job is not None else None
        if job is None:
            return expired_page()
        if zip_path is None or not zip_path.is_file():
            abort(404)
        return send_file(zip_path, mimetype="application/zip", as_attachment=True,
                         download_name="payloads.zip")

    return app


if __name__ == "__main__":
    # Bind first, so a second copy fails before touching the first one's folders.
    server = make_server(HOST, PORT, create_app(), threaded=True)
    remove_stale_workdirs()
    # Turn kill and closed-terminal signals into a normal exit so the
    # JobStore's atexit cleanup runs, as it does for Ctrl+C.
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: sys.exit(0))
    print(f"Serving on http://{HOST}:{PORT} (stop with Ctrl+C)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
