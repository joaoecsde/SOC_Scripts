"""In-memory store for background analysis jobs.

The web app starts each analysis as a job, polls ``status`` and renders the
stored result. Job folders are deleted when the job ends, unless the job
registered downloads, in which case they live until the job expires.
"""
from __future__ import annotations

import atexit
import logging
import secrets
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from tools import Progress, ToolError

WORKDIR_PREFIX = "soc-web-"
GENERIC_ERROR = ("The analysis failed unexpectedly. "
                 "Details were written to the server console.")


def remove_stale_workdirs() -> None:
    """Delete job folders left by an earlier server that was killed or crashed."""
    for path in Path(tempfile.gettempdir()).glob(f"{WORKDIR_PREFIX}*"):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=True)


class Job:
    """One analysis run.

    Attributes:
        id: Unguessable job id used in URLs.
        tool: "email", "ioc" or "pdf".
        status: "running", "done" or "error".
        done, total, label: Progress counters and current step text.
        result: Value returned by the job function.
        error: User-facing error message, if any.
        workdir: Temporary folder for this job's files.
        finished_at: Epoch seconds when the job ended.
        downloads: Files that must survive until expiry, by name.
    """

    def __init__(self, tool: str, workdir: Path) -> None:
        self.id: str = secrets.token_urlsafe(16)
        self.tool = tool
        self.status = "running"
        self.done = 0
        self.total = 0
        self.label = ""
        self.result: Any = None
        self.error: Optional[str] = None
        self.workdir = workdir
        self.finished_at: Optional[float] = None
        self.downloads: Dict[str, Path] = {}
        self._thread: Optional[threading.Thread] = None


class JobStore:
    """Thread-safe registry of jobs with time-based expiry.

    Args:
        ttl_seconds: How long a finished job is kept.
    """

    def __init__(self, ttl_seconds: int = 1800) -> None:
        self.ttl_seconds = ttl_seconds
        self._jobs: Dict[str, Job] = {}
        self._lock = threading.Lock()
        atexit.register(self.close)

    def close(self) -> None:
        """Delete every job folder; runs at interpreter exit."""
        with self._lock:
            jobs = list(self._jobs.values())
        for job in jobs:
            shutil.rmtree(job.workdir, ignore_errors=True)

    def start(self, tool: str, fn: Callable[[Job], Any]) -> Job:
        """Create a job and run ``fn(job)`` in a daemon thread.

        Args:
            tool: Tool name.
            fn: Job function; its return value becomes ``job.result``.

        Returns:
            The running job.
        """
        job = Job(tool, Path(tempfile.mkdtemp(prefix=WORKDIR_PREFIX)))
        with self._lock:
            self._jobs[job.id] = job
        job._thread = threading.Thread(target=self._run, args=(job, fn), daemon=True)
        job._thread.start()
        return job

    def _run(self, job: Job, fn: Callable[[Job], Any]) -> None:
        result, error, status = None, None, "done"
        try:
            result = fn(job)
        except ToolError as exc:
            status, error = "error", str(exc)
        except Exception:
            logging.exception("Job %s (%s) failed", job.id, job.tool)
            status, error = "error", GENERIC_ERROR
        if not job.downloads:
            shutil.rmtree(job.workdir, ignore_errors=True)
        with self._lock:
            job.result, job.error, job.status = result, error, status
            job.finished_at = time.time()

    def get(self, job_id: str) -> Optional[Job]:
        """Return the job, or None if unknown or expired."""
        self.sweep()
        with self._lock:
            return self._jobs.get(job_id)

    def progress_callback(self, job: Job) -> Progress:
        """Return a ``progress(done, total, label)`` function for ``job``."""
        def progress(done: int, total: int, label: str) -> None:
            with self._lock:
                job.done, job.total, job.label = done, total, label
        return progress

    def sweep(self, now: Optional[float] = None) -> None:
        """Remove expired jobs and delete their folders."""
        now = time.time() if now is None else now
        with self._lock:
            expired = [j for j in self._jobs.values()
                       if j.finished_at is not None
                       and now - j.finished_at > self.ttl_seconds]
            for job in expired:
                del self._jobs[job.id]
        for job in expired:
            shutil.rmtree(job.workdir, ignore_errors=True)

    def status(self, job: Job) -> dict:
        """Return the pollable state of a job (never the result)."""
        with self._lock:
            return {"status": job.status, "done": job.done, "total": job.total,
                    "label": job.label, "error": job.error}
