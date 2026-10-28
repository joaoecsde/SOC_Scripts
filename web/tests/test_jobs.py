"""Tests for the background job store in web/jobs.py.

Run from the web folder:
    python3 -m unittest tests.test_jobs -v
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import jobs                                     # noqa: E402
from tools import ToolError                     # noqa: E402


def run(store, fn):
    """Start a job and wait for its thread to finish."""
    job = store.start("email", fn)
    job._thread.join(timeout=5)
    return job


class JobStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = jobs.JobStore()

    def test_job_runs_and_stores_result(self):
        job = run(self.store, lambda j: {"ok": 1})
        self.assertEqual(job.status, "done")
        self.assertEqual(job.result, {"ok": 1})
        self.assertFalse(job.workdir.exists())

    def test_close_removes_all_workdirs(self):
        def fn(job):
            (job.workdir / "payloads.zip").write_bytes(b"x")
            job.downloads["payloads"] = job.workdir / "payloads.zip"
        job = run(self.store, fn)
        self.assertTrue(job.workdir.exists())
        self.store.close()
        self.assertFalse(job.workdir.exists())

    def test_progress_callback_updates_status(self):
        def fn(job):
            self.store.progress_callback(job)(2, 5, "x")
            return None
        job = run(self.store, fn)
        info = self.store.status(job)
        self.assertEqual((info["done"], info["total"], info["label"]), (2, 5, "x"))
        self.assertEqual(set(info), {"status", "done", "total", "label", "error"})

    def test_tool_error_message_is_kept(self):
        def fn(job):
            raise ToolError("Bad file")
        job = run(self.store, fn)
        self.assertEqual(job.status, "error")
        self.assertEqual(job.error, "Bad file")

    def test_failed_job_cleans_up_and_hides_traceback(self):
        def fn(job):
            raise ValueError("secret detail")
        with self.assertLogs(level="ERROR"):
            job = run(self.store, fn)
        self.assertEqual(job.status, "error")
        self.assertNotIn("secret detail", job.error)
        self.assertNotIn("Traceback", job.error)
        self.assertFalse(job.workdir.exists())

    def test_downloads_keep_workdir_until_expiry(self):
        def fn(job):
            job.downloads["payloads"] = job.workdir / "payloads.zip"
            return None
        job = run(self.store, fn)
        self.assertTrue(job.workdir.exists())
        self.store.sweep(now=time.time() + 1801)
        self.assertFalse(job.workdir.exists())
        self.assertIsNone(self.store.get(job.id))


class StaleWorkdirTests(unittest.TestCase):
    def test_removes_only_job_folders(self):
        with tempfile.TemporaryDirectory() as tmp:
            stale = Path(tmp, jobs.WORKDIR_PREFIX + "old")
            stale.mkdir()
            (stale / "phish.eml").write_bytes(b"x")
            other = Path(tmp, "unrelated")
            other.mkdir()
            with mock.patch("jobs.tempfile.gettempdir", return_value=tmp):
                jobs.remove_stale_workdirs()
            self.assertFalse(stale.exists())
            self.assertTrue(other.exists())


if __name__ == "__main__":
    unittest.main()
