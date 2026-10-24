"""Tests for pdf_analyser.py (the command line).

Run from the PDF_analyser folder:
    python3 -m unittest tests.test_cli -v

Tests with -out / --json write to the real repo-root pdf-analysis-results/,
so each uses a unique PDF name and removes only its own run folder.
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from pdfgen import make_pdf  # noqa: E402

SCRIPT = os.path.join(ROOT, "pdf_analyser.py")
RESULTS = Path(ROOT).parent / "pdf-analysis-results"

CLEAN = make_pdf({1: "<< /Type /Catalog >>"})
PLAIN_JS = make_pdf({1: "<< /Type /Catalog >>",
                     2: "<< /S /JavaScript /JS (app.alert\\(1\\)) >>"})
OPEN_JS = make_pdf({1: "<< /Type /Catalog /OpenAction 2 0 R >>",
                    2: "<< /S /JavaScript /JS (app.alert\\(1\\)) >>"})
TWO_JS = make_pdf({1: "<< /Type /Catalog /OpenAction 2 0 R >>",
                   2: "<< /S /JavaScript /JS (app.alert\\(1\\)) >>",
                   3: "<< /S /JavaScript /JS (app.alert\\(2\\)) >>"})


def run(*args):
    return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)


class CliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.stem = "cli_test_" + uuid.uuid4().hex
        self.run_dir = RESULTS / f"{date.today().strftime('%d-%m-%Y')}-{self.stem}"
        # Remove exactly this test's run folder, never the results folder itself.
        self.addCleanup(lambda: shutil.rmtree(self.run_dir, ignore_errors=True))

    def pdf(self, data, name=None):
        path = os.path.join(self._tmp.name, (name or self.stem) + ".pdf")
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def test_missing_file_exit_3(self):
        r = run(os.path.join(self._tmp.name, "nope.pdf"))
        self.assertEqual(r.returncode, 3)
        self.assertIn("Error", r.stderr)

    def test_not_a_pdf_exit_3(self):
        path = os.path.join(self._tmp.name, "a.txt")
        with open(path, "w") as fh:
            fh.write("just text")
        r = run(path)
        self.assertEqual(r.returncode, 3)
        self.assertIn("Error", r.stderr)

    def test_usage_error_exit_3(self):
        # argparse would exit 2, which means HIGH under --exit-code.
        r = run(self.pdf(CLEAN), "--bogus-flag")
        self.assertEqual(r.returncode, 3)
        self.assertIn("usage:", r.stderr)
        self.assertIn("--bogus-flag", r.stderr)
        self.assertEqual(run().returncode, 3)

    def test_exit_code_flag(self):
        self.assertEqual(run(self.pdf(CLEAN, "clean"), "--exit-code").returncode, 0)
        self.assertEqual(run(self.pdf(PLAIN_JS, "plain"), "--exit-code").returncode, 1)
        self.assertEqual(run(self.pdf(OPEN_JS, "open"), "--exit-code").returncode, 2)

    def test_without_exit_code_flag_is_0(self):
        r = run(self.pdf(OPEN_JS))
        self.assertEqual(r.returncode, 0)
        self.assertIn("HIGH", r.stdout)

    def test_json_only_creates_folder_with_json(self):
        r = run(self.pdf(OPEN_JS), "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Results saved to", r.stdout)
        self.assertEqual({p.name for p in self.run_dir.iterdir()}, {"JSON_report.json"})
        data = json.loads((self.run_dir / "JSON_report.json").read_text(encoding="utf-8"))
        self.assertEqual(data["verdict"], "HIGH")

    def test_out_and_json_share_folder(self):
        r = run(self.pdf(OPEN_JS), "-out", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        names = {p.name for p in self.run_dir.iterdir()}
        self.assertIn("report.txt", names)
        self.assertIn("JSON_report.json", names)
        self.assertFalse((RESULTS / (self.run_dir.name + "-2")).exists())

    def test_out_zips_payloads_and_removes_staging(self):
        before = {p.name for p in RESULTS.glob(".payloads-*")} if RESULTS.exists() else set()
        r = run(self.pdf(OPEN_JS), "-out")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual({p.name for p in self.run_dir.iterdir()}, {"report.txt", "payloads.zip"})
        self.assertEqual({p.name for p in RESULTS.glob(".payloads-*")}, before)

    def test_staging_failure_still_prints_verdict(self):
        # A hostile file can fill the disk while payloads are staged; the
        # verdict must still be printed before the write error.
        # The run folder still gets report.txt and the JSON, only no zip.
        import pdf_analyser
        full = OSError(28, "No space left on device")
        cases = {"payload write fails": (OPEN_JS, mock.patch.object(
                     Path, "write_bytes", side_effect=full)),
                 # The first payload is staged, the second fails: no zip, so the
                 # JSON must not name the first one as inside payloads.zip.
                 "second payload write fails": (TWO_JS, mock.patch.object(
                     Path, "write_bytes", side_effect=[None, full])),
                 "staging folder cannot be made": (OPEN_JS, mock.patch.object(
                     pdf_analyser, "payload_stage", side_effect=full))}
        for name, (data, failure) in cases.items():
            with self.subTest(name):
                shutil.rmtree(self.run_dir, ignore_errors=True)
                out, err = io.StringIO(), io.StringIO()
                with mock.patch.object(sys, "argv",
                                       ["pdf_analyser.py", self.pdf(data), "-out", "--json"]), \
                     failure, redirect_stdout(out), redirect_stderr(err):
                    with self.assertRaises(SystemExit) as cm:
                        pdf_analyser.main()
                self.assertEqual(cm.exception.code, 3)
                self.assertIn("HIGH", out.getvalue())
                self.assertIn("cannot save payloads", err.getvalue())
                self.assertIn("No space left on device", err.getvalue())
                self.assertEqual({p.name for p in self.run_dir.iterdir()},
                                 {"report.txt", "JSON_report.json"})
                saved = json.loads((self.run_dir / "JSON_report.json").read_text(encoding="utf-8"))
                self.assertTrue(saved["extracted"])
                self.assertEqual([e["payload_name"] for e in saved["extracted"]],
                                 [None] * len(saved["extracted"]))

    def test_out_flag_creates_folder(self):
        r = run(self.pdf(CLEAN), "-out")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((self.run_dir / "report.txt").is_file())


if __name__ == "__main__":
    unittest.main()
