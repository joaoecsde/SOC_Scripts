"""Tests for pdf_analyser_lib.output.

Run from the PDF_analyser folder:
    python3 -m unittest tests.test_output -v
"""
import os
import sys
import tempfile
import unittest
import zipfile
from datetime import date
from pathlib import Path
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from pdf_analyser_lib import output  # noqa: E402

TODAY = date(2026, 10, 19)


def item(obj, kind, data=b"x", name=None):
    return {"object": obj, "kind": kind, "name": name, "data": data}


def payloads(run):
    """Name -> bytes of every file in the run's payloads.zip (password 'infected')."""
    with zipfile.ZipFile(run / "payloads.zip") as zf:
        return {n: zf.read(n, pwd=b"infected") for n in zf.namelist()}


def result_with(*items):
    return {"file": "a.pdf", "sha256": "0" * 64, "size": 1, "verdict": "LOW",
            "encrypted": False, "partial": False, "errors": [], "findings": [],
            "extracted": list(items)}


def write(run, *items):
    """Stage ``items`` the way analyse_pdf does, then write_outputs into ``run``."""
    with tempfile.TemporaryDirectory() as d:
        stage = output.PayloadStage(Path(d))
        r = result_with(*[stage.add({k: v for k, v in i.items() if k != "data"}, i["data"])
                          for i in items])
        return output.write_outputs(r, run, Path(d))


class OutputTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name) / "results"  # does not exist yet

    def test_run_dir_name(self):
        d = output.make_run_dir("/x/Invoice March.pdf", TODAY, self.base)
        self.assertEqual(d.name, "19-10-2026-Invoice_March")
        self.assertTrue(d.is_dir())

    def test_same_day_suffix(self):
        a = output.make_run_dir("/x/a.pdf", TODAY, self.base)
        b = output.make_run_dir("/x/a.pdf", TODAY, self.base)
        c = output.make_run_dir("/x/a.pdf", TODAY, self.base)
        self.assertEqual(b.name, a.name + "-2")
        self.assertEqual(c.name, a.name + "-3")

    def test_files_written(self):
        run = output.make_run_dir("/x/a.pdf", TODAY, self.base)
        paths = write(run, item(12, "javascript", "app.alert(1)".encode()),
                      item(27, "embedded_file", b"MZ", "inv.exe"))
        self.assertEqual({p.name for p in paths}, {"report.txt", "payloads.zip"})
        # The staging folder is gone: no loose payload is left on disk.
        self.assertEqual(sorted(os.listdir(run)), ["payloads.zip", "report.txt"])
        files = payloads(run)
        self.assertEqual(set(files), {"obj12_javascript.js.txt", "obj27_embedded_inv.exe.bin"})
        self.assertEqual(files["obj27_embedded_inv.exe.bin"], b"MZ")

    def test_zip_needs_password(self):
        run = output.make_run_dir("/x/a.pdf", TODAY, self.base)
        write(run, item(27, "embedded_file", b"MZ", "inv.exe"))
        with zipfile.ZipFile(run / "payloads.zip") as zf:
            with self.assertRaises(RuntimeError):   # "password required"
                zf.read("obj27_embedded_inv.exe.bin")

    def test_no_zip_when_nothing_extracted(self):
        run = output.make_run_dir("/x/a.pdf", TODAY, self.base)
        self.assertEqual([p.name for p in write(run)], ["report.txt"])
        self.assertEqual(os.listdir(run), ["report.txt"])

    def test_missing_zip_command_is_oserror(self):
        run = output.make_run_dir("/x/a.pdf", TODAY, self.base)
        with mock.patch.object(output.shutil, "which", return_value=None):
            with self.assertRaises(OSError):
                write(run, item(1, "javascript", b"j"))
        self.assertEqual(os.listdir(run), ["report.txt"])

    def test_traversal_name_stays_inside(self):
        run = output.make_run_dir("/x/a.pdf", TODAY, self.base)
        for p in write(run, item(5, "embedded_file", b"a", "../../evil.exe")):
            self.assertEqual(p.parent, run)
        self.assertEqual(sorted(os.listdir(self.base)), [run.name])
        self.assertEqual(list(payloads(run)), ["obj5_embedded_evil.exe.bin"])

    def test_empty_sanitised_name(self):
        run = output.make_run_dir("/x/a.pdf", TODAY, self.base)
        write(run, item(5, "embedded_file", b"a", ".."), item(6, "embedded_file", b"b", "/"))
        names = set(payloads(run))
        self.assertIn("obj5_embedded.bin", names)
        self.assertIn("obj6_embedded.bin", names)

    def test_duplicates_never_overwrite(self):
        run = output.make_run_dir("/x/a.pdf", TODAY, self.base)
        write(run, item(3, "javascript", b"one"), item(3, "javascript", b"two"),
              item(3, "javascript", b"three"),
              item(4, "richmedia", b"r1"), item(4, "richmedia", b"r2"),
              item(7, "embedded_file", b"e1", "a.exe"),
              item(7, "embedded_file", b"e2", "a.exe"))
        files = payloads(run)
        self.assertEqual(len(files), 7)
        self.assertEqual(files["obj3_javascript.js.txt"], b"one")
        self.assertEqual(files["obj3_javascript_2.js.txt"], b"two")
        self.assertEqual(files["obj3_javascript_3.js.txt"], b"three")
        self.assertEqual(files["obj4_richmedia_2.bin"], b"r2")
        self.assertEqual(files["obj7_embedded_a.exe_2.bin"], b"e2")

    def test_no_bare_executable_extensions(self):
        run = output.make_run_dir("/x/a.pdf", TODAY, self.base)
        write(run, item(1, "javascript", b"j"), item(2, "embedded_file", b"e", "x.js"),
              item(3, "richmedia", b"r"))
        for name in payloads(run):
            self.assertTrue(name.endswith((".txt", ".bin")), name)

    def test_javascript_utf8_and_bytes_exact(self):
        run = output.make_run_dir("/x/a.pdf", TODAY, self.base)
        write(run, item(1, "javascript", "café".encode("utf-8")),
              item(2, "richmedia", bytes(range(256))))
        files = payloads(run)
        self.assertEqual(files["obj1_javascript.js.txt"], "café".encode("utf-8"))
        self.assertEqual(files["obj2_richmedia.bin"], bytes(range(256)))

    def test_failed_write_is_kept_and_hashing_continues(self):
        with tempfile.TemporaryDirectory() as d:
            stage = output.PayloadStage(Path(d))
            full = OSError(28, "No space left on device")
            with mock.patch.object(Path, "write_bytes", side_effect=full):
                a = stage.add({"object": 1, "kind": "richmedia", "name": None}, b"one")
            b = stage.add({"object": 2, "kind": "richmedia", "name": None}, b"two")
        self.assertIs(stage.error, full)
        self.assertEqual((a["payload_name"], b["payload_name"]), (None, None))
        self.assertEqual(b["size"], 3)   # still hashed, no longer written

    def test_results_dir_is_repo_root(self):
        repo_root = Path(ROOT).resolve().parent
        self.assertEqual(output.RESULTS_DIR.parent, repo_root)
        self.assertEqual(output.RESULTS_DIR.name, "pdf-analysis-results")


if __name__ == "__main__":
    unittest.main()
