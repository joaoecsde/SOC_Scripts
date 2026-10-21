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
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import pdfgen                                      # noqa: E402
from pdf_analyser_lib import extract as ex         # noqa: E402
from pdf_analyser_lib import output, pipeline, report  # noqa: E402
from pdf_analyser_lib.parser import PdfObject, load_pdf  # noqa: E402
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
        self.assertEqual(ex.find_triggers(pdf), [{"object": 1, "objstm": None, "copy": None,
                                                  "keyword": "/Names", "action": "/JavaScript",
                                                  "target_object": None, "target_copy": None}])

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


class DuplicateObjectTests(unittest.TestCase):
    """An earlier copy of an object must not be hidden by a later one."""

    JS = "<< /S /JavaScript /JS (app.alert\\(1\\)) >>"

    def test_script_in_earlier_copy_is_found(self):
        r = analyse([(1, CATALOG), (5, self.JS), (5, "<< /Type /Page >>")])
        js = findings(r, "/JavaScript")
        self.assertEqual([(f["object"], f["copy"]) for f in js], [(5, 1)])
        self.assertEqual(r["verdict"], "MEDIUM")

    def test_duplicate_with_active_content_is_medium(self):
        r = analyse([(1, CATALOG), (5, self.JS), (5, "<< /Type /Page >>")])
        dup = findings(r, "Duplicate object")
        self.assertEqual([(f["object"], f["severity"]) for f in dup], [(5, "medium")])
        self.assertIn("occurs 2 times", dup[0]["finding"])
        self.assertIn("/JS", dup[0]["finding"])

    def test_harmless_duplicate_is_info(self):
        r = analyse([(1, CATALOG), (2, "<< /Type /Page >>"), (2, "<< /Type /Page /Rotate 90 >>")])
        dup = findings(r, "Duplicate object")
        self.assertEqual([(f["object"], f["severity"]) for f in dup], [(2, "info")])
        self.assertIn("Object 2 occurs 2 times", dup[0]["finding"])
        self.assertEqual(r["verdict"], "LOW")

    def test_reference_follows_every_copy(self):
        r = analyse([(1, "<< /Type /Catalog /OpenAction 5 0 R >>"), (5, self.JS),
                     (5, "<< /S /GoTo /D [1 0 R /Fit] >>")])
        self.assertEqual(sorted(f["severity"] for f in findings(r, "/OpenAction")),
                         ["high", "info"])
        self.assertEqual(r["verdict"], "HIGH")

    def test_stream_script_in_earlier_copy_is_extracted(self):
        r = analyse([(1, CATALOG), (2, "<< /S /JavaScript /JS 3 0 R >>"),
                     (3, pdfgen.stream_obj("", b"evil()")),
                     (3, pdfgen.stream_obj("", b"fine()"))])
        js = [e["data"] for e in r["extracted"] if e["kind"] == "javascript"]
        self.assertEqual(sorted(js), [b"evil()", b"fine()"])

    def test_single_copy_has_no_copy_label(self):
        r = analyse({1: CATALOG, 5: self.JS})
        self.assertIsNone(findings(r, "/JavaScript")[0]["copy"])
        self.assertEqual(findings(r, "Duplicate object"), [])

    def test_report_and_files_name_the_copy(self):
        r = analyse([(1, CATALOG), (5, self.JS), (5, "<< /Type /Page >>")])
        self.assertIn("obj 5, copy 1", report.render(r, Colors(False)))
        with tempfile.TemporaryDirectory() as d:
            names = [p.name for p in output.write_outputs(r, Path(d))]
        self.assertIn("obj5_copy1_javascript.js.txt", names)

    def test_page_openaction_in_duplicate_is_info(self):
        r = analyse([(1, "<< /Type /Catalog /OpenAction [3 0 R /Fit] >>"),
                     (3, "<< /Type /Page >>"),
                     (1, "<< /Type /Catalog /OpenAction [3 0 R /Fit] /PageMode /UseNone >>")])
        self.assertEqual([f["severity"] for f in findings(r, "Duplicate object")], ["info"])
        self.assertEqual(r["verdict"], "LOW")

    def test_trigger_names_target_copy(self):
        r = analyse([(1, "<< /Type /Catalog /OpenAction 5 0 R >>"), (5, self.JS),
                     (5, "<< /S /GoTo /D [1 0 R /Fit] >>")])
        text = {f["severity"]: f["finding"] for f in findings(r, "/OpenAction")}
        self.assertIn("obj 5, copy 1", text["high"])
        self.assertIn("obj 5, copy 2", text["info"])

    def test_referenced_script_names_source_copy(self):
        r = analyse([(1, CATALOG), (2, "<< /S /JavaScript /JS 3 0 R >>"),
                     (3, pdfgen.stream_obj("", b"evil()")),
                     (3, pdfgen.stream_obj("", b"fine()"))])
        self.assertEqual(sorted("script in obj 3, copy 1" in f["finding"]
                                for f in findings(r, "/JavaScript")), [False, True])
        with tempfile.TemporaryDirectory() as d:
            files = {p.name: p.read_bytes() for p in output.write_outputs(r, Path(d))}
        self.assertEqual(files["obj2_javascript_from_obj3_copy1.js.txt"], b"evil()")
        self.assertEqual(files["obj2_javascript_from_obj3_copy2.js.txt"], b"fine()")

    def test_embedded_name_only_on_attachment_copy(self):
        r = analyse([(1, "<< /Type /Catalog /Names << /EmbeddedFiles << /Names [ (x) "
                         "<< /Type /Filespec /F (payload.exe) /EF << /F 7 0 R >> >> ] >> >> >>"),
                     (7, pdfgen.stream_obj("/Type /XObject /Subtype /Image", b"\x89PNG")),
                     (7, pdfgen.stream_obj("/Type /EmbeddedFile", b"MZ\x90\x00"))])
        emb = [(e["object"], e["copy"], e["name"]) for e in r["extracted"]
               if e["kind"] == "embedded_file"]
        self.assertEqual(emb, [(7, 1, None), (7, 2, "payload.exe")])

    def test_attachment_disguised_as_image_is_still_extracted(self):
        r = analyse([(1, "<< /Type /Catalog /Names << /EmbeddedFiles << /Names [ (x) "
                         "<< /Type /Filespec /F (evil.exe) /EF << /F 9 0 R >> >> ] >> >> >>"),
                     (9, pdfgen.stream_obj("", b"harmless")),
                     (9, pdfgen.stream_obj("/Subtype /Image", b"MZ\x90\x00payload"))])
        emb = [(e["copy"], e["name"]) for e in r["extracted"] if e["kind"] == "embedded_file"]
        self.assertEqual(emb, [(1, "evil.exe"), (2, None)])
        self.assertEqual(r["verdict"], "HIGH")

    def test_embedded_keeps_every_copy_when_none_looks_like_attachment(self):
        pdf = load([(2, "<< /Type /Filespec /F (a.bin) /EF << /F 7 0 R >> >>"),
                    (7, pdfgen.stream_obj("/Type /XObject", b"one")),
                    (7, pdfgen.stream_obj("/Type /XObject", b"two"))])
        self.assertEqual([e["data"] for e in ex.find_embedded_files(pdf)], [b"one", b"two"])

    def test_shared_script_stream_decoded_once(self):
        pdf = load([(1, "<< /JS 4 0 R >>"), (2, "<< /JS 4 0 R >>"), (3, "<< /JS 4 0 R >>"),
                    (4, pdfgen.stream_obj("/Filter /Foo", b"x", flate=False))])
        ex.find_javascript(pdf)
        self.assertEqual(len([e for e in pdf.errors if e.startswith("object 4:")]), 1)

    def test_undecodable_script_logged_once_in_report(self):
        r = analyse([(1, CATALOG), (2, "<< /JS 4 0 R >>"), (3, "<< /JS 4 0 R >>"),
                     (4, pdfgen.stream_obj("/Filter /Foo", b"x", flate=False))])
        self.assertEqual(len([e for e in r["errors"] if e.startswith("object 4:")]), 1)

    def test_keyword_listed_once_per_id(self):
        pdf = load([(2, "<< /Type /XObject >>"), (2, "<< /Type /XObject /X 1 >>")])
        self.assertEqual(ex.find_keywords(pdf)["/XObject"], [2])

    def _analyse_bytes(self, data):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "gen.pdf")
            with open(path, "wb") as fh:
                fh.write(data)
            return pipeline.analyse_pdf(path)

    def test_reference_follows_every_generation(self):
        # Readers may ignore a generation mismatch, so no copy is skipped.
        for ref in ("5 0 R", "5 1 R", "5 3 R"):
            data = pdfgen.make_pdf([(1, "<< /Type /Catalog /OpenAction %s >>" % ref),
                                    (5, "<< /S /GoTo /D [1 0 R /Fit] >>"), (5, self.JS)])
            r = self._analyse_bytes(data.replace(b"5 0 obj\n<< /S /JavaScript",
                                                 b"5 1 obj\n<< /S /JavaScript"))
            self.assertEqual(sorted(f["severity"] for f in findings(r, "/OpenAction")),
                             ["high", "info"], ref)

    def test_next_chain_follows_every_generation(self):
        data = pdfgen.make_pdf([(1, "<< /Type /Catalog /OpenAction << /S /GoTo /D [1 0 R /Fit] "
                                    "/Next 8 0 R >> >>"),
                                (8, "<< /S /GoTo /D [1 0 R /Fit] >>"),
                                (8, "<< /S /Launch /F (a.exe) >>")])
        r = self._analyse_bytes(data.replace(b"8 0 obj\n<< /S /Launch", b"8 1 obj\n<< /S /Launch"))
        self.assertEqual([f["severity"] for f in findings(r, "/OpenAction")], ["high"])

    def test_decimal_generation_does_not_crash(self):
        r = analyse({1: "<< /Type /Catalog /RichMedia 2 0.0 R >>",
                     2: pdfgen.stream_obj("", b"swf")})
        self.assertEqual(r["verdict"], "MEDIUM")

    def test_document_js_names_each_copy(self):
        pdf = load([(1, "<< /Type /Catalog /Names << /JavaScript 12 0 R >> >>"),
                    (12, "<< /Names [ (a) << /S /JavaScript /JS (one) >> ] >>"),
                    (12, "<< /Names [ (a) << /S /JavaScript /JS (two) >> ] >>")])
        got = [(t["target_object"], t["target_copy"]) for t in ex.find_triggers(pdf)
               if t["keyword"] == "/Names"]
        self.assertEqual(got, [(12, 1), (12, 2)])

    def test_trigger_fan_out_stays_linear(self):
        # k copies each of the /AA holder, the /AA container and the action.
        k = 60
        objs = []
        for i in range(k):
            objs += [(1, "<< /Type /Catalog /AA 2 0 R /X %d >>" % i),
                     (2, "<< /O 3 0 R /C 3 0 R /X %d >>" % i),
                     (3, "<< /S /GoTo /D [1 0 R /Fit] /X %d >>" % i)]
        triggers = ex.find_triggers(load(objs))
        self.assertEqual(sorted(t["target_copy"] for t in triggers if t["target_object"] == 3),
                         list(range(1, k + 1)))
        self.assertLessEqual(len(triggers), 2 * k)   # plus one unresolved entry per /X value

    def test_repeated_openaction_reported_once_per_target_copy(self):
        k = 40
        objs = []
        for _ in range(k):
            objs += [(1, "<< /Type /Catalog /OpenAction 2 0 R >>"),
                     (2, "<< /S /GoTo /D [1 0 R /Fit] >>")]
        triggers = ex.find_triggers(load(objs))
        self.assertEqual(len(triggers), k)

    def test_repeated_names_tree_reported_once_per_node_copy(self):
        k = 40
        objs = []
        for _ in range(k):
            objs += [(1, "<< /Type /Catalog /Names << /JavaScript 4 0 R >> >>"),
                     (4, "<< /Names [ (a) << /S /JavaScript /JS (x) >> ] >>")]
        triggers = ex.find_triggers(load(objs))
        self.assertEqual(len(triggers), k)

    def test_next_chain_walked_once_for_all_target_copies(self):
        k = 60
        objs = [(1, "<< /Type /Catalog /OpenAction 2 0 R >>")]
        for i in range(k):
            objs += [(2, "<< /S /GoTo /D [1 0 R /Fit] /Next 3 0 R /X %d >>" % i),
                     (3, "<< /S /GoTo /D [1 0 R /Fit] /Next 4 0 R /X %d >>" % i),
                     (4, "<< /S /Launch /F (a.exe) /X %d >>" % i)]
        pdf = load(objs)
        calls, real = [], PdfObject.items

        def counting(obj):
            calls.append(obj.id)
            return real(obj)
        with mock.patch.object(PdfObject, "items", counting):
            triggers = ex.find_triggers(pdf)
        self.assertEqual({t["action"] for t in triggers}, {"/Launch"})
        self.assertLessEqual(calls.count(4), k)

    def _count_streams(self, run):
        calls, real = [], PdfObject.stream

        def counting(obj):
            calls.append((obj.id, obj.copy))
            return real(obj)
        with mock.patch.object(PdfObject, "stream", counting):
            run()
        return calls

    def test_shared_richmedia_stream_decoded_once(self):
        pdf = load([(1, "<< /RichMedia 4 0 R >>"), (2, "<< /RichMedia 4 0 R >>"),
                    (3, "<< /RichMedia 4 0 R >>"), (4, pdfgen.stream_obj("", b"swf"))])
        calls = self._count_streams(lambda: ex.find_richmedia_streams(pdf))
        self.assertEqual(calls.count((4, 1)), 1)

    def test_referenced_script_decoded_once_in_pipeline(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_pdf(d, {1: CATALOG, 2: "<< /S /JavaScript /JS 3 0 R >>",
                                 3: pdfgen.stream_obj("", b"evil()")})
            calls = self._count_streams(lambda: pipeline.analyse_pdf(path))
        self.assertEqual(calls.count((3, 1)), 1)


class CodeReviewGapTests(unittest.TestCase):
    """Detection gaps from the code review (verdicts that were too low)."""

    def test_uncompressed_objstm_is_expanded(self):
        index, body = "3 0\n", "<< /S /JavaScript /JS (app.alert(1)) >>\n"
        objstm = ("<< /Type /ObjStm /N 1 /First %d /Length %d >>\nstream\n%s%s\nendstream"
                  % (len(index), len(index + body), index, body))
        r = analyse({1: "<< /Type /Catalog /OpenAction 3 0 R >>", 4: objstm})
        self.assertEqual(r["errors"], [])
        self.assertEqual(r["verdict"], "HIGH")
        self.assertEqual([f["object"] for f in findings(r, "/JavaScript")], [3])

    def test_script_in_indirect_string_is_checked_for_markers(self):
        r = analyse({1: CATALOG, 3: "<< /S /JavaScript /JS 5 0 R >>",
                     5: "(eval(unescape('%u9090')))"})
        js = findings(r, "/JavaScript")
        self.assertEqual([f["severity"] for f in js], ["high"])
        self.assertIn("eval", js[0]["markers"])

    def test_xfa_form_is_medium(self):
        r = analyse({1: "<< /Type /Catalog /AcroForm << /XFA 6 0 R >> >>",
                     6: pdfgen.stream_obj("", b"<script>x()</script>")})
        self.assertEqual(r["verdict"], "MEDIUM")
        self.assertEqual([f["object"] for f in findings(r, "/XFA")], [1])

    def test_gotoe_local_is_medium_and_on_open_is_high(self):
        gotoe = "<< /S /GoToE /T << /R /C /N (x.pdf) >> >>"
        self.assertEqual(analyse({1: CATALOG, 2: gotoe})["verdict"], "MEDIUM")
        r = analyse({1: "<< /Type /Catalog /OpenAction %s >>" % gotoe})
        self.assertEqual(r["verdict"], "HIGH")
        self.assertEqual([f["severity"] for f in findings(r, "/GoToE")], ["medium"])

    def test_gotoe_external_is_high(self):
        r = analyse({1: CATALOG, 2: "<< /S /GoToE /F (http://evil.com/x.pdf) >>"})
        self.assertEqual([f["severity"] for f in findings(r, "/GoToE")], ["high"])

    def test_importdata_is_medium_and_on_open_is_high(self):
        imp = "<< /S /ImportData /F (data.fdf) >>"
        r = analyse({1: CATALOG, 2: imp})
        self.assertEqual([f["target"] for f in findings(r, "/ImportData")], ["data.fdf"])
        self.assertEqual(r["verdict"], "MEDIUM")
        r = analyse({1: "<< /Type /Catalog /OpenAction %s >>" % imp})
        self.assertEqual(r["verdict"], "HIGH")

    def test_rendition_with_js_on_open_is_high(self):
        r = analyse({1: "<< /Type /Catalog /OpenAction "
                        "<< /S /Rendition /JS (app.alert(1)) >> >>"})
        self.assertEqual([f["severity"] for f in findings(r, "/OpenAction")], ["high"])
        self.assertEqual(r["verdict"], "HIGH")

    def test_duplicate_with_new_action_types_is_medium(self):
        for action in ("/GoToE", "/ImportData"):
            r = analyse([(1, CATALOG), (2, "<< /Type /Annot >>"),
                         (2, "<< /S %s /F (x.pdf) >>" % action)])
            dup = findings(r, "Duplicate object")
            self.assertEqual([f["severity"] for f in dup], ["medium"], action)

    def test_undecodable_objstm_error_says_not_expanded(self):
        objstm = "<< /Type /ObjStm /N 1 /First 4 /Filter /DCTDecode /Length 3 >>\nstream\nxyz\nendstream"
        r = analyse({1: CATALOG, 4: objstm})
        self.assertEqual(len(r["errors"]), 1)
        self.assertIn("/ObjStm not expanded", r["errors"][0])
        self.assertNotIn("index", r["errors"][0])

    def test_escaped_encrypt_name_in_trailer(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "enc.pdf")
            with open(path, "wb") as fh:
                fh.write(pdfgen.make_pdf({1: CATALOG},
                                         trailer="<< /Root 1 0 R /Encr#79pt 9 0 R >>"))
            self.assertTrue(load_pdf(path).encrypted)


if __name__ == "__main__":
    unittest.main()
