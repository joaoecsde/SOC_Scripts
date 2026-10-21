"""Tests for pdf_analyser_lib.extract.

Run from the PDF_analyser folder:
    python3 -m unittest discover tests -v
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import pdfgen                                    # noqa: E402
from pdf_analyser_lib.parser import load_pdf     # noqa: E402
from pdf_analyser_lib import extract as ex       # noqa: E402


def _load(objects, trailer="<< /Root 1 0 R >>"):
    data = pdfgen.make_pdf(objects, trailer)
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        f.write(data)
    try:
        return load_pdf(f.name)
    finally:
        os.unlink(f.name)


class ExtractTests(unittest.TestCase):
    def test_decode_literal_escapes(self):
        toks = ["(", "a\\", "(", "b\\", ")", "\\n\\101", ")"]
        self.assertEqual(ex.decode_pdf_string(toks), "a(b)\nA")
        self.assertEqual(ex.decode_pdf_string(["(", "ab\\\ncd", ")"]), "abcd")

    def test_decode_hex_and_utf16(self):
        self.assertEqual(ex.decode_pdf_string(["<", "6170702e616c657274", ">", " "]), "app.alert")
        self.assertEqual(ex.decode_pdf_string(["<", "FEFF00410042", ">"]), "AB")
        self.assertEqual(ex.decode_pdf_string(["<", "4 1 4", ">"]), "A@")
        self.assertEqual(ex.decode_pdf_string(["/Name"]), "")
        self.assertEqual(ex.decode_pdf_string(None), "")

    def test_ref_ids(self):
        self.assertEqual(ex.ref_ids(["3", " ", "0", " ", "R", " "]), [3])
        self.assertEqual(ex.ref_ids(["[", "4", " ", "0", " ", "R", " ", "5", " ", "0", " ", "R", "]"]), [4, 5])
        self.assertEqual(ex.ref_ids(None), [])

    def test_inline_js(self):
        pdf = _load({1: "<< /Type /Catalog >>", 4: "<< /S /JavaScript /JS (app.alert\\(1\\)) >>"})
        res = ex.find_javascript(pdf)
        self.assertEqual(res, [{"object": 4, "objstm": None, "copy": None, "source_object": 4,
                                "source_copy": None, "code": "app.alert(1)",
                                "data": None}])

    def test_js_in_referenced_stream(self):
        pdf = _load({1: "<< /Type /Catalog >>", 2: "<< /S /JavaScript /JS 3 0 R >>",
                     3: pdfgen.stream_obj("", b"var x=1;")})
        res = ex.find_javascript(pdf)
        self.assertEqual(len(res), 1)
        self.assertEqual((res[0]["object"], res[0]["source_object"], res[0]["code"]),
                         (2, 3, "var x=1;"))

    def test_nested_inline_js(self):
        pdf = _load({1: "<< /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >>"})
        res = ex.find_javascript(pdf)
        self.assertEqual([(r["object"], r["source_object"], r["code"]) for r in res],
                         [(1, 1, "app.alert(1)")])

    def test_js_string_containing_ref_pattern(self):
        pdf = _load({1: "<< /JS (see 3 0 R now) >>", 3: pdfgen.stream_obj("", b"other")})
        self.assertEqual([r["code"] for r in ex.find_javascript(pdf)], ["see 3 0 R now"])

    def test_dangling_js_reference(self):
        pdf = _load({1: "<< /JS 9 0 R >>"})
        self.assertEqual(ex.find_javascript(pdf), [{"object": 1, "objstm": None, "copy": None,
                                                    "source_object": 9, "source_copy": None,
                                                    "code": "", "data": None}])

    def test_js_dedup_by_source(self):
        pdf = _load({2: "<< /JS 3 0 R >>", 4: "<< /JS 3 0 R >>",
                     3: pdfgen.stream_obj("", b"x")})
        self.assertEqual(len(ex.find_javascript(pdf)), 1)

    def test_hex_escaped_names_detected(self):
        pdf = _load({1: "<< /Open#41ction 2 0 R >>", 2: "<< /S /JavaScript /J#53 (x) >>"})
        js = ex.find_javascript(pdf)
        self.assertEqual([j["code"] for j in js], ["x"])
        trig = ex.find_triggers(pdf)
        self.assertEqual(len(trig), 1)
        self.assertEqual(trig[0]["keyword"], "/OpenAction")
        self.assertEqual(trig[0]["action"], "/JavaScript")

    def test_openaction_to_js_ref(self):
        pdf = _load({1: "<< /OpenAction 2 0 R >>", 2: "<< /S /JavaScript /JS (x) >>"})
        self.assertEqual(ex.find_triggers(pdf), [{"object": 1, "objstm": None, "copy": None,
                         "keyword": "/OpenAction", "action": "/JavaScript", "target_object": 2,
                         "target_copy": None}])

    def test_openaction_inline_dict(self):
        pdf = _load({1: "<< /OpenAction << /S /Launch /F (a.exe) >> >>"})
        t = ex.find_triggers(pdf)
        self.assertEqual((t[0]["action"], t[0]["target_object"]), ("/Launch", None))

    def test_openaction_destination_array(self):
        pdf = _load({1: "<< /OpenAction [3 0 R /Fit] >>", 3: "<< /Type /Page >>"})
        t = ex.find_triggers(pdf)
        self.assertEqual(len(t), 1)
        self.assertIsNone(t[0]["action"])

    def test_aa_subentry(self):
        pdf = _load({1: "<< /AA << /O 5 0 R >> >>", 5: "<< /S /URI /URI (http://a.b) >>"})
        t = ex.find_triggers(pdf)
        self.assertEqual(len(t), 1)
        self.assertEqual((t[0]["keyword"], t[0]["action"], t[0]["target_object"]),
                         ("/AA", "/URI", 5))

    def test_aa_multiple_subentries(self):
        pdf = _load({1: "<< /AA << /O 5 0 R /C 6 0 R >> >>",
                     5: "<< /S /URI /URI (http://a.b) >>", 6: "<< /S /JavaScript /JS (y) >>"})
        self.assertEqual(sorted(t["action"] for t in ex.find_triggers(pdf)),
                         ["/JavaScript", "/URI"])

    def test_uri_and_submitform_targets(self):
        pdf = _load({1: "<< /S /URI /URI (http://evil.com/a) >>",
                     2: "<< /S /SubmitForm /F (https://x.io/p) >>",
                     3: "<< /S /GoToR /F << /F (r.pdf) /UF (u.pdf) >> >>",
                     4: "<< /S /Launch /F 5 0 R >>",
                     5: "<< /Type /Filespec /UF (cmd.exe) >>"})
        got = {a["object"]: (a["type"], a["target"]) for a in ex.find_actions(pdf)}
        self.assertEqual(got[1], ("/URI", "http://evil.com/a"))
        self.assertEqual(got[2], ("/SubmitForm", "https://x.io/p"))
        self.assertEqual(got[3], ("/GoToR", "u.pdf"))
        self.assertEqual(got[4][0], "/Launch")

    def test_embedded_file_with_name(self):
        pdf = _load({2: "<< /Type /Filespec /F (inv.exe) /EF << /F 3 0 R >> >>",
                     3: pdfgen.stream_obj("/Type /EmbeddedFile", b"MZ\x90\x00")})
        res = ex.find_embedded_files(pdf)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["name"], "inv.exe")
        self.assertTrue(res[0]["data"].startswith(b"MZ"))
        self.assertEqual(res[0]["object"], 3)

    def test_embedded_file_without_filespec(self):
        pdf = _load({3: pdfgen.stream_obj("/Type /EmbeddedFile", b"abc")})
        res = ex.find_embedded_files(pdf)
        self.assertEqual((res[0]["name"], res[0]["data"]), (None, b"abc"))

    def test_keywords_include_objstm_children(self):
        pdf = _load({1: "<< /Type /Catalog >>",
                     5: pdfgen.objstm_obj({10: "<< /Type /RichMedia >>"})})
        kw = ex.find_keywords(pdf)
        self.assertEqual(kw["/RichMedia"], [10])
        self.assertEqual(kw["/ObjStm"], [5])
        self.assertEqual(kw["/XObject"], [])

    def test_richmedia_streams(self):
        pdf = _load({1: "<< /RichMedia << /Assets 3 0 R >> >>", 2: "<< /Type /Page >>",
                     3: pdfgen.stream_obj("", b"SWF")})
        res = ex.find_richmedia_streams(pdf)
        self.assertEqual([(r["object"], r["data"]) for r in res], [(3, b"SWF")])


if __name__ == "__main__":
    unittest.main()
