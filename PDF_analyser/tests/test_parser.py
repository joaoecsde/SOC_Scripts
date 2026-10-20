"""Tests for pdf_analyser_lib.parser.

Run from the PDF_analyser folder:
    python3 -m unittest discover tests -v
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import pdfgen                                    # noqa: E402
from pdf_analyser_lib.parser import load_pdf     # noqa: E402
import tempfile                                  # noqa: E402


def _load(data):
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        f.write(data)
    try:
        return load_pdf(f.name)
    finally:
        os.unlink(f.name)


class ParserTests(unittest.TestCase):
    def test_loads_plain_objects(self):
        pdf = _load(pdfgen.make_pdf({1: "<< /Type /Catalog >>", 2: "<< /A 1 >>", 3: "<< /B 2 >>"}))
        self.assertEqual(set(pdf.objects), {1, 2, 3})
        self.assertFalse(pdf.partial)

    def test_stream_is_decoded(self):
        pdf = _load(pdfgen.make_pdf({1: pdfgen.stream_obj("", b"hello")}))
        self.assertEqual(pdf.objects[1][0].stream(), b"hello")
        self.assertIsNone(_load(pdfgen.make_pdf({1: "<< /A 1 >>"})).objects[1][0].stream())

    def test_objstm_children_are_loaded(self):
        pdf = _load(pdfgen.make_pdf({5: pdfgen.objstm_obj({10: "<< /S /JavaScript /JS (x) >>"})}))
        self.assertEqual(pdf.objects[10][0].objstm, 5)
        self.assertTrue(pdf.objects[10][0].has_name("/JS"))
        self.assertIsNone(pdf.objects[5][0].objstm)

    def test_encrypted_flagged(self):
        pdf = _load(pdfgen.make_pdf({1: "<< /A 1 >>"}, trailer="<< /Root 1 0 R /Encrypt 9 0 R >>"))
        self.assertTrue(pdf.encrypted)
        self.assertTrue(pdf.partial)

    def test_truncated_pdf_is_partial_not_crash(self):
        data = pdfgen.make_pdf({1: "<< /A 1 >>", 2: "<< /B 2 >>", 3: "<< /C 3 >>"})[:-40] + b"\x00garbage"
        pdf = _load(data)
        self.assertIn(1, pdf.objects)
        self.assertTrue(pdf.partial)

    def test_broken_objstm_index_is_partial(self):
        body = b"1 0 \n<< /A 1 >>\n"
        obj = pdfgen.stream_obj("/Type /ObjStm /N 3 /First %d" % 5, body)
        pdf = _load(pdfgen.make_pdf({5: obj}))
        self.assertTrue(pdf.partial)
        self.assertTrue(pdf.errors)

    def test_every_copy_is_kept_in_file_order(self):
        pdf = _load(pdfgen.make_pdf({1: "<< /A 1 >>"}) + b"1 0 obj\n<< /Marker true >>\nendobj\n")
        copies = pdf.objects[1]
        self.assertEqual([o.copy for o in copies], [1, 2])
        self.assertFalse(copies[0].has_name("/Marker"))
        self.assertTrue(copies[1].has_name("/Marker"))
        self.assertTrue(copies[0].duplicated)

    def test_single_object_is_not_duplicated(self):
        pdf = _load(pdfgen.make_pdf({1: "<< /A 1 >>"}))
        self.assertFalse(pdf.objects[1][0].duplicated)

    def test_objstm_copy_counts_as_copy(self):
        pdf = _load(pdfgen.make_pdf([(6, "<< /A 1 >>"),
                                     (5, pdfgen.objstm_obj({6: "<< /S /JavaScript /JS (x) >>"}))]))
        self.assertEqual([(o.copy, o.objstm) for o in pdf.objects[6]], [(1, None), (2, 5)])

    def test_helpers(self):
        pdf = _load(pdfgen.make_pdf({1: "<< /Type /Catalog /Pages 2 0 R >>"}))
        obj = pdf.objects[1][0]
        self.assertEqual(obj.type(), "/Catalog")
        self.assertEqual(obj.refs(), [2])
        self.assertEqual("".join(obj.get("/Pages")).strip(), "2 0 R")
        self.assertIsNone(obj.get("/Nope"))


if __name__ == "__main__":
    unittest.main()
