"""Tests for pdf_analyser_lib.pipeline and report.

Run from the PDF_analyser folder:
    python3 -m unittest tests.test_report -v
"""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import pdfgen  # noqa: E402
from pdf_analyser_lib import pipeline, report  # noqa: E402
from pdf_analyser_lib.utils import Colors  # noqa: E402


def analyse(objects, trailer="<< /Root 1 0 R >>"):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "sample.pdf")
        with open(path, "wb") as fh:
            fh.write(pdfgen.make_pdf(objects, trailer))
        return pipeline.analyse_pdf(path), path


def js_pdf(code):
    return {1: "<< /Type /Catalog /OpenAction 2 0 R >>",
            2: "<< /S /JavaScript /JS 3 0 R >>",
            3: pdfgen.stream_obj("", code.encode("latin-1"))}


class ReportTests(unittest.TestCase):
    def test_end_to_end_high(self):
        r, _ = analyse(js_pdf("eval(unescape('%41'));"))
        self.assertEqual(r["verdict"], "HIGH")
        self.assertEqual(r["file"], "sample.pdf")
        self.assertEqual(len(r["sha256"]), 64)
        self.assertIn("javascript", [e["kind"] for e in r["extracted"]])
        self.assertEqual(r["extracted"][0]["size"], len("eval(unescape('%41'));"))
        self.assertNotIn("data", r["extracted"][0])   # payload bytes are not kept in memory

    def test_render_defangs_and_strips(self):
        r, _ = analyse(js_pdf("app.launchURL('http://evil.com/x'); \x1b[2J eval(1);"))
        text = report.render(r, Colors(False))
        self.assertIn("hxxp://evil[.]com", text)
        self.assertNotIn("\x1b", text)

    def test_render_plain_has_no_ansi(self):
        r, _ = analyse(js_pdf("eval(1);"))
        self.assertNotIn("\033[", report.render(r, Colors(False)))
        self.assertIn("The verdict is a heuristic, not a final answer. Always confirm manually.",
                      report.render(r, Colors(False)))

    def test_encrypted_warning_shown(self):
        r, _ = analyse({1: "<< /Type /Catalog >>"}, "<< /Root 1 0 R /Encrypt 9 0 R >>")
        self.assertIn("may be understated", report.render(r, Colors(False)))

    def test_keyword_counts_before_findings(self):
        r, _ = analyse(js_pdf("eval(1);"))
        f = lambda kw: {"severity": "info", "keyword": kw, "object": 1, "finding": "x"}
        r["findings"] = [f("/ObjStm"), f("/URI"), f("/URI"), f("/AA"), f("/URI"), f("/ObjStm")]
        lines = report.render(r, Colors(False)).splitlines()
        start = lines.index("Findings (6)") + 2
        self.assertEqual([l.split() for l in lines[start:start + 3]],
                         [["/URI", "3"], ["/ObjStm", "2"], ["/AA", "1"]])
        self.assertTrue(lines[start + 3].lstrip().startswith("INFO"))

    def test_no_keyword_counts_without_findings(self):
        r, _ = analyse({1: "<< /Type /Catalog >>"})
        r["findings"] = []
        lines = report.render(r, Colors(False)).splitlines()
        start = lines.index("Findings (0)") + 2
        self.assertIn("No suspicious indicators found", lines[start])

    def test_json_has_no_payload_bytes(self):
        r, _ = analyse(js_pdf("eval(1);"))
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "JSON_report.json")
            report.save_json(r, out)
            with open(out, encoding="utf-8") as fh:
                loaded = json.load(fh)
        item = loaded["extracted"][0]
        self.assertIn("sha256", item)
        self.assertIn("size", item)
        self.assertNotIn("data", item)


if __name__ == "__main__":
    unittest.main()
