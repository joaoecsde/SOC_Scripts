"""Tests for pdf_analyser_lib.rules.

Run from the PDF_analyser folder:
    python3 -m unittest tests.test_rules -v
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from pdf_analyser_lib import rules  # noqa: E402


def facts(**kw):
    base = {"javascript": [], "actions": [], "triggers": [], "embedded": [],
            "keywords": {"/RichMedia": [], "/ObjStm": [], "/XObject": []},
            "richmedia": []}
    base.update(kw)
    return base


def js(code, oid=5):
    return {"object": oid, "objstm": None, "source_object": oid, "code": code}


def sev(findings):
    return sorted(f["severity"] for f in findings)


class RulesTests(unittest.TestCase):
    def test_clean_pdf_low(self):
        self.assertEqual(rules.evaluate(facts()), [])
        self.assertEqual(rules.verdict([]), "LOW")

    def test_destination_openaction_stays_low(self):
        f = rules.evaluate(facts(
            triggers=[{"object": 1, "objstm": None, "keyword": "/OpenAction",
                       "action": None, "target_object": None}],
            keywords={"/RichMedia": [], "/ObjStm": [7], "/XObject": [8]},
            actions=[{"object": 3, "objstm": None, "type": "/URI", "target": "http://a.io"}]))
        self.assertEqual(sev(f), ["info"] * 4)
        self.assertEqual(rules.verdict(f), "LOW")

    def test_openaction_js_high(self):
        f = rules.evaluate(facts(triggers=[{"object": 1, "objstm": None, "keyword": "/OpenAction",
                                            "action": "/JavaScript", "target_object": 2}]))
        self.assertEqual(f[0]["severity"], "high")
        self.assertEqual(f[0]["keyword"], "/OpenAction")
        self.assertEqual(rules.verdict(f), "HIGH")

    def test_plain_js_medium(self):
        f = rules.evaluate(facts(javascript=[js("app.alert('hi');")]))
        self.assertEqual(rules.js_markers("app.alert('hi');"), [])
        self.assertEqual(f[0]["severity"], "medium")
        self.assertEqual(f[0]["keyword"], "/JavaScript")
        self.assertEqual(rules.verdict(f), "MEDIUM")

    def test_unresolved_js_medium(self):
        f = rules.evaluate(facts(javascript=[js("")]))
        self.assertEqual(f[0]["severity"], "medium")
        self.assertIn("could not be resolved", f[0]["finding"])
        self.assertIsNone(f[0]["preview"])

    def test_obfuscated_js_high(self):
        code = 'eval(unescape("' + "%u9090" * 8 + '"))'
        m = rules.js_markers(code)
        for name in ("eval", "unescape", "%u shellcode"):
            self.assertIn(name, m)
        f = rules.evaluate(facts(javascript=[js(code)]))
        self.assertEqual(f[0]["severity"], "high")
        self.assertEqual(f[0]["markers"], m)

    def test_string_building_marker(self):
        self.assertIn("string building", rules.js_markers('"a" + ' * 41))
        self.assertNotIn("string building", rules.js_markers('"a" + ' * 5))
        self.assertIn("string building", rules.js_markers("'a' + " * 41))

    def test_executable_embedded_high(self):
        for name, data in (("invoice.pdf.exe", b"hi"), (None, b"MZ..")):
            f = rules.evaluate(facts(embedded=[{"object": 4, "objstm": None,
                                                "name": name, "data": data}]))
            self.assertEqual(f[0]["severity"], "high")
            self.assertEqual(f[0]["keyword"], "/EmbeddedFile")
        self.assertTrue(rules.is_executable("X.PS1", b""))
        self.assertTrue(rules.is_executable(None, b"#!/bin/sh"))

    def test_text_embedded_medium(self):
        f = rules.evaluate(facts(embedded=[{"object": 4, "objstm": None,
                                            "name": "notes.txt", "data": b"hi"}]))
        self.assertEqual(rules.verdict(f), "MEDIUM")

    def test_external_submitform_high(self):
        def run(target, typ="/SubmitForm"):
            return rules.evaluate(facts(actions=[{"object": 3, "objstm": None,
                                                  "type": typ, "target": target}]))
        self.assertEqual(run("https://x.io/p")[0]["severity"], "high")
        self.assertEqual(run("\\\\host\\share\\f")[0]["severity"], "high")
        self.assertEqual(run("local.fdf")[0]["severity"], "medium")
        self.assertEqual(run("https://x.io/p", "/GoToR")[0]["severity"], "high")
        f = run("calc.exe", "/Launch")
        self.assertEqual(f[0]["severity"], "medium")
        self.assertEqual(f[0]["target"], "calc.exe")
        self.assertTrue(rules.is_external("ftp://a"))
        self.assertFalse(rules.is_external("local.fdf"))

    def test_richmedia_medium(self):
        f = rules.evaluate(facts(keywords={"/RichMedia": [9, 10], "/ObjStm": [], "/XObject": []}))
        self.assertEqual(sev(f), ["medium", "medium"])
        self.assertEqual(sorted(x["object"] for x in f), [9, 10])

    def test_js_preview_is_first_lines(self):
        code = "\n".join(("x" * 200) + str(i) for i in range(10))
        f = rules.evaluate(facts(javascript=[js(code)]))
        lines = f[0]["preview"].split("\n")
        self.assertEqual(len(lines), 5)
        self.assertTrue(all(len(l) == 120 for l in lines))

    def test_finding_keys(self):
        f = rules.evaluate(facts(javascript=[js("x")]))
        self.assertEqual(set(f[0]), {"severity", "keyword", "object", "objstm",
                                     "finding", "preview", "markers", "target"})


if __name__ == "__main__":
    unittest.main()
