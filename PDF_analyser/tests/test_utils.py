"""Tests for pdf_analyser_lib.utils."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pdf_analyser_lib.utils import defang_text, safe  # noqa: E402


class UtilsTests(unittest.TestCase):
    def test_defang_text(self):
        self.assertEqual(defang_text("go to https://evil.example.com/a.php?x=1 now"),
                         "go to hxxps://evil[.]example[.]com/a.php?x=1 now")
        self.assertEqual(defang_text("app.launchURL('http://a.b/c.d')"),
                         "app.launchURL('hxxp://a[.]b/c.d')")
        self.assertEqual(defang_text("no url here v1.2"), "no url here v1.2")

    def test_safe_strips_escape(self):
        self.assertEqual(safe("a\x1b[31mb"), "a?[31mb")


if __name__ == "__main__":
    unittest.main()
