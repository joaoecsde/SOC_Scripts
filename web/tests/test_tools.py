"""Tests for the email and PDF adapters in web/tools.py.

Run from the web folder:
    python3 -m unittest tests.test_tools -v
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import samples                                  # noqa: E402
import tools                                    # noqa: E402
from tools import ToolError, run_email, run_pdf  # noqa: E402


def _write(tmp, name, data):
    path = os.path.join(tmp, name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


class EmailAdapterTests(unittest.TestCase):
    def test_run_email_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "up.eml", samples.phishing_eml())
            r = run_email(path, "phish.eml", None, 0)
        self.assertIn(r["verdict"], ("LOW", "MEDIUM", "HIGH"))
        self.assertEqual(r["source"], "phish.eml")
        self.assertTrue(r["findings"])
        json.dumps(r)

    def test_run_email_rejects_msg(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "up.msg", samples.msg_file())
            with self.assertRaises(ToolError) as cm:
                run_email(path, "mail.msg", None, 0)
        self.assertIn(".msg", str(cm.exception))

    def test_run_email_capitalises_loader_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "up.msg", samples.msg_file())
            with self.assertRaises(ToolError) as cm:
                run_email(path, "mail.msg", None, 0)
        self.assertTrue(str(cm.exception)[0].isupper())

    def test_run_email_online_errors_are_friendly(self):
        keys = {"abuseipdb": "k1", "virustotal": "k2"}
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "up.eml", samples.phishing_eml())
            with mock.patch("email_analyser_lib.online.check_ip",
                            return_value={"error": "Read timed out. (read timeout=15)"}), \
                    mock.patch("email_analyser_lib.online.check_hash",
                               return_value={"error": "Max retries exceeded"}):
                r = run_email(path, "phish.eml", keys, 0)
        errs = [x["error"] for x in r["online_ip_results"].values()]
        errs += [a["online"]["error"] for a in r["attachments"]
                 if a.get("online") and "error" in a["online"]]
        self.assertTrue(errs)
        self.assertNotIn("timed out", " ".join(errs).replace("did not answer in time", ""))
        self.assertTrue(all(e in ("The service did not answer in time. Try again.",
                                  "Could not reach the service. Check the internet connection.")
                            for e in errs))

    def test_run_email_online_needs_a_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "up.eml", samples.phishing_eml())
            with self.assertRaises(ToolError):
                run_email(path, "phish.eml", {"abuseipdb": "", "virustotal": ""}, 0)

    def test_run_email_reports_progress(self):
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "up.eml", samples.phishing_eml())
            with mock.patch("email_analyser_lib.online.check_ip", return_value={}), \
                    mock.patch("email_analyser_lib.online.check_hash", return_value={}):
                run_email(path, "phish.eml", {"abuseipdb": "k1", "virustotal": "k2"}, 0,
                          progress=lambda d, t, label: calls.append((d, t, label)))
        self.assertTrue(calls)
        self.assertEqual(calls[-1][0], calls[-1][1])


class PdfAdapterTests(unittest.TestCase):
    def test_run_pdf_flags_javascript(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "up.pdf", samples.js_pdf())
            r = run_pdf(path, "doc.pdf", False, Path(tmp))
        self.assertEqual(r["verdict"], "HIGH")
        self.assertEqual(r["file"], "doc.pdf")
        self.assertEqual(r["path"], "doc.pdf")
        self.assertIsNone(r["payloads_zip"])

    def test_run_pdf_extract_writes_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "up.pdf", samples.js_pdf())
            work = Path(tmp) / "work"
            work.mkdir()
            r = run_pdf(path, "doc.pdf", True, work)
            self.assertTrue(os.path.exists(r["payloads_zip"]))
            self.assertEqual(Path(r["payloads_zip"]).parent, work)

    def test_run_pdf_extract_removes_stage_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "up.pdf", samples.js_pdf())
            work = Path(tmp) / "work"
            work.mkdir()
            run_pdf(path, "doc.pdf", True, work)
            self.assertEqual([p.name for p in work.iterdir() if p.is_dir()], [])

    def test_run_pdf_payload_error_when_write_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "up.pdf", samples.js_pdf())
            work = Path(tmp) / "work"
            work.mkdir()
            with mock.patch("tools.write_outputs", side_effect=OSError("disk full")):
                r = run_pdf(path, "doc.pdf", True, work)
            self.assertIsNone(r["payloads_zip"])
            self.assertIn("could not be saved", r["payload_error"])
            self.assertEqual([p for p in work.iterdir() if p.is_dir()], [])

    def test_run_pdf_not_a_pdf(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "up.pdf", samples.not_pdf())
            with self.assertRaises(ToolError) as cm:
                run_pdf(path, "doc.pdf", False, Path(tmp))
        self.assertIn("not a PDF", str(cm.exception))


MD5 = "44d88612fea8a8f36de82e1278abb02f"
KEYS = {"abuseipdb": "a" * 40, "virustotal": "v" * 64}


@mock.patch("tools.time.sleep")
@mock.patch("tools.threat_lookup.lookup_hash", return_value={"malicious": 0})
@mock.patch("tools.threat_lookup.lookup_ip", return_value={"abuse_score": 0})
class IocAdapterTests(unittest.TestCase):
    def test_invalid_lines_finds_only_lines_that_are_not_indicators(self, *_):
        text = "\n".join((
            "# comment", "", "8.8.8.8", "2001:4860:4860::8888", "1[.]2[.]3[.]4", "2001[:]db8::1",
            "d41d8cd98f00b204e9800998ecf8427e",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "d41d8cd98f00b204e9800998ecf8427",
            "8.8.8.8:443", "8.8.8.0/24", "evil.example"))
        self.assertEqual(tools.invalid_lines(text), [10, 11, 12, 13])

    def test_parse_indicators_refangs_and_dedupes(self, *_):
        text = "1[.]2[.]3[.]4\n\n# note\n1.2.3.4\n" + MD5
        self.assertEqual(tools.parse_indicators(text), ["1.2.3.4", MD5])

    def test_needed_keys(self, *_):
        self.assertEqual(tools.needed_keys(["10.0.0.1"]), set())
        self.assertEqual(tools.needed_keys(["8.8.8.8", MD5]), {"abuseipdb", "virustotal"})

    def test_ioc_mixed_batch(self, lookup_ip, lookup_hash, sleep):
        r = tools.run_ioc(["8.8.8.8", "10.0.0.1", "nonsense", MD5], KEYS, 90, 0)
        self.assertEqual([x["type"] for x in r], ["ip", "ip", "unknown", "hash"])
        self.assertIn("skipped", r[1]["result"])
        self.assertIn("error", r[2]["result"])
        self.assertEqual(lookup_ip.call_count, 1)

    def test_ioc_sleeps_between_vt_calls_only(self, lookup_ip, lookup_hash, sleep):
        hashes = [MD5, "a" * 32, "b" * 32]
        tools.run_ioc(hashes, KEYS, 90, 15)
        self.assertEqual(sleep.call_args_list, [mock.call(15), mock.call(15)])

    def test_ioc_progress_counts(self, *_):
        seen = []
        tools.run_ioc(["8.8.8.8", "1.1.1.1", "nonsense", MD5], KEYS, 90, 0,
                      progress=lambda d, t, label: seen.append((d, t)))
        dones = []
        for d, _ in seen:
            if d > 0 and d not in dones:
                dones.append(d)
        self.assertEqual(dones, [1, 2, 3, 4])
        self.assertTrue(all(t == 4 for _, t in seen))

    def test_ioc_one_error_does_not_stop_batch(self, lookup_ip, lookup_hash, sleep):
        lookup_hash.side_effect = [{"error": "HTTP 401: bad key"}, {"malicious": 5}]
        r = tools.run_ioc([MD5, "a" * 32], KEYS, 90, 0)
        self.assertEqual(len(r), 2)
        self.assertIn("API key was rejected (HTTP 401)", r[0]["result"]["error"])
        self.assertEqual(r[1]["result"], {"malicious": 5})

    def test_friendly_error_429(self, *_):
        self.assertEqual(tools.friendly_error("HTTP 429: slow down"),
                         "Rate limit reached (HTTP 429). Wait a minute or raise the delay, then try again.")

    def test_friendly_error_network(self, *_):
        self.assertEqual(tools.friendly_error("HTTPSConnectionPool: Read timed out."),
                         "The service did not answer in time. Try again.")
        for text in ("Max retries exceeded", "Failed to establish a new connection",
                     "ConnectionError(x)", "Name or service not known"):
            self.assertEqual(tools.friendly_error(text),
                             "Could not reach the service. Check the internet connection.")

    def test_usable_key(self, *_):
        self.assertTrue(tools.usable_key("abc"))
        self.assertFalse(tools.usable_key(""))
        self.assertFalse(tools.usable_key("your_key_here"))

    def test_friendly_error_other(self, *_):
        self.assertIn("(HTTP 403)", tools.friendly_error("HTTP 403: x"))
        self.assertIn("Not found on VirusTotal", tools.friendly_error("Hash not found in VirusTotal"))
        self.assertEqual(len(tools.friendly_error("x" * 500)), 200)


if __name__ == "__main__":
    unittest.main()
