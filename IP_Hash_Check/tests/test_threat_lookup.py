"""Regression tests for threat_lookup.py.

Run from the IP_Hash_Check folder:
    python3 -m unittest discover tests -v

The API lookups and time.sleep are replaced with fakes, so no network
access or API keys are needed.
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import threat_lookup as tl  # noqa: E402

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
MD5 = "d41d8cd98f00b204e9800998ecf8427e"


def run(argv):
    """Run main() with argv and fake lookups; return (calls, sleeps, output, exit code)."""
    calls, sleeps = [], []
    fake_ip = lambda ip, key, age: calls.append(("ip", ip)) or {"ip": ip}
    fake_hash = lambda h, key: calls.append(("hash", h)) or {"hash_sha256": h}
    out = io.StringIO()
    code = 0
    with mock.patch.object(sys, "argv", ["threat_lookup.py"] + argv), \
         mock.patch.object(tl, "lookup_ip", fake_ip), \
         mock.patch.object(tl, "lookup_hash", fake_hash), \
         mock.patch.object(tl.time, "sleep", sleeps.append), \
         redirect_stdout(out):
        try:
            tl.main()
        except SystemExit as e:
            code = e.code
    return calls, sleeps, out.getvalue(), code


class TestDetection(unittest.TestCase):
    def test_ipv6_with_trailing_text_is_not_an_ip(self):
        self.assertFalse(tl.is_ip("2606:4700:4700::1111%' OR 1=1--"))
        self.assertFalse(tl.is_ip("fe80::1%eth0"))

    def test_valid_ipv4(self):
        self.assertTrue(tl.is_ip("8.8.8.8"))

    def test_out_of_range_ipv4_rejected(self):
        self.assertFalse(tl.is_ip("999.1.1.1"))

    def test_ipv6_accepted(self):
        self.assertTrue(tl.is_ip("2001:4860:4860::8888"))

    def test_hashes(self):
        self.assertTrue(tl.is_hash(MD5))
        self.assertTrue(tl.is_hash(SHA256))
        self.assertFalse(tl.is_hash("xyz"))

    def test_public_vs_private(self):
        self.assertTrue(tl.is_public_ip("8.8.8.8"))
        for ip in ("10.0.0.1", "192.168.1.1", "127.0.0.1", "::1", "fe80::1",
                   "239.255.255.250", "ff02::1"):
            self.assertFalse(tl.is_public_ip(ip), ip)


class TestKeys(unittest.TestCase):
    def test_has_key(self):
        self.assertTrue(tl.has_key("abc123"))
        self.assertFalse(tl.has_key(""))
        self.assertFalse(tl.has_key("your_virustotal_key_here"))

    def test_placeholder_key_counts_as_missing(self):
        calls, _, out, code = run(["--vtkey", "your_virustotal_key_here", "--indicators", SHA256])
        self.assertEqual(code, 1)
        self.assertEqual(calls, [])
        self.assertIn("VirusTotal", out)


class TestMain(unittest.TestCase):
    def test_private_ip_skipped_with_reason(self):
        calls, _, out, _ = run(["--abusekey", "k", "--indicators", "192.168.1.10"])
        self.assertEqual(calls, [])
        self.assertIn("private", out.lower())

    def test_private_ip_recorded_as_skipped_in_json(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.json")
            run(["--indicators", "10.0.0.1", "--json", path])
            with open(path) as f:
                results = json.load(f)
        self.assertEqual(results[0]["indicator"], "10.0.0.1")
        self.assertIn("skipped", results[0]["result"])

    def test_defanged_ips_are_looked_up(self):
        calls, _, _, _ = run(["--abusekey", "k", "--indicators", "8[.]8[.]8[.]8", "1(.)1[dot]1.1",
                              "2001[:]4860[:]4860::8888", "9.9.9.9"])
        self.assertEqual(calls, [("ip", "8.8.8.8"), ("ip", "1.1.1.1"),
                                 ("ip", "2001:4860:4860::8888"), ("ip", "9.9.9.9")])

    def test_defanged_ips_in_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "iocs.txt")
            with open(path, "w") as f:
                f.write("# comment\n1[.]2[.]3[.]4 \n8.8.8.8\n")
            calls, _, _, _ = run(["--abusekey", "k", "--file", path])
        self.assertEqual(calls, [("ip", "1.2.3.4"), ("ip", "8.8.8.8")])

    def test_defanged_domain_stays_defanged(self):
        calls, _, out, _ = run(["--abusekey", "k", "--indicators", "evil[.]com"])
        self.assertEqual(calls, [])
        self.assertIn("evil[.]com", out)
        self.assertNotIn("evil.com", out)

    def test_invalid_ip_not_looked_up(self):
        calls, _, out, _ = run(["--abusekey", "k", "--indicators", "999.1.1.1"])
        self.assertEqual(calls, [])
        self.assertIn("not a valid IP address", out)

    def test_private_ip_needs_no_key(self):
        calls, _, _, code = run(["--abusekey", "", "--indicators", "10.0.0.1"])
        self.assertEqual(code, 0)
        self.assertEqual(calls, [])

    def test_delay_only_between_virustotal_calls(self):
        calls, sleeps, _, _ = run(["--abusekey", "k", "--vtkey", "k", "--indicators",
                                   "8.8.8.8", SHA256, "1.1.1.1", MD5, "9.9.9.9"])
        self.assertEqual(len(calls), 5)
        self.assertEqual(sleeps, [15.0])

    def test_custom_delay(self):
        _, sleeps, out, _ = run(["--vtkey", "k", "--delay", "20", "--indicators", SHA256, MD5])
        self.assertEqual(sleeps, [20.0])
        self.assertEqual(out.count("Waiting 20s"), 1)


if __name__ == "__main__":
    unittest.main()
