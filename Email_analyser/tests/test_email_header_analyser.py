"""Regression tests for email_header_analyser.py.

Run from the Email_analyser folder:
    python3 -m unittest discover tests -v

Each test builds a small email in memory, so no sample files or network
access are needed. The goal is to lock in two things when the rules change:
clean mail stays clean, and phishing keeps being caught.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from email.message import EmailMessage

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from email_analyser_lib import config                          # noqa: E402
from email_analyser_lib.loader import InputError, parse_email  # noqa: E402
from email_analyser_lib.pipeline import analyse_message        # noqa: E402
from email_analyser_lib.utils import safe, valid_ips           # noqa: E402

SCRIPT = os.path.join(ROOT, "email_header_analyser.py")
RECEIVED = "from a.sender.net (a.sender.net [8.8.8.8]) by mx.me.com; Mon, 1 Jan 2024 10:00:01 +0000"
DATE = "Mon, 1 Jan 2024 10:00:00 +0000"
AUTH_PASS = "mx.me.com; spf=pass smtp.mailfrom={d}; dkim=pass header.d={d}; dmarc=pass"


def build(headers, text="hello", html=None, attachments=()):
    """Build a message; ``headers`` is a list of (name, value)."""
    m = EmailMessage()
    for k, v in [("Received", RECEIVED), ("Date", DATE)] + list(headers):
        m[k] = v
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    for a in attachments:
        if isinstance(a, EmailMessage):
            m.add_attachment(a, filename="fwd.eml")
        else:
            data, name = a
            m.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return m


def analyse(*args, **kwargs):
    msg, warnings = parse_email(bytes(build(*args, **kwargs)))
    return analyse_message(msg, warnings=warnings)


def texts(result, category=None):
    return [f["finding"] for f in result["findings"] if category in (None, f["category"])]


class CleanMailStaysClean(unittest.TestCase):
    """False positives found in the old script must not come back."""

    def test_newsletter_via_esp_is_low(self):
        r = analyse([("From", "Shop <news@shop.com>"),
                     ("Return-Path", "<bounce-mc.us1_1@mail123.mcsv.net>"),
                     ("Message-ID", "<abc@mail123.mcsv.net>"),
                     ("Authentication-Results", "mx.me.com; spf=pass smtp.mailfrom=b@mail123.mcsv.net; "
                                                "dkim=pass header.d=mcsv.net; dkim=pass header.d=shop.com; dmarc=pass")])
        self.assertEqual(r["verdict"], "LOW")
        self.assertTrue(r["authentication"]["dkim_aligned"])
        self.assertTrue(any("Mailchimp" in t for t in texts(r)))

    def test_google_workspace_message_id(self):
        r = analyse([("From", "Ana <ana@company.pt>"), ("Message-ID", "<CAabc@mail.gmail.com>"),
                     ("Authentication-Results", AUTH_PASS.format(d="company.pt"))])
        self.assertFalse(any("Message-ID" in t for t in texts(r)))
        self.assertEqual(r["risk_score"], 0)

    def test_short_brand_words_do_not_match(self):
        for sender in ('"IT Groups Newsletter" <n@company.com>', '"Your Purchase Receipt" <s@store.com>',
                       '"Pineapple Studio" <hi@pineapple-studio.com>', '"Community" <noreply@groups.io>'):
            with self.subTest(sender=sender):
                r = analyse([("From", sender), ("Message-ID", "<1@x.com>")])
                self.assertEqual(texts(r, "impersonation"), [])

    def test_at_sign_in_display_name_is_not_an_address(self):
        r = analyse([("From", '"John @ Home" <john@company.com>'), ("Message-ID", "<1@company.com>")])
        self.assertEqual(texts(r, "impersonation"), [])

    def test_real_brand_domains(self):
        for sender in ("Microsoft <no-reply@microsoftonline.com>", "PayPal <service@paypal.de>",
                       "Amazon <ship@amazon.co.uk>", "Apple <no_reply@email.apple.com>", "UPS <pkg@ups.com>"):
            with self.subTest(sender=sender):
                r = analyse([("From", sender), ("Message-ID", "<1@x.com>")])
                self.assertEqual(texts(r, "impersonation"), [])

    def test_safelinks_are_unwrapped(self):
        wrapped = ("https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.shop.com%2Fa&data=x")
        r = analyse([("From", "Shop <n@shop.com>")], html=f'<a href="{wrapped}">www.shop.com</a>')
        self.assertEqual(r["indicators"]["urls"], ["https://www.shop.com/a"])
        self.assertEqual(texts(r, "links"), [])

    def test_esp_click_tracking_is_only_low(self):
        r = analyse([("From", "Shop <n@shop.com>")],
                    html='<a href="https://shop.us1.list-manage.mcsv.net/track?u=1">www.shop.com</a>')
        self.assertTrue(all(f["points"] <= 5 for f in r["findings"] if f["category"] == "links"))

    def test_schema_urls_ignored_and_entities_decoded(self):
        r = analyse([("From", "a@b.com")],
                    html='<html xmlns="http://www.w3.org/1999/xhtml"><a href="https://b.com/x?a=1&amp;b=2">go</a></html>')
        self.assertEqual(r["indicators"]["urls"], ["https://b.com/x?a=1&b=2"])


class PhishingIsCaught(unittest.TestCase):

    def test_lookalike_ending_in_real_domain(self):
        r = analyse([("From", "Alert <a@secure-paypal.com>")])
        self.assertTrue(any("secure-paypal" in t for t in texts(r, "impersonation")))

    def test_digit_swapped_domains(self):
        for dom, brand in (("paypa1.com", "paypal"), ("p4ypal.xyz", "paypal"), ("m1crosoft.com", "microsoft")):
            with self.subTest(dom=dom):
                r = analyse([("From", f"Security <a@{dom}>")])
                self.assertTrue(any(f"character-substituted '{brand}'" in t for t in texts(r)))

    def test_brand_display_name_from_free_mail(self):
        r = analyse([("From", '"UPS Delivery" <track@gmail.com>')])
        self.assertTrue(any("free mail" in t for t in texts(r, "impersonation")))

    def test_link_tricks(self):
        html = ('<a href="https://evil.xyz/login">https://www.paypal.com</a>'
                '<a href="https://paypal.com@evil.top/x">x</a>'
                '<a href="http://203.0.113.9/inv.iso">y</a>'
                '<form action="https://steal.top/p"></form>')
        found = " | ".join(texts(analyse([("From", "a@b.com")], html=html), "links"))
        for expected in ("Link text shows", "behind '@'", "bare IP", "risky file type (.iso)", "HTML form"):
            self.assertIn(expected, found)

    def test_link_category_is_capped(self):
        html = "".join(f'<a href="http://203.0.113.{i}/a.exe">www.bank{i}.com</a>' for i in range(10))
        r = analyse([("From", "a@b.com")], html=html)
        self.assertEqual(r["category_scores"]["links"]["counted"], config.CATEGORY_CAPS["links"])

    def test_full_phishing_email_is_high(self):
        r = analyse([("From", '"PayPal Support support@paypal.com" <alert@paypa1.xyz>'),
                     ("Reply-To", "x@gmail.com"), ("Message-ID", "<1@mailer.ru>"),
                     ("Authentication-Results", "mx.me.com; spf=fail smtp.mailfrom=paypa1.xyz; dkim=none; dmarc=fail")],
                    attachments=[(b"MZ\x90\x00", "invoice.pdf.exe")])
        self.assertEqual(r["verdict"], "HIGH")


class Attachments(unittest.TestCase):

    def test_attached_email_is_hashed_and_searched(self):
        inner = EmailMessage()
        inner["From"], inner["Subject"] = "boss@corp.com", "fwd"
        inner.set_content("see attached")
        inner.add_attachment(b"<form action=x>", maintype="text", subtype="html", filename="login.html")
        r = analyse([("From", "a@b.com")], attachments=[inner])
        email_att = [a for a in r["attachments"] if a["kind"] == "email"][0]
        self.assertGreater(email_att["size"], 0)
        self.assertNotEqual(email_att["md5"], "d41d8cd98f00b204e9800998ecf8427e")
        html = [a for a in r["attachments"] if a["filename"] == "login.html"][0]
        self.assertEqual(html["container"], "fwd.eml")
        self.assertTrue(any("credential phishing" in f["flag"] for f in html["flags"]))

    def test_rtl_override_filename(self):
        r = analyse([("From", "a@b.com")], attachments=[(b"x", "invoice‮fdp.exe")])
        self.assertTrue(any("RTL" in t for t in texts(r, "attachments")))


class InputHandling(unittest.TestCase):

    def test_msg_file_rejected_with_help(self):
        with self.assertRaises(InputError) as ctx:
            parse_email(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100)
        self.assertIn(".eml", str(ctx.exception))

    def test_pdf_rejected(self):
        with self.assertRaises(InputError):
            parse_email(b"%PDF-1.7 ...")

    def test_text_without_headers_rejected(self):
        with self.assertRaises(InputError):
            parse_email(b"just some notes about an email\nnothing else")

    def test_leading_blank_line_fixed(self):
        msg, warnings = parse_email(b"\r\n\r\nFrom: a@b.com\r\nSubject: hi\r\n\r\nbody")
        self.assertEqual(str(msg["From"]), "a@b.com")
        self.assertTrue(warnings)


class Helpers(unittest.TestCase):

    def test_safe_removes_terminal_codes(self):
        self.assertNotIn("\x1b", safe("Invoice \x1b[2J\x1b[32mSAFE"))
        self.assertIn("<U+202E>", safe("a‮b"))

    def test_ip_extraction(self):
        self.assertEqual(valid_ips("from x [IPv6:2001:db8::1] by y (1.2.3.4) at 10:00:01 v1.2.3.4.5"),
                         ["2001:db8::1", "1.2.3.4"])


class CommandLine(unittest.TestCase):
    """End-to-end checks of the script's exit codes."""

    def run_cli(self, *args):
        return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)

    def test_exit_codes(self):
        phish = build([("From", '"PayPal" <a@paypa1.xyz>'), ("Reply-To", "x@gmail.com"),
                       ("Authentication-Results", "mx; spf=fail; dkim=fail; dmarc=fail")])
        with tempfile.TemporaryDirectory() as d:
            eml = os.path.join(d, "p.eml")
            with open(eml, "wb") as f:
                f.write(bytes(phish))
            self.assertEqual(self.run_cli(eml).returncode, 0)
            self.assertEqual(self.run_cli(eml, "--exit-code").returncode, 2)
            msg_file = os.path.join(d, "x.msg")
            with open(msg_file, "wb") as f:
                f.write(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 50)
            self.assertEqual(self.run_cli(msg_file).returncode, 3)
            self.assertEqual(self.run_cli(os.path.join(d, "missing.eml")).returncode, 3)
            self.assertEqual(self.run_cli(d).returncode, 3)   # a folder
            bad_json = self.run_cli(eml, "--json", os.path.join(d, "no_such_dir", "o.json"))
            self.assertEqual(bad_json.returncode, 3)
            self.assertNotIn("Traceback", bad_json.stderr)


if __name__ == "__main__":
    unittest.main()
