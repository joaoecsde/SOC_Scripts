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
                       "Amazon <ship@amazon.co.uk>", "Apple <no_reply@email.apple.com>", "UPS <pkg@ups.com>",
                       "iCloud <noreply@insideicloud.icloud.com>"):
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

    def test_brand_display_name_from_brands_own_free_mail(self):
        for sender in ('"Microsoft Account Team" <alert1987@outlook.com>', '"Google Security" <x@gmail.com>',
                       '"Apple Support" <x@icloud.com>', '"Apple Support" <x@me.com>'):
            with self.subTest(sender=sender):
                r = analyse([("From", sender), ("Message-ID", "<1@x.com>")])
                imp = [f for f in r["findings"] if f["category"] == "impersonation"]
                self.assertEqual([(f["points"], f["severity"]) for f in imp], [(15, "medium")])
                self.assertIn("personal", imp[0]["finding"])

    def test_link_tricks(self):
        html = ('<a href="https://evil.xyz/login">https://www.paypal.com</a>'
                '<a href="https://paypal.com@evil.top/x">x</a>'
                '<a href="http://203.0.113.9/inv.iso">y</a>'
                '<form action="https://steal.top/p"></form>')
        found = " | ".join(texts(analyse([("From", "a@b.com")], html=html), "links"))
        for expected in ("Link text shows", "behind '@'", "bare IP", "risky file type (.iso)", "HTML form"):
            self.assertIn(expected, found)

    def test_unclosed_and_nested_links_are_checked(self):
        for html in ('<a href="https://evil.xyz/login">Click here',
                     '<a href="https://evil.xyz/login">x<a href="https://ok.com">ok</a>'):
            with self.subTest(html=html):
                r = analyse([("From", "a@b.com")], html=html)
                self.assertIn("https://evil.xyz/login", [l["url"] for l in r["links"]])

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

    def test_trailing_dots_and_spaces_do_not_hide_extension(self):
        # Windows drops trailing dots and spaces, so these save as .exe / .pdf.exe.
        for name in ("payload.exe.", "payload.exe ", "payload.exe. .", "invoice.pdf.exe."):
            r = analyse([("From", "a@b.com")], attachments=[(b"x", name)])
            self.assertTrue(any("risky file extension (.exe)" in t for t in texts(r, "attachments")), name)
        r = analyse([("From", "a@b.com")], attachments=[(b"x", "invoice.pdf.exe.")])
        self.assertTrue(any("double extension" in t for t in texts(r, "attachments")))

    def test_long_windows_extensions(self):
        for ext in (".settingcontent-ms", ".library-ms", ".appref-ms", ".search-ms", ".searchconnector-ms"):
            r = analyse([("From", "a@b.com")], attachments=[(b"x", "file" + ext)])
            self.assertTrue(any(f"risky file extension ({ext})" in t for t in texts(r, "attachments")), ext)

    def test_hyphenated_document_name_is_not_risky(self):
        r = analyse([("From", "a@b.com")], attachments=[(b"x", "report.v1-final.pdf")])
        self.assertEqual(texts(r, "attachments"), [])


def chain(received, extra=()):
    """Analyse a message whose Received headers are ``received``, newest (top) first."""
    m = EmailMessage()
    for r in received:
        m["Received"] = r + "; " + DATE
    for k, v in [("From", "a@sender.net"), ("Date", DATE)] + list(extra):
        m[k] = v
    m.set_content("hello")
    msg, warnings = parse_email(bytes(m))
    return analyse_message(msg, warnings=warnings)


class OriginIp(unittest.TestCase):
    """The origin IP is read from the top (recipient side) down, not from the forgeable bottom."""

    M365 = ["from SA1PR.prod.outlook.com (2603:10b6:806:1::1) by MN2PR.prod.outlook.com",
            "from DM6NAM.prod.protection.outlook.com (2603:10b6:5:2::1) by DM6PR.outlook.office365.com",
            "from mail.sender.net (mail.sender.net [8.8.8.8]) by DM6NAM.mail.protection.outlook.com"]
    FORGED = "from fake.host (fake.host [1.1.1.1]) by mail.sender.net"

    def test_m365_chain_and_forged_bottom_hop(self):
        r = chain(self.M365 + [self.FORGED])
        self.assertEqual(r["originating_ip"], "8.8.8.8")
        ind = r["indicators"]
        self.assertEqual(ind["ips_public"], ["1.1.1.1", "8.8.8.8", "2603:10b6:5:2::1", "2603:10b6:806:1::1"])
        self.assertEqual(ind["ips_receiving"], [])

    def test_gmail_chain_with_internal_ip_hop_on_top(self):
        r = chain(["by 2002:a05:6a10::1 with SMTP id abc",
                   "from mail.sender.net (mail.sender.net. [8.8.8.8]) by mx.google.com with ESMTPS id x",
                   self.FORGED])
        self.assertEqual(r["originating_ip"], "8.8.8.8")
        self.assertEqual(r["indicators"]["ips_public"], ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(r["indicators"]["ips_receiving"], ["2002:a05:6a10::1"])

    # A forged hop can mislead the origin IP, but the real sending server
    # must stay an indicator (looked up online), never a receiving IP.

    def test_forged_hop_naming_recipient_org_keeps_real_sender(self):
        r = chain(self.M365 + ["from x (x [1.1.1.1]) by evil.outlook.com"])
        self.assertIn("8.8.8.8", r["indicators"]["ips_public"])
        self.assertNotIn("8.8.8.8", r["indicators"]["ips_receiving"])

    def test_forged_named_hop_below_ip_only_top_keeps_real_sender(self):
        r = chain(["from a (a [8.8.8.8]) by 10.0.0.1", "from b (b [1.1.1.1]) by mail.sender.net"])
        self.assertIn("8.8.8.8", r["indicators"]["ips_public"])
        self.assertNotIn("8.8.8.8", r["indicators"]["ips_receiving"])

    def test_helo_containing_by_keeps_real_sender(self):
        r = chain(["from mx1.corp.com (10.0.0.5) by mbx.corp.com",
                   "from x by mx1.corp.com (unknown [45.33.32.156]) by mx1.corp.com (Postfix) with ESMTPS id X"])
        self.assertEqual(r["originating_ip"], "45.33.32.156")
        self.assertEqual(r["indicators"]["ips_public"], ["45.33.32.156"])
        self.assertEqual(r["indicators"]["ips_receiving"], [])

    def test_helo_ip_literal_does_not_choose_origin(self):
        for received in ("from [8.8.8.8] (unknown [45.33.32.156]) by mx.me.com",          # Postfix
                         "from [45.33.32.156] (helo=[8.8.8.8]) by mx.me.com",            # Exim, no rDNS
                         "from h.net ([45.33.32.156] helo=[8.8.8.8]) by mx.me.com",      # Exim
                         "from [8.8.8.8] (h.ext.com [45.33.32.156] (may be forged)) by mx.me.com"):  # Sendmail
            with self.subTest(received=received):
                r = chain([received])
                self.assertEqual(r["originating_ip"], "45.33.32.156")
                self.assertIn("8.8.8.8", r["indicators"]["ips_public"])

    def test_forged_hop_below_single_label_top_keeps_real_sender(self):
        r = chain(["from mail.attacker.net (x [8.8.8.8]) by EXCH01",
                   "from y (y [1.1.1.1]) by mail.attacker.net"])
        self.assertIn("8.8.8.8", r["indicators"]["ips_public"])
        self.assertNotIn("8.8.8.8", r["indicators"]["ips_receiving"])

    def test_x_originating_ip_does_not_override(self):
        r = chain(self.M365, extra=[("X-Originating-IP", "[9.9.9.9]")])
        self.assertEqual(r["originating_ip"], "8.8.8.8")
        self.assertIn("9.9.9.9", r["indicators"]["ips_public"])

    def test_private_entry_ip_gives_no_origin(self):
        for received in ("from [192.168.1.5] (unknown [192.168.1.5]) by mx.me.com",
                         "from [10.0.0.5] (helo=[8.8.8.8]) by mx.me.com"):
            with self.subTest(received=received):
                self.assertEqual(chain([received])["originating_ip"], "")

    def test_unknown_receiving_side_falls_back_to_oldest(self):
        r = chain(["from a (a [8.8.8.8]) by 10.0.0.1", "from b (b [1.1.1.1]) by 10.0.0.2"])
        self.assertEqual(r["originating_ip"], "1.1.1.1")
        self.assertEqual(r["indicators"]["ips_receiving"], [])


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

    def test_no_terminal_codes_from_headers(self):
        # Hand-written bytes: EmailMessage would refuse these control characters.
        raw = (b"From: a@evil.com\r\nSubject: hi\r\nDate: " + DATE.encode() + b"\r\n"
               b"Authentication-Results: mx; spf=pass smtp.mailfrom=x@\x1b[2Jevil.com\r\n"
               b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n"
               b"--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
               b"--B\r\nContent-Type: application/x-\x1b[31mevil\r\n"
               b"Content-Disposition: attachment; filename=a.bin\r\n\r\nxx\r\n--B--\r\n")
        with tempfile.TemporaryDirectory() as d:
            eml = os.path.join(d, "esc.eml")
            with open(eml, "wb") as f:
                f.write(raw)
            r = self.run_cli(eml)
        self.assertEqual(r.returncode, 0, r.stderr)
        # stdout is not a terminal here, so colours are off and any ESC is injected.
        self.assertNotIn("\x1b", r.stdout)
        self.assertIn("SPF envelope domain", r.stdout)


if __name__ == "__main__":
    unittest.main()
