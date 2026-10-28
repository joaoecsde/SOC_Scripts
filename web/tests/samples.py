"""In-memory sample files for the web tests, so no fixtures are needed."""
from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "PDF_analyser", "tests"))

from pdfgen import make_pdf  # noqa: E402


def phishing_eml() -> bytes:
    """A hostile email: HTML in the subject, a link that lies, an exe in disguise."""
    return (
        b"From: PayPal Support <support@paypa1-secure.example>\r\n"
        b"To: victim@example.org\r\n"
        b"Subject: <script>alert(1)</script>\r\n"
        b"Date: Mon, 1 Jan 2024 10:00:00 +0000\r\n"
        b"Message-ID: <abc@paypa1-secure.example>\r\n"
        b"Received: from mail.evil.example (mail.evil.example [45.9.148.12]) "
        b"by mx.me.com; Mon, 1 Jan 2024 10:00:01 +0000\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=BOUND\r\n"
        b"\r\n"
        b"--BOUND\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b'<html><body><a href="http://45.9.148.12/login">paypal.com</a></body></html>\r\n'
        b"--BOUND\r\n"
        b"Content-Type: application/octet-stream; name=\"invoice.pdf.exe\"\r\n"
        b"Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n"
        b"Content-Transfer-Encoding: 7bit\r\n"
        b"\r\n"
        b"MZ\x90 fake executable body\r\n"
        b"--BOUND--\r\n"
    )


def msg_file() -> bytes:
    """Starts with the OLE magic of an Outlook .msg file."""
    return b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64


def js_pdf() -> bytes:
    """A PDF whose /OpenAction runs JavaScript."""
    return make_pdf({1: "<< /Type /Catalog /OpenAction 2 0 R >>",
                     2: "<< /S /JavaScript /JS (app.alert\\(1\\)) >>"})


def not_pdf() -> bytes:
    """Plain text with no %PDF- header."""
    return b"just some text, nothing to see\n" * 10
