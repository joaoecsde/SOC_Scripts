"""Read the input and make sure it really is an email.

The standard library parser never fails: give it a PDF, an Outlook .msg or
a file starting with a blank line and it returns an "email" with no
headers. The old script then scored that silently. This module catches
those cases and explains what to do instead.
"""
from __future__ import annotations

import os
import sys
from email import policy
from email.parser import BytesParser


class InputError(Exception):
    """Raised when the input cannot be analysed; the message is user-facing."""


# File signatures of formats that are commonly passed by mistake.
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"   # Outlook .msg (and old .doc/.xls)
_OTHER_MAGIC = {b"%PDF": "a PDF", b"PK\x03\x04": "a ZIP/Office file", b"\x89PNG": "a PNG image"}

# Headers that virtually every real email or header dump contains. If none
# are present the input was not parsed as an email.
_EXPECTED_HEADERS = ("From", "Received", "Subject", "Date", "Message-ID", "Return-Path")

_MSG_HELP = """this looks like an Outlook .msg file, which this tool cannot read.
Save the email in .eml format instead:
  - New Outlook / Outlook on the web: open the email > ... > Save / Download (.eml)
  - Classic Outlook: File > Properties > copy "Internet headers" into a .txt file
  - Or forward the email as an attachment from Outlook on the web and save that .eml
  - Gmail: open the email > three-dot menu > Download message"""


def read_input(path: str) -> bytes:
    """Read raw bytes from a file or stdin.

    Args:
        path: File path, or ``-`` for stdin.

    Returns:
        The raw bytes.

    Raises:
        InputError: If the file is missing, a folder, unreadable or empty.
    """
    # Checked up front because Windows reports a folder as "permission denied".
    if path != "-" and os.path.isdir(path):
        raise InputError(f"{path} is a folder, not a file")
    try:
        if path == "-":
            raw = sys.stdin.buffer.read()
        else:
            with open(path, "rb") as f:
                raw = f.read()
    except FileNotFoundError:
        raise InputError(f"file not found: {path}")
    except IsADirectoryError:
        raise InputError(f"{path} is a folder, not a file")
    except PermissionError:
        raise InputError(f"no permission to read {path}")
    except OSError as e:
        raise InputError(f"could not read {path}: {e}")
    if not raw.strip():
        raise InputError("the input is empty")
    return raw


def parse_email(raw: bytes):
    """Validate raw bytes and parse them into an email message.

    Leading blank lines and a UTF-8 BOM are removed, because the parser
    treats a blank first line as "end of headers" and would push every
    header into the body. This often happens when headers are copied from a
    mail client into a text file.

    Args:
        raw: Raw email or header bytes.

    Returns:
        ``(message, warnings)`` where ``message`` is an
        ``email.message.EmailMessage`` and ``warnings`` is a list of
        user-facing notes about fixes applied to the input.

    Raises:
        InputError: If the input is a .msg or other non-email file, or has no
            recognisable email headers.
    """
    warnings = []
    if raw.startswith(_OLE_MAGIC):
        raise InputError(_MSG_HELP)
    for magic, kind in _OTHER_MAGIC.items():
        if raw.startswith(magic):
            raise InputError(f"this is {kind}, not an email (.eml) or header text file")

    cleaned = raw.lstrip(b"\xef\xbb\xbf").lstrip(b" \t\r\n")
    if cleaned != raw and raw.lstrip(b"\xef\xbb\xbf")[:1] in (b"\r", b"\n", b" ", b"\t"):
        warnings.append("Removed blank lines at the start of the input so the headers could be read.")

    # policy.default gives the modern EmailMessage API and decodes
    # encoded-word headers (=?utf-8?...?=) for us.
    msg = BytesParser(policy=policy.default).parsebytes(cleaned)
    if not any(msg.get(h) for h in _EXPECTED_HEADERS):
        raise InputError("no email headers found. Make sure the file starts with the raw headers "
                         "(From:, Received:, Subject:...), e.g. a full .eml or 'Show original' text")
    return msg, warnings


def load_message(path: str):
    """Read and parse an email from ``path`` (``-`` for stdin).

    Returns:
        ``(message, warnings)``, see ``parse_email``.

    Raises:
        InputError: See ``read_input`` and ``parse_email``.
    """
    return parse_email(read_input(path))
