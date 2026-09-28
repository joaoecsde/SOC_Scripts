"""Hashing and static checks on attachments. Nothing is ever executed.

Attachments are only read as bytes in memory: hashed for pivoting in
VirusTotal / EDR, and checked for the usual tricks used to get a payload
past a user. They are never written to disk or opened.
"""
from __future__ import annotations

import hashlib
import re

from . import config
from .headers import hdr
from .utils import has_hidden_chars

# Signs that an HTML attachment is a credential-harvesting page or an HTML
# smuggling dropper rather than a harmless document.
_HTML_THREAT_RE = re.compile(
    rb"<form|type=[\"']?password|window\.location|document\.write|atob\(|"
    rb"msSaveOrOpenBlob|\.click\(\)|<meta[^>]+refresh", re.I)


def _hashes(data: bytes) -> dict:
    """Return MD5, SHA1 and SHA256 hex digests of ``data``."""
    return {"md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()}


def _flags_for(fname: str, data: bytes) -> list:
    """Return ``(points, flag_text)`` tuples for one file.

    Deliberate disguise (double extension, renamed executable, hidden
    characters) scores higher than a risky extension alone, because it
    shows intent to deceive.
    """
    low = fname.lower()
    exts = re.findall(r"\.[a-z0-9]{1,5}", low)
    ext = exts[-1] if exts and low.endswith(exts[-1]) else ""
    flags = []
    if ext in config.RISKY_EXT:
        flags.append((15, f"risky file extension ({ext})"))
    if len(exts) >= 2 and exts[-2] in config.DOC_EXT and ext in config.RISKY_EXT:
        flags.append((25, "double extension disguising an executable/script as a document"))
    # U+202E (right-to-left override) can make "invoice_fdp.exe" display as
    # "invoice_exe.pdf"; zero-width characters hide parts of the name.
    if has_hidden_chars(fname):
        flags.append((25, "filename contains hidden/RTL-override characters"))
    # "MZ" is the magic header of Windows PE files (.exe/.dll). Finding it in
    # a file named otherwise means the extension is lying.
    if data[:2] == b"MZ" and ext not in (".exe", ".dll", ".scr", ".com", ".cpl", ".msi"):
        flags.append((25, "file content is a Windows executable (MZ header) despite its name"))
    if ext in (".html", ".htm", ".shtml", ".svg") and _HTML_THREAT_RE.search(data):
        flags.append((20, "HTML/SVG contains a form, redirect or script (credential phishing / HTML smuggling)"))
    return flags


def _attached_messages(part) -> list:
    """Return the email(s) inside a message/rfc822 part.

    ``iter_parts()`` only returns them on Python 3.10+; on 3.8/3.9 it
    yields nothing for message/rfc822, so the payload list is read directly.
    """
    payload = part.get_payload()
    return [p for p in payload if hasattr(p, "get_content_type")] if isinstance(payload, list) else []


def _iter_leaf_parts(part, container=""):
    """Yield ``(part, container)`` for every attachment-like part, recursively.

    Attached emails (message/rfc822) are yielded themselves *and* descended
    into, with ``container`` naming the email they came from, so files
    hidden inside a forwarded email are not missed.
    """
    ctype = part.get_content_type()
    if ctype == "message/rfc822":
        yield part, container
        name = part.get_filename() or "attached email"
        for inner in _attached_messages(part):
            yield from _iter_leaf_parts(inner, name)
    elif part.is_multipart():
        for sub in part.iter_parts():
            yield from _iter_leaf_parts(sub, container)
    else:
        yield part, container


def inspect_attachments(msg) -> list:
    """Hash and statically inspect every attachment.

    Inline parts with a filename (e.g. embedded images) are included, as
    they can also carry payloads. Attached emails are hashed as their full
    message bytes (the old script hashed them as empty files) and summarised
    with their own From / Subject; since those bytes are re-serialised by
    the parser, the hash may differ slightly from the original file and is
    not looked up online.

    Args:
        msg: Parsed email message.

    Returns:
        List of attachment dicts with ``filename``, ``kind`` ("file" or
        "email"), ``container``, ``content_type``, ``size``, hashes,
        ``flags`` (list of ``{"points", "flag"}``), ``inner`` (summary for
        attached emails) and ``online`` (filled by --online lookups).
    """
    out = []
    for part, container in _iter_leaf_parts(msg):
        if part is msg:
            continue
        fname = part.get_filename()
        is_email = part.get_content_type() == "message/rfc822"
        if not fname and not is_email and part.get_content_disposition() != "attachment":
            continue   # Normal body text / HTML.
        fname = fname or ("(attached email)" if is_email else "(unnamed)")

        inner = None
        if is_email:
            inner_msg = next(iter(_attached_messages(part)), None)
            data = inner_msg.as_bytes() if inner_msg is not None else b""
            if inner_msg is not None:
                inner = {"from": hdr(inner_msg, "From"), "subject": hdr(inner_msg, "Subject"),
                         "date": hdr(inner_msg, "Date")}
        else:
            try:
                # decode=True undoes base64 / quoted-printable so we hash the real file.
                data = part.get_payload(decode=True) or b""
            except Exception:
                data = b""

        out.append({
            "filename": fname,
            "kind": "email" if is_email else "file",
            "container": container,
            "content_type": part.get_content_type(),
            "size": len(data),
            **_hashes(data),
            "flags": [] if is_email else [{"points": p, "flag": f} for p, f in _flags_for(fname, data)],
            "inner": inner,
            "online": None,
        })
    return out
