"""Turn extracted PDF facts into findings and a LOW / MEDIUM / HIGH verdict.

Severity:
    high    automatic or clearly malicious behaviour (JS on open, obfuscated JS,
            executable attachment, form submission to an external target)
    medium  active content that needs a look (plain JS, attachments, /Launch,
            /RichMedia, local /SubmitForm or /GoToR)
    info    context only (/URI, /ObjStm, /XObject, destination triggers)

Values are stored raw; defanging happens in the report.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from . import config

_MARKER_RES = {name: re.compile(rx) for name, rx in config.JS_MARKERS.items()}
_HIGH_TRIGGER_ACTIONS = ("/JavaScript", "/URI", "/SubmitForm", "/GoToR", "/Launch")
_EXTERNAL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")


def js_markers(code: str) -> List[str]:
    """Return the names of the obfuscation markers found in a script."""
    found = [name for name, rx in _MARKER_RES.items() if rx.search(code)]
    if code.count('" + "') + code.count("' + '") >= config.CONCAT_MIN:
        found.append("string building")
    return found


def is_executable(name: Optional[str], data: bytes) -> bool:
    """True for an ``MZ`` or ``#!`` prefix, or a name with an executable extension."""
    if data[:2] in (b"MZ", b"#!"):
        return True
    return bool(name) and name.lower().endswith(config.EXEC_EXTENSIONS)


def is_external(target: str) -> bool:
    """True for a ``scheme://`` URL or a UNC path starting with two backslashes."""
    return bool(target) and (target.startswith("\\\\") or bool(_EXTERNAL_RE.match(target)))


def _finding(severity: str, keyword: str, item: dict, text: str, preview: Optional[str] = None,
             markers: Optional[List[str]] = None, target: Optional[str] = None) -> dict:
    return {"severity": severity, "keyword": keyword, "object": item["object"],
            "objstm": item.get("objstm"), "finding": text, "preview": preview,
            "markers": markers or [], "target": target}


def _preview(code: str) -> str:
    lines = code.splitlines()[:config.PREVIEW_LINES]
    return "\n".join(l[:config.PREVIEW_WIDTH] for l in lines)


def evaluate(facts: Dict) -> List[dict]:
    """Build findings from the extracted facts.

    Args:
        facts: Dict with ``javascript``, ``actions``, ``triggers``, ``embedded``,
            ``keywords`` and ``richmedia`` (Task 2 output).

    Returns:
        List of finding dicts with severity, keyword, object, objstm, finding,
        preview, markers and target.
    """
    out: List[dict] = []

    for t in facts.get("triggers", []):
        kw = t["keyword"]
        if t.get("action") in _HIGH_TRIGGER_ACTIONS:
            if kw == "/Names":
                text = "Document-level JavaScript runs when the document opens"
            elif kw == "/OpenAction":
                text = ("Runs a %s action automatically when the document is opened"
                        % t["action"].lstrip("/"))
            else:
                text = ("Runs a %s action automatically on a document event"
                        % t["action"].lstrip("/"))
            out.append(_finding("high", kw, t, text))
        else:
            out.append(_finding("info", kw, t, "Automatic trigger with no active action "
                                "(page destination or other action type)"))

    for j in facts.get("javascript", []):
        code = j.get("code") or ""
        if not code:
            out.append(_finding("medium", "/JavaScript", j,
                                "Contains JavaScript, but the script could not be resolved"))
            continue
        markers = js_markers(code)
        if markers:
            out.append(_finding("high", "/JavaScript", j,
                                "Contains JavaScript with obfuscation markers: " + ", ".join(markers),
                                _preview(code), markers))
        else:
            out.append(_finding("medium", "/JavaScript", j, "Contains JavaScript",
                                _preview(code)))

    for e in facts.get("embedded", []):
        name = e.get("name")
        label = repr(name) if name else "(unnamed)"
        if is_executable(name, e.get("data") or b""):
            out.append(_finding("high", "/EmbeddedFile", e,
                                "Embeds an executable or script file: " + label))
        else:
            out.append(_finding("medium", "/EmbeddedFile", e, "Embeds a file: " + label))

    for a in facts.get("actions", []):
        typ, target = a["type"], a.get("target")
        if typ == "/URI":
            out.append(_finding("info", typ, a, "Contains a link", target=target))
        elif typ == "/Launch":
            out.append(_finding("medium", typ, a, "Launches an external program or file",
                                target=target))
        elif typ in ("/SubmitForm", "/GoToR"):
            what = "Submits form data to" if typ == "/SubmitForm" else "Opens a remote document at"
            if is_external(target or ""):
                out.append(_finding("high", typ, a, what + " an external target", target=target))
            else:
                out.append(_finding("medium", typ, a, what + " a local target", target=target))

    for oid in facts.get("keywords", {}).get("/RichMedia", []):
        out.append(_finding("medium", "/RichMedia", {"object": oid},
                            "Contains embedded rich media (Flash/video/3D)"))
    for kw, text in (("/ObjStm", "Uses object streams (compressed objects)"),
                     ("/XObject", "Contains external objects (images or forms)")):
        for oid in facts.get("keywords", {}).get(kw, []):
            out.append(_finding("info", kw, {"object": oid}, text))
    return out


def verdict(findings: List[dict]) -> str:
    """HIGH if any high finding, else MEDIUM if any medium, else LOW."""
    sevs = {f["severity"] for f in findings}
    if "high" in sevs:
        return "HIGH"
    return "MEDIUM" if "medium" in sevs else "LOW"
