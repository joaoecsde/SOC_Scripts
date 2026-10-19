"""Runs every analysis stage in order and returns one result dict.

This is the library entry point: other tools (e.g. the email analyser) only
need ``analyse_pdf()``. Nothing in the PDF is executed.
"""
from __future__ import annotations

import hashlib
import os
from typing import List

from . import __version__
from .extract import (find_actions, find_embedded_files, find_javascript, find_keywords,
                      find_richmedia_streams, find_triggers)
from .parser import load_pdf
from .rules import evaluate, verdict


def analyse_pdf(path: str) -> dict:
    """Analyse one PDF file statically.

    Args:
        path: Path to the PDF.

    Returns:
        Dict with ``file``, ``path``, ``size``, ``sha256``, ``tool_version``,
        ``verdict``, ``encrypted``, ``partial``, ``errors``, ``findings`` and
        ``extracted`` (list of ``{"object", "kind", "name", "data"}``).

    Raises:
        OSError: If the file cannot be read.
    """
    with open(path, "rb") as fh:
        raw = fh.read()
    pdf = load_pdf(path)

    javascript = find_javascript(pdf)
    embedded = find_embedded_files(pdf)
    richmedia = find_richmedia_streams(pdf)
    facts = {"javascript": javascript, "actions": find_actions(pdf),
             "triggers": find_triggers(pdf), "embedded": embedded,
             "keywords": find_keywords(pdf), "richmedia": richmedia}
    findings = evaluate(facts)

    extracted: List[dict] = []
    for j in javascript:
        if j.get("code"):
            # A script from a referenced stream is saved byte-exact; an inline
            # string script is saved as UTF-8 text.
            source = pdf.objects.get(j["source_object"])
            data = source.stream() if source is not None and \
                j["source_object"] != j["object"] else None
            if data is None:
                data = j["code"].encode("utf-8", "replace")
            extracted.append({"object": j["object"], "kind": "javascript", "name": None,
                              "data": data})
    for e in embedded:
        extracted.append({"object": e["object"], "kind": "embedded_file",
                          "name": e.get("name"), "data": e["data"]})
    for m in richmedia:
        extracted.append({"object": m["object"], "kind": "richmedia", "name": None,
                          "data": m["data"]})

    return {"file": os.path.basename(path), "path": path, "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(), "tool_version": __version__,
            "verdict": verdict(findings), "encrypted": pdf.encrypted,
            "partial": pdf.partial, "errors": list(pdf.errors),
            "findings": findings, "extracted": extracted}
