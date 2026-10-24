"""Runs every analysis stage in order and returns one result dict.

This is the library entry point: other tools (e.g. the email analyser) only
need ``analyse_pdf()``. Nothing in the PDF is executed.
"""
from __future__ import annotations

import hashlib
import os
from typing import List, Optional

from . import __version__
from .extract import (find_actions, find_duplicates, find_keywords, find_triggers,
                      iter_embedded_files, iter_javascript, iter_richmedia_streams)
from .output import PayloadStage
from .parser import load_pdf
from .rules import embedded_finding, javascript_finding, other_findings, trigger_findings, verdict


def analyse_pdf(path: str, stage: Optional[PayloadStage] = None) -> dict:
    """Analyse one PDF file statically.

    Scripts, embedded files and rich media are graded and hashed one at a
    time as they are decoded, then dropped, so memory holds a few decoded
    streams at most instead of all of them. Every stream is still analysed.

    Args:
        path: Path to the PDF.
        stage: Writes each payload to its folder (for ``-out``, see
            ``output.payload_stage``); None keeps only the hashes. A write
            error is kept in ``stage.error``, not raised.

    Returns:
        Dict with ``file``, ``path``, ``size``, ``sha256``, ``tool_version``,
        ``verdict``, ``encrypted``, ``partial``, ``errors``, ``findings`` and
        ``extracted`` (list of ``{"object", "copy", "kind", "name", "size",
        "sha256", "payload_name"}``; JavaScript items also carry
        ``source_object`` and ``source_copy``).

    Raises:
        OSError: If the file cannot be read.
    """
    with open(path, "rb") as fh:
        raw = fh.read()
    pdf = load_pdf(path)
    if stage is None:
        stage = PayloadStage()

    extracted: List[dict] = []
    js_findings = []
    for j in iter_javascript(pdf):
        js_findings.append(javascript_finding(j))
        if j.get("code"):
            # A script from a referenced stream is saved byte-exact; an inline
            # string script is saved as UTF-8 text.
            data = j["data"] if j["source_object"] != j["object"] else None
            if data is None:
                data = j["code"].encode("utf-8", "replace")
            extracted.append(stage.add({"object": j["object"], "copy": j["copy"],
                                        "kind": "javascript", "name": None,
                                        "source_object": j["source_object"],
                                        "source_copy": j["source_copy"]}, data))
    embedded_findings = []
    for e in iter_embedded_files(pdf):
        embedded_findings.append(embedded_finding(e))
        extracted.append(stage.add({"object": e["object"], "copy": e["copy"],
                                    "kind": "embedded_file", "name": e.get("name")}, e["data"]))
    for m in iter_richmedia_streams(pdf):
        extracted.append(stage.add({"object": m["object"], "copy": m["copy"],
                                    "kind": "richmedia", "name": None}, m["data"]))

    facts = {"actions": find_actions(pdf), "triggers": find_triggers(pdf),
             "keywords": find_keywords(pdf), "duplicates": find_duplicates(pdf)}
    # Same order as rules.evaluate().
    findings = (trigger_findings(facts["triggers"]) + js_findings + embedded_findings
                + other_findings(facts))

    return {"file": os.path.basename(path), "path": path, "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(), "tool_version": __version__,
            "verdict": verdict(findings), "encrypted": pdf.encrypted,
            "partial": pdf.partial, "errors": list(pdf.errors),
            "findings": findings, "extracted": extracted}
