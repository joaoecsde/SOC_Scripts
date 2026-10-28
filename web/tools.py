"""Adapters that run the SOC tools for the web UI.

Each ``run_*`` function takes a saved upload, calls the tool's library and
returns a JSON-serialisable dict. Errors the user can act on are raised as
``ToolError`` with a plain-language message.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, List, Optional, Set

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _folder in ("Email_analyser", "PDF_analyser", "IP_Hash_Check"):
    _path = os.path.join(_REPO, _folder)
    if _path not in sys.path:
        sys.path.insert(0, _path)

from email_analyser_lib.loader import InputError, load_message   # noqa: E402
from email_analyser_lib.online import has_key                    # noqa: E402
from email_analyser_lib.pipeline import analyse_message          # noqa: E402
from email_analyser_lib.report import to_json                    # noqa: E402
from email_analyser_lib.utils import defang                      # noqa: E402,F401
from pdf_analyser_lib.output import PayloadStage, write_outputs  # noqa: E402
from pdf_analyser_lib.pipeline import analyse_pdf                # noqa: E402
import threat_lookup                                             # noqa: E402

Progress = Callable[[int, int, str], None]


class ToolError(Exception):
    """Raised when a tool cannot run; the message is user-facing."""


def check_online_keys(keys: dict) -> None:
    """Raise ``ToolError`` unless at least one of the two API keys is usable."""
    if not any(has_key(keys.get(k) or "") for k in ("abuseipdb", "virustotal")):
        raise ToolError("Online lookups need an AbuseIPDB key, a VirusTotal key, or both.")


def usable_key(key: str) -> bool:
    """Return True for a real API key; empty and template placeholders are not."""
    return has_key(key or "")


def run_email(path: str, filename: str, keys: Optional[dict], delay: float,
              progress: Optional[Progress] = None) -> dict:
    """Analyse one email file.

    Args:
        path: Saved upload.
        filename: Original name, shown in the result as ``source``.
        keys: ``{"abuseipdb": ..., "virustotal": ...}`` for online lookups, or None for offline.
        delay: Seconds between VirusTotal calls.
        progress: Optional ``progress(done, total, label)`` callback.

    Returns:
        The ``report.to_json`` result plus ``"source"``.

    Raises:
        ToolError: If the file is not a readable email, or ``keys`` has no usable key.
    """
    if keys is not None:
        check_online_keys(keys)
    try:
        msg, warnings = load_message(path)
    except InputError as e:
        text = str(e)
        raise ToolError(text[:1].upper() + text[1:])
    result = analyse_message(msg, keys=keys, delay=delay, warnings=warnings, progress=progress)
    out = to_json(result)
    out["source"] = filename
    for att in out.get("attachments") or []:
        online = att.get("online")
        if isinstance(online, dict) and "error" in online:
            online["error"] = friendly_error(online["error"])
    for rep in (out.get("online_ip_results") or {}).values():
        if isinstance(rep, dict) and "error" in rep:
            rep["error"] = friendly_error(rep["error"])
    return out


def run_pdf(path: str, filename: str, extract: bool, workdir: Path) -> dict:
    """Analyse one PDF file.

    Args:
        path: Saved upload.
        filename: Original name, used for ``path`` and ``file`` in the result.
        extract: Write the extracted payloads to a password-protected zip in ``workdir``.
        workdir: Existing folder for the zip.

    Returns:
        The ``analyse_pdf`` result plus ``"payloads_zip"`` (absolute path or None), and
        ``"payload_error"`` when extraction was asked for but failed.

    Raises:
        ToolError: If the file is unreadable or has no ``%PDF-`` header.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(1024)
    except OSError as e:
        raise ToolError(f"Could not read the uploaded file: {e.strerror or e}")
    if b"%PDF-" not in head:
        raise ToolError("This file is not a PDF: it has no %PDF- header in the first 1024 bytes.")

    stage = PayloadStage(Path(tempfile.mkdtemp(dir=workdir))) if extract else None
    try:
        result = analyse_pdf(path, stage)
        result["path"] = filename
        result["file"] = filename
        result["payloads_zip"] = None
        if stage is not None:
            problem = None
            if stage.error is not None:
                problem = stage.error
            else:
                try:
                    for written in write_outputs(result, workdir, stage.folder):
                        if written.name == "payloads.zip":
                            result["payloads_zip"] = os.path.abspath(written)
                except OSError as e:
                    problem = e
            if problem is not None:
                result["payloads_zip"] = None
                result["payload_error"] = ("The extracted payloads could not be saved: "
                                           f"{getattr(problem, 'strerror', None) or problem}")
    finally:
        if stage is not None:
            shutil.rmtree(stage.folder, ignore_errors=True)
    return result


def parse_indicators(text: str) -> List[str]:
    """Split pasted text into indicators.

    Args:
        text: One indicator per line; blank lines and ``#`` lines are skipped.

    Returns:
        Refanged indicators, duplicates removed, order kept.
    """
    seen = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = threat_lookup.refang(line)
        if line not in seen:
            seen.append(line)
    return seen


def needed_keys(indicators: List[str]) -> Set[str]:
    """Return which API keys the indicators need: ``abuseipdb`` and/or ``virustotal``."""
    needed = set()
    for ind in indicators:
        if threat_lookup.is_ip(ind) and threat_lookup.is_public_ip(ind):
            needed.add("abuseipdb")
        elif threat_lookup.is_hash(ind):
            needed.add("virustotal")
    return needed


def friendly_error(message: str) -> str:
    """Turn a lookup error string into a plain-language message."""
    message = str(message)
    if message.startswith("HTTP 401") or message.startswith("HTTP 403"):
        code = message[5:8]
        return f"The API key was rejected (HTTP {code}). Check the key and try again."
    if message.startswith("HTTP 429"):
        return "Rate limit reached (HTTP 429). Wait a minute or raise the delay, then try again."
    if message.startswith("Hash not found"):
        return "Not found on VirusTotal: no one has uploaded this file yet."
    if "timed out" in message:
        return "The service did not answer in time. Try again."
    if any(t in message for t in ("Max retries", "Failed to establish", "ConnectionError",
                                  "Name or service not known")):
        return "Could not reach the service. Check the internet connection."
    return message[:200]


def run_ioc(indicators: List[str], keys: dict, max_age: int, delay: float,
            progress: Optional[Progress] = None) -> List[dict]:
    """Look up IPs on AbuseIPDB and hashes on VirusTotal.

    Mirrors the loop in ``threat_lookup.main``.

    Args:
        indicators: Output of ``parse_indicators``.
        keys: ``{"abuseipdb": ..., "virustotal": ...}``.
        max_age: AbuseIPDB look-back window in days.
        delay: Seconds to wait between VirusTotal calls.
        progress: Optional ``progress(done, total, label)`` callback.

    Returns:
        ``[{"type": "ip"|"hash"|"unknown", "indicator": str, "result": dict}]``, with
        every ``result["error"]`` made user-friendly.
    """
    total = len(indicators)
    results = []
    vt_called = False

    def report(done: int, label: str) -> None:
        if progress is not None:
            progress(done, total, label)

    for done, indicator in enumerate(indicators):
        report(done, f"Checking {defang(indicator)}")
        if threat_lookup.is_ip(indicator) and not threat_lookup.is_public_ip(indicator):
            kind = "ip"
            result = {"skipped": "Private or reserved IP address, not looked up"}
        elif threat_lookup.is_ip(indicator):
            kind = "ip"
            result = threat_lookup.lookup_ip(indicator, keys.get("abuseipdb") or "", max_age)
        elif threat_lookup.is_hash(indicator):
            kind = "hash"
            if vt_called:
                report(done, f"Waiting {delay:g} s for VirusTotal's rate limit")
                time.sleep(delay)
            vt_called = True
            result = threat_lookup.lookup_hash(indicator, keys.get("virustotal") or "")
        else:
            kind = "unknown"
            result = {"error": "Unrecognised format"}
        if "error" in result:
            result["error"] = friendly_error(result["error"])
        results.append({"type": kind, "indicator": indicator, "result": result})
        report(done + 1, f"Checking {defang(indicator)}")
    return results
