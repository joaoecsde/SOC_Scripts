"""Terminal report and JSON export.

Every attacker-controlled string (finding text, previews, targets, names,
errors, file name) goes through ``safe()`` and then ``defang_text()``, so a
hostile PDF cannot hijack the terminal or leave a clickable link. The JSON
export keeps raw values, except that extracted payload bytes are replaced by
their size and SHA-256.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Union

from . import __version__
from .utils import C, Colors, defang_text, safe

_SEV_ORDER = {"high": 0, "medium": 1, "info": 2}
_CAVEAT = "The verdict is a heuristic, not a final answer. Always confirm manually."
_ENCRYPTED_WARNING = ("Encrypted PDF: strings and streams could not be decoded; "
                      "the verdict may be understated.")


def _clean(value) -> str:
    """Safe, defanged, single-line text.

    Line breaks are shown as the two characters ``\\r`` / ``\\n`` so a hostile
    value cannot start a fake report line (e.g. a forged ``Verdict``).
    """
    if value is None:
        return ""
    return defang_text(safe(str(value).replace("\r", "\\r").replace("\n", "\\n")))


def _section(c: Colors, title: str) -> str:
    return f"\n{c.BOLD}{c.CYAN}{'-' * 70}{c.RESET}\n{c.BOLD}{title}{c.RESET}\n{'-' * 70}"


def _sev_color(c: Colors, sev: str) -> str:
    return {"high": c.RED, "medium": c.YELLOW}.get(sev, c.GRAY)


def _verdict_color(c: Colors, v: str) -> str:
    return c.RED if v == "HIGH" else c.YELLOW if v == "MEDIUM" else c.GREEN


def render(result: dict, colors: Colors) -> str:
    """Build the full report text.

    Args:
        result: ``pipeline.analyse_pdf`` result.
        colors: ``Colors`` instance; ``Colors(False)`` gives plain text.

    Returns:
        The report as one string.
    """
    c = colors
    v = result["verdict"]
    lines = [f"\n{c.BOLD}PDF Static Analysis v{__version__} - {_clean(result['file'])}{c.RESET}",
             _section(c, "File"),
             f"  {'Name':<8}: {_clean(result['file'])}",
             f"  {'SHA-256':<8}: {result['sha256']}",
             f"  {'Size':<8}: {result['size']} bytes",
             f"  {'Verdict':<8}: {_verdict_color(c, v)}{c.BOLD}{v}{c.RESET}"]
    if result["encrypted"]:
        lines.append(f"  {c.YELLOW}{_ENCRYPTED_WARNING}{c.RESET}")
    if result["partial"] and not result["encrypted"]:
        errs = "; ".join(_clean(e) for e in result["errors"])
        lines.append(f"  {c.YELLOW}Parsing was partial: {errs}{c.RESET}")

    lines.append(_section(c, f"Findings ({len(result['findings'])})"))
    if not result["findings"]:
        lines.append(f"  {c.GREEN}No suspicious indicators found{c.RESET}")
    for f in sorted(result["findings"], key=lambda x: _SEV_ORDER.get(x["severity"], 9)):
        where = f"obj {f['object']}"
        if f.get("copy") is not None:
            where += f", copy {f['copy']}"
        if f.get("objstm") is not None:
            where += f" (in ObjStm {f['objstm']})"
        lines.append(f"  {_sev_color(c, f['severity'])}{f['severity'].upper():<6}{c.RESET} "
                     f"{_clean(f['keyword'])}  {where}")
        lines.append(f"      {_clean(f['finding'])}")
        if f.get("target"):
            lines.append(f"      Target: {_clean(f['target'])}")
        if f.get("markers"):
            lines.append(f"      Markers: {', '.join(_clean(m) for m in f['markers'])}")
        if f.get("preview"):
            for pl in f["preview"].splitlines():
                lines.append(f"      {c.GRAY}| {_clean(pl)}{c.RESET}")

    lines.append(_section(c, "Verdict"))
    lines.append(f"  {_verdict_color(c, v)}{c.BOLD}{v}{c.RESET}")
    lines.append(f"  {c.GRAY}{_CAVEAT}{c.RESET}\n")
    return "\n".join(lines)


def print_report(result: dict) -> None:
    """Print the colour-coded report to the terminal."""
    print(render(result, C))


def save_json(result: dict, path: Union[str, "os.PathLike[str]"]) -> None:
    """Write the result as JSON (raw values, UTF-8, no payload bytes).

    Each ``extracted`` item has ``data`` replaced by ``size`` and ``sha256``.

    Raises:
        OSError: If the file cannot be written (handled by the caller).
    """
    out = dict(result)
    out["extracted"] = []
    for item in result.get("extracted", []):
        slim = {k: v for k, v in item.items() if k != "data"}
        slim["size"] = len(item["data"])
        slim["sha256"] = hashlib.sha256(item["data"]).hexdigest()
        out["extracted"].append(slim)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, default=str, ensure_ascii=False)
