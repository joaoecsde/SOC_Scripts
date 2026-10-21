"""Results folder for ``-out``: report.txt plus the extracted payloads.

Extracted content is only ever written as inert data. JavaScript gets the
``.js.txt`` extension and everything else ``.bin``, so nothing written here
can be double-clicked and run. File names built from attacker-controlled
PDF names are reduced to ``[A-Za-z0-9._-]`` and never leave the run folder.
"""
from __future__ import annotations

import os
import re
from datetime import date
from pathlib import Path
from typing import Dict, List, Tuple

from .report import render
from .utils import Colors

# Repo root (parent of PDF_analyser/), resolved from this file, not the CWD.
RESULTS_DIR = Path(__file__).resolve().parents[2] / "pdf-analysis-results"

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")
# Longest embedded-file name kept in an output file name (avoids ENAMETOOLONG).
_MAX_NAME = 100


def _sanitise(text: str) -> str:
    return _UNSAFE.sub("_", text)


def make_run_dir(pdf_path: str, today: date, base: Path = RESULTS_DIR) -> Path:
    """Create the folder for one run.

    Args:
        pdf_path: Path of the analysed PDF (only its name is used, taken).
        today: Date used in the folder name.
        base: Parent folder; created if missing.

    Returns:
        The new folder ``base/DD-MM-YYYY-<stem>``, or ``-2``, ``-3`` and so on
        if that name is already taken.

    Raises:
        OSError: If the folder cannot be created (handled by the caller).
    """
    base.mkdir(parents=True, exist_ok=True)
    name = f"{today.strftime('%d-%m-%Y')}-{_sanitise(Path(pdf_path).stem)}"
    n = 1
    while True:
        run_dir = base / (name if n == 1 else f"{name}-{n}")
        try:
            run_dir.mkdir(exist_ok=False)
            return run_dir
        except FileExistsError:
            n += 1


def _unique(run_dir: Path, stem: str, ext: str, used: Dict[Tuple[str, str], int],
            taken: set) -> Path:
    """Return ``stem+ext``, or ``stem_2+ext``, ``stem_3+ext`` for repeats."""
    while True:
        count = used[(stem, ext)] = used.get((stem, ext), 0) + 1
        name = f"{stem}{ext}" if count == 1 else f"{stem}_{count}{ext}"
        if name not in taken:
            taken.add(name)
            return run_dir / name


def write_outputs(result: dict, run_dir: Path) -> List[Path]:
    """Write report.txt and every extracted payload into ``run_dir``.

    Args:
        result: ``pipeline.analyse_pdf`` result.
        run_dir: Existing folder, normally from ``make_run_dir``.

    Returns:
        The paths written.

    Raises:
        OSError: If a file cannot be written (handled by the caller).
    """
    written: List[Path] = []
    report_path = run_dir / "report.txt"
    report_path.write_text(render(result, Colors(False)), encoding="utf-8")
    written.append(report_path)

    used: Dict[Tuple[str, str], int] = {}
    taken = {"report.txt"}
    for item in result.get("extracted", []):
        obj, kind = item["object"], item["kind"]
        if item.get("copy") is not None:
            obj = f"{obj}_copy{item['copy']}"
        if kind == "javascript":
            stem = f"obj{obj}_javascript"
            # A script from another, repeated object: say which copy it came from.
            if item.get("source_copy") is not None and item["source_object"] != item["object"]:
                stem += f"_from_obj{item['source_object']}_copy{item['source_copy']}"
            path = _unique(run_dir, stem, ".js.txt", used, taken)
        elif kind == "embedded_file":
            name = _sanitise(os.path.basename(item.get("name") or "")).strip(".")[:_MAX_NAME]
            stem = f"obj{obj}_embedded_{name}" if name else f"obj{obj}_embedded"
            path = _unique(run_dir, stem, ".bin", used, taken)
        else:
            path = _unique(run_dir, f"obj{obj}_richmedia", ".bin", used, taken)
        path.write_bytes(item["data"])  # payload bytes exactly as given
        written.append(path)
    return written
