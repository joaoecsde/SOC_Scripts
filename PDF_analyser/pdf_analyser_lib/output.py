"""Results folder for ``-out``: report.txt plus the extracted payloads.

Extracted content is only ever written as inert data, inside
``payloads.zip`` protected with the password ``infected`` (the usual
convention for sharing malware samples), so antivirus does not delete it and
nobody opens a payload by accident. Inside the zip, JavaScript gets the
``.js.txt`` extension and everything else ``.bin``. File names built from
attacker-controlled PDF names are reduced to ``[A-Za-z0-9._-]``.

The zip is made with the system ``zip`` command (standard on macOS and
Linux), because Python's zipfile cannot write password-protected archives.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from datetime import date
from pathlib import Path
from typing import Dict, List, Tuple

from .report import render
from .utils import Colors

# Repo root (parent of PDF_analyser/), resolved from this file, not the CWD.
RESULTS_DIR = Path(__file__).resolve().parents[2] / "pdf-analysis-results"
PAYLOADS_ZIP = "payloads.zip"
ZIP_PASSWORD = "infected"

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
    """Write report.txt, and every extracted payload into ``payloads.zip``, in ``run_dir``.

    Payloads are staged in a temporary folder inside ``run_dir`` only long
    enough to zip them; the folder is always removed. No zip is made when
    nothing was extracted.

    Args:
        result: ``pipeline.analyse_pdf`` result.
        run_dir: Existing folder, normally from ``make_run_dir``.

    Returns:
        The paths written.

    Raises:
        OSError: If a file cannot be written or zipped, or the ``zip``
            command is missing (handled by the caller).
    """
    written: List[Path] = []
    report_path = run_dir / "report.txt"
    report_path.write_text(render(result, Colors(False)), encoding="utf-8")
    written.append(report_path)

    items = result.get("extracted", [])
    if not items:
        return written
    zip_cmd = shutil.which("zip")
    if zip_cmd is None:
        raise OSError("the 'zip' command is needed to save extracted payloads "
                      "(install zip, or use --json without -out)")

    zip_path = run_dir / PAYLOADS_ZIP
    with tempfile.TemporaryDirectory(dir=run_dir) as tmp:
        stage = Path(tmp)
        used: Dict[Tuple[str, str], int] = {}
        taken: set = set()
        names: List[str] = []
        for item in items:
            obj, kind = item["object"], item["kind"]
            if item.get("copy") is not None:
                obj = f"{obj}_copy{item['copy']}"
            if kind == "javascript":
                stem = f"obj{obj}_javascript"
                # A script from another, repeated object: say which copy it came from.
                if item.get("source_copy") is not None and item["source_object"] != item["object"]:
                    stem += f"_from_obj{item['source_object']}_copy{item['source_copy']}"
                path = _unique(stage, stem, ".js.txt", used, taken)
            elif kind == "embedded_file":
                name = _sanitise(os.path.basename(item.get("name") or "")).strip(".")[:_MAX_NAME]
                stem = f"obj{obj}_embedded_{name}" if name else f"obj{obj}_embedded"
                path = _unique(stage, stem, ".bin", used, taken)
            else:
                path = _unique(stage, f"obj{obj}_richmedia", ".bin", used, taken)
            path.write_bytes(item["data"])  # payload bytes exactly as given
            names.append(path.name)
        # Names go in on stdin (-@): a hostile PDF can have more payloads than
        # fit on a command line. They are already reduced to [A-Za-z0-9._-].
        proc = subprocess.run([zip_cmd, "-q", "-P", ZIP_PASSWORD, os.path.abspath(zip_path), "-@"],
                              cwd=stage, input="\n".join(names) + "\n",
                              capture_output=True, text=True)
        if proc.returncode != 0:
            raise OSError(f"zip failed (exit {proc.returncode}): {proc.stderr.strip()}")
    written.append(zip_path)
    return written
