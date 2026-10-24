"""Results folder for ``-out``: report.txt plus the extracted payloads.

Extracted content is only ever written as inert data, inside
``payloads.zip`` protected with the password ``infected`` (the usual
convention for sharing malware samples), so antivirus does not delete it and
nobody opens a payload by accident. Inside the zip, JavaScript gets the
``.js.txt`` extension and everything else ``.bin``. File names built from
attacker-controlled PDF names are reduced to ``[A-Za-z0-9._-]``. While
the PDF is analysed, payloads wait in a temporary ``.payloads-*`` folder
inside the results folder (see ``PayloadStage``), removed once zipped.

The zip is made with the system ``zip`` command (standard on macOS and
Linux), because Python's zipfile cannot write password-protected archives.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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


def payload_stage(base: Path = RESULTS_DIR) -> tempfile.TemporaryDirectory:
    """Temporary folder in ``base`` holding payloads until ``write_outputs`` zips them.

    Use it as a context manager; the folder and anything left in it are
    removed on exit.

    Raises:
        OSError: If ``base`` cannot be created (handled by the caller).
    """
    base.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(dir=base, prefix=".payloads-")


class PayloadStage:
    """Takes each extracted payload as soon as it is decoded.

    The bytes are hashed and, when a folder is given, written there under
    their final ``payloads.zip`` name; only the size, SHA-256 and name are
    kept. So memory holds a few decoded streams at most instead of every
    payload until the end, and nothing is skipped.

    A failed write (e.g. disk full, which a hostile file can cause) does not
    stop the analysis: the first error is kept in ``error`` for the caller to
    report after the verdict, and later payloads are only hashed.
    """

    def __init__(self, folder: Optional[Path] = None):
        self.folder = folder
        self.error: Optional[OSError] = None
        self._used: Dict[Tuple[str, str], int] = {}
        self._taken: set = set()

    def add(self, item: dict, data: bytes) -> dict:
        """Return ``item`` with ``size``, ``sha256`` and ``payload_name``.

        ``payload_name`` is None without a folder or once a write has failed.

        Args:
            item: ``{"object", "copy", "kind", "name"}``, plus ``source_object`` /
                ``source_copy`` for JavaScript.
            data: The payload bytes, written exactly as given.
        """
        name = None
        if self.folder is not None and self.error is None:
            path = self._path(item)
            try:
                path.write_bytes(data)
                name = path.name
            except OSError as e:
                self.error = e
        return dict(item, size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                    payload_name=name)

    def _path(self, item: dict) -> Path:
        obj, kind = item["object"], item["kind"]
        if item.get("copy") is not None:
            obj = f"{obj}_copy{item['copy']}"
        if kind == "javascript":
            stem = f"obj{obj}_javascript"
            # A script from another, repeated object: say which copy it came from.
            if item.get("source_copy") is not None and item["source_object"] != item["object"]:
                stem += f"_from_obj{item['source_object']}_copy{item['source_copy']}"
            return _unique(self.folder, stem, ".js.txt", self._used, self._taken)
        if kind == "embedded_file":
            name = _sanitise(os.path.basename(item.get("name") or "")).strip(".")[:_MAX_NAME]
            stem = f"obj{obj}_embedded_{name}" if name else f"obj{obj}_embedded"
            return _unique(self.folder, stem, ".bin", self._used, self._taken)
        return _unique(self.folder, f"obj{obj}_richmedia", ".bin", self._used, self._taken)


def write_outputs(result: dict, run_dir: Path, stage: Optional[Path] = None) -> List[Path]:
    """Write report.txt, and the staged payloads into ``payloads.zip``, in ``run_dir``.

    No zip is made when nothing was staged (``stage`` is None, or no
    ``extracted`` item has a ``payload_name``).

    Args:
        result: ``pipeline.analyse_pdf`` result.
        run_dir: Existing folder, normally from ``make_run_dir``.
        stage: The folder of the ``PayloadStage`` given to ``analyse_pdf``.

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

    names = [i["payload_name"] for i in result.get("extracted", []) if i.get("payload_name")]
    if stage is None or not names:
        return written
    zip_cmd = shutil.which("zip")
    if zip_cmd is None:
        raise OSError("the 'zip' command is needed to save extracted payloads "
                      "(install zip, or use --json without -out)")

    zip_path = run_dir / PAYLOADS_ZIP
    # Names go in on stdin (-@): a hostile PDF can have more payloads than
    # fit on a command line. They are already reduced to [A-Za-z0-9._-].
    proc = subprocess.run([zip_cmd, "-q", "-P", ZIP_PASSWORD, os.path.abspath(zip_path), "-@"],
                          cwd=stage, input="\n".join(names) + "\n",
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise OSError(f"zip failed (exit {proc.returncode}): {proc.stderr.strip()}")
    written.append(zip_path)
    return written
