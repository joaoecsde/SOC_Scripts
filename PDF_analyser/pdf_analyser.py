#!/usr/bin/env python3
"""Static PDF triage tool.

Inspects a suspicious PDF for active content (JavaScript, auto-run actions,
embedded files, launch/submit actions) and produces a LOW / MEDIUM / HIGH
verdict with the reasons behind it, so an analyst can triage quickly and then
confirm by hand.

This file only handles the command line; the analysis lives in the
``pdf_analyser_lib`` package next to it (one module per stage).

Input:
    A PDF file. The file must contain ``%PDF-`` in its first 1024 bytes.

Design choices:
    * Offline: no network access of any kind.
    * Static only: JavaScript and embedded files are decoded and written as
      inert text/bytes (``.js.txt`` / ``.bin``) inside ``payloads.zip``
      (password ``infected``), never executed or opened.
    * Parsing uses the vendored Didier Stevens ``pdf-parser``, kept unmodified.
    * Everything printed is defanged and stripped of terminal control codes.

Exit codes:
    0  analysis finished (or LOW verdict with --exit-code)
    1  MEDIUM verdict (only with --exit-code)
    2  HIGH verdict (only with --exit-code)
    3  input or output error (file missing, not a PDF, results not writable...)

Assumptions / limitations:
    * Encrypted or heavily malformed PDFs can hide content; the report says
      when the verdict may be understated.
    * The verdict is a heuristic, not a conclusion. Always confirm manually.
"""
from __future__ import annotations

import argparse
import sys
from contextlib import ExitStack
from datetime import date
from pathlib import Path

from pdf_analyser_lib import __version__
from pdf_analyser_lib.output import PayloadStage, make_run_dir, payload_stage, write_outputs
from pdf_analyser_lib.pipeline import analyse_pdf
from pdf_analyser_lib.report import print_report, save_json
from pdf_analyser_lib.utils import C

EXIT_ERROR = 3
_VERDICT_EXIT = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


class _ArgumentParser(argparse.ArgumentParser):
    """ArgumentParser whose usage errors exit with ``EXIT_ERROR`` (3), not 2.

    Exit code 2 means HIGH under ``--exit-code``, so a bad flag must not use it.
    """

    def error(self, message: str) -> None:
        """Print the usage and the message to stderr, then exit with ``EXIT_ERROR``."""
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    p = _ArgumentParser(
        description="Static PDF triage: finds JavaScript, auto-run actions and embedded files.")
    p.add_argument("input", help="Path to the PDF file")
    p.add_argument("-out", action="store_true", dest="out",
                   help="Save report.txt, and extracted scripts/files in payloads.zip "
                        "(password: infected), to pdf-analysis-results/")
    p.add_argument("--json", action="store_true",
                   help="Save JSON_report.json (raw, not defanged) to the results folder")
    p.add_argument("--exit-code", action="store_true",
                   help="Exit with 0/1/2 for LOW/MEDIUM/HIGH, for use in scripts and automation")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def fail(message: str) -> None:
    """Print a clean error (no traceback) and exit with ``EXIT_ERROR``."""
    print(f"{C.RED}Error: {message}{C.RESET}", file=sys.stderr)
    sys.exit(EXIT_ERROR)


def check_pdf(path: str) -> None:
    """Exit with an error unless ``path`` is a readable file containing ``%PDF-``."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(1024)
    except FileNotFoundError:
        fail(f"file not found: {path}")
    except OSError as e:
        fail(f"cannot read {path}: {e.strerror or e}")
    if b"%PDF-" not in head:
        fail(f"{path} is not a PDF (no %PDF- header in the first 1024 bytes)")


def main() -> None:
    """Parse arguments, run the analysis and output the results."""
    args = build_parser().parse_args()
    check_pdf(args.input)

    # With -out, payloads are written to a staging folder as they are decoded
    # (not kept in memory) and zipped into the run folder at the end. A
    # staging error is only reported after the verdict has been printed.
    with ExitStack() as cleanup:
        stage, stage_error = None, None
        if args.out:
            try:
                stage = PayloadStage(Path(cleanup.enter_context(payload_stage())))
            except OSError as e:
                stage_error = e
        try:
            result = analyse_pdf(args.input, stage)
        except OSError as e:
            fail(f"cannot read {args.input}: {e.strerror or e}")
        except Exception as e:  # defensive: a hostile file must never print a traceback
            fail(f"analysis failed: {type(e).__name__}: {e}")

        print_report(result)  # first, so the verdict shows even if writing fails

        if args.out or args.json:
            try:
                run_dir = make_run_dir(args.input, date.today())
                if args.out:
                    stage_error = stage_error or stage.error
                    if stage_error is not None:
                        # Nothing is zipped, so no payload has a name in payloads.zip.
                        for item in result["extracted"]:
                            item["payload_name"] = None
                    # Without a complete staging folder only report.txt is written,
                    # so the run folder is never left empty.
                    write_outputs(result, run_dir, None if stage_error else stage.folder)
                if args.json:
                    save_json(result, run_dir / "JSON_report.json")
            except (OSError, UnicodeEncodeError) as e:
                fail(f"cannot write results: {e}")
            if stage_error is not None:
                fail(f"cannot save payloads: {stage_error} (the other results are in {run_dir})")
            print(f"{C.GREEN}Results saved to: {run_dir}{C.RESET}")

    if args.exit_code:
        sys.exit(_VERDICT_EXIT[result["verdict"]])


if __name__ == "__main__":
    main()
