#!/usr/bin/env python3
"""Phishing email header analyser.

Parses a suspicious email and produces a risk score with the
reasons behind it, so an analyst can triage quickly and then confirm by hand.

This file only handles the command line; the analysis lives in the
``email_analyser_lib`` package next to it (one module per stage).

Input:
    A full ``.eml`` file (links and attachments are analysed too), a
    text file with only the raw headers, or ``-`` to read from stdin.
    Outlook ``.msg`` files are detected and refused with instructions.

Design choices:
    * Offline by default: no API keys needed and no indicators leave your
      machine unless ``--online`` is passed.
    * Attachments are hashed and inspected as bytes only, never opened.
    * Everything printed is defanged and stripped of terminal control codes.

Exit codes:
    0  analysis finished (or LOW verdict with --exit-code)
    1  MEDIUM verdict (only with --exit-code)
    2  HIGH verdict (only with --exit-code)
    3  input or output error (file missing, not an email, JSON not writable...)

Assumptions / limitations:
    * Authentication-Results is trusted as-is; it is only meaningful when
      added by *your* receiving mail server.
    * The score is a heuristic, not a verdict. Always confirm manually.
"""
import argparse
import os
import sys

from email_analyser_lib import __version__
from email_analyser_lib.loader import InputError, load_message
from email_analyser_lib.online import has_key, load_api_keys
from email_analyser_lib.pipeline import analyse_message
from email_analyser_lib.report import print_report, save_json
from email_analyser_lib.utils import C

EXIT_ERROR = 3
_VERDICT_EXIT = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def build_parser(keys: dict) -> argparse.ArgumentParser:
    """Create the CLI parser. Key defaults come from env / api_keys.py."""
    p = argparse.ArgumentParser(
        description="Phishing email header analyser: offline by default, optional online lookups.")
    p.add_argument("input", help="Path to .eml / raw headers file, or '-' for stdin")
    p.add_argument("--json", metavar="OUTPUT_PATH", help="Save full results (raw, not defanged) to a JSON file")
    p.add_argument("--online", action="store_true",
                   help="Also check public IPs (AbuseIPDB) and attachment hashes (VirusTotal)")
    p.add_argument("--abusekey", default=keys["abuseipdb"], help="AbuseIPDB API key")
    p.add_argument("--vtkey", default=keys["virustotal"], help="VirusTotal API key")
    p.add_argument("--delay", type=float, default=15.0,
                   help="Seconds between VirusTotal calls with --online (default 15, free tier = 4/min)")
    p.add_argument("--exit-code", action="store_true",
                   help="Exit with 0/1/2 for LOW/MEDIUM/HIGH, for use in scripts and automation")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def fail(message: str) -> None:
    """Print a clean error (no traceback) and exit with ``EXIT_ERROR``."""
    print(f"{C.RED}Error: {message}{C.RESET}", file=sys.stderr)
    sys.exit(EXIT_ERROR)


def main() -> None:
    """Parse arguments, run the analysis and output the results."""
    args = build_parser(load_api_keys()).parse_args()

    try:
        msg, warnings = load_message(args.input)
    except InputError as e:
        fail(str(e))

    keys = None
    if args.online:
        keys = {"abuseipdb": args.abusekey, "virustotal": args.vtkey}
        if not any(has_key(k) for k in keys.values()):
            fail("--online needs an AbuseIPDB and/or VirusTotal key "
                 "(--abusekey / --vtkey, environment variables, or api_keys.py)")

    result = analyse_message(msg, keys=keys, delay=args.delay, warnings=warnings)
    source = "stdin" if args.input == "-" else os.path.basename(args.input)
    print_report(result, source)

    if args.json:
        try:
            save_json(result, args.json)
        except OSError as e:
            fail(f"could not write JSON to {args.json}: {e.strerror or e}")
        print(f"{C.GREEN}Results saved to: {args.json}{C.RESET}")

    sys.exit(_VERDICT_EXIT[result["verdict"]] if args.exit_code else 0)


if __name__ == "__main__":
    main()
