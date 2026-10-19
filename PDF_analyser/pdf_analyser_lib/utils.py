"""Small shared helpers: terminal colours, safe printing and defanging."""
from __future__ import annotations

import re
import sys


# Terminal colours
class Colors:
    """ANSI colour codes, blanked when stdout is not a terminal.

    Redirecting the report to a file would otherwise fill it with escape
    sequences.
    """

    def __init__(self, enabled: bool):
        on = enabled
        self.RESET = "\033[0m" if on else ""
        self.BOLD = "\033[1m" if on else ""
        self.RED = "\033[91m" if on else ""
        self.YELLOW = "\033[93m" if on else ""
        self.GREEN = "\033[92m" if on else ""
        self.CYAN = "\033[96m" if on else ""
        self.GRAY = "\033[90m" if on else ""


C = Colors(sys.stdout.isatty())


# Safe text for the terminal
# Invisible characters that change how text is displayed. Shown as <U+XXXX>
# so the analyst sees they are there instead of being fooled by them
# (e.g. U+202E makes "invoice_fdp.exe" display as "invoice_exe.pdf").
_BIDI_INVISIBLE = re.compile("[​-‏‪-‮⁦-⁩﻿]")
# Other control characters (incl. ESC, which starts terminal escape codes).
# Attacker-controlled content could otherwise clear the screen or recolour
# the report. Tab is kept.
_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def safe(text) -> str:
    """Make any value safe to print in a terminal.

    Args:
        text: Value to display; ``None`` becomes an empty string.

    Returns:
        String with invisible/bidi characters made visible and control
        characters replaced by ``?``.
    """
    if text is None:
        return ""
    text = _BIDI_INVISIBLE.sub(lambda m: f"<U+{ord(m.group()):04X}>", str(text))
    return _CONTROL.sub("?", text)


# Defanging
# No \b before the scheme: "1http://evil.com" must be defanged too.
_URL_RE = re.compile(r"(?i)([a-z][a-z0-9+.-]*)://([^\s/?#<>\"'()\[\]]*)")


def defang_text(text: str) -> str:
    """Defang every ``scheme://host...`` URL found in free text.

    Only the scheme ``http`` (including ``https``) becomes ``hxxp`` and the
    dots of the host become ``[.]``; the path and the rest of the text are
    left alone.

    Args:
        text: Any text, e.g. extracted JavaScript or a report line.

    Returns:
        Text with each URL made non-clickable, e.g.
        ``hxxps://evil[.]com/a.php``.
    """
    def _fix(m: re.Match) -> str:
        scheme = re.sub(r"(?i)^http", "hxxp", m.group(1))
        return f"{scheme}://{m.group(2).replace('.', '[.]')}"

    return _URL_RE.sub(_fix, text or "")
