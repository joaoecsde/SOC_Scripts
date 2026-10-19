"""Tunable lists and thresholds for the PDF analyser."""
from __future__ import annotations

# JavaScript obfuscation markers: name -> regex (searched in decoded script text).
JS_MARKERS = {
    "eval":             r"\beval\s*\(",
    "unescape":         r"\bunescape\s*\(",
    "fromCharCode":     r"String\.fromCharCode",
    "%u shellcode":     r"(%u[0-9a-fA-F]{4}){8,}",
    "long hex string":  r"[0-9a-fA-F]{200,}",
}

# Number of '" + "' or "' + '" string joins that counts as heavy string building.
CONCAT_MIN = 40

# Embedded file extensions treated as executable or script content.
EXEC_EXTENSIONS = (".exe", ".dll", ".scr", ".com", ".pif", ".js", ".jse", ".vbs", ".vbe",
                   ".ps1", ".bat", ".cmd", ".hta", ".wsf", ".msi", ".lnk", ".jar")

# JavaScript preview shown in findings.
PREVIEW_LINES = 5
PREVIEW_WIDTH = 120
