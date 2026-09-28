"""Optional AbuseIPDB / VirusTotal lookups (only used with --online).

Written without any dependency on the email code, so threat_lookup.py can
reuse it later instead of keeping its own copy. ``requests`` is imported
inside the functions so the default offline mode works on a plain Python
install without extra packages.
"""
from __future__ import annotations

import os
import sys


def load_api_keys() -> dict:
    """Load API keys: environment variable > shared ``api_keys.py``.

    ``api_keys.py`` lives in the repo root (two folders up from this file) and
    is git-ignored, so every script shares one private keys file. A missing
    file is fine because keys are only needed for --online. CLI flags, which
    take priority over both, are applied by the caller.

    Returns:
        ``{"abuseipdb": str, "virustotal": str}`` (empty strings if unset).
    """
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    try:
        import api_keys
    except ImportError:
        api_keys = None
    return {
        "abuseipdb": os.environ.get("ABUSEIPDB_API_KEY") or getattr(api_keys, "ABUSEIPDB_API_KEY", ""),
        "virustotal": os.environ.get("VIRUSTOTAL_API_KEY") or getattr(api_keys, "VIRUSTOTAL_API_KEY", ""),
    }


def has_key(key: str) -> bool:
    """Return True for a real key; unedited templates ("your_..._here") count as missing."""
    return bool(key) and not key.startswith("your_")


def _requests():
    """Import requests lazily with a helpful message if it is missing."""
    try:
        import requests
        return requests
    except ImportError:
        raise RuntimeError("the 'requests' library is not installed (python3 -m pip install requests)")


def _http_error(r) -> str:
    """Short, actionable message for the HTTP errors analysts actually hit."""
    return {401: "HTTP 401: API key is wrong or not set",
            403: "HTTP 403: API key lacks permission for this lookup",
            429: "HTTP 429: rate limit reached, wait or increase --delay"}.get(
        r.status_code, f"HTTP {r.status_code}")


def check_ip(ip: str, key: str, max_age_days: int = 90) -> dict:
    """Look up an IP's reputation on AbuseIPDB.

    Args:
        ip: Public IPv4/IPv6 address.
        key: AbuseIPDB API key.
        max_age_days: Only count reports newer than this.

    Returns:
        Dict with ``abuse_score``, ``reports``, ``country``, ``isp`` and
        ``is_tor``, or ``{"error": str}``. Errors are returned, not raised,
        so one failed lookup does not stop the report.
    """
    try:
        requests = _requests()
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Accept": "application/json", "Key": key},
                         params={"ipAddress": ip, "maxAgeInDays": max_age_days}, timeout=10)
        if r.status_code != 200:
            return {"error": _http_error(r)}
        d = r.json().get("data", {})
        return {"abuse_score": d.get("abuseConfidenceScore"), "reports": d.get("totalReports"),
                "country": d.get("countryCode"), "isp": d.get("isp"), "is_tor": d.get("isTor")}
    except Exception as e:
        return {"error": str(e)}


def check_hash(sha256: str, key: str) -> dict:
    """Look up a file hash on VirusTotal. Only the hash is sent, never the file.

    A 404 just means VirusTotal has never seen the file. That is common for
    targeted malware and does not mean the file is safe.

    Args:
        sha256: SHA256 of the file.
        key: VirusTotal API key.

    Returns:
        Dict with ``malicious``, ``suspicious``, ``total`` and ``link``, or
        ``{"error": str}``.
    """
    try:
        requests = _requests()
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                         headers={"x-apikey": key}, timeout=10)
        if r.status_code == 404:
            return {"error": "Not found in VirusTotal (unknown file, not proof it is safe)"}
        if r.status_code != 200:
            return {"error": _http_error(r)}
        stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
        return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                "total": sum(stats.values()),
                "link": f"https://www.virustotal.com/gui/file/{sha256}"}
    except Exception as e:
        return {"error": str(e)}
