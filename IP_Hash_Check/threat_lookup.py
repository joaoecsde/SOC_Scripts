#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
import time
from typing import Optional
import requests

# ── API keys (CLI flag > environment variable > ../api_keys.py) ────────────────
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
try:
    import api_keys
except ImportError:
    api_keys = None
ABUSEIPDB_API_KEY  = os.environ.get("ABUSEIPDB_API_KEY")  or getattr(api_keys, "ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY") or getattr(api_keys, "VIRUSTOTAL_API_KEY", "")

# ── Regex helpers ───────────────────────────────────────────────────────────────
IPV4_RE  = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
HASH_RE  = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")

def is_ip(value: str) -> bool:
    return bool(IPV4_RE.match(value.strip()))

def is_hash(value: str) -> bool:
    return bool(HASH_RE.match(value.strip()))


# ── AbuseIPDB ──────────────────────────────────────────────────────────────────
def lookup_ip(ip: str, api_key: str, max_age_days: int = 90) -> dict:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key}
    params  = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": True}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", {})
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {resp.status_code}: {resp.text}"}
    except Exception as e:
        return {"error": str(e)}

    return {
        "ip":              data.get("ipAddress"),
        "abuse_score":     data.get("abuseConfidenceScore"),
        "total_reports":   data.get("totalReports"),
        "distinct_users":  data.get("numDistinctUsers"),
        "country":         data.get("countryCode"),
        "isp":             data.get("isp"),
        "domain":          data.get("domain"),
        "is_tor":          data.get("isTor"),
        "is_whitelisted":  data.get("isWhitelisted"),
        "last_reported":   data.get("lastReportedAt"),
        "usage_type":      data.get("usageType"),
    }


# ── VirusTotal ─────────────────────────────────────────────────────────────────
def lookup_hash(hash_value: str, api_key: str) -> dict:
    url     = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 404:
            return {"error": "Hash not found in VirusTotal database"}
        resp.raise_for_status()
        attr = resp.json().get("data", {}).get("attributes", {})
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {resp.status_code}: {resp.text}"}
    except Exception as e:
        return {"error": str(e)}

    stats = attr.get("last_analysis_stats", {})
    names = attr.get("names", [])

    return {
        "hash_sha256":      attr.get("sha256"),
        "hash_sha1":        attr.get("sha1"),
        "hash_md5":         attr.get("md5"),
        "meaningful_name":  attr.get("meaningful_name"),
        "file_names":       names[:5] if names else [],
        "file_type":        attr.get("type_description"),
        "file_size":        attr.get("size"),
        "malicious":        stats.get("malicious", 0),
        "suspicious":       stats.get("suspicious", 0),
        "undetected":       stats.get("undetected", 0),
        "harmless":         stats.get("harmless", 0),
        "first_submission": attr.get("first_submission_date"),
        "last_submission":  attr.get("last_submission_date"),
        "last_analysis":    attr.get("last_analysis_date"),
        "times_submitted":  attr.get("times_submitted"),
        "vt_link":          f"https://www.virustotal.com/gui/file/{attr.get('sha256', hash_value)}",
    }


# ── Pretty printing ────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"

# Text from the APIs and the indicator file can contain terminal escape codes
# (VirusTotal file names are chosen by whoever uploaded the file). Control
# characters become "?" and invisible / right-to-left characters are shown
# as <U+XXXX>, so nothing can recolour or rewrite the output.
_BIDI_INVISIBLE = re.compile("[​-‏‪-‮⁦-⁩﻿]")
_CONTROL = re.compile("[\x00-\x08\x0a-\x1f\x7f-\x9f]")

def safe(value) -> str:
    text = _BIDI_INVISIBLE.sub(lambda m: f"<U+{ord(m.group()):04X}>", str(value))
    return _CONTROL.sub("?", text)

def color_score(score: Optional[int], thresholds=(25, 75)) -> str:
    if score is None:
        return f"{GRAY}N/A{RESET}"
    if score >= thresholds[1]:
        return f"{RED}{score}{RESET}"
    if score >= thresholds[0]:
        return f"{YELLOW}{score}{RESET}"
    return f"{GREEN}{score}{RESET}"

def print_ip_result(ip: str, result: dict) -> None:
    print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
    print(f"{BOLD}IP Address : {ip}{RESET}")
    print(f"{'─'*60}")

    if "error" in result:
        print(f"  {RED}Error: {safe(result['error'])}{RESET}")
        return

    score = result.get("abuse_score")
    print(f"  Abuse Score     : {color_score(score)} / 100")
    print(f"  Total Reports   : {safe(result.get('total_reports', 'N/A'))}")
    print(f"  Distinct Users  : {safe(result.get('distinct_users', 'N/A'))}")
    print(f"  Country         : {safe(result.get('country', 'N/A'))}")
    print(f"  ISP             : {safe(result.get('isp', 'N/A'))}")
    print(f"  Domain          : {safe(result.get('domain', 'N/A'))}")
    print(f"  Usage Type      : {safe(result.get('usage_type', 'N/A'))}")
    print(f"  Is Tor          : {safe(result.get('is_tor', 'N/A'))}")
    print(f"  Whitelisted     : {safe(result.get('is_whitelisted', 'N/A'))}")
    print(f"  Last Reported   : {safe(result.get('last_reported', 'N/A'))}")

def print_hash_result(hash_val: str, result: dict) -> None:
    print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
    print(f"{BOLD}Hash : {hash_val}{RESET}")
    print(f"{'─'*60}")

    if "error" in result:
        print(f"  {RED}Error: {safe(result['error'])}{RESET}")
        return

    malicious  = result.get("malicious", 0)
    suspicious = result.get("suspicious", 0)
    total      = malicious + suspicious + result.get("undetected", 0) + result.get("harmless", 0)

    detection_str = f"{malicious} / {total}"
    if malicious > 0:
        detection_str = f"{RED}{detection_str}{RESET}"
    elif suspicious > 0:
        detection_str = f"{YELLOW}{detection_str}{RESET}"
    else:
        detection_str = f"{GREEN}{detection_str}{RESET}"

    print(f"  Detection       : {detection_str} engines flagged as malicious")
    print(f"  Suspicious      : {suspicious}")
    print(f"  Name            : {safe(result.get('meaningful_name', 'N/A'))}")
    print(f"  File Type       : {safe(result.get('file_type', 'N/A'))}")
    print(f"  File Size       : {safe(result.get('file_size', 'N/A'))} bytes")
    print(f"  SHA256          : {safe(result.get('hash_sha256', 'N/A'))}")
    print(f"  SHA1            : {safe(result.get('hash_sha1', 'N/A'))}")
    print(f"  MD5             : {safe(result.get('hash_md5', 'N/A'))}")
    known_names = result.get("file_names", [])
    if known_names:
        print(f"  Known Names     : {', '.join(safe(n) for n in known_names)}")
    print(f"  Times Submitted : {safe(result.get('times_submitted', 'N/A'))}")
    print(f"  First Seen      : {safe(result.get('first_submission', 'N/A'))}")
    print(f"  Last Seen       : {safe(result.get('last_submission', 'N/A'))}")
    print(f"  VT Link         : {safe(result.get('vt_link', 'N/A'))}")


# ── JSON output ────────────────────────────────────────────────────────────────
def export_json(results: list, path: str) -> None:
    with open(path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n{GREEN}Results saved to: {path}{RESET}")


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Threat intelligence lookup: IPs via AbuseIPDB, hashes via VirusTotal",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python threat_lookup.py --abusekey YOUR_KEY --vtkey YOUR_KEY \\
      --indicators 1.2.3.4 d41d8cd98f00b204e9800998ecf8427e

  python threat_lookup.py --abusekey KEY --vtkey KEY \\
      --file indicators.txt --json results.json
        """
    )
    parser.add_argument("--indicators", nargs="+", metavar="VALUE",
                        help="One or more IPs or file hashes (MD5/SHA1/SHA256)")
    parser.add_argument("--file", metavar="PATH",
                        help="Text file with one IP or hash per line")
    parser.add_argument("--abusekey", default=ABUSEIPDB_API_KEY,
                        help="AbuseIPDB API key")
    parser.add_argument("--vtkey", default=VIRUSTOTAL_API_KEY,
                        help="VirusTotal API key")
    parser.add_argument("--json", metavar="OUTPUT_PATH",
                        help="Also save results to a JSON file")
    parser.add_argument("--max-age", type=int, default=90, metavar="DAYS",
                        help="AbuseIPDB: max age of reports in days (default: 90)")
    parser.add_argument("--delay", type=float, default=0.5, metavar="SECONDS",
                        help="Delay between API calls in seconds (default: 0.5)")

    args = parser.parse_args()

    # Collect indicators
    indicators = list(args.indicators or [])
    if args.file:
        try:
            with open(args.file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        indicators.append(line)
        except FileNotFoundError:
            print(f"{RED}Error: File not found: {args.file}{RESET}")
            sys.exit(1)

    if not indicators:
        parser.print_help()
        sys.exit(1)

    # Validate API keys
    missing_keys = []
    for indicator in indicators:
        if is_ip(indicator) and not args.abusekey:
            missing_keys.append("--abusekey (AbuseIPDB) required for IP lookups")
            break
    for indicator in indicators:
        if is_hash(indicator) and not args.vtkey:
            missing_keys.append("--vtkey (VirusTotal) required for hash lookups")
            break
    if missing_keys:
        for msg in set(missing_keys):
            print(f"{RED}Error: {msg}{RESET}")
        sys.exit(1)

    all_results = []
    print(f"\n{BOLD}Threat Intelligence Lookup — {len(indicators)} indicator(s){RESET}")

    for i, indicator in enumerate(indicators):
        indicator = indicator.strip()
        if i > 0:
            time.sleep(args.delay)

        if is_ip(indicator):
            result = lookup_ip(indicator, args.abusekey, args.max_age)
            print_ip_result(indicator, result)
            all_results.append({"type": "ip", "indicator": indicator, "result": result})

        elif is_hash(indicator):
            result = lookup_hash(indicator, args.vtkey)
            print_hash_result(indicator, result)
            all_results.append({"type": "hash", "indicator": indicator, "result": result})

        else:
            print(f"\n{YELLOW}Skipping '{safe(indicator)}' — not a valid IPv4 address or MD5/SHA1/SHA256 hash{RESET}")
            all_results.append({"type": "unknown", "indicator": indicator, "result": {"error": "Unrecognised format"}})

    print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
    print(f"{BOLD}Done. {len(all_results)} indicator(s) processed.{RESET}\n")

    if args.json:
        export_json(all_results, args.json)


if __name__ == "__main__":
    main()