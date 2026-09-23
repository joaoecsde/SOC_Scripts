#!/usr/bin/env python3
"""
Phishing Email Header Analyser
==============================
Offline analysis of an email (.eml file or raw headers) for signs of phishing
or spoofing. Optional online checks (--online) query AbuseIPDB for IPs and
VirusTotal for attachment hashes.

Usage:
  python email_header_analyser.py suspicious.eml
  python email_header_analyser.py headers.txt --json report.json
  cat headers.txt | python email_header_analyser.py -
  python email_header_analyser.py suspicious.eml --online --abusekey KEY --vtkey KEY

Attachments are only hashed and inspected as bytes. They are never opened or executed.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
from datetime import timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime

# -- API keys (only needed with --online; flag > environment variable > ../api_keys.py)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
try:
    import api_keys
except ImportError:
    api_keys = None
ABUSEIPDB_API_KEY  = os.environ.get("ABUSEIPDB_API_KEY")  or getattr(api_keys, "ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY") or getattr(api_keys, "VIRUSTOTAL_API_KEY", "")

# -- Colours --------------------------------------------------------------------
if sys.stdout.isatty():
    RESET, BOLD, RED, YELLOW, GREEN, CYAN, GRAY = (
        "\033[0m", "\033[1m", "\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[90m")
else:
    RESET = BOLD = RED = YELLOW = GREEN = CYAN = GRAY = ""

# -- Constants ------------------------------------------------------------------
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)

BRANDS = ["paypal", "microsoft", "office365", "outlook", "apple", "icloud", "amazon",
          "google", "netflix", "dhl", "fedex", "ups", "docusign", "dropbox", "linkedin",
          "facebook", "instagram", "santander", "caixa", "millennium", "bankofamerica",
          "wellsfargo", "chase", "hsbc", "binance", "coinbase"]
FREE_MAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com",
             "proton.me", "protonmail.com", "gmx.com", "mail.com", "icloud.com"}
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml",
                   "cf", "ga", "work", "support", "rest", "monster", "icu", "buzz"}
BULK_MAILERS = ["phpmailer", "swiftmailer", "the bat", "mass mail", "sendblaster",
                "mailer", "smtp client", "leaf pgp", "python", "php/"]
RISKY_EXT = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".bat", ".cmd",
             ".ps1", ".com", ".pif", ".jar", ".msi", ".dll", ".lnk", ".iso", ".img",
             ".hta", ".cpl", ".reg", ".docm", ".xlsm", ".pptm", ".xlam", ".one",
             ".html", ".htm", ".svg", ".zip", ".rar", ".7z", ".ace", ".gz"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
           ".jpg", ".jpeg", ".png", ".gif", ".rtf", ".csv"}


# -- Helpers --------------------------------------------------------------------
def defang(value: str) -> str:
    return value.replace("http", "hxxp").replace(".", "[.]")

def refang(value: str) -> str:
    return (value.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
            .replace("hxxp", "http").replace("[:]", ":").replace("[at]", "@"))

def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[1].lower().strip(">") if addr and "@" in addr else ""

def root_domain(domain: str) -> str:
    """Rough registrable domain (last two labels; handles common co.xx style)."""
    parts = domain.lower().split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()

def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

def valid_ips(text: str) -> list:
    out = []
    for m in IPV4_RE.findall(text or ""):
        try:
            ipaddress.ip_address(m)
            if m not in out:
                out.append(m)
        except ValueError:
            pass
    return out

def hdr(msg, name: str) -> str:
    v = msg.get(name)
    return " ".join(str(v).split()) if v is not None else ""


# -- 1. Input handling ----------------------------------------------------------
def load_message(path: str):
    if path == "-":
        raw = sys.stdin.buffer.read()
    else:
        with open(path, "rb") as f:
            raw = f.read()
    return BytesParser(policy=policy.default).parsebytes(raw)


# -- 2. Header extraction -------------------------------------------------------
def extract_headers(msg) -> dict:
    def addrs(name):
        vals = msg.get_all(name) or []
        return [(n, a) for n, a in getaddresses([str(v) for v in vals])]
    frm = addrs("From")
    return {
        "from": hdr(msg, "From"),
        "from_name": frm[0][0] if frm else "",
        "from_addr": frm[0][1].lower() if frm else "",
        "reply_to": hdr(msg, "Reply-To"),
        "reply_to_addr": (addrs("Reply-To") or [("", "")])[0][1].lower(),
        "return_path": hdr(msg, "Return-Path"),
        "return_path_addr": (addrs("Return-Path") or [("", "")])[0][1].lower(),
        "to": hdr(msg, "To"),
        "subject": hdr(msg, "Subject"),
        "date": hdr(msg, "Date"),
        "message_id": hdr(msg, "Message-ID"),
        "x_mailer": hdr(msg, "X-Mailer") or hdr(msg, "User-Agent"),
        "x_originating_ip": hdr(msg, "X-Originating-IP").strip("[] "),
    }


# -- 3. Received chain ----------------------------------------------------------
def parse_received(msg) -> list:
    hops = []
    for raw in msg.get_all("Received") or []:
        text = " ".join(str(raw).split())
        date_part = text.rsplit(";", 1)[1].strip() if ";" in text else ""
        ts = None
        try:
            ts = parsedate_to_datetime(date_part)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except Exception:
            pass
        frm = re.search(r"\bfrom\s+(\S+)", text, re.I)
        by = re.search(r"\bby\s+([^\s;]+)", text, re.I)
        ips = valid_ips(text.split(";")[0])
        hops.append({"from": frm.group(1) if frm else "", "by": by.group(1) if by else "",
                     "ips": ips, "timestamp": ts, "raw": text})
    hops.reverse()  # oldest first = real delivery order
    for i, hop in enumerate(hops):
        prev = hops[i - 1]["timestamp"] if i else None
        hop["delay_s"] = int((hop["timestamp"] - prev).total_seconds()) if (prev and hop["timestamp"]) else None
    return hops

def originating_ip(hops: list, headers: dict) -> str:
    for hop in hops:
        for ip in hop["ips"]:
            if is_public_ip(ip):
                return ip
    xo = headers.get("x_originating_ip", "")
    return xo if xo and is_public_ip(xo) else ""


# -- 4. Authentication ----------------------------------------------------------
def parse_auth(msg) -> dict:
    res = {"spf": "none", "dkim": "none", "dmarc": "none", "dkim_domain": "", "spf_domain": ""}
    ar = " ".join(" ".join(str(v).split()) for v in (msg.get_all("Authentication-Results") or []))
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}\s*=\s*(\w+)", ar, re.I)
        if m:
            res[mech] = m.group(1).lower()
    if res["spf"] == "none":
        rs = hdr(msg, "Received-SPF")
        if rs:
            res["spf"] = rs.split()[0].lower()
    m = re.search(r"header\.d\s*=\s*([\w.-]+)", ar, re.I)
    if m:
        res["dkim_domain"] = m.group(1).lower()
    else:
        sig = hdr(msg, "DKIM-Signature")
        m = re.search(r"\bd\s*=\s*([\w.-]+)", sig)
        if m:
            res["dkim_domain"] = m.group(1).lower()
    m = re.search(r"smtp\.mailfrom\s*=\s*([^\s;]+)", ar, re.I)
    if m:
        res["spf_domain"] = domain_of(m.group(1)) or m.group(1).lower()
    res["has_auth_header"] = bool(ar or hdr(msg, "Received-SPF"))
    return res


# -- 5/7. Spoofing detection + scoring -----------------------------------------
def analyse(headers: dict, hops: list, auth: dict, attachments: list) -> list:
    """Returns findings as (points, severity, text)."""
    f = []
    add = lambda pts, sev, txt: f.append({"points": pts, "severity": sev, "finding": txt})

    from_dom = domain_of(headers["from_addr"])
    rt_dom = domain_of(headers["reply_to_addr"])
    ret_dom = domain_of(headers["return_path_addr"])
    mid_dom = domain_of(headers["message_id"].strip("<>"))
    name = headers["from_name"].lower()

    if not from_dom:
        add(20, "high", "No valid From address could be parsed")

    # Authentication
    if not auth["has_auth_header"]:
        add(10, "medium", "No Authentication-Results / Received-SPF header present (auth cannot be verified)")
    for mech, pts in (("spf", 15), ("dkim", 15), ("dmarc", 20)):
        v = auth[mech]
        if v in ("fail", "softfail", "permerror", "temperror", "neutral") :
            add(pts if v != "neutral" else 5, "high" if v == "fail" else "medium", f"{mech.upper()} result: {v}")
        elif v == "none" and auth["has_auth_header"]:
            add(5, "low", f"{mech.upper()} not present in authentication results")
    if auth["dkim_domain"] and from_dom and root_domain(auth["dkim_domain"]) != root_domain(from_dom):
        add(10, "medium", f"DKIM signing domain ({auth['dkim_domain']}) does not align with From domain ({from_dom})")
    if auth["spf_domain"] and from_dom and root_domain(auth["spf_domain"]) != root_domain(from_dom):
        add(10, "medium", f"SPF envelope domain ({auth['spf_domain']}) does not align with From domain ({from_dom})")

    # Address mismatches
    if rt_dom and from_dom and root_domain(rt_dom) != root_domain(from_dom):
        add(20, "high", f"Reply-To domain ({rt_dom}) differs from From domain ({from_dom})")
    if ret_dom and from_dom and root_domain(ret_dom) != root_domain(from_dom):
        add(10, "medium", f"Return-Path domain ({ret_dom}) differs from From domain ({from_dom})")
    if mid_dom and from_dom and root_domain(mid_dom) != root_domain(from_dom):
        add(10, "medium", f"Message-ID domain ({mid_dom}) differs from From domain ({from_dom})")
    if not headers["message_id"]:
        add(5, "low", "Message-ID header is missing")
    if not headers["date"]:
        add(5, "low", "Date header is missing")

    # Display name tricks
    if "@" in name:
        shown = domain_of(re.sub(r"[^\w@.\-]", "", name))
        if shown and shown != from_dom:
            add(25, "high", f"Display name contains an email address ({shown}) different from the real sender ({from_dom})")
    for brand in BRANDS:
        if brand in name and brand not in from_dom:
            why = "a free mail provider" if from_dom in FREE_MAIL else f"unrelated domain {from_dom}"
            add(20, "high", f"Display name references '{brand}' but the email is sent from {why}")
            break

    # Lookalike / odd domains
    if from_dom:
        if "xn--" in from_dom or any(ord(c) > 127 for c in from_dom):
            add(25, "high", f"From domain uses punycode / non-ASCII characters (possible homograph): {from_dom}")
        leet = from_dom.translate(str.maketrans("01358", "oleba"))
        for brand in BRANDS:
            if brand in leet and brand not in from_dom:
                add(25, "high", f"From domain looks like a character-substituted '{brand}': {from_dom}")
                break
            if brand in from_dom and not from_dom.endswith((brand + ".com", brand + ".net", brand + ".org")) \
                    and root_domain(from_dom).split(".")[0] != brand:
                add(15, "medium", f"From domain embeds brand '{brand}' in a different domain: {from_dom}")
                break
        if from_dom.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            add(10, "medium", f"From domain uses a TLD often abused in phishing: .{from_dom.rsplit('.', 1)[-1]}")
        if from_dom.count("-") >= 3 or from_dom.count(".") >= 4:
            add(5, "low", f"From domain looks unusually long or complex: {from_dom}")

    # Mailer
    xm = headers["x_mailer"].lower()
    if xm and any(k in xm for k in BULK_MAILERS):
        add(10, "medium", f"Unusual / bulk-mail client: {headers['x_mailer']}")

    # Received chain
    if not hops:
        add(10, "medium", "No Received headers found (headers may be stripped or incomplete)")
    else:
        if len(hops) > 8:
            add(5, "low", f"Unusually long relay chain ({len(hops)} hops)")
        for h in hops:
            if h["delay_s"] is not None and h["delay_s"] > 3600:
                add(5, "low", f"Large delay of {h['delay_s']//60} min before hop via {h['by'] or '?'}")
            if h["delay_s"] is not None and h["delay_s"] < -60:
                add(10, "medium", f"Timestamps go backwards at hop via {h['by'] or '?'} (forged or clock skew)")
    if not originating_ip(hops, headers) and hops:
        add(5, "low", "No public originating IP could be identified")

    # Attachments
    for a in attachments:
        for flag in a["flags"]:
            add(a["points_per_flag"], "high" if a["points_per_flag"] >= 20 else "medium",
                f"Attachment '{a['filename']}': {flag}")
    return f

def verdict(score: int) -> str:
    return "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"


# -- 6. Indicators --------------------------------------------------------------
def extract_indicators(msg, headers, hops) -> dict:
    ips, domains, urls = [], set(), set()
    for h in hops:
        for ip in h["ips"]:
            if ip not in ips:
                ips.append(ip)
    for key in ("x_originating_ip",):
        for ip in valid_ips(headers.get(key, "")):
            if ip not in ips:
                ips.append(ip)
    for key in ("from_addr", "reply_to_addr", "return_path_addr"):
        d = domain_of(headers.get(key, ""))
        if d:
            domains.add(d)
    for hop in hops:
        for k in ("from", "by"):
            v = hop[k].strip("[]();").lower()
            if "." in v and not valid_ips(v):
                domains.add(v)
    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html") and part.get_content_disposition() != "attachment":
            try:
                body = part.get_content()
            except Exception:
                continue
            for u in URL_RE.findall(body):
                urls.add(u.rstrip(".,;"))
    return {
        "ips_public": [i for i in ips if is_public_ip(i)],
        "ips_private": [i for i in ips if not is_public_ip(i)],
        "domains": sorted(domains),
        "urls": sorted(urls),
    }


# -- Attachments ----------------------------------------------------------------
def inspect_attachments(msg) -> list:
    out = []
    for part in msg.walk():
        fname = part.get_filename()
        if not fname and part.get_content_disposition() != "attachment":
            continue
        fname = fname or "(unnamed)"
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:
            data = b""
        low = fname.lower()
        exts = [e for e in re.findall(r"\.[a-z0-9]{1,5}", low)]
        ext = exts[-1] if exts else ""
        flags = []
        if ext in RISKY_EXT:
            flags.append(f"risky file extension ({ext})")
        if len(exts) >= 2 and exts[-2] in DOC_EXT and ext in RISKY_EXT:
            flags.append("double extension disguising an executable/script as a document")
        if re.search(r"[‮​]", fname):
            flags.append("filename contains hidden/RTL-override characters")
        if data[:2] == b"MZ" and ext not in (".exe", ".dll", ".scr"):
            flags.append("file content is a Windows executable (MZ header) despite its name")
        out.append({
            "filename": fname,
            "content_type": part.get_content_type(),
            "size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "flags": flags,
            "points_per_flag": 25 if any("executable" in x or "double" in x for x in flags) else 15,
            "online": None,
        })
    return out


# -- Online lookups (optional) --------------------------------------------------
def online_ip(ip: str, key: str) -> dict:
    import requests
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Accept": "application/json", "Key": key},
                         params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10)
        r.raise_for_status()
        d = r.json().get("data", {})
        return {"abuse_score": d.get("abuseConfidenceScore"), "reports": d.get("totalReports"),
                "country": d.get("countryCode"), "isp": d.get("isp"), "is_tor": d.get("isTor")}
    except Exception as e:
        return {"error": str(e)}

def online_hash(sha256: str, key: str) -> dict:
    import requests
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                         headers={"x-apikey": key}, timeout=10)
        if r.status_code == 404:
            return {"error": "Not found in VirusTotal"}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
        return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                "total": sum(stats.values()),
                "link": f"https://www.virustotal.com/gui/file/{sha256}"}
    except Exception as e:
        return {"error": str(e)}


# -- 8. Reporting ---------------------------------------------------------------
def sev_color(sev: str) -> str:
    return {"high": RED, "medium": YELLOW, "low": GRAY}.get(sev, "")

def line(title):
    print(f"\n{BOLD}{CYAN}{'-'*70}{RESET}\n{BOLD}{title}{RESET}\n{'-'*70}")

def print_report(path, headers, hops, auth, indicators, attachments, findings, score, orig_ip, online_ips):
    print(f"\n{BOLD}Phishing Email Header Analysis - {os.path.basename(path) if path != '-' else 'stdin'}{RESET}")

    line("Key headers")
    for label, key in (("From", "from"), ("Reply-To", "reply_to"), ("Return-Path", "return_path"),
                       ("To", "to"), ("Subject", "subject"), ("Date", "date"),
                       ("Message-ID", "message_id"), ("X-Mailer", "x_mailer")):
        print(f"  {label:<12}: {headers[key] or GRAY + 'N/A' + RESET}")
    print(f"  {'Origin IP':<12}: {defang(orig_ip) if orig_ip else GRAY + 'not identified' + RESET}")

    line("Received chain (oldest -> newest)")
    if not hops:
        print(f"  {YELLOW}No Received headers{RESET}")
    for i, h in enumerate(hops, 1):
        ts = h["timestamp"].strftime("%Y-%m-%d %H:%M:%S %z") if h["timestamp"] else "unknown time"
        delay = f"  (+{h['delay_s']}s)" if h["delay_s"] is not None and i > 1 else ""
        ips = ", ".join(defang(x) for x in h["ips"]) or "no IP"
        print(f"  {i:>2}. {h['from'] or '?'} -> {h['by'] or '?'}  [{ips}]  {ts}{delay}")

    line("Authentication")
    for mech in ("spf", "dkim", "dmarc"):
        v = auth[mech]
        col = GREEN if v == "pass" else RED if v in ("fail", "softfail", "permerror") else YELLOW
        print(f"  {mech.upper():<6}: {col}{v}{RESET}")
    if auth["dkim_domain"]:
        print(f"  DKIM signing domain : {auth['dkim_domain']}")
    if auth["spf_domain"]:
        print(f"  SPF envelope domain : {auth['spf_domain']}")

    line("Indicators (defanged)")
    print(f"  Public IPs : {', '.join(defang(i) for i in indicators['ips_public']) or 'none'}")
    print(f"  Private IPs: {', '.join(defang(i) for i in indicators['ips_private']) or 'none'}")
    print(f"  Domains    : {', '.join(defang(d) for d in indicators['domains']) or 'none'}")
    print(f"  URLs       : {len(indicators['urls'])}")
    for u in indicators["urls"][:15]:
        print(f"     {defang(u)}")
    if len(indicators["urls"]) > 15:
        print(f"     ... and {len(indicators['urls']) - 15} more (see --json)")

    line(f"Attachments ({len(attachments)})")
    if not attachments:
        print("  none")
    for a in attachments:
        print(f"  {BOLD}{a['filename']}{RESET}  ({a['content_type']}, {a['size']} bytes)")
        print(f"     MD5   : {a['md5']}\n     SHA1  : {a['sha1']}\n     SHA256: {a['sha256']}")
        for fl in a["flags"]:
            print(f"     {RED}! {fl}{RESET}")
        o = a.get("online")
        if o:
            if "error" in o:
                print(f"     VirusTotal: {YELLOW}{o['error']}{RESET}")
            else:
                col = RED if o["malicious"] else GREEN
                print(f"     VirusTotal: {col}{o['malicious']}/{o['total']} malicious{RESET}  {o['link']}")

    if online_ips:
        line("Online IP reputation (AbuseIPDB)")
        for ip, r in online_ips.items():
            if "error" in r:
                print(f"  {defang(ip)}: {YELLOW}{r['error']}{RESET}")
            else:
                s = r["abuse_score"] or 0
                col = RED if s >= 75 else YELLOW if s >= 25 else GREEN
                print(f"  {defang(ip)}: score {col}{s}{RESET}/100, {r['reports']} reports, "
                      f"{r['country']}, {r['isp']}, Tor={r['is_tor']}")

    line("Findings")
    if not findings:
        print(f"  {GREEN}No suspicious indicators found{RESET}")
    for x in sorted(findings, key=lambda z: -z["points"]):
        print(f"  {sev_color(x['severity'])}[+{x['points']:>2}] {x['severity'].upper():<6}{RESET} {x['finding']}")

    v = verdict(score)
    col = RED if v == "HIGH" else YELLOW if v == "MEDIUM" else GREEN
    line("Verdict")
    print(f"  Risk score: {BOLD}{score}{RESET}   Verdict: {col}{BOLD}{v} RISK{RESET}")
    print(f"  {GRAY}(Heuristic score - always confirm manually before closing or escalating.){RESET}\n")


def main():
    p = argparse.ArgumentParser(description="Offline phishing email header analyser (optional online lookups)")
    p.add_argument("input", help="Path to .eml / raw headers file, or '-' for stdin")
    p.add_argument("--json", metavar="OUTPUT_PATH", help="Save results to a JSON file")
    p.add_argument("--online", action="store_true",
                   help="Also check public IPs (AbuseIPDB) and attachment hashes (VirusTotal)")
    p.add_argument("--abusekey", default=ABUSEIPDB_API_KEY, help="AbuseIPDB API key")
    p.add_argument("--vtkey", default=VIRUSTOTAL_API_KEY, help="VirusTotal API key")
    p.add_argument("--delay", type=float, default=15.0,
                   help="Seconds between VirusTotal calls when --online (default 15, free tier = 4/min)")
    args = p.parse_args()

    try:
        msg = load_message(args.input)
    except FileNotFoundError:
        print(f"{RED}Error: file not found: {args.input}{RESET}")
        sys.exit(1)

    headers = extract_headers(msg)
    hops = parse_received(msg)
    auth = parse_auth(msg)
    attachments = inspect_attachments(msg)
    indicators = extract_indicators(msg, headers, hops)
    orig_ip = originating_ip(hops, headers)

    online_ips = {}
    if args.online:
        placeholder = lambda k: (not k) or k.startswith("your_")
        if placeholder(args.abusekey) and placeholder(args.vtkey):
            print(f"{RED}Error: --online needs an AbuseIPDB and/or VirusTotal key (flags or edit the script).{RESET}")
            sys.exit(1)
        if not placeholder(args.abusekey):
            for ip in indicators["ips_public"]:
                online_ips[ip] = online_ip(ip, args.abusekey)
                time.sleep(0.5)
        if not placeholder(args.vtkey):
            for i, a in enumerate(attachments):
                if i:
                    time.sleep(args.delay)
                a["online"] = online_hash(a["sha256"], args.vtkey)

    findings = analyse(headers, hops, auth, attachments)
    for ip, r in online_ips.items():
        s = r.get("abuse_score") or 0
        if s >= 75:
            findings.append({"points": 25, "severity": "high", "finding": f"IP {defang(ip)} has AbuseIPDB score {s}/100"})
        elif s >= 25:
            findings.append({"points": 10, "severity": "medium", "finding": f"IP {defang(ip)} has AbuseIPDB score {s}/100"})
    for a in attachments:
        o = a.get("online") or {}
        if o.get("malicious"):
            findings.append({"points": 40, "severity": "high",
                             "finding": f"Attachment '{a['filename']}' flagged malicious by {o['malicious']} VirusTotal engines"})

    score = min(100, sum(x["points"] for x in findings))
    print_report(args.input, headers, hops, auth, indicators, attachments, findings, score, orig_ip, online_ips)

    if args.json:
        out = {
            "headers": headers,
            "originating_ip": orig_ip,
            "received_chain": [{**h, "timestamp": h["timestamp"].isoformat() if h["timestamp"] else None} for h in hops],
            "authentication": auth,
            "indicators": indicators,
            "attachments": attachments,
            "online_ip_results": online_ips,
            "findings": findings,
            "risk_score": score,
            "verdict": verdict(score),
        }
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=2, default=str)
        print(f"{GREEN}Results saved to: {args.json}{RESET}")


if __name__ == "__main__":
    main()
