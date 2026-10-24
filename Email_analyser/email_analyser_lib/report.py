"""Terminal report and JSON export.

Everything printed goes through ``safe()`` (no terminal control codes from
attacker-controlled headers) and every IP, domain, address and URL is
defanged. The JSON export keeps raw values so other tools can use them.
"""
from __future__ import annotations

import json

from . import __version__
from .utils import C, defang, safe

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_URL_LIMIT = 15   # Keep the terminal readable; the JSON always has every URL.


def _sev_color(sev: str) -> str:
    return {"high": C.RED, "medium": C.YELLOW}.get(sev, C.GRAY)


def _section(title: str) -> None:
    print(f"\n{C.BOLD}{C.CYAN}{'-' * 70}{C.RESET}\n{C.BOLD}{title}{C.RESET}\n{'-' * 70}")


def _na(value: str) -> str:
    return safe(value) if value else f"{C.GRAY}N/A{C.RESET}"


def _print_headers(r: dict) -> None:
    h = r["headers"]
    _section("Key headers")
    # Address headers are defanged; Subject/Date/X-Mailer are shown as-is.
    for label, key, fang in (("From", "from", True), ("Reply-To", "reply_to", True),
                             ("Return-Path", "return_path", True), ("To", "to", True),
                             ("Subject", "subject", False), ("Date", "date", False),
                             ("Message-ID", "message_id", True), ("X-Mailer", "x_mailer", False)):
        value = defang(h[key]) if fang else h[key]
        print(f"  {label:<12}: {_na(value)}")
    ip = r["originating_ip"]
    print(f"  {'Origin IP':<12}: {defang(ip) if ip else C.GRAY + 'not identified' + C.RESET}")
    if h["x_originating_ip"]:
        print(f"  {'X-Orig. IP':<12}: {safe(defang(h['x_originating_ip']))}  "
              f"{C.GRAY}(unverified: anyone can add this header){C.RESET}")


def _print_chain(hops: list) -> None:
    _section("Received chain (oldest -> newest)")
    if not hops:
        print(f"  {C.YELLOW}No Received headers{C.RESET}")
    for i, h in enumerate(hops, 1):
        ts = h["timestamp"].strftime("%Y-%m-%d %H:%M:%S %z") if h["timestamp"] else "unknown time"
        delay = f"  (+{h['delay_s']}s)" if h["delay_s"] is not None and i > 1 else ""
        ips = ", ".join(defang(x) for x in h["ips"]) or "no IP"
        print(f"  {i:>2}. {safe(defang(h['from'])) or '?'} -> {safe(defang(h['by'])) or '?'}  [{ips}]  {ts}{delay}")


def _print_auth(a: dict) -> None:
    _section("Authentication")
    for mech in ("spf", "dkim", "dmarc"):
        v = a[mech]
        col = C.GREEN if v == "pass" else C.RED if v in ("fail", "softfail", "permerror") else C.YELLOW
        print(f"  {mech.upper():<6}: {col}{safe(v)}{C.RESET}")
    if a["spf_domain"]:
        mark = "aligned" if a["spf_aligned"] else "not aligned with From"
        print(f"  SPF envelope domain : {safe(defang(a['spf_domain']))} ({mark})")
    for s in a["dkim_signatures"]:
        print(f"  DKIM signature      : {safe(defang(s['domain'])) or '?'} = {safe(s['result'])}")


def _print_indicators(r: dict) -> None:
    ind = r["indicators"]
    _section("Indicators (defanged)")
    for label, key in (("Public IPs", "ips_public"), ("Private IPs", "ips_private"),
                       ("Receiving IPs", "ips_receiving"),
                       ("Sender domains", "sender_domains"), ("Relay domains", "relay_domains"),
                       ("Link domains", "link_domains")):
        print(f"  {label:<15}: {', '.join(safe(defang(x)) for x in ind[key]) or 'none'}")
    print(f"  {'URLs':<15}: {len(ind['urls'])}")
    for link in r["links"][:_URL_LIMIT]:
        text = f"  {C.GRAY}(text: {safe(link['text'][:50])}){C.RESET}" if link["text"] else ""
        print(f"     {safe(defang(link['url']))}{text}")
    if len(r["links"]) > _URL_LIMIT:
        print(f"     ... and {len(r['links']) - _URL_LIMIT} more (see --json)")


def _print_attachments(atts: list) -> None:
    _section(f"Attachments ({len(atts)})")
    if not atts:
        print("  none")
    for a in atts:
        where = f"  {C.GRAY}inside {safe(a['container'])}{C.RESET}" if a["container"] else ""
        print(f"  {C.BOLD}{safe(a['filename'])}{C.RESET}  ({safe(a['content_type'])}, {a['size']} bytes){where}")
        if a["kind"] == "email" and a["inner"]:
            print(f"     Attached email - From: {safe(defang(a['inner']['from']))}  "
                  f"Subject: {safe(a['inner']['subject'])}")
        print(f"     MD5   : {a['md5']}\n     SHA1  : {a['sha1']}\n     SHA256: {a['sha256']}")
        for fl in a["flags"]:
            print(f"     {C.RED}! {safe(fl['flag'])}{C.RESET}")
        o = a.get("online")
        if o:
            if "error" in o:
                print(f"     VirusTotal: {C.YELLOW}{safe(o['error'])}{C.RESET}")
            else:
                col = C.RED if o["malicious"] else C.GREEN
                print(f"     VirusTotal: {col}{o['malicious']}/{o['total']} malicious{C.RESET}  {o['link']}")


def _print_online_ips(online_ips: dict) -> None:
    if not online_ips:
        return
    _section("Online IP reputation (AbuseIPDB)")
    for ip, r in online_ips.items():
        if "error" in r:
            print(f"  {defang(ip)}: {C.YELLOW}{safe(r['error'])}{C.RESET}")
            continue
        s = r["abuse_score"] or 0
        col = C.RED if s >= 75 else C.YELLOW if s >= 25 else C.GREEN
        print(f"  {defang(ip)}: score {col}{s}{C.RESET}/100, {r['reports']} reports, "
              f"{safe(r['country'])}, {safe(r['isp'])}, Tor={r['is_tor']}")


def _print_findings(r: dict) -> None:
    _section("Findings")
    if not r["findings"]:
        print(f"  {C.GREEN}No suspicious indicators found{C.RESET}")
    # Highest-impact findings first so the key reasons are read first.
    for x in sorted(r["findings"], key=lambda z: (-z["points"], _SEV_ORDER.get(z["severity"], 9))):
        print(f"  {_sev_color(x['severity'])}[+{x['points']:>2}] {x['severity'].upper():<6}{C.RESET} "
              f"{safe(x['finding'])}")
    capped = [f"{c} {v['raw']}->{v['counted']}" for c, v in r["category_scores"].items() if v["raw"] > v["counted"]]
    if capped:
        print(f"  {C.GRAY}Category caps applied: {', '.join(capped)}{C.RESET}")


def print_report(r: dict, source: str) -> None:
    """Print the full colour-coded report.

    Sections follow an analyst's usual triage order: who sent it, how it
    travelled, did it authenticate, what IOCs it carries, and the verdict.

    Args:
        r: ``pipeline.analyse_message`` result.
        source: Input name shown in the title.
    """
    print(f"\n{C.BOLD}Phishing Email Header Analysis v{__version__} - {safe(source)}{C.RESET}")
    for w in r["warnings"]:
        print(f"  {C.YELLOW}Note: {safe(w)}{C.RESET}")
    _print_headers(r)
    _print_chain(r["received_chain"])
    _print_auth(r["authentication"])
    _print_indicators(r)
    _print_attachments(r["attachments"])
    _print_online_ips(r["online_ip_results"])
    _print_findings(r)

    v = r["verdict"]
    col = C.RED if v == "HIGH" else C.YELLOW if v == "MEDIUM" else C.GREEN
    _section("Verdict")
    print(f"  Risk score: {C.BOLD}{r['risk_score']}{C.RESET}   Verdict: {col}{C.BOLD}{v} RISK{C.RESET}")
    print(f"  {C.GRAY}(Heuristic score - always confirm manually before closing or escalating.){C.RESET}\n")


def to_json(r: dict) -> dict:
    """Return a JSON-serialisable copy of the result (raw, not defanged).

    Datetimes become ISO strings and the bulky raw Received text is kept so
    the export is self-contained evidence.
    """
    out = dict(r)
    out["tool_version"] = __version__
    out["received_chain"] = [{**h, "timestamp": h["timestamp"].isoformat() if h["timestamp"] else None}
                             for h in r["received_chain"]]
    return out


def save_json(r: dict, path: str) -> None:
    """Write ``to_json(r)`` to ``path`` as UTF-8.

    Raises:
        OSError: If the file cannot be written (handled by the caller).
    """
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_json(r), fh, indent=2, default=str, ensure_ascii=False)
