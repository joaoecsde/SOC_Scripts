"""Run every analysis stage in order and return one result dict.

Kept separate from the command-line script so the whole analysis can be
called from tests or other tools with an already-parsed message.
"""
from __future__ import annotations

import time

from . import online as online_mod
from .attachments import inspect_attachments
from .auth import parse_auth
from .headers import extract_headers, originating_ip, parse_received
from .links import extract_links
from .rules import evaluate, score, verdict
from .utils import domain_of, is_ip, is_public_ip, valid_ips


def collect_indicators(headers: dict, hops: list, links: list, attachments: list) -> dict:
    """Gather IOCs for blocking, hunting or enrichment.

    Relay hostnames are included because they reveal the sending
    infrastructure. Values are raw here; defanging happens when printing.

    Returns:
        Dict with ``ips_public``, ``ips_private``, ``sender_domains``,
        ``relay_domains``, ``link_domains``, ``urls`` and ``sha256``.
    """
    ips = []
    for h in hops:
        for ip in h["ips"]:
            if ip not in ips:
                ips.append(ip)
    for ip in valid_ips(headers.get("x_originating_ip", "")):
        if ip not in ips:
            ips.append(ip)

    sender = {domain_of(headers[k]) for k in ("from_addr", "reply_to_addr", "return_path_addr")}
    relay = set()
    for h in hops:
        for k in ("from", "by"):
            # Skip bare IPs and single-label names ("localhost") that are not useful IOCs.
            v = h[k].strip("[]();").lower()
            if "." in v and not is_ip(v) and not valid_ips(v):
                relay.add(v)
    return {
        "ips_public": [i for i in ips if is_public_ip(i)],
        "ips_private": [i for i in ips if not is_public_ip(i)],
        "sender_domains": sorted(d for d in sender if d),
        "relay_domains": sorted(relay),
        "link_domains": sorted({l["host"] for l in links}),
        "urls": [l["url"] for l in links],
        "sha256": [a["sha256"] for a in attachments if a["kind"] == "file" and a["size"]],
    }


def run_online(indicators: dict, attachments: list, keys: dict, delay: float, max_age: int = 90) -> dict:
    """Enrich public IPs (AbuseIPDB) and attachment hashes (VirusTotal).

    Each service runs independently, so having only one key still works.
    Attached emails and empty files are skipped: their hashes are not
    meaningful on VirusTotal.

    Args:
        indicators: ``collect_indicators`` output.
        attachments: Attachment dicts; their ``online`` field is filled in place.
        keys: ``{"abuseipdb": str, "virustotal": str}``.
        delay: Seconds between VirusTotal calls (free tier: 4 per minute).
        max_age: AbuseIPDB report age limit in days.

    Returns:
        Mapping of IP -> AbuseIPDB result.
    """
    online_ips = {}
    if online_mod.has_key(keys.get("abuseipdb", "")):
        for ip in indicators["ips_public"]:
            online_ips[ip] = online_mod.check_ip(ip, keys["abuseipdb"], max_age)
            time.sleep(0.5)   # AbuseIPDB's limit is daily, so a short pause is enough.
    if online_mod.has_key(keys.get("virustotal", "")):
        first = True
        for a in attachments:
            if a["kind"] != "file" or not a["size"]:
                continue
            if not first:
                time.sleep(delay)
            first = False
            a["online"] = online_mod.check_hash(a["sha256"], keys["virustotal"])
    return online_ips


def analyse_message(msg, keys: dict = None, delay: float = 15.0, warnings: list = None) -> dict:
    """Analyse a parsed email end to end.

    Order matters: authentication needs the From domain, indicators need
    the hops and links, and scoring needs everything (incl. online results).

    Args:
        msg: Parsed ``EmailMessage`` (see ``loader.load_message``).
        keys: API keys to enable online lookups; ``None`` means offline.
        delay: Seconds between VirusTotal calls when online.
        warnings: Notes from the loader, passed through to the report.

    Returns:
        Result dict with every stage's output, ``findings``,
        ``category_scores``, ``risk_score`` and ``verdict``.
    """
    headers = extract_headers(msg)
    hops = parse_received(msg)
    auth = parse_auth(msg, domain_of(headers["from_addr"]))
    orig_ip = originating_ip(hops, headers)
    links = extract_links(msg)
    attachments = inspect_attachments(msg)
    indicators = collect_indicators(headers, hops, links, attachments)

    online_ips = run_online(indicators, attachments, keys, delay) if keys else {}

    findings = evaluate(headers, hops, auth, orig_ip, links, attachments, online_ips)
    total, breakdown = score(findings)
    return {
        "headers": headers,
        "originating_ip": orig_ip,
        "received_chain": hops,
        "authentication": auth,
        "links": links,
        "attachments": attachments,
        "indicators": indicators,
        "online_ip_results": online_ips,
        "findings": findings,
        "category_scores": breakdown,
        "risk_score": total,
        "verdict": verdict(total),
        "warnings": list(warnings or []),
        "online": bool(keys),
    }
