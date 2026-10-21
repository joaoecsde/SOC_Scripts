"""Turn the extracted facts into scored findings.

Rough weighting used throughout:
    20-25 pts  strong phishing signal on its own (e.g. Reply-To to another domain)
    10-15 pts  suspicious, but has legitimate causes (e.g. third-party senders)
    3-5   pts  weak or hygiene issue, only meaningful combined with others
    0     pts  "info": context for the analyst, does not change the score

Each finding has a category; categories are capped (config.CATEGORY_CAPS)
so one problem cannot max out the score on its own.
"""
from __future__ import annotations

import re

from . import config
from .links import check_link
from .utils import (brand_impersonation, brand_in, defang, domain_of, is_homograph,
                    is_legit_brand_domain, root_domain, same_org, tld_of)

# A real email address in a display name, e.g. "support@paypal.com".
# Requires a dot-separated domain so "John @ Home" does not count.
_EMAIL_IN_NAME_RE = re.compile(r"[\w.+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})", re.I)


class Findings:
    """Collects findings; one instance per analysis."""

    def __init__(self):
        self.items = []

    def add(self, category: str, points: int, severity: str, text: str) -> None:
        """Record a finding. ``severity`` is high / medium / low / info."""
        self.items.append({"category": category, "points": points,
                           "severity": severity, "finding": text})


def _auth_rules(f: Findings, auth: dict, from_dom: str) -> None:
    """SPF / DKIM / DMARC results and alignment."""
    if not auth["has_auth_header"]:
        f.add("authentication", 10, "medium",
              "No Authentication-Results / Received-SPF header (SPF, DKIM, DMARC cannot be verified)")
        return
    # DMARC weighs most because it is the check that ties SPF/DKIM to From.
    # "neutral" and "temperror" mean no verdict (policy absent / DNS hiccup),
    # so they are only low.
    for mech, pts in (("spf", 15), ("dkim", 15), ("dmarc", 20)):
        v = auth[mech]
        if v in ("fail", "softfail", "permerror"):
            f.add("authentication", pts, "high" if v == "fail" else "medium", f"{mech.upper()} result: {v}")
        elif v in ("neutral", "temperror"):
            f.add("authentication", 5, "low", f"{mech.upper()} result: {v}")
        elif v == "none":
            f.add("authentication", 5, "low", f"{mech.upper()} not present in authentication results")
    # When DMARC passes, alignment has already been verified by the receiving
    # server; re-checking it would only produce noise for newsletters.
    if auth["dmarc"] == "pass" or not from_dom:
        return
    if auth["dkim"] == "pass" and not auth["dkim_aligned"]:
        f.add("authentication", 10, "medium",
              f"No DKIM signature aligns with the From domain ({defang(from_dom)}); "
              f"signed by {defang(auth['dkim_domain'])}")
    if auth["spf_domain"] and not same_org(auth["spf_domain"], from_dom):
        f.add("authentication", 10, "medium",
              f"SPF envelope domain ({defang(auth['spf_domain'])}) does not align with From ({defang(from_dom)})")


def _sender_rules(f: Findings, headers: dict, auth: dict, from_dom: str) -> None:
    """Consistency between From, Reply-To, Return-Path and Message-ID."""
    if not from_dom:
        f.add("sender", 20, "high", "No valid From address could be parsed")
        return
    dmarc_ok = auth["dmarc"] == "pass"
    rt_dom = domain_of(headers["reply_to_addr"])
    ret_dom = domain_of(headers["return_path_addr"])
    mid_dom = domain_of(headers["message_id"])

    # Reply-To elsewhere routes the victim's answer to the attacker (typical
    # BEC). Helpdesk and marketing tools do it legitimately, so it is only
    # medium when DMARC proves the sender is genuine.
    if rt_dom and not same_org(rt_dom, from_dom):
        free = " (free mail provider)" if root_domain(rt_dom) in config.FREE_MAIL else ""
        if dmarc_ok:
            f.add("sender", 10, "medium", f"Reply-To domain ({defang(rt_dom)}){free} differs from From "
                                          f"({defang(from_dom)}); DMARC passed, but check replies go where expected")
        else:
            f.add("sender", 20, "high", f"Reply-To domain ({defang(rt_dom)}){free} differs from From ({defang(from_dom)})")

    # Return-Path and Message-ID are set by whatever system sent the mail, so
    # they differ for every newsletter / helpdesk. With DMARC passing, those
    # mismatches are collapsed into one info note instead of scoring twice.
    ret_mismatch = bool(ret_dom) and not same_org(ret_dom, from_dom)
    mid_mismatch = (bool(mid_dom) and not same_org(mid_dom, from_dom)
                    and root_domain(mid_dom) not in config.MAIL_PROVIDER_DOMAINS)
    if dmarc_ok and (ret_mismatch or mid_mismatch):
        via = ret_dom if ret_mismatch else mid_dom
        esp = config.ESP_DOMAINS.get(root_domain(via))
        name = f"{esp} ({defang(via)})" if esp else defang(via)
        f.add("sender", 0, "info", f"Sent through a third-party service: {name}. Normal for "
                                   f"newsletters/helpdesks; DMARC passed for {defang(from_dom)}")
    else:
        if ret_mismatch:
            f.add("sender", 10, "medium", f"Return-Path domain ({defang(ret_dom)}) differs from From ({defang(from_dom)})")
        if mid_mismatch:
            f.add("sender", 10, "medium", f"Message-ID domain ({defang(mid_dom)}) differs from From ({defang(from_dom)})")
    if not headers["message_id"]:
        f.add("sender", 5, "low", "Message-ID header is missing")
    if not headers["date"]:
        f.add("sender", 5, "low", "Date header is missing")


def _impersonation_rules(f: Findings, headers: dict, from_dom: str) -> None:
    """Display-name tricks, brand abuse and lookalike sender domains."""
    name = headers["from_name"].lower()

    # e.g. "support@paypal.com" <x@evil.tld>: many clients show only the name.
    m = _EMAIL_IN_NAME_RE.search(name)
    if m and not same_org(m.group(1), from_dom):
        f.add("impersonation", 25, "high", f"Display name shows the address of {defang(m.group(1).lower())} "
                                           f"but the real sender is {defang(from_dom) or 'unknown'}")
    # Only the first brand hit is reported to avoid stacking points.
    for brand in config.BRANDS:
        if brand_in(brand, name) and not is_legit_brand_domain(brand, from_dom):
            why = "a free mail provider" if root_domain(from_dom) in config.FREE_MAIL else \
                  f"unrelated domain {defang(from_dom)}"
            f.add("impersonation", 20, "high", f"Display name mentions '{brand}' but the email is sent from {why}")
            break

    if not from_dom:
        return
    if is_homograph(from_dom):
        f.add("impersonation", 25, "high", f"From domain uses punycode / non-ASCII characters "
                                           f"(possible homograph): {defang(from_dom)}")
    imp = brand_impersonation(from_dom)
    if imp:
        brand, kind = imp
        if kind == "lookalike":
            f.add("impersonation", 25, "high", f"From domain looks like a character-substituted '{brand}': {defang(from_dom)}")
        else:
            f.add("impersonation", 15, "medium", f"From domain embeds brand '{brand}' but is not "
                                                 f"one of its real domains: {defang(from_dom)}")
    if tld_of(from_dom) in config.SUSPICIOUS_TLDS:
        f.add("impersonation", 10, "medium", f"From domain uses a TLD often abused in phishing: .{tld_of(from_dom)}")
    # Long, hyphen-heavy domains are typical of throwaway phishing domains.
    if from_dom.count("-") >= 3 or from_dom.count(".") >= 4:
        f.add("impersonation", 5, "low", f"From domain looks unusually long or complex: {defang(from_dom)}")


def _relay_rules(f: Findings, hops: list, orig_ip: str, headers: dict) -> None:
    """Received chain oddities and the X-Mailer."""
    xm = headers["x_mailer"].lower()
    if xm and any(k in xm for k in config.BULK_MAILERS):
        f.add("mailer", 10, "medium", f"Unusual / bulk-mail client: {headers['x_mailer']}")
    if not hops:
        f.add("relay", 10, "medium", "No Received headers found (headers may be stripped or incomplete)")
        return
    if len(hops) > 8:
        f.add("relay", 5, "low", f"Unusually long relay chain ({len(hops)} hops)")
    for h in hops:
        # Over an hour between relays: queued/throttled or batched sending.
        if h["delay_s"] is not None and h["delay_s"] > 3600:
            f.add("relay", 5, "low", f"Large delay of {h['delay_s'] // 60} min before hop via {defang(h['by']) or '?'}")
        # 60 s tolerance absorbs normal clock drift between servers.
        if h["delay_s"] is not None and h["delay_s"] < -60:
            f.add("relay", 10, "medium", f"Timestamps go backwards at hop via {defang(h['by']) or '?'} "
                                         f"(forged header or clock skew)")
    if not orig_ip:
        f.add("relay", 5, "low", "No public originating IP could be identified")


def _link_rules(f: Findings, links: list) -> None:
    """Per-link checks; identical finding texts are only counted once."""
    seen = set()
    for link in links:
        for pts, sev, text in check_link(link):
            if text not in seen:
                seen.add(text)
                f.add("links", pts, sev, text)


def _attachment_rules(f: Findings, attachments: list) -> None:
    """One finding per attachment flag."""
    for a in attachments:
        where = f" (inside {a['container']})" if a["container"] else ""
        for fl in a["flags"]:
            f.add("attachments", fl["points"], "high" if fl["points"] >= 20 else "medium",
                  f"Attachment '{a['filename']}'{where}: {fl['flag']}")
        if a["kind"] == "email" and a["inner"]:
            f.add("attachments", 0, "info", f"Contains an attached email '{a['filename']}' "
                                            f"(From: {defang(a['inner']['from']) or '?'}, Subject: {a['inner']['subject'] or '?'})")


def _reputation_rules(f: Findings, online_ips: dict, attachments: list) -> None:
    """Online AbuseIPDB / VirusTotal results (only present with --online)."""
    for ip, r in online_ips.items():
        s = r.get("abuse_score") or 0
        if s >= config.ABUSE_HIGH:
            f.add("reputation", 25, "high", f"IP {defang(ip)} has AbuseIPDB score {s}/100")
        elif s >= config.ABUSE_MEDIUM:
            f.add("reputation", 10, "medium", f"IP {defang(ip)} has AbuseIPDB score {s}/100")
    for a in attachments:
        o = a.get("online") or {}
        if o.get("malicious"):
            f.add("reputation", 40, "high", f"Attachment '{a['filename']}' flagged malicious by "
                                            f"{o['malicious']} VirusTotal engines")
        elif o.get("suspicious"):
            f.add("reputation", 10, "medium", f"Attachment '{a['filename']}' flagged suspicious by "
                                              f"{o['suspicious']} VirusTotal engines")


def evaluate(headers, hops, auth, orig_ip, links, attachments, online_ips) -> list:
    """Run every rule group and return the list of findings.

    Args:
        headers: ``headers.extract_headers`` output.
        hops: ``headers.parse_received`` output.
        auth: ``auth.parse_auth`` output.
        orig_ip: ``headers.originating_ip`` output.
        links: ``links.extract_links`` output.
        attachments: ``attachments.inspect_attachments`` output.
        online_ips: IP -> AbuseIPDB result (empty when offline).

    Returns:
        List of ``{"category", "points", "severity", "finding"}`` dicts.
    """
    f = Findings()
    from_dom = domain_of(headers["from_addr"])
    _auth_rules(f, auth, from_dom)
    _sender_rules(f, headers, auth, from_dom)
    _impersonation_rules(f, headers, from_dom)
    _relay_rules(f, hops, orig_ip, headers)
    _link_rules(f, links)
    _attachment_rules(f, attachments)
    _reputation_rules(f, online_ips, attachments)
    return f.items


def score(findings: list):
    """Sum points per category, apply category caps, then the overall cap.

    Returns:
        ``(total_score, per_category)`` where ``per_category`` maps each
        category to ``{"raw": points before cap, "counted": points after cap}``.
    """
    per_cat = {}
    for x in findings:
        per_cat.setdefault(x["category"], 0)
        per_cat[x["category"]] += x["points"]
    breakdown = {c: {"raw": p, "counted": min(p, config.CATEGORY_CAPS.get(c, config.MAX_SCORE))}
                 for c, p in per_cat.items()}
    total = min(config.MAX_SCORE, sum(v["counted"] for v in breakdown.values()))
    return total, breakdown


def verdict(total: int) -> str:
    """Map a 0-100 score to LOW / MEDIUM / HIGH using the config thresholds."""
    if total >= config.HIGH_THRESHOLD:
        return "HIGH"
    return "MEDIUM" if total >= config.MEDIUM_THRESHOLD else "LOW"
