"""Key header extraction, Received chain and originating IP."""
from __future__ import annotations

import re
from datetime import timezone
from email.utils import getaddresses, parsedate_to_datetime

from . import config
from .utils import is_ip, is_public_ip, root_domain, valid_ips


def hdr(msg, name: str) -> str:
    """Return a header value with folded whitespace collapsed.

    Long headers are wrapped across lines (RFC 5322 folding); normalising
    makes regex matching and printing reliable.

    Args:
        msg: Parsed ``EmailMessage``.
        name: Header name (case-insensitive).

    Returns:
        Cleaned value, or an empty string if the header is absent or cannot
        be decoded.
    """
    try:
        v = msg.get(name)
    except Exception:
        # Badly malformed headers can raise during decoding; treat as absent.
        return ""
    return " ".join(str(v).split()) if v is not None else ""


def _first_address(msg, name: str):
    """Return ``(display_name, lowercase_address)`` of the first address in a header."""
    try:
        vals = [str(v) for v in (msg.get_all(name) or [])]
    except Exception:
        return "", ""
    pairs = getaddresses(vals)
    return (pairs[0][0], pairs[0][1].lower()) if pairs else ("", "")


def extract_headers(msg) -> dict:
    """Collect the headers used for triage into a flat dict.

    Both the raw header (for display) and the bare lowercase address (for
    comparisons) are kept, because display names are exactly what
    attackers manipulate. Only the first address of each header is used.

    Args:
        msg: Parsed email message.

    Returns:
        Dict of header fields; missing values are empty strings.
    """
    from_name, from_addr = _first_address(msg, "From")
    return {
        "from": hdr(msg, "From"),
        "from_name": from_name,
        "from_addr": from_addr,
        "reply_to": hdr(msg, "Reply-To"),
        "reply_to_addr": _first_address(msg, "Reply-To")[1],
        "return_path": hdr(msg, "Return-Path"),
        "return_path_addr": _first_address(msg, "Return-Path")[1],
        "to": hdr(msg, "To"),
        "subject": hdr(msg, "Subject"),
        "date": hdr(msg, "Date"),
        "message_id": hdr(msg, "Message-ID"),
        # Some clients use User-Agent instead of X-Mailer.
        "x_mailer": hdr(msg, "X-Mailer") or hdr(msg, "User-Agent"),
        # Webmail (e.g. Outlook.com) may record the client IP here, in brackets.
        "x_originating_ip": hdr(msg, "X-Originating-IP").strip("[] "),
    }


def parse_received(msg) -> list:
    """Rebuild the delivery path from the Received headers.

    Each relay *prepends* a Received header, so the list is reversed to get
    real delivery order (oldest first). The time between hops helps spot
    queuing or forged headers (timestamps going backwards).

    IPs are split into ``from_ips`` (the host that handed over the message)
    and ``ips`` (every IP in the header), because only the former says
    where the email came from.

    Assumes the usual ``from X (...) by Y ...; <date>`` layout; hops that
    do not follow it keep empty fields rather than raising.

    Args:
        msg: Parsed email message.

    Returns:
        List of hop dicts, oldest first, with ``from``, ``by``, ``from_ips``,
        ``ips``, ``timestamp`` (aware datetime or None), ``delay_s``,
        ``receiving`` (see ``_mark_receiving``) and ``raw``.
    """
    hops = []
    for raw in msg.get_all("Received") or []:
        text = " ".join(str(raw).split())
        # The timestamp is defined as everything after the last ';'.
        head, _, date_part = text.rpartition(";") if ";" in text else (text, "", "")
        ts = None
        try:
            ts = parsedate_to_datetime(date_part.strip())
            # Treat naive timestamps as UTC so they can be subtracted from aware ones.
            if ts is not None and ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except Exception:
            ts = None   # Malformed date: keep the hop, just without timing info.
        # Split at the last "by": the sender chooses the HELO name in the
        # "from" clause and can put " by " in it, but the receiving server
        # writes its own "by" after that.
        by = None
        for by in re.finditer(r"\bby\s+([^\s;]+)", head, re.I):
            pass
        from_part = head[:by.start()] if by else head
        frm = re.search(r"\bfrom\s+(\S+)", from_part, re.I)
        # The "from" clause's IPs identify the sending host.
        from_clause = re.search(r"\bfrom\s(.*)", from_part, re.I)
        hops.append({
            "from": frm.group(1) if frm else "",
            "by": by.group(1) if by else "",
            "from_ips": valid_ips(from_clause.group(1)) if from_clause else [],
            # Only look before the ';' so digits in the date are not misread.
            "ips": valid_ips(head),
            "timestamp": ts,
            "raw": text,
        })
    hops.reverse()  # oldest first = real delivery order
    for i, hop in enumerate(hops):
        prev = hops[i - 1]["timestamp"] if i else None
        hop["delay_s"] = int((hop["timestamp"] - prev).total_seconds()) if (prev and hop["timestamp"]) else None
    _mark_receiving(hops)
    return hops


def _relay_org(host: str) -> str:
    """Root domain of a relay host, with ``config.RELAY_ORG_GROUPS`` merged into one name."""
    root = root_domain(host)
    for group in config.RELAY_ORG_GROUPS:
        if root in group:
            return group[0]
    return root


def _mark_receiving(hops: list) -> None:
    """Set ``hop["receiving"]`` on the hops added by the recipient's own mail servers.

    Each server prepends its Received header, so the newest hops were
    written by the recipient's side and cannot be forged by the sender.
    Walking down from the newest hop, the recipient's organisation is the
    root domain of the first ``by`` host name; hops stay on the receiving
    side while their ``by`` host belongs to it. Hops at the very top whose
    ``by`` is only an IP or missing (Gmail's internal hops) count as
    receiving too. The walk stops at the first hop received by another
    organisation: that hop and everything below it came from the sender's
    side and may be forged.

    If no ``by`` host name is found, every hop is marked False.

    Limitation: a sender who forges hops whose ``by`` names the recipient's
    servers extends the receiving side into the forged part. This only
    misleads ``originating_ip``: ``collect_indicators`` keeps every ``from``
    side IP as an indicator.
    """
    org = None
    for hop in hops:
        hop["receiving"] = False
    for hop in reversed(hops):   # newest first
        by = hop["by"].strip("[]()")
        named = "." in by and not is_ip(by)
        if org is None:
            if named:
                org = _relay_org(by)
            hop["receiving"] = True
        elif named and _relay_org(by) == org:
            hop["receiving"] = True
        else:
            break
    if org is None:
        for hop in hops:
            hop["receiving"] = False


def entry_hop(hops: list):
    """Return the hop where the email entered the recipient's servers, or None if unknown."""
    return next((h for h in hops if h["receiving"]), None)


def originating_ip(hops: list) -> str:
    """Best guess at the public IP of the server that sent the email.

    This is the public IP in the ``from`` clause of ``entry_hop``: the
    server that handed the email to the recipient's servers, as recorded
    by those servers. A private IP there (e.g. mail sent inside the same
    organisation) gives an empty result.

    When the receiving side cannot be identified, falls back to the first
    public IP of the oldest hops. Those hops are the easiest to forge, so
    that result is only a lead.

    X-Originating-IP is not used: anyone can add that header. It is still
    reported and listed as an indicator.

    Args:
        hops: Output of ``parse_received`` (oldest first).

    Returns:
        Public IP string, or an empty string if none was found.
    """
    entry = entry_hop(hops)
    if entry is not None:
        return next((ip for ip in entry["from_ips"] if is_public_ip(ip)), "")
    for key in ("from_ips", "ips"):
        for hop in hops:
            for ip in hop[key]:
                if is_public_ip(ip):
                    return ip
    return ""
