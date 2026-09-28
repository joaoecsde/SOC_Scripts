"""Key header extraction, Received chain and originating IP."""
from __future__ import annotations

import re
from datetime import timezone
from email.utils import getaddresses, parsedate_to_datetime

from .utils import is_public_ip, valid_ips


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
        ``ips``, ``timestamp`` (aware datetime or None), ``delay_s`` and ``raw``.
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
        frm = re.search(r"\bfrom\s+(\S+)", head, re.I)
        by = re.search(r"\bby\s+([^\s;]+)", head, re.I)
        # The "from" clause runs until " by "; its IPs identify the sending host.
        from_clause = re.search(r"\bfrom\s(.*?)(?:\sby\s|$)", head, re.I)
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
    return hops


def originating_ip(hops: list, headers: dict) -> str:
    """Best guess at the sender's public IP.

    X-Originating-IP wins when present, because webmail adds it with the
    real client's IP while the Received chain only shows the provider's
    servers. Otherwise takes the first public IP in the ``from`` clause of
    the oldest hops (earlier private IPs are the sender's own network), then
    any public IP in the chain. Old hops are the easiest to forge, so treat
    the result as a lead, not proof.

    Args:
        hops: Output of ``parse_received`` (oldest first).
        headers: Output of ``extract_headers``.

    Returns:
        Public IP string, or an empty string if none was found.
    """
    xo = headers.get("x_originating_ip", "")
    if xo and is_public_ip(xo):
        return xo
    for key in ("from_ips", "ips"):
        for hop in hops:
            for ip in hop[key]:
                if is_public_ip(ip):
                    return ip
    return ""
