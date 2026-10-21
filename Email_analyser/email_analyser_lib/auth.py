"""SPF, DKIM and DMARC results, and whether they align with the From domain."""
from __future__ import annotations

import re

from .headers import hdr
from .utils import domain_of, same_org

_METHOD_RE = re.compile(r"^\s*(spf|dkim|dmarc)\s*=\s*([\w-]+)", re.I)


def _pick_auth_results(msg) -> str:
    """Return the Authentication-Results header to trust.

    The topmost one is used: it was added last, by the server that received
    the email for your organisation. Lower ones may come from other hops or
    be forged by the sender. Headers without SPF/DKIM/DMARC results are
    skipped (some gateways add empty ones).
    """
    for value in msg.get_all("Authentication-Results") or []:
        text = " ".join(str(value).split())
        if re.search(r"\b(spf|dkim|dmarc)\s*=", text, re.I):
            return text
    return ""


def parse_auth(msg, from_domain: str) -> dict:
    """Read SPF, DKIM and DMARC results and check domain alignment.

    Every DKIM signature is read, not just the first. Newsletters are often
    signed twice (by the sender and by their mail provider), and only one
    of them needs to match From. Falls back to Received-SPF for SPF and to
    DKIM-Signature ``d=`` tags when Authentication-Results lacks them.

    Alignment matters because an attacker can pass SPF/DKIM for their *own*
    domain; a "pass" only helps if it is for the domain shown in From.

    Args:
        msg: Parsed email message.
        from_domain: Domain of the From address (may be empty).

    Returns:
        Dict with:
            ``spf``, ``dkim``, ``dmarc``: lowercase result or ``"none"``
                (``dkim`` is ``"pass"`` if any signature passed);
            ``spf_domain``: envelope (smtp.mailfrom) domain;
            ``dkim_signatures``: list of ``{"domain", "result"}``;
            ``dkim_domain``: the aligned passing domain, else the first one;
            ``spf_aligned`` / ``dkim_aligned``: bool;
            ``has_auth_header``: True if any auth result header was present.
    """
    res = {"spf": "none", "dkim": "none", "dmarc": "none", "spf_domain": "",
           "dkim_signatures": [], "dkim_domain": "", "spf_aligned": False, "dkim_aligned": False}
    ar = _pick_auth_results(msg)

    # Results are ';'-separated: "spf=pass smtp.mailfrom=x; dkim=pass header.d=y".
    for segment in ar.split(";"):
        m = _METHOD_RE.match(segment)
        if not m:
            continue
        method, result = m.group(1).lower(), m.group(2).lower()
        if method == "dkim":
            d = re.search(r"header\.(?:d|i)\s*=\s*@?([\w.-]+)", segment, re.I)
            res["dkim_signatures"].append({"domain": d.group(1).lower() if d else "", "result": result})
        elif res[method] == "none":   # First SPF / DMARC result wins.
            res[method] = result
            if method == "spf":
                mf = re.search(r"smtp\.mailfrom\s*=\s*([^\s;]+)", segment, re.I)
                if mf:
                    # smtp.mailfrom may be a full address or just a domain.
                    res["spf_domain"] = domain_of(mf.group(1)) or mf.group(1).lower()

    if res["spf"] == "none":
        rs = hdr(msg, "Received-SPF")
        if rs:
            # The result is the first word, e.g. "Pass (domain of ...)".
            res["spf"] = rs.split()[0].lower()
    if not res["dkim_signatures"]:
        # No verdict available, but the signing domains still show who signed.
        for sig in msg.get_all("DKIM-Signature") or []:
            d = re.search(r"\bd\s*=\s*([\w.-]+)", " ".join(str(sig).split()))
            if d:
                res["dkim_signatures"].append({"domain": d.group(1).lower(), "result": "unverified"})

    passing = [s for s in res["dkim_signatures"] if s["result"] == "pass"]
    if passing:
        res["dkim"] = "pass"
    elif res["dkim_signatures"] and res["dkim_signatures"][0]["result"] != "unverified":
        res["dkim"] = res["dkim_signatures"][0]["result"]

    aligned = [s for s in passing if same_org(s["domain"], from_domain)]
    res["dkim_aligned"] = bool(aligned)
    chosen = aligned or passing or res["dkim_signatures"]
    res["dkim_domain"] = chosen[0]["domain"] if chosen else ""
    res["spf_aligned"] = res["spf"] == "pass" and same_org(res["spf_domain"], from_domain)
    res["has_auth_header"] = bool(ar or hdr(msg, "Received-SPF"))
    return res
