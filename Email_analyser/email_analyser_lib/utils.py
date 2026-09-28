"""Small shared helpers: safe printing, defanging, domains, brands and IPs."""
from __future__ import annotations

import ipaddress
import re
import sys
from urllib.parse import urlsplit

from . import config


# Terminal colours
class Colors:
    """ANSI colour codes, blanked when stdout is not a terminal.

    Redirecting the report to a file (``> report.txt``) would otherwise fill
    it with escape sequences.
    """

    def __init__(self, enabled: bool):
        on = enabled
        self.RESET = "\033[0m" if on else ""
        self.BOLD = "\033[1m" if on else ""
        self.RED = "\033[91m" if on else ""
        self.YELLOW = "\033[93m" if on else ""
        self.GREEN = "\033[92m" if on else ""
        self.CYAN = "\033[96m" if on else ""
        self.GRAY = "\033[90m" if on else ""


C = Colors(sys.stdout.isatty())


# Safe text for the terminal
# Invisible characters that change how text is displayed. Shown as <U+XXXX>
# so the analyst sees they are there instead of being fooled by them
# (e.g. U+202E makes "invoice_fdp.exe" display as "invoice_exe.pdf").
_BIDI_INVISIBLE = re.compile("[​-‏‪-‮⁦-⁩﻿]")
# Other control characters (incl. ESC, which starts terminal escape codes).
# Attacker-controlled headers could otherwise clear the screen or recolour
# the report. Tab is kept.
_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def safe(text) -> str:
    """Make any value safe to print in a terminal.

    Args:
        text: Value to display; ``None`` becomes an empty string.

    Returns:
        String with invisible/bidi characters made visible and control
        characters replaced by ``?``.
    """
    if text is None:
        return ""
    text = _BIDI_INVISIBLE.sub(lambda m: f"<U+{ord(m.group()):04X}>", str(text))
    return _CONTROL.sub("?", text)


def has_hidden_chars(text: str) -> bool:
    """Return True if ``text`` contains bidi-override or zero-width characters."""
    return bool(_BIDI_INVISIBLE.search(text or ""))


# Defanging
def defang(value: str) -> str:
    """Make an IP, domain, email address or URL non-clickable.

    Only the URL scheme is changed (``http`` -> ``hxxp``) so hostnames that
    merely contain "http" are left alone.

    Args:
        value: Indicator, e.g. ``https://evil.com/a``.

    Returns:
        Defanged string, e.g. ``hxxps://evil[.]com/a``.
    """
    if not value:
        return ""
    value = re.sub(r"(?i)^http", "hxxp", value)
    return value.replace(".", "[.]")


def refang(value: str) -> str:
    """Reverse common defanging styles back to a usable indicator.

    Used when reading links from bodies of emails that were already
    defanged, e.g. a phishing report forwarded by a colleague.

    Args:
        value: Possibly defanged text.

    Returns:
        Refanged text.
    """
    return (value.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
            .replace("hxxp", "http").replace("[:]", ":").replace("[at]", "@"))


# Domains
# Second-level labels that act as public suffixes under a ccTLD
# (co.uk, com.pt, org.br...). Not a full Public Suffix List.
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "gob", "ne", "or"}


def domain_of(addr: str) -> str:
    """Return the lowercase domain part of an email address or Message-ID.

    ``rsplit`` on the last ``@`` because a quoted local part may contain one.

    Args:
        addr: Address such as ``user@example.com`` or ``<id@host>``.

    Returns:
        The domain, or an empty string if there is no ``@``.
    """
    if not addr or "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].lower().strip("<> ").rstrip(".")


def root_domain(domain: str) -> str:
    """Approximate the registrable domain, used to compare organisations.

    ``mail.example.com`` and ``example.com`` both return ``example.com``.
    Keeps three labels for ``co.uk`` / ``com.pt`` style suffixes. This is a
    heuristic, not a Public Suffix List lookup, so exotic suffixes and
    shared hosting (``*.github.io``) may be grouped too broadly.

    Args:
        domain: Fully qualified domain name.

    Returns:
        Lowercase approximate registrable domain.
    """
    parts = (domain or "").lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in _SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else (domain or "").lower()


def same_org(a: str, b: str) -> bool:
    """Return True if two domains share the same root domain."""
    return bool(a and b and root_domain(a) == root_domain(b))


def tld_of(domain: str) -> str:
    """Return the last label of a domain (``evil.xyz`` -> ``xyz``)."""
    return (domain or "").rstrip(".").rsplit(".", 1)[-1].lower()


def host_of(url: str) -> str:
    """Return the lowercase hostname of a URL, or an empty string if invalid."""
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


# Brands
def brand_in(brand: str, text: str) -> bool:
    """Return True if ``brand`` appears in ``text``, avoiding false matches.

    Brands shorter than ``config.SHORT_BRAND_LEN`` must stand alone (not
    touching another letter or digit), so "UPS Delivery" and
    "ups-tracking.com" match but "Groups" and "groups.io" do not. Longer
    brands match anywhere so "paypalsecure.com" is still caught.

    Trade-off: a short brand glued to another word ("upsdelivery.com") is not
    detected; other checks on that domain still apply.

    Args:
        brand: Brand name from ``config.BRANDS``.
        text: Display name or domain, already lowercase.
    """
    if len(brand) >= config.SHORT_BRAND_LEN:
        return brand in text
    return re.search(rf"(?<![a-z0-9]){re.escape(brand)}(?![a-z0-9])", text) is not None


def is_legit_brand_domain(brand: str, domain: str) -> bool:
    """Return True if ``domain`` genuinely belongs to ``brand``.

    Genuine means the root domain is listed in ``config.BRAND_DOMAINS``, or
    is the brand's own name on a country TLD (``paypal.pt``,
    ``amazon.com.br``). Suspicious TLDs are excluded so ``paypal.xyz`` does
    not pass. Comparing root domains (not string endings) is what stops
    ``secure-paypal.com`` from counting as ``paypal.com``.

    Args:
        brand: Brand name from ``config.BRANDS``.
        domain: Domain to test.
    """
    root = root_domain(domain)
    if root in config.BRAND_DOMAINS.get(brand, ()):
        return True
    label, _, suffix = root.partition(".")
    if label != brand or tld_of(root) in config.SUSPICIOUS_TLDS:
        return False
    # Two-letter ccTLD ("pt") or second-level ccTLD ("com.br", "co.uk").
    return len(suffix) == 2 or (suffix.count(".") == 1 and len(suffix.split(".")[1]) == 2)


def is_brand_domain(domain: str) -> bool:
    """Return True if ``domain`` genuinely belongs to any known brand."""
    return any(is_legit_brand_domain(b, domain) for b in config.BRANDS)


def brand_impersonation(domain: str):
    """Detect a domain that imitates a known brand.

    Args:
        domain: Sender or link domain, lowercase.

    Returns:
        ``(brand, "lookalike")`` for digit-swapped names (``paypa1.com``),
        ``(brand, "embedded")`` for a brand inside someone else's domain
        (``paypal-login.com``), or ``None`` if nothing was found or the
        domain genuinely belongs to a brand.
    """
    if not domain or is_brand_domain(domain):
        return None
    for brand in config.BRANDS:
        if brand_in(brand, domain):
            return brand, "embedded"
    variants = [domain.translate(m) for m in config.LEET_MAPS]
    for brand in config.BRANDS:
        if any(brand_in(brand, v) for v in variants):
            return brand, "lookalike"
    return None


def is_homograph(domain: str) -> bool:
    """Return True for punycode or non-ASCII domains (possible homograph).

    Internationalised domains can use look-alike letters from other
    alphabets (e.g. Cyrillic "а" vs Latin "a").
    """
    return "xn--" in (domain or "") or any(ord(c) > 127 for c in domain or "")


# IP addresses
# Lookarounds stop matches inside longer dotted numbers (version strings).
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# Loose IPv6 candidate: hex groups with at least two colons, optionally an
# embedded IPv4 tail. Real validation is done by ipaddress, which also
# rejects times such as "10:00:01".
_IPV6_RE = re.compile(r"(?<![0-9A-Za-z:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{1,4}|(?:\d{1,3}\.){3}\d{1,3})?(?![0-9A-Za-z:])")


def valid_ips(text: str) -> list:
    """Extract unique, valid IPv4 and IPv6 addresses in the order found.

    Order is preserved because position in the Received chain matters.
    The ``IPv6:`` literal prefix used in Received headers is removed first
    so it is not mistaken for part of the address.

    Args:
        text: Any text, e.g. a Received header.

    Returns:
        List of IP strings (IPv6 in compressed form) without duplicates.
    """
    text = re.sub(r"(?i)ipv6:", " ", text or "")
    found = []
    for m in re.finditer(f"{_IPV4_RE.pattern}|{_IPV6_RE.pattern}", text):
        try:
            ip = str(ipaddress.ip_address(m.group()))
        except ValueError:
            continue
        if ip not in found:
            found.append(ip)
    return found


def is_ip(value: str) -> bool:
    """Return True if ``value`` is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address((value or "").strip("[]"))
        return True
    except ValueError:
        return False


def is_public_ip(ip: str) -> bool:
    """Return True if ``ip`` is globally routable.

    Private, loopback and reserved ranges belong to internal relays and are
    useless for reputation lookups.
    """
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False
