"""Link extraction from the email body and per-link phishing checks."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

from . import config
from .utils import (brand_impersonation, defang, host_of, is_homograph, is_ip,
                    refang, root_domain, tld_of)

# Plain-text URLs, including scheme-less "www." links. Stops at whitespace,
# quotes and brackets so surrounding punctuation is not captured.
_TEXT_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'()\[\]{}]+", re.I)
# Something that looks like a domain or URL in visible link text,
# e.g. "paypal.com" or "https://paypal.com/login".
_DOMAIN_LIKE_RE = re.compile(r"^(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})(?:[/:?#].*)?$", re.I)
# Web pages are normal link targets; only flag downloads of other risky types.
_LINK_RISKY_EXT = config.RISKY_EXT - {".html", ".htm", ".shtml"}
# Security gateways that rewrite every link, with the real URL in a query
# parameter. Unwrapped so the checks see the real destination.
# host suffix -> query parameter holding the original URL
_WRAPPERS = {"safelinks.protection.outlook.com": "url", "google.com": "q"}


class _LinkParser(HTMLParser):
    """Collect link targets, their visible text, and form actions from HTML.

    HTMLParser unescapes attribute values (``&amp;`` -> ``&``), so URLs come
    out exactly as the browser would use them. Tags such as ``xmlns`` or
    DOCTYPE declarations are ignored, which removes schema URLs that are
    not real links.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []          # list of (url, visible_text, source)
        self.text_chunks = []    # visible text, scanned for bare URLs later
        self._open_href = None
        self._open_text = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("a", "area") and attrs.get("href"):
            if tag == "area":
                self.links.append((attrs["href"], "", "html-area"))
            else:
                self._open_href, self._open_text = attrs["href"], []
        elif tag == "form" and attrs.get("action"):
            # Forms inside emails post data straight to the attacker.
            self.links.append((attrs["action"], "", "html-form"))

    def handle_endtag(self, tag):
        if tag == "a" and self._open_href is not None:
            text = " ".join("".join(self._open_text).split())
            self.links.append((self._open_href, text, "html-a"))
            self._open_href = None

    def handle_data(self, data):
        # Text inside <a> is the link's label, already tied to its href;
        # only text outside links is scanned for bare URLs.
        if self._open_href is not None:
            self._open_text.append(data)
        else:
            self.text_chunks.append(data)


def _normalise(url: str) -> str:
    """Clean a raw URL and unwrap known link-rewriting services.

    Trims trailing punctuation and adds a scheme to "www." links. Microsoft
    Safe Links (Microsoft 365 rewrites every link) and Google redirect
    links (``google.com/url?q=``) are unwrapped to the real destination.
    """
    url = url.strip().rstrip(".,;:!?")
    if url.lower().startswith("www."):
        url = "http://" + url
    host = host_of(url)
    for suffix, param in _WRAPPERS.items():
        if host == suffix or host.endswith("." + suffix):
            if suffix == "google.com" and not urlsplit(url).path.startswith("/url"):
                continue
            inner = parse_qs(urlsplit(url).query).get(param)
            if inner and inner[0].lower().startswith(("http://", "https://")):
                return inner[0]
    return url


def _body_parts(msg):
    """Yield ``(content_type, text)`` for body parts that are not attachments."""
    for part in msg.walk():
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        if part.get_content_disposition() == "attachment":
            continue
        try:
            yield part.get_content_type(), part.get_content()
        except Exception:
            continue   # Undecodable part (bad charset); skip instead of crashing.


def extract_links(msg) -> list:
    """Collect unique http(s) links from the email body.

    HTML parts are parsed properly so each link keeps its visible text,
    which is needed to spot "text says paypal.com, link goes elsewhere".
    Plain-text parts, and visible HTML text, are refanged and scanned for
    bare URLs. Non-web schemes (mailto:, tel:, cid:) and schema URLs
    (w3.org...) are dropped.

    Args:
        msg: Parsed email message.

    Returns:
        List of ``{"url", "text", "source", "host"}`` dicts, first
        occurrence of each URL kept.
    """
    raw = []
    for ctype, body in _body_parts(msg):
        if ctype == "text/html":
            p = _LinkParser()
            try:
                p.feed(body)
                p.close()
            except Exception:
                pass   # Broken HTML: keep whatever was parsed so far.
            raw.extend(p.links)
            text = refang(" ".join(p.text_chunks))
        else:
            text = refang(body)
        raw.extend((u, "", "text") for u in _TEXT_URL_RE.findall(text))

    links, seen = [], set()
    for url, text, source in raw:
        url = _normalise(url)
        if not url.lower().startswith(("http://", "https://")):
            continue
        host = host_of(url)
        if not host or host in config.IGNORED_URL_HOSTS or url in seen:
            continue
        seen.add(url)
        links.append({"url": url, "text": text, "source": source, "host": host})
    return links


def check_link(link: dict) -> list:
    """Run phishing checks on one link.

    Args:
        link: One item from ``extract_links``.

    Returns:
        List of ``(points, severity, finding)`` tuples (may be empty).
    """
    url, host, text = link["url"], link["host"], link["text"]
    shown = defang(url if len(url) <= 80 else url[:77] + "...")
    out = []

    # Visible text shows one site, the link goes to another. The strongest
    # link signal: the user checks the text and trusts it.
    # Newsletter platforms route links through their own click-tracking
    # domain, so a mismatch there is normal and only noted as low.
    m = _DOMAIN_LIKE_RE.match(text or "")
    if m and root_domain(m.group(1)) != root_domain(host):
        if root_domain(host) in config.ESP_DOMAINS:
            out.append((3, "low", f"Link text shows {defang(m.group(1))} but goes via click-tracking "
                                  f"domain {defang(host)} ({config.ESP_DOMAINS[root_domain(host)]})"))
        else:
            out.append((20, "high", f"Link text shows {defang(m.group(1))} but points to {defang(host)}"))
    if link["source"] == "html-form":
        out.append((20, "high", f"HTML form in the email submits data to {defang(host)}"))
    if is_ip(host):
        out.append((15, "medium", f"Link points to a bare IP address: {shown}"))
    # user@host URLs: everything before "@" is ignored by the browser, so
    # "https://paypal.com@evil.xyz" really opens evil.xyz.
    if "@" in (urlsplit(url).netloc or ""):
        out.append((15, "high", f"Link hides its real host behind '@': {shown}"))
    if is_homograph(host):
        out.append((20, "high", f"Link uses a punycode / non-ASCII domain (possible homograph): {shown}"))
    imp = brand_impersonation(host)
    if imp:
        brand, kind = imp
        what = "looks like a character-substituted" if kind == "lookalike" else "embeds the brand"
        out.append((15, "medium", f"Link domain {what} '{brand}': {defang(host)}"))
    if tld_of(host) in config.SUSPICIOUS_TLDS:
        out.append((5, "low", f"Link uses a TLD often abused in phishing: {defang(host)}"))
    if host in config.URL_SHORTENERS:
        out.append((5, "low", f"Link shortener hides the real destination: {shown}"))
    path_ext = re.search(r"(\.[a-z0-9]{1,5})$", (urlsplit(url).path or "").lower())
    if path_ext and path_ext.group(1) in _LINK_RISKY_EXT:
        out.append((15, "medium", f"Link downloads a risky file type ({path_ext.group(1)}): {shown}"))
    return out
