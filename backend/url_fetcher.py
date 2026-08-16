"""
url_fetcher.py

Stage 2 of quishing: safely fetches a QR-decoded URL's visible text
content, so the AI can reason about what's actually AT the destination
(a fake login form, urgency language, brand impersonation) rather than
just the URL's appearance.

## SSRF (server-side request forgery) -- what we're defending against
If our server fetches a URL on the user's behalf, an attacker could put
a URL in a QR code pointing at something INTERNAL to our own
infrastructure (localhost, a cloud metadata endpoint, an internal
network address), tricking our server into making a request it should
never make, from a position of trust inside our own network.

## This is "defense in depth," not a single silver-bullet check
No individual layer below is claimed to be perfect on its own -- real
attackers have documented bypass techniques (DNS rebinding, redirect
tricks, alternate IP encodings). Several independent layers, each
closing a different bypass category, is the honest, industry-standard
approach -- reducing risk to a genuinely low level, not promising zero.

KNOWN, STATED LIMITATION: there is a narrow time-of-check-to-time-of-use
(TOCTOU) window between validating a hostname's resolved IP and the
actual HTTP connection being made a moment later, since the underlying
HTTP library performs its own DNS resolution at connection time. This
narrows (does not perfectly eliminate) DNS-rebinding risk. Documented
here honestly rather than silently ignored.
"""

from __future__ import annotations

import ipaddress
import socket
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

MAX_REDIRECTS = 5
TIMEOUT_SECONDS = 5.0
MAX_RESPONSE_BYTES = 500_000  # 500 KB cap
MAX_TEXT_CHARS = 8000  # keep prompt size reasonable regardless of page length

ALLOWED_SCHEMES = {"http", "https"}


class _VisibleTextExtractor(HTMLParser):
    """Minimal HTML-to-text extractor using only the standard library --
    no new dependency needed. Strips script/style content and tags,
    keeps visible text."""

    def __init__(self):
        super().__init__()
        self._skip = False
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript"):
            self._skip = True

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript"):
            self._skip = False

    def handle_data(self, data):
        if not self._skip:
            stripped = data.strip()
            if stripped:
                self.parts.append(stripped)

    def get_text(self) -> str:
        return " ".join(self.parts)


def _is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # can't parse it -- treat as unsafe
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _validate_hostname(hostname: str) -> bool:
    """Resolves ALL IPs a hostname maps to and rejects if ANY of them are
    private/internal/reserved -- a hostname could resolve to multiple
    addresses, and only checking one would leave a gap."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    for info in infos:
        ip_str = info[4][0]
        if _is_blocked_ip(ip_str):
            return False
    return True


def fetch_page_text(url: str) -> tuple[str | None, str]:
    """Attempts to fetch a URL's visible text content, safely. Returns
    (text, reason) -- text is None if the fetch failed or was blocked for
    any reason, in which case reason explains why (used for an honest
    note to the AI, e.g. "page unreachable" vs "blocked as unsafe" --
    NEVER raises to the caller, since a failed fetch just means "couldn't
    verify," not a hard error for the whole check."""
    current_url = url
    session = requests.Session()
    # (Previously disabled proxy/env trust here as a defensive default, but
    # that's unrelated to the actual SSRF defense -- an attacker via a
    # malicious QR code has no ability to control server-level proxy
    # config, so honoring it isn't a real risk, and disabling it broke
    # legitimate connectivity in some deployment environments.)

    for hop in range(MAX_REDIRECTS + 1):
        parsed = urlparse(current_url)
        if parsed.scheme not in ALLOWED_SCHEMES:
            return None, f"Blocked: unsupported URL scheme ({parsed.scheme})"
        if not parsed.hostname:
            return None, "Blocked: could not parse a hostname from the URL"

        if not _validate_hostname(parsed.hostname):
            return None, "Blocked: destination resolves to a private/internal/unreachable address"

        try:
            response = session.get(
                current_url,
                timeout=TIMEOUT_SECONDS,
                allow_redirects=False,  # handled manually so each hop gets re-validated
                stream=True,
                headers={"User-Agent": "PhishyMax-SafetyCheck/1.0"},
            )
        except requests.exceptions.RequestException:
            return None, "Could not reach the destination (timeout, connection refused, or similar)"

        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("location")
            response.close()
            if not location:
                return None, "Blocked: redirect with no destination given"
            current_url = urljoin(current_url, location)
            continue  # loop -- re-validate the NEW url's hostname/IP next iteration

        if response.status_code != 200:
            response.close()
            return None, f"Destination returned an error (HTTP {response.status_code})"

        content_type = response.headers.get("content-type", "")
        if "text/html" not in content_type and "text/plain" not in content_type:
            response.close()
            return None, f"Destination is not a text/HTML page (content-type: {content_type or 'unknown'})"

        raw = b""
        for chunk in response.iter_content(chunk_size=8192):
            raw += chunk
            if len(raw) >= MAX_RESPONSE_BYTES:
                break
        response.close()

        try:
            html = raw.decode(response.encoding or "utf-8", errors="replace")
        except (LookupError, TypeError):
            html = raw.decode("utf-8", errors="replace")

        extractor = _VisibleTextExtractor()
        try:
            extractor.feed(html)
        except Exception:  # noqa: BLE001 -- malformed HTML shouldn't crash the check
            pass

        text = extractor.get_text()[:MAX_TEXT_CHARS]
        if not text.strip():
            return None, "Page fetched successfully but contained no readable text"
        return text, "OK"

    return None, "Blocked: too many redirects"
