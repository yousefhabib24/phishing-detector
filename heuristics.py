"""
heuristics.py

Rule-based detection layer for the phishing email checker.

This module looks at the RAW TEXT a user pastes in (subject + body, and
optionally a "From:" line if they included one) and extracts objective,
checkable signals -- things that are either true or false, not a matter
of AI judgment.

These findings get handed to the LLM layer later, which reasons over
them alongside the actual email content to produce a final verdict.

Known limitation (v1): because we only accept pasted VISIBLE TEXT (not
raw email source/headers), we can't verify SPF/DKIM/DMARC, and if a
link's display text differs from its real destination, plain-text
copy/paste usually loses that distinction. We flag any URLs we find in
the text itself. Raw-header support is a planned v2 feature that will
unlock much stronger sender-verification checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_bytes
from email.message import Message


# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

# A small set of frequently-impersonated brands, used for lookalike-domain
# detection. This is intentionally short for v1 -- easy to extend later,
# or replace with a proper brand-domain database.
COMMON_BRANDS = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com"],
    "google": ["google.com", "gmail.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "chase": ["chase.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "emirates nbd": ["emiratesnbd.com"],
    "adcb": ["adcb.com"],
    "etisalat": ["etisalat.ae"],
    "du": ["du.ae"],
}

KNOWN_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}

URGENCY_PHRASES = [
    "act now", "immediate action", "urgent", "verify your account",
    "your account will be suspended", "your account has been limited",
    "confirm your identity", "unusual activity", "click here immediately",
    "failure to comply", "final notice", "within 24 hours",
    "within 48 hours", "account will be closed", "suspended",
    "unauthorized login", "security alert", "limited time",
]

SENSITIVE_REQUEST_PHRASES = [
    "enter your password", "confirm your password", "ssn", "social security",
    "credit card number", "cvv", "bank account number", "wire transfer",
    "gift card", "itunes card", "routing number", "one-time password",
    "otp", "login credentials", "update your payment", "billing information",
]


URL_REGEX = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
FROM_LINE_REGEX = re.compile(
    r"^from:\s*(?P<name>.*?)?\s*<?(?P<email>[\w.+-]+@[\w-]+\.[\w.-]+)>?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
EMAIL_DOMAIN_REGEX = re.compile(r"@([\w-]+(?:\.[\w-]+)+)")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single objective signal found by the heuristics engine."""
    id: str
    severity: str          # "high" | "medium" | "low"
    summary: str            # short human-readable description
    evidence: str = ""       # the specific text/url that triggered it


@dataclass
class HeuristicsResult:
    findings: list[Finding] = field(default_factory=list)
    urls_found: list[str] = field(default_factory=list)
    sender_email: str | None = None
    sender_name: str | None = None
    # Real SPF/DKIM/DMARC verdicts from the receiving mail server, only
    # available when a raw .eml file was uploaded (not from pasted text).
    # Each value is "pass", "fail", "softfail", "none", etc., or None if
    # that check wasn't present in the email's headers at all.
    auth_results: dict = field(default_factory=dict)

    def to_summary_dict(self) -> dict:
        """Compact representation to hand to the LLM prompt."""
        return {
            "sender_name": self.sender_name,
            "sender_email": self.sender_email,
            "urls_found": self.urls_found,
            "authentication_results": self.auth_results or "not available (pasted text only, no raw headers)",
            "findings": [
                {"id": f.id, "severity": f.severity, "summary": f.summary, "evidence": f.evidence}
                for f in self.findings
            ],
        }


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _extract_sender(text: str) -> tuple[str | None, str | None]:
    """Pull a sender name/email out of an optional 'From:' line, if present."""
    match = FROM_LINE_REGEX.search(text)
    if not match:
        return None, None
    name = (match.group("name") or "").strip().strip('"') or None
    email = match.group("email")
    return name, email


def _extract_urls(text: str) -> list[str]:
    return URL_REGEX.findall(text)


def _levenshtein(a: str, b: str) -> int:
    """Small edit-distance implementation (no external dependency needed)."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _domain_from_email(email: str) -> str | None:
    match = EMAIL_DOMAIN_REGEX.search(email)
    return match.group(1).lower() if match else None


def check_sender_lookalike(sender_name: str | None, sender_email: str | None) -> list[Finding]:
    """Flag a sender whose display name references a brand but whose domain
    doesn't match that brand's real domain(s) -- classic spoofing pattern."""
    findings: list[Finding] = []
    if not sender_name or not sender_email:
        return findings

    domain = _domain_from_email(sender_email)
    if not domain:
        return findings

    name_lower = sender_name.lower()
    for brand, real_domains in COMMON_BRANDS.items():
        if brand in name_lower:
            if domain not in real_domains:
                # Check if it's a close-but-not-exact lookalike (higher signal)
                # vs. wildly different (still suspicious either way)
                closest = min(real_domains, key=lambda d: _levenshtein(domain, d))
                distance = _levenshtein(domain, closest)
                if distance <= 3:
                    findings.append(Finding(
                        id="sender_lookalike_domain",
                        severity="high",
                        summary=(
                            f"Sender claims to be '{sender_name}' (associated with "
                            f"{brand.title()}) but the email domain '{domain}' is a "
                            f"close lookalike of the real domain '{closest}', not an exact match."
                        ),
                        evidence=sender_email,
                    ))
                else:
                    findings.append(Finding(
                        id="sender_brand_mismatch",
                        severity="high",
                        summary=(
                            f"Sender display name references '{brand.title()}' but the "
                            f"email address domain '{domain}' has no relation to "
                            f"{brand.title()}'s real domain(s)."
                        ),
                        evidence=sender_email,
                    ))
            break
    return findings


def check_suspicious_urls(urls: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    ip_regex = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

    for url in urls:
        # IP-address-based links are a strong phishing signal
        if ip_regex.match(url):
            findings.append(Finding(
                id="ip_based_url",
                severity="high",
                summary="A link points directly to a raw IP address instead of a domain name, which is unusual for legitimate businesses.",
                evidence=url,
            ))
            continue

        domain_match = re.search(r"https?://([^/]+)", url)
        if not domain_match:
            continue
        domain = domain_match.group(1).lower().split(":")[0]

        if domain in KNOWN_URL_SHORTENERS:
            findings.append(Finding(
                id="url_shortener",
                severity="medium",
                summary="A link uses a URL shortener, which hides the real destination until you click it.",
                evidence=url,
            ))

        # Lookalike domain check against known brands
        for brand, real_domains in COMMON_BRANDS.items():
            for real_domain in real_domains:
                if domain == real_domain:
                    continue
                distance = _levenshtein(domain, real_domain)
                if distance <= 2 and domain != real_domain:
                    findings.append(Finding(
                        id="url_lookalike_domain",
                        severity="high",
                        summary=(
                            f"A link's domain '{domain}' closely resembles "
                            f"'{real_domain}' ({brand.title()}) but is not an exact match."
                        ),
                        evidence=url,
                    ))

    return findings


def check_authentication_results(auth_results: dict) -> list[Finding]:
    """Unlike every other check in this file, this one isn't pattern-matching
    -- it's reading a verdict that was already cryptographically verified by
    the RECEIVING mail server (Gmail, Outlook, etc.) before the email ever
    reached the user. A failure here is much stronger evidence than anything
    else we can detect from text alone, because it can't be faked by clever
    wording -- it's a mathematical check on whether the sending server was
    actually authorized to send as that domain."""
    findings: list[Finding] = []
    labels = {
        "spf": "SPF (sender server authorization)",
        "dkim": "DKIM (message integrity signature)",
        "dmarc": "DMARC (domain-level policy)",
    }
    for mechanism, label in labels.items():
        status = auth_results.get(mechanism)
        if status in ("fail", "softfail", "permerror"):
            findings.append(Finding(
                id=f"{mechanism}_auth_failed",
                severity="high",
                summary=(
                    f"{label} check FAILED. This is a verified technical result from the "
                    f"receiving mail server, not a guess -- it means this email likely did "
                    f"not actually come from an authorized server for the claimed sending domain."
                ),
                evidence=f"{mechanism}={status}",
            ))
    return findings


def check_urgency_language(text: str) -> list[Finding]:
    findings: list[Finding] = []
    lower = text.lower()
    hits = [phrase for phrase in URGENCY_PHRASES if phrase in lower]
    if hits:
        findings.append(Finding(
            id="urgency_language",
            severity="medium",
            summary="The email uses urgency or pressure language, a common tactic to rush readers into acting without thinking.",
            evidence=", ".join(hits[:5]),
        ))
    return findings


def check_sensitive_requests(text: str) -> list[Finding]:
    findings: list[Finding] = []
    lower = text.lower()
    hits = [phrase for phrase in SENSITIVE_REQUEST_PHRASES if phrase in lower]
    if hits:
        findings.append(Finding(
            id="sensitive_info_request",
            severity="high",
            summary="The email asks for sensitive information (credentials, payment details, or codes) that legitimate organizations rarely request via email.",
            evidence=", ".join(hits[:5]),
        ))
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def analyze(text: str) -> HeuristicsResult:
    """Run all heuristic checks against pasted email text and return a
    structured result ready to hand off to the LLM analysis layer."""
    sender_name, sender_email = _extract_sender(text)
    urls = _extract_urls(text)

    result = HeuristicsResult(
        urls_found=urls,
        sender_name=sender_name,
        sender_email=sender_email,
    )

    result.findings.extend(check_sender_lookalike(sender_name, sender_email))
    result.findings.extend(check_suspicious_urls(urls))
    result.findings.extend(check_urgency_language(text))
    result.findings.extend(check_sensitive_requests(text))

    return result


# ---------------------------------------------------------------------------
# .eml file parsing (unlocks real SPF/DKIM/DMARC verification)
# ---------------------------------------------------------------------------

def _extract_auth_results(msg: Message) -> dict:
    """Reads the 'Authentication-Results' header(s), added by the mail
    server that RECEIVED the email, which record whether SPF/DKIM/DMARC
    checks passed. A raw .eml file can contain more than one of these
    headers (added by different servers as the email hopped between them),
    so we search all of them combined."""
    results = {"spf": None, "dkim": None, "dmarc": None}
    auth_headers = msg.get_all("Authentication-Results", failobj=[])
    combined = " ".join(auth_headers)
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{mechanism}=(\w+)", combined, re.IGNORECASE)
        if match:
            results[mechanism] = match.group(1).lower()
    return results


def _extract_body(msg: Message) -> str:
    """Emails are often 'multipart' (a plain-text version AND an HTML
    version bundled together). We specifically want the plain-text part --
    walk() lets us look through every part of the email to find it."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not part.get_filename():
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    return payload.decode(charset, errors="replace")
        return ""
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
        return str(msg.get_payload())


def analyze_eml(raw_bytes: bytes) -> tuple[HeuristicsResult, str]:
    """Entry point for uploaded .eml files. Parses real headers (unlocking
    SPF/DKIM/DMARC verification) and the message body, then reuses the same
    checks analyze() uses for pasted text, plus the new authentication check.
    Returns the HeuristicsResult, plus a reconstructed text block (matching
    the shape analyze() expects) so the LLM sees a consistent format either way.
    """
    msg = message_from_bytes(raw_bytes)

    subject = msg.get("Subject", "")
    from_header = msg.get("From", "")
    body = _extract_body(msg)
    auth_results = _extract_auth_results(msg)

    reconstructed_text = f"From: {from_header}\nSubject: {subject}\n\n{body}"

    # Reuse every existing text-based check by running them on the
    # reconstructed text -- no need to duplicate that logic.
    result = analyze(reconstructed_text)
    result.auth_results = auth_results
    result.findings.extend(check_authentication_results(auth_results))

    return result, reconstructed_text
