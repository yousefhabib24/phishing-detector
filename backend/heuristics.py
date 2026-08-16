"""
heuristics.py

Rule-based detection layer for the phishing checker. Looks at raw text
(email, SMS, or a decoded QR URL) and extracts objective, checkable
signals -- things that are either true or false, not a matter of AI
judgment. These findings get handed to the LLM layer, which reasons over
them alongside the actual content to produce a final verdict.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_bytes
from email.message import Message


# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

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
    # English
    "act now", "immediate action", "urgent", "verify your account",
    "your account will be suspended", "your account has been limited",
    "confirm your identity", "unusual activity", "click here immediately",
    "failure to comply", "final notice", "within 24 hours",
    "within 48 hours", "account will be closed", "suspended",
    "unauthorized login", "security alert", "limited time",
    # Arabic
    "يرجى التحقق من حسابك", "سيتم تعليق حسابك", "نشاط غير عادي",
    "خلال 24 ساعة", "تنبيه أمني عاجل", "إجراء فوري", "بشكل دائم",
    "أكد هويتك",
]

SENSITIVE_REQUEST_PHRASES = [
    # English
    "enter your password", "confirm your password", "ssn", "social security",
    "credit card number", "cvv", "bank account number", "wire transfer",
    "gift card", "itunes card", "routing number", "one-time password",
    "otp", "login credentials", "update your payment", "billing information",
    # Arabic
    "أدخل كلمة المرور", "رمز التحقق", "رقم البطاقة",
    "بيانات الحساب البنكي", "تحويل بنكي",
]


URL_REGEX = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
FROM_LINE_REGEX = re.compile(
    r"^from:\s*(?P<name>.*?)?\s*<?(?P<email>[\w.+-]+@[\w-]+\.[\w.-]+)>?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
SMS_FROM_LINE_REGEX = re.compile(
    r"^from:\s*(?P<sender>.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
EMAIL_DOMAIN_REGEX = re.compile(r"@([\w-]+(?:\.[\w-]+)+)")
_ARABIC_CHAR_REGEX = re.compile(r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF]")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    id: str
    severity: str
    summary: str
    evidence: str = ""


@dataclass
class HeuristicsResult:
    findings: list[Finding] = field(default_factory=list)
    urls_found: list[str] = field(default_factory=list)
    sender_email: str | None = None
    sender_name: str | None = None
    auth_results: dict = field(default_factory=dict)

    def to_summary_dict(self) -> dict:
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
# Shared helpers
# ---------------------------------------------------------------------------

def _extract_sender(text: str) -> tuple[str | None, str | None]:
    match = FROM_LINE_REGEX.search(text)
    if not match:
        return None, None
    name = (match.group("name") or "").strip().strip('"') or None
    email = match.group("email")
    return name, email


def _extract_urls(text: str) -> list[str]:
    return URL_REGEX.findall(text)


def _levenshtein(a: str, b: str) -> int:
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


def detect_language(text: str) -> str:
    if not text:
        return "english"
    arabic_chars = len(_ARABIC_CHAR_REGEX.findall(text))
    total_letters = len(re.findall(r"[^\W\d_]", text, re.UNICODE))
    if total_letters == 0:
        return "english"
    if arabic_chars / total_letters > 0.2:
        return "arabic"
    return "english"


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_sender_lookalike(sender_name: str | None, sender_email: str | None) -> list[Finding]:
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
            summary="The message uses urgency or pressure language, a common tactic to rush readers into acting without thinking.",
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
            summary="The message asks for sensitive information (credentials, payment details, or codes) that legitimate organizations rarely request this way.",
            evidence=", ".join(hits[:5]),
        ))
    return findings


# ---------------------------------------------------------------------------
# Entry point: email/general text
# ---------------------------------------------------------------------------

def analyze(text: str) -> HeuristicsResult:
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
# SMS / smishing support
# ---------------------------------------------------------------------------

def _extract_sms_sender(text: str) -> str | None:
    match = SMS_FROM_LINE_REGEX.search(text)
    return match.group("sender").strip() if match else None


def check_sms_brand_mismatch(sender: str | None, text: str) -> list[Finding]:
    findings: list[Finding] = []
    if not sender:
        return findings

    text_lower = text.lower()
    looks_like_ordinary_number = bool(re.fullmatch(r"[+]?[\d\s().-]{8,}", sender))

    for brand in COMMON_BRANDS:
        if brand in text_lower and looks_like_ordinary_number:
            findings.append(Finding(
                id="sms_sender_brand_mismatch",
                severity="medium",
                summary=(
                    f"This message claims to be from '{brand.title()}', but it was sent from "
                    f"an ordinary phone number rather than a registered short code or the "
                    f"company's official sender ID. Legitimate businesses usually send SMS "
                    f"from a consistent, registered sender ID, not a random number."
                ),
                evidence=sender,
            ))
            break

    return findings


def analyze_sms(text: str) -> HeuristicsResult:
    sender = _extract_sms_sender(text)
    urls = _extract_urls(text)

    result = HeuristicsResult(
        urls_found=urls,
        sender_name=sender,
        sender_email=None,
    )

    result.findings.extend(check_sms_brand_mismatch(sender, text))
    result.findings.extend(check_suspicious_urls(urls))
    result.findings.extend(check_urgency_language(text))
    result.findings.extend(check_sensitive_requests(text))

    return result


# ---------------------------------------------------------------------------
# QR code / quishing support
# ---------------------------------------------------------------------------

def decode_qr_url(image_bytes: bytes) -> str | None:
    """Decodes a QR code from raw image bytes using OpenCV's built-in
    detector -- deterministic computer vision, NOT the AI (a vision LLM
    asked to 'read' a QR code directly is unreliable in a way a real
    decoder isn't). Tries several preprocessed variants (grayscale,
    upscaled, contrast-enhanced, adaptively thresholded) since the raw
    single-pass detector is a known weak point on real-world photos."""
    import cv2
    import numpy as np

    array = np.frombuffer(image_bytes, dtype=np.uint8)
    image = cv2.imdecode(array, cv2.IMREAD_COLOR)
    if image is None:
        return None

    detector = cv2.QRCodeDetector()
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    candidates = [image, gray]

    height, width = gray.shape
    if max(height, width) < 1000:
        scale = 1000 / max(height, width)
        upscaled = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
        candidates.append(upscaled)

    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
    candidates.append(clahe.apply(gray))

    candidates.append(
        cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 35, 5)
    )

    for candidate in candidates:
        data, _points, _straight_qrcode = detector.detectAndDecode(candidate)
        if data:
            return data

    return None


def analyze_qr_url(url: str, page_text: str | None = None, fetch_note: str | None = None) -> tuple[HeuristicsResult, str]:
    """Entry point for a decoded QR URL. Reuses check_suspicious_urls (the
    same lookalike-domain/IP/shortener checks used for email and SMS
    links). If page_text is provided (Stage 2 -- a safely fetched preview
    of the destination page's visible text), it's included so the LLM can
    reason about what's actually AT the URL, not just its appearance."""
    findings = check_suspicious_urls([url])
    result = HeuristicsResult(
        urls_found=[url],
        sender_name=None,
        sender_email=None,
    )
    result.findings.extend(findings)

    parts = [f"A QR code was scanned. It encodes the following destination URL:\n{url}"]
    if page_text:
        parts.append(f"\nHere is a preview of the VISIBLE TEXT on that page (fetched safely, read-only):\n---\n{page_text}\n---")
    elif fetch_note:
        parts.append(f"\n({fetch_note})")
    synthetic_text = "\n".join(parts)

    return result, synthetic_text


# ---------------------------------------------------------------------------
# .eml file parsing (unlocks real SPF/DKIM/DMARC verification)
# ---------------------------------------------------------------------------

def _extract_auth_results(msg: Message) -> dict:
    results = {"spf": None, "dkim": None, "dmarc": None}
    auth_headers = msg.get_all("Authentication-Results", failobj=[])
    combined = " ".join(auth_headers)
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{mechanism}=(\w+)", combined, re.IGNORECASE)
        if match:
            results[mechanism] = match.group(1).lower()
    return results


def _extract_body(msg: Message) -> str:
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
    msg = message_from_bytes(raw_bytes)

    subject = msg.get("Subject", "")
    from_header = msg.get("From", "")
    body = _extract_body(msg)
    auth_results = _extract_auth_results(msg)

    reconstructed_text = f"From: {from_header}\nSubject: {subject}\n\n{body}"

    result = analyze(reconstructed_text)
    result.auth_results = auth_results
    result.findings.extend(check_authentication_results(auth_results))

    return result, reconstructed_text
