"""
Arabic-language sample emails for manually testing heuristics.py and the
full pipeline. Built after real testers reported strong results with Arabic
emails -- this suite exists to turn that anecdotal result into something we
deliberately test and can stand behind, the same way sample_emails.py did
for English. Run: python tests/arabic_sample_emails.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from heuristics import analyze  # noqa: E402


# Impersonates Emirates NBD (a real UAE bank already in our COMMON_BRANDS
# list), with a lookalike domain, an IP-based link, and genuinely urgent
# Arabic-language pressure tactics.
ARABIC_PHISHING_EXAMPLE = """
From: Emirates NBD Support <support@emirates-nbd-verify.com>
Subject: تنبيه أمني عاجل من بنك الإمارات دبي الوطني

عزيزي العميل، لاحظنا نشاطاً غير عادي في حسابك. يرجى التحقق من حسابك فوراً
خلال 24 ساعة وإلا سيتم تعليق حسابك بشكل دائم.

اضغط هنا للتحقق من حسابك: http://192.168.1.10/verify
"""

# A realistic, everyday legitimate email in Arabic -- a telecom billing
# notice from du (also already in COMMON_BRANDS), correct domain, no
# pressure tactics. Tests for false positives, not just catches.
ARABIC_LEGITIMATE_EXAMPLE = """
From: du <billing@du.ae>
Subject: فاتورتك الشهرية جاهزة الآن

عزيزي العميل،

فاتورتك لشهر يوليو جاهزة الآن. يمكنك الاطلاع عليها من خلال تطبيق du
أو زيارة موقعنا الرسمي عند الحاجة.

شكراً لتعاملكم معنا.
فريق du
"""

# A short, vague, low-signal Arabic email -- tests whether the checks
# correctly find nothing rather than over-triggering on ordinary text.
ARABIC_AMBIGUOUS_EXAMPLE = """
Subject: متابعة

مرحباً، فقط أتابع بخصوص المستند الذي أرسلته الأسبوع الماضي. أخبرني إذا
كان لديك أي أسئلة.

تحياتي
"""


def run(label: str, text: str) -> None:
    print(f"\n{'=' * 60}\n{label}\n{'=' * 60}")
    result = analyze(text)
    print(f"Sender name:  {result.sender_name}")
    print(f"Sender email: {result.sender_email}")
    print(f"URLs found:   {result.urls_found}")
    if not result.findings:
        print("No heuristic findings.")
    for f in result.findings:
        print(f"  [{f.severity.upper()}] {f.id}: {f.summary}")
        if f.evidence:
            print(f"      evidence: {f.evidence}")


if __name__ == "__main__":
    run("ARABIC PHISHING EXAMPLE", ARABIC_PHISHING_EXAMPLE)
    run("ARABIC LEGITIMATE EXAMPLE", ARABIC_LEGITIMATE_EXAMPLE)
    run("ARABIC AMBIGUOUS EXAMPLE", ARABIC_AMBIGUOUS_EXAMPLE)
