"""
A few hand-written sample emails for manually testing heuristics.py.
Not a formal pytest suite yet -- just enough to sanity-check behavior
while building. Run: python tests/sample_emails.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from heuristics import analyze  # noqa: E402


PHISHING_EXAMPLE = """
From: PayPal Support <support@paypa1-secure.com>
Subject: Your account will be suspended - Immediate action required

Dear Customer,

We noticed unusual activity on your account. Your account will be suspended
within 24 hours unless you verify your account immediately.

Please click here to confirm your identity: http://192.168.1.5/verify

If you do not act now, your account will be closed permanently.

PayPal Security Team
"""

LEGITIMATE_EXAMPLE = """
From: Amazon <order-update@amazon.com>
Subject: Your order has shipped

Hi there,

Your recent order (#112-3456789) has shipped and is on its way. You can
track your package here: https://www.amazon.com/orders/track

Thanks for shopping with us!

Amazon Customer Service
"""

AMBIGUOUS_EXAMPLE = """
Subject: Meeting notes from today

Hey, just following up on our call. Let me know if you have questions.
Talk soon.
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
    run("PHISHING EXAMPLE", PHISHING_EXAMPLE)
    run("LEGITIMATE EXAMPLE", LEGITIMATE_EXAMPLE)
    run("AMBIGUOUS EXAMPLE", AMBIGUOUS_EXAMPLE)
