"""
llm_analysis.py

The reasoning layer of the phishing checker. Takes the raw email text a
user pasted plus the structured findings from heuristics.py, and asks
Claude to weigh everything together and produce ONE final verdict with
a plain-English explanation a non-technical person can trust.

Design principle: the LLM does not re-derive facts the heuristics layer
already established (like "this domain doesn't match the real one") --
it's told those facts directly. Its job is judgment: does this add up
as a whole, and how do we explain it clearly.

Requires an ANTHROPIC_API_KEY environment variable to call the real API.
If no key is set, `analyze_with_llm` falls back to a clearly-labeled
mock response so the rest of the app can be built and tested without a
key yet.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from heuristics import HeuristicsResult

try:
    import anthropic
except ImportError:  # pragma: no cover
    anthropic = None


MODEL = "claude-haiku-4-5-20251001"

SYSTEM_PROMPT = """You are a phishing-detection assistant used inside a public web tool. \
A non-technical person has pasted an email they're unsure about. You will be given:
1. The raw email text they pasted
2. A list of objective technical findings already detected by a separate rule-based system \
(you should treat these findings as established facts -- do not doubt or re-derive them)

Your job is to weigh the technical findings together with the actual content, tone, and \
context of the email, then produce ONE final verdict.

Think about things the rule-based system CANNOT detect on its own, such as:
- Does the email's claimed identity make sense given what it's asking for?
- Is there a plausible, low-risk explanation for anything that looks suspicious?
- Does the overall narrative of the email hold together, or does it feel like a pretext?
- Are there social-engineering patterns even if no technical red flags were found (e.g. \
a fake "CEO" asking for a favor, romance/relationship pretexts, fake job offers)?

IMPORTANT -- weighing evidence types: most findings from the rule-based system are pattern \
matches (e.g. "this domain looks similar to a known brand"), which are strong but not \
absolute signals. However, any finding with an id ending in "_auth_failed" (SPF/DKIM/DMARC) \
represents a real cryptographic verification already performed by the email's own receiving \
mail server -- not a guess, not a pattern match, an actual technical fact. Treat any such \
finding as very strong evidence of spoofing, close to conclusive on its own, even if the \
email's wording otherwise seems calm or professional. Conversely, if authentication_results \
shows "pass" for all three (spf, dkim, dmarc), treat that as strong (though not absolute -- \
a compromised legitimate account could still pass) evidence in favor of legitimacy.

Respond with ONLY valid JSON, no other text, in exactly this shape:
{
  "risk_level": "safe" | "suspicious" | "dangerous",
  "confidence": "low" | "medium" | "high",
  "summary": "one or two plain-English sentences explaining the overall verdict",
  "red_flags": [
    {"title": "short label", "explanation": "plain-English explanation a non-technical person would understand"}
  ],
  "reassurance_notes": "optional: if risk_level is 'safe' or findings are weak, briefly note what looked fine (can be empty string)"
}

Guidelines:
- "dangerous": clear phishing/scam intent, real potential for harm if acted on
- "suspicious": some concerning signals, but not conclusive -- advise caution
- "safe": no meaningful red flags found
- STRICT RULE: if risk_level is "safe", red_flags MUST be an empty list []. Any minor \
observations that aren't serious enough to change the verdict belong in reassurance_notes \
instead, phrased as reassurance (e.g. "The vague wording is common in normal follow-up \
emails and isn't concerning on its own"). If something is concerning enough to list as a \
red_flag, the risk_level cannot be "safe" -- use "suspicious" instead.
- Keep language simple. Avoid jargon like "DKIM" or "SPF" -- translate technical findings \
into plain consequences (e.g. "the sender's address doesn't actually belong to the company it claims to be from")
- Do not invent findings that aren't supported by the provided evidence or the email text itself
- If the email is too short/ambiguous to judge confidently, say so honestly rather than guessing
"""


@dataclass
class RedFlag:
    title: str
    explanation: str


@dataclass
class Verdict:
    risk_level: str          # "safe" | "suspicious" | "dangerous"
    confidence: str          # "low" | "medium" | "high"
    summary: str
    red_flags: list[RedFlag] = field(default_factory=list)
    reassurance_notes: str = ""
    is_mock: bool = False     # True if no API key was available and this is a fallback


def _build_user_message(email_text: str, heuristics: HeuristicsResult) -> str:
    findings_json = json.dumps(heuristics.to_summary_dict(), indent=2)
    return (
        f"EMAIL TEXT PASTED BY USER:\n---\n{email_text.strip()}\n---\n\n"
        f"TECHNICAL FINDINGS FROM RULE-BASED SYSTEM:\n{findings_json}\n\n"
        "Produce your JSON verdict now."
    )


def _enforce_consistency(verdict: Verdict) -> Verdict:
    """Backstop that doesn't rely on the AI following instructions perfectly.
    If the AI ever says "safe" while still listing red flags (a contradiction
    we saw happen in testing), we don't silently discard what it noticed --
    that information might matter. Instead we upgrade the verdict to
    "suspicious", since a verdict with real flags attached was never
    genuinely a clean "safe" in the first place."""
    if verdict.risk_level == "safe" and verdict.red_flags:
        verdict.risk_level = "suspicious"
        if not verdict.summary.startswith("[Adjusted]"):
            verdict.summary = (
                "[Adjusted] " + verdict.summary +
                " (Upgraded from 'safe' because some observations were still noted below.)"
            )
    return verdict


def _parse_response(raw_text: str) -> Verdict:
    data = json.loads(raw_text)
    red_flags = [
        RedFlag(title=rf.get("title", ""), explanation=rf.get("explanation", ""))
        for rf in data.get("red_flags", [])
    ]
    verdict = Verdict(
        risk_level=data.get("risk_level", "suspicious"),
        confidence=data.get("confidence", "low"),
        summary=data.get("summary", ""),
        red_flags=red_flags,
        reassurance_notes=data.get("reassurance_notes", ""),
    )
    return _enforce_consistency(verdict)


def _mock_verdict(heuristics: HeuristicsResult) -> Verdict:
    """A simple, clearly-labeled stand-in used when no API key is configured
    yet, so the rest of the app can be built/tested without one."""
    high_findings = [f for f in heuristics.findings if f.severity == "high"]
    if high_findings:
        risk_level = "dangerous"
        summary = "[MOCK] Multiple high-severity technical red flags were found."
    elif heuristics.findings:
        risk_level = "suspicious"
        summary = "[MOCK] Some concerning signals were found, but nothing conclusive."
    else:
        risk_level = "safe"
        summary = "[MOCK] No red flags detected by the rule-based checks."

    red_flags = [
        RedFlag(title=f.id.replace("_", " ").title(), explanation=f.summary)
        for f in heuristics.findings
    ]
    return Verdict(
        risk_level=risk_level,
        confidence="low",
        summary=summary,
        red_flags=red_flags,
        reassurance_notes="[MOCK MODE] This is a placeholder verdict generated without calling the LLM, because no ANTHROPIC_API_KEY was found.",
        is_mock=True,
    )


def analyze_with_llm(email_text: str, heuristics: HeuristicsResult) -> Verdict:
    """Main entry point. Calls Claude to produce a final verdict, combining
    heuristic findings with the model's own reasoning over the email content.
    Falls back to a mock verdict if no API key is configured."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")

    if not api_key or anthropic is None:
        return _mock_verdict(heuristics)

    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=MODEL,
        max_tokens=1000,
        system=SYSTEM_PROMPT,
        messages=[
            {"role": "user", "content": _build_user_message(email_text, heuristics)}
        ],
    )

    raw_text = "".join(
        block.text for block in message.content if getattr(block, "type", None) == "text"
    ).strip()

    # Defensive cleanup in case the model wraps JSON in markdown fences
    if raw_text.startswith("```"):
        raw_text = raw_text.strip("`")
        if raw_text.lower().startswith("json"):
            raw_text = raw_text[4:].strip()

    return _parse_response(raw_text)
