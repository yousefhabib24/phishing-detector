"""
core.py

The single entry point the UI (or anything else) calls. Wires the
heuristics layer and the LLM analysis layer together so callers don't
need to know about either one individually.
"""

from __future__ import annotations

from heuristics import analyze as run_heuristics
from heuristics import analyze_eml as run_heuristics_on_eml
from llm_analysis import analyze_with_llm, Verdict


def check_email(email_text: str) -> Verdict:
    """Run the full pipeline: heuristics -> LLM reasoning -> final verdict."""
    if not email_text or not email_text.strip():
        raise ValueError("email_text must not be empty")

    heuristics_result = run_heuristics(email_text)
    verdict = analyze_with_llm(email_text, heuristics_result)
    return verdict


def check_email_file(raw_bytes: bytes) -> Verdict:
    """Same pipeline as check_email, but for an uploaded raw .eml file
    instead of pasted text. This path unlocks real SPF/DKIM/DMARC
    verification, since raw files contain the actual email headers that
    pasted visible text never includes."""
    if not raw_bytes:
        raise ValueError("uploaded file is empty")

    heuristics_result, reconstructed_text = run_heuristics_on_eml(raw_bytes)
    verdict = analyze_with_llm(reconstructed_text, heuristics_result)
    return verdict
