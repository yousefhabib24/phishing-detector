"""
core.py

The single entry point the UI (or anything else) calls. Wires the
heuristics layer and the LLM analysis layer together so callers don't
need to know about either one individually.
"""

from __future__ import annotations

from heuristics import analyze as run_heuristics
from llm_analysis import analyze_with_llm, Verdict


def check_email(email_text: str) -> Verdict:
    """Run the full pipeline: heuristics -> LLM reasoning -> final verdict."""
    if not email_text or not email_text.strip():
        raise ValueError("email_text must not be empty")

    heuristics_result = run_heuristics(email_text)
    verdict = analyze_with_llm(email_text, heuristics_result)
    return verdict
