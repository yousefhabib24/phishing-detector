"""
core.py

The single entry point the UI (or anything else) calls. Wires the
heuristics layer and the LLM analysis layer together so callers don't
need to know about either one individually.
"""

from __future__ import annotations

from heuristics import analyze as run_heuristics
from heuristics import analyze_eml as run_heuristics_on_eml
from llm_analysis import analyze_with_llm, extract_text_from_image, Verdict


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


def check_email_detailed(email_text: str):
    """Same as check_email, but also returns the underlying HeuristicsResult
    -- used by the new frontend's expandable 'technical details' section.
    Kept separate from check_email so the existing Streamlit app (which only
    expects a Verdict back) doesn't need to change at all."""
    if not email_text or not email_text.strip():
        raise ValueError("email_text must not be empty")

    heuristics_result = run_heuristics(email_text)
    verdict = analyze_with_llm(email_text, heuristics_result)
    return verdict, heuristics_result


def check_email_file_detailed(raw_bytes: bytes):
    """Same as check_email_file, but also returns the underlying
    HeuristicsResult (including real auth_results from the uploaded file)."""
    if not raw_bytes:
        raise ValueError("uploaded file is empty")

    heuristics_result, reconstructed_text = run_heuristics_on_eml(raw_bytes)
    verdict = analyze_with_llm(reconstructed_text, heuristics_result)
    return verdict, heuristics_result


def check_email_image_detailed(image_bytes: bytes, media_type: str):
    """Entry point for an uploaded screenshot. Uses Claude's vision to read
    the visible email content and reconstruct it as plain text, then reuses
    the exact same heuristics + reasoning pipeline as pasted text -- no
    separate detection logic. No mock-mode fallback: reading an image
    genuinely requires the real model, unlike text/file checks."""
    if not image_bytes:
        raise ValueError("uploaded image is empty")

    reconstructed_text = extract_text_from_image(image_bytes, media_type)
    if not reconstructed_text.strip():
        raise ValueError("Could not read any text from the uploaded image.")

    heuristics_result = run_heuristics(reconstructed_text)
    verdict = analyze_with_llm(reconstructed_text, heuristics_result)
    return verdict, heuristics_result
