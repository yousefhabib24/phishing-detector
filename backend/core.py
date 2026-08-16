"""
core.py

The single entry point the API calls. Wires the heuristics layer, the
LLM analysis layer, and (for QR codes) the safe URL-fetch layer together.
"""

from __future__ import annotations

from heuristics import analyze as run_heuristics
from heuristics import analyze_eml as run_heuristics_on_eml
from heuristics import analyze_sms as run_heuristics_on_sms
from heuristics import decode_qr_url, analyze_qr_url
from llm_analysis import analyze_with_llm, extract_text_from_image, Verdict
from url_fetcher import fetch_page_text


def check_email(email_text: str) -> Verdict:
    """Legacy entry point (kept for the original Streamlit version)."""
    if not email_text or not email_text.strip():
        raise ValueError("email_text must not be empty")
    heuristics_result = run_heuristics(email_text)
    return analyze_with_llm(email_text, heuristics_result)


def check_email_file(raw_bytes: bytes) -> Verdict:
    """Legacy entry point (kept for the original Streamlit version)."""
    if not raw_bytes:
        raise ValueError("uploaded file is empty")
    heuristics_result, reconstructed_text = run_heuristics_on_eml(raw_bytes)
    return analyze_with_llm(reconstructed_text, heuristics_result)


def check_email_detailed(email_text: str):
    if not email_text or not email_text.strip():
        raise ValueError("email_text must not be empty")
    heuristics_result = run_heuristics(email_text)
    verdict = analyze_with_llm(email_text, heuristics_result)
    return verdict, heuristics_result


def check_email_file_detailed(raw_bytes: bytes):
    if not raw_bytes:
        raise ValueError("uploaded file is empty")
    heuristics_result, reconstructed_text = run_heuristics_on_eml(raw_bytes)
    verdict = analyze_with_llm(reconstructed_text, heuristics_result)
    return verdict, heuristics_result


def check_email_image_detailed(image_bytes: bytes, media_type: str):
    if not image_bytes:
        raise ValueError("uploaded image is empty")
    reconstructed_text = extract_text_from_image(image_bytes, media_type, channel="email")
    if not reconstructed_text.strip():
        raise ValueError("Could not read any text from the uploaded image.")
    heuristics_result = run_heuristics(reconstructed_text)
    verdict = analyze_with_llm(reconstructed_text, heuristics_result)
    return verdict, heuristics_result


def check_sms_text_detailed(sms_text: str):
    if not sms_text or not sms_text.strip():
        raise ValueError("sms_text must not be empty")
    heuristics_result = run_heuristics_on_sms(sms_text)
    verdict = analyze_with_llm(sms_text, heuristics_result)
    return verdict, heuristics_result


def check_sms_image_detailed(image_bytes: bytes, media_type: str):
    if not image_bytes:
        raise ValueError("uploaded image is empty")
    reconstructed_text = extract_text_from_image(image_bytes, media_type, channel="sms")
    if not reconstructed_text.strip():
        raise ValueError("Could not read any text from the uploaded image.")
    heuristics_result = run_heuristics_on_sms(reconstructed_text)
    verdict = analyze_with_llm(reconstructed_text, heuristics_result)
    return verdict, heuristics_result


def check_qr_image_detailed(image_bytes: bytes):
    """Entry point for an uploaded QR code image.
    Stage 1: decode the QR deterministically, run URL heuristics.
    Stage 2: safely fetch the destination page's visible text (with
    layered SSRF protections) and include it for the AI to reason about,
    if the fetch succeeds. If it fails/is blocked, we don't fail the
    whole check -- we just note that the destination couldn't be
    verified and reason from the URL alone, same as Stage 1 did before."""
    if not image_bytes:
        raise ValueError("uploaded image is empty")

    url = decode_qr_url(image_bytes)
    if not url:
        raise ValueError(
            "Could not detect a QR code in this image. Make sure the QR "
            "code is clearly visible and not cropped or blurry."
        )

    page_text, fetch_reason = fetch_page_text(url)
    heuristics_result, synthetic_text = analyze_qr_url(url, page_text=page_text, fetch_note=fetch_reason if not page_text else None)
    verdict = analyze_with_llm(synthetic_text, heuristics_result)
    return verdict, heuristics_result
