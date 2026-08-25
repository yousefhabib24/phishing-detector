"""
transcription.py

Vishing (voice phishing) support. Claude's API does not accept audio
input directly (verified before building this -- it's a real, current
constraint, not an assumption), so this uses a separate provider
(OpenAI's Whisper API) to transcribe audio to text first. The resulting
transcript then flows through the exact same text-reasoning pipeline
already built for email/SMS -- no new detection logic needed once we
have words on a page.

## Honest limitation, worth restating here in code too
A transcript captures WORDS, not tone. Vocal pressure tactics, a
distressed-sounding voice, background call-center noise -- none of that
survives transcription. This can still catch wording-based red flags
("wire the funds immediately," "this is the IRS," a request for a gift
card), but it cannot detect manipulation conveyed purely through tone.

It also cannot verify whether a voice belongs to who it claims to --
that's voice-biometric matching, a fundamentally different (and much
harder) problem, out of scope regardless of provider.
"""

from __future__ import annotations

import os

import requests

WHISPER_API_URL = "https://api.openai.com/v1/audio/transcriptions"
TIMEOUT_SECONDS = 60.0  # transcription can take longer than a text/vision call


def transcribe_audio(audio_bytes: bytes, filename: str, content_type: str) -> str:
    """Sends audio to OpenAI's Whisper API and returns the transcript.
    No mock-mode fallback -- transcription genuinely requires a live
    connection to a real provider, same as image analysis does."""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError(
            "Voice message analysis requires a live connection to OpenAI's "
            "transcription service (no OPENAI_API_KEY configured). This is a "
            "separate service from the one used for the rest of the site."
        )

    try:
        response = requests.post(
            WHISPER_API_URL,
            headers={"Authorization": f"Bearer {api_key}"},
            files={"file": (filename, audio_bytes, content_type or "audio/mpeg")},
            data={"model": "whisper-1"},
            timeout=TIMEOUT_SECONDS,
        )
    except requests.exceptions.RequestException as e:
        raise ValueError(f"Could not reach the transcription service: {e}")

    if response.status_code != 200:
        raise ValueError(
            f"Transcription failed (HTTP {response.status_code}). The audio file "
            f"may be an unsupported format, too large, or corrupted."
        )

    transcript = response.json().get("text", "").strip()
    if not transcript:
        raise ValueError("Transcription returned no text -- the audio may be silent or unrecognizable speech.")

    return transcript
