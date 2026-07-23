"""
main.py

The web API for the phishing checker's new custom frontend. This is a
thin wrapper -- it doesn't contain any detection logic itself, it just
exposes the existing core.py functions (heuristics + LLM analysis,
completely unchanged) over HTTP, so a separately-hosted HTML/CSS/JS
frontend can call them.

Run locally with: uvicorn main:app --reload
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import asdict

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from core import check_email_detailed, check_email_file_detailed


app = FastAPI(title="Phishy Max API")

# CORS lets our frontend (hosted on a different domain than this API)
# make requests to it at all -- browsers block cross-origin requests by
# default unless the server explicitly allows them. Since this API has no
# accounts or sensitive mutating actions (it only analyzes text/files you
# send it), allowing any origin is a reasonable choice for now.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
# Streamlit's st.session_state doesn't exist here -- there's no browser
# session concept at all in a plain HTML/JS + API architecture. Instead we
# track requests by IP address, in memory, within a rolling time window.
# Same honest limitation as before: not bulletproof (shared IPs, and this
# resets if the server restarts/redeploys), but a reasonable, lightweight
# guard against casual abuse -- consistent with how soft our original
# per-session limit already was.
MAX_CHECKS_PER_WINDOW = 10
WINDOW_SECONDS = 24 * 60 * 60  # 24 hours

_request_log: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(ip: str) -> None:
    now = time.time()
    recent = [t for t in _request_log[ip] if now - t < WINDOW_SECONDS]
    _request_log[ip] = recent

    if len(recent) >= MAX_CHECKS_PER_WINDOW:
        raise HTTPException(
            status_code=429,
            detail=f"You've used all {MAX_CHECKS_PER_WINDOW} checks allowed per day. Please try again later.",
        )

    _request_log[ip].append(now)


def _build_response(verdict, heuristics_result) -> dict:
    """Combines the verdict (what the user sees by default) with the raw
    heuristics facts (sender info, URLs, auth results) under a separate
    'technical_details' key -- the frontend shows this only when someone
    expands the optional details section, keeping the default view simple."""
    data = asdict(verdict)
    data["technical_details"] = {
        "sender_name": heuristics_result.sender_name,
        "sender_email": heuristics_result.sender_email,
        "urls_found": heuristics_result.urls_found,
        "auth_results": heuristics_result.auth_results,
    }
    return data


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict:
    """Simple endpoint to confirm the API is running -- useful for checking
    deployment status, and for the frontend to verify connectivity."""
    return {"status": "ok"}


@app.post("/api/check-text")
def api_check_text(request: Request, email_text: str = Form(...)) -> dict:
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    try:
        verdict, heuristics_result = check_email_detailed(email_text)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")

    return _build_response(verdict, heuristics_result)


@app.post("/api/check-file")
async def api_check_file(request: Request, file: UploadFile = File(...)) -> dict:
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    raw_bytes = await file.read()

    try:
        verdict, heuristics_result = check_email_file_detailed(raw_bytes)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")

    return _build_response(verdict, heuristics_result)
