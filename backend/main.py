"""
main.py

The web API for PhishyMax's custom frontend. Thin wrapper around
core.py -- no detection logic lives here.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import asdict

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from core import (
    check_email_detailed,
    check_email_file_detailed,
    check_email_image_detailed,
    check_sms_text_detailed,
    check_sms_image_detailed,
    check_qr_image_detailed,
)

app = FastAPI(title="PhishyMax API")

ALLOWED_ORIGINS = [
    "https://phishy-max.onrender.com",
    "https://phishymax.com",
    "https://www.phishymax.com",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

MAX_CHECKS_PER_WINDOW = 5
WINDOW_SECONDS = 24 * 60 * 60

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
    data = asdict(verdict)
    data["technical_details"] = {
        "sender_name": heuristics_result.sender_name,
        "sender_email": heuristics_result.sender_email,
        "urls_found": heuristics_result.urls_found,
        "auth_results": heuristics_result.auth_results,
    }
    return data


@app.get("/health")
def health() -> dict:
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


@app.post("/api/check-image")
async def api_check_image(request: Request, file: UploadFile = File(...)) -> dict:
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    image_bytes = await file.read()
    media_type = file.content_type or "image/png"
    try:
        verdict, heuristics_result = check_email_image_detailed(image_bytes, media_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")
    return _build_response(verdict, heuristics_result)


@app.post("/api/check-sms-text")
def api_check_sms_text(request: Request, sms_text: str = Form(...)) -> dict:
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    try:
        verdict, heuristics_result = check_sms_text_detailed(sms_text)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")
    return _build_response(verdict, heuristics_result)


@app.post("/api/check-sms-image")
async def api_check_sms_image(request: Request, file: UploadFile = File(...)) -> dict:
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    image_bytes = await file.read()
    media_type = file.content_type or "image/png"
    try:
        verdict, heuristics_result = check_sms_image_detailed(image_bytes, media_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")
    return _build_response(verdict, heuristics_result)


@app.post("/api/check-qr-image")
async def api_check_qr_image(request: Request, file: UploadFile = File(...)) -> dict:
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    image_bytes = await file.read()
    try:
        verdict, heuristics_result = check_qr_image_detailed(image_bytes)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")
    return _build_response(verdict, heuristics_result)
