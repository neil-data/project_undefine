"""
backend/app/routers/health.py — Health check endpoint.

Public (no auth) — this is what the dashboard's "SANDBOX ONLINE"
status pill polls, and what the GCP load balancer / uptime monitor
would hit too.
"""

import os
from fastapi import APIRouter
from .. import db
from ..models.api_models import HealthResponse

router = APIRouter(prefix="/api/health", tags=["health"])

APP_VERSION = "0.1.0-alpha"


@router.get("", response_model=HealthResponse)
def health_check():
    sandbox_configured = bool(
        os.environ.get("SANDBOX_API_URL")
        or os.environ.get("CAPE_API_URL")
        or os.environ.get("HYBRID_ANALYSIS_API_KEY")
    )
    
    return HealthResponse(
        status="ok",
        sandbox_online=sandbox_configured,  # Wire to real GCP sandbox status via environment configuration
        version=APP_VERSION,
        database_online=db.is_available(),
    )