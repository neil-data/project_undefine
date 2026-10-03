"""
Network Intelligence API Router

Provides REST endpoints for network intelligence analysis:
- Start/stop network capture and analysis
- Query analysis results
- Get network statistics
- Retrieve extracted IOCs from network traffic
"""

import logging
from typing import Optional, Dict, Any
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..network_intelligence import NetworkIntelligenceOrchestrator
from ..models.db_models import NetworkAnalysisResult

_LOGGER = logging.getLogger(__name__)

router = APIRouter(prefix="/api/network-intelligence", tags=["network-intelligence"])

# Global orchestrator instances (keyed by analysis_id)
_active_orchestrators: Dict[UUID, NetworkIntelligenceOrchestrator] = {}


class StartAnalysisRequest(BaseModel):
    """Request to start network intelligence analysis."""

    interface: Optional[str] = Field(None, description="Network interface for live capture")
    pcap_file: Optional[str] = Field(None, description="Path to PCAP file for offline analysis")
    filter_expression: Optional[str] = Field(None, description="BPF filter expression")
    duration: Optional[int] = Field(None, description="Duration in seconds for live capture")


class AnalysisStatusResponse(BaseModel):
    """Response with analysis status."""

    analysis_id: str
    is_running: bool
    processed_packets: int
    capture_stats: Dict[str, Any]


class AnalysisResultsResponse(BaseModel):
    """Response with analysis results."""

    analysis_id: str
    timestamp: str
    total_packets_processed: int
    dns_data: Optional[Dict[str, Any]] = None
    http_data: Optional[Dict[str, Any]] = None
    https_data: Optional[Dict[str, Any]] = None
    tcp_data: Optional[Dict[str, Any]] = None
    udp_data: Optional[Dict[str, Any]] = None
    tls_data: Optional[Dict[str, Any]] = None
    capture_stats: Optional[Dict[str, Any]] = None


@router.post("/start", response_model=Dict[str, str])
async def start_analysis(
    request: StartAnalysisRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Start network intelligence analysis.

    Supports both live capture from network interfaces and offline analysis of PCAP files.
    """
    import redis.asyncio as redis
    from ..main import get_redis

    # Validate request
    if not request.interface and not request.pcap_file:
        raise HTTPException(
            status_code=400,
            detail="Either 'interface' or 'pcap_file' must be provided"
        )

    # Get Redis client
    redis_client = await get_redis()

    # Load configuration from environment variables
    import os
    config = {
        "capture_interface": os.environ.get("NETWORK_CAPTURE_INTERFACE", "eth0"),
        "max_capture_size_mb": int(os.environ.get("MAX_CAPTURE_SIZE_MB", "100")),
        "enable_dns_analysis": os.environ.get("ENABLE_DNS_ANALYSIS", "true").lower() == "true",
        "enable_http_analysis": os.environ.get("ENABLE_HTTP_ANALYSIS", "true").lower() == "true",
        "threat_intel_enabled": os.environ.get("THREAT_INTEL_ENABLED", "true").lower() == "true",
        "virustotal_api_key": os.environ.get("VIRUSTOTAL_API_KEY", ""),
        "abuseipdb_api_key": os.environ.get("ABUSEIPDB_API_KEY", ""),
    }

    # Create orchestrator
    orchestrator = NetworkIntelligenceOrchestrator(
        redis_client=redis_client,
        db_session=db,
        config=config,  # Load from app config
    )

    # Store orchestrator
    _active_orchestrators[orchestrator.analysis_id] = orchestrator

    # Start analysis in background
    async def run_analysis():
        try:
            await orchestrator.start_analysis(
                interface=request.interface,
                pcap_file=request.pcap_file,
                filter_expression=request.filter_expression,
                duration=request.duration,
            )
        finally:
            # Clean up orchestrator when done
            if orchestrator.analysis_id in _active_orchestrators:
                del _active_orchestrators[orchestrator.analysis_id]

    background_tasks.add_task(run_analysis)

    return {
        "analysis_id": str(orchestrator.analysis_id),
        "status": "started",
        "message": "Network intelligence analysis started",
    }


@router.post("/stop/{analysis_id}", response_model=Dict[str, str])
async def stop_analysis(analysis_id: UUID):
    """
    Stop a running network intelligence analysis.
    """
    orchestrator = _active_orchestrators.get(analysis_id)
    if not orchestrator:
        raise HTTPException(status_code=404, detail="Analysis not found or already completed")

    orchestrator.stop_analysis()

    return {
        "analysis_id": str(analysis_id),
        "status": "stopped",
        "message": "Network intelligence analysis stopped",
    }


@router.get("/status/{analysis_id}", response_model=AnalysisStatusResponse)
async def get_analysis_status(analysis_id: UUID):
    """
    Get the status of a running network intelligence analysis.
    """
    orchestrator = _active_orchestrators.get(analysis_id)
    if not orchestrator:
        raise HTTPException(status_code=404, detail="Analysis not found or already completed")

    status = orchestrator.get_status()

    return AnalysisStatusResponse(
        analysis_id=str(status["analysis_id"]),
        is_running=status["is_running"],
        processed_packets=status["processed_packets"],
        capture_stats=status["capture_stats"],
    )


@router.get("/results/{analysis_id}", response_model=AnalysisResultsResponse)
async def get_analysis_results(analysis_id: UUID, db: Session = Depends(get_db)):
    """
    Get the results of a completed network intelligence analysis.
    """
    # Query from database
    stmt = select(NetworkAnalysisResult).where(
        NetworkAnalysisResult.analysis_id == analysis_id
    )
    result = db.execute(stmt).scalar_one_or_none()

    if not result:
        raise HTTPException(status_code=404, detail="Analysis results not found")

    return AnalysisResultsResponse(
        analysis_id=str(result.analysis_id),
        timestamp=result.timestamp.isoformat(),
        total_packets_processed=result.total_packets_processed,
        dns_data=result.dns_data,
        http_data=result.http_data,
        https_data=result.https_data,
        tcp_data=result.tcp_data,
        udp_data=result.udp_data,
        tls_data=result.tls_data,
        capture_stats=result.capture_stats,
    )


@router.get("/interfaces")
async def list_interfaces():
    """
    List available network interfaces for live capture.
    """
    from ..network_intelligence.capture import PacketCapture

    interfaces = PacketCapture.list_interfaces()

    return {
        "interfaces": interfaces,
    }


@router.post("/validate-pcap")
async def validate_pcap(pcap_file: str):
    """
    Validate if a PCAP file can be read.
    """
    from ..network_intelligence.capture import PacketCapture

    is_valid = PacketCapture.validate_pcap_file(pcap_file)

    return {
        "pcap_file": pcap_file,
        "is_valid": is_valid,
    }


@router.get("/active-analyses")
async def list_active_analyses():
    """
    List all currently running network intelligence analyses.
    """
    return {
        "active_analyses": [
            {
                "analysis_id": str(analysis_id),
                "status": orchestrator.get_status(),
            }
            for analysis_id, orchestrator in _active_orchestrators.items()
        ],
    }
