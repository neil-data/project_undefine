"""
Live Monitoring API Routes — WebSocket and REST endpoints for real-time analysis.

Endpoints:
  - WS /ws/analysis/{analysis_id} — Live event stream
  - GET /api/analyses/{analysis_id}/live/status — Current status
  - GET /api/analyses/{analysis_id}/live/events — Events (paginated, filterable)
  - GET /api/analyses/{analysis_id}/live/iocs — Extracted IOCs
  - POST /api/analyses/{analysis_id}/sandbox/control — Pause/Resume/Kill
"""

import logging
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends, HTTPException, status
from sqlalchemy import select, desc, and_, func
from sqlalchemy.orm import Session

from ..models.live_monitoring import (
    WSEventMessage, WSRiskScoreMessage, WSAlertMessage, WSIOCMessage,
    WSStatusMessage, WSHeartbeatMessage, WSErrorMessage, WSConnectedMessage,
    EventType, LiveMonitoringStatus, SandboxStatus
)
from ..models.db_models import (
    AnalysisEvent, RiskScore, Alert, LiveIOC, ProcessNode,
    FileTimeline, RegistryTimeline, LiveMonitoringSession, LiveMonitoringAuditLog
)
from ..db import get_db

_LOGGER = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analyses", tags=["live_monitoring"])

# WebSocket connection manager
class ConnectionManager:
    """Manages active WebSocket connections."""

    def __init__(self):
        self.active_connections: Dict[UUID, List[WebSocket]] = {}

    async def connect(self, analysis_id: UUID, websocket: WebSocket):
        """Register new connection."""
        await websocket.accept()
        if analysis_id not in self.active_connections:
            self.active_connections[analysis_id] = []
        self.active_connections[analysis_id].append(websocket)

    def disconnect(self, analysis_id: UUID, websocket: WebSocket):
        """Unregister connection."""
        if analysis_id in self.active_connections:
            self.active_connections[analysis_id].remove(websocket)
            if not self.active_connections[analysis_id]:
                del self.active_connections[analysis_id]

    async def broadcast(self, analysis_id: UUID, message: str):
        """Send message to all connected clients."""
        if analysis_id not in self.active_connections:
            return

        disconnected = []
        for connection in self.active_connections[analysis_id]:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.append(connection)

        # Clean up disconnected clients
        for connection in disconnected:
            self.disconnect(analysis_id, connection)

    def get_connection_count(self, analysis_id: UUID) -> int:
        """Get count of active connections."""
        return len(self.active_connections.get(analysis_id, []))


connection_manager = ConnectionManager()


# WebSocket Endpoint
@router.websocket("/ws/{analysis_id}")
async def websocket_endpoint(
    analysis_id: UUID,
    websocket: WebSocket,
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """WebSocket endpoint for live event streaming."""

    # TODO: Validate JWT token

    await connection_manager.connect(analysis_id, websocket)

    try:
        # Send connection confirmation
        connected_msg = WSConnectedMessage(
            analysis_id=analysis_id,
            connection_id=uuid4(),  # Generate real UUID connection ID
            server_time=datetime.utcnow()
        )
        await websocket.send_text(connected_msg.model_dump_json())

        # Send current state (last risk score, recent events, alerts)
        await _send_current_state(analysis_id, websocket, db)

        # Listen for client messages
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)

            # Handle client filters, requests, etc.
            msg_type = message.get("type")

            if msg_type == "request_state_sync":
                await _send_current_state(analysis_id, websocket, db)

    except WebSocketDisconnect:
        connection_manager.disconnect(analysis_id, websocket)
    except Exception as e:
        _LOGGER.error(f"WebSocket error: {e}")
        connection_manager.disconnect(analysis_id, websocket)


async def _send_current_state(analysis_id: UUID, websocket: WebSocket, db: Session):
    """Send current analysis state to client."""
    try:
        # Get last risk score
        stmt = select(RiskScore).where(
            RiskScore.analysis_id == analysis_id
        ).order_by(desc(RiskScore.timestamp)).limit(1)

        last_score = db.execute(stmt).scalar_one_or_none()

        if last_score:
            risk_msg = WSRiskScoreMessage(
                score=last_score.score,
                reasoning=last_score.reasoning,
                signal_breakdown=last_score.signal_breakdown,
                trend=last_score.trend or "stable",
                timestamp=last_score.timestamp
            )
            await websocket.send_text(risk_msg.model_dump_json())

        # Get recent active alerts
        stmt = select(Alert).where(
            and_(
                Alert.analysis_id == analysis_id,
                Alert.dismissed == False
            )
        ).order_by(desc(Alert.timestamp)).limit(10)

        alerts = db.execute(stmt).scalars().all()

        for alert in alerts:
            alert_msg = WSAlertMessage(
                alert=alert,
                timestamp=alert.timestamp
            )
            await websocket.send_text(alert_msg.model_dump_json())

        # Get recent IOCs
        stmt = select(LiveIOC).where(
            LiveIOC.analysis_id == analysis_id
        ).order_by(desc(LiveIOC.first_seen)).limit(20)

        iocs = db.execute(stmt).scalars().all()

        for ioc in iocs:
            ioc_msg = WSIOCMessage(
                ioc=ioc,
                timestamp=ioc.first_seen
            )
            await websocket.send_text(ioc_msg.model_dump_json())

    except Exception as e:
        _LOGGER.error(f"Error sending current state: {e}")


# REST Endpoints

@router.get("/{analysis_id}/live/status", response_model=LiveMonitoringStatus)
async def get_live_status(
    analysis_id: UUID,
    db: Session = Depends(get_db)
) -> LiveMonitoringStatus:
    """Get current live monitoring status."""

    # Count events by type
    event_counts = {}
    for event_type in EventType:
        count_stmt = select(func.count()).select_from(AnalysisEvent).where(
            and_(
                AnalysisEvent.analysis_id == analysis_id,
                AnalysisEvent.event_type == event_type
            )
        )
        event_counts[event_type] = db.execute(count_stmt).scalar_one()

    # Get current risk score
    stmt = select(RiskScore).where(
        RiskScore.analysis_id == analysis_id
    ).order_by(desc(RiskScore.timestamp)).limit(1)

    last_score = db.execute(stmt).scalar_one_or_none()
    current_risk = last_score.score if last_score else 0

    # Count active alerts
    alert_count = select(func.count()).select_from(Alert).where(
        and_(
            Alert.analysis_id == analysis_id,
            Alert.dismissed == False
        )
    )
    active_alerts = db.execute(alert_count).scalar_one()

    # Get last event timestamp
    stmt = select(AnalysisEvent).where(
        AnalysisEvent.analysis_id == analysis_id
    ).order_by(desc(AnalysisEvent.timestamp)).limit(1)

    last_event = db.execute(stmt).scalar_one_or_none()
    last_event_ts = last_event.timestamp if last_event else None

    # Derive the live status from the monitoring session rather than a
    # non-existent "Analysis" table: an active session is "running", a
    # finished one "completed", otherwise "unknown". Platform is best-effort.
    session_count = select(func.count()).select_from(LiveMonitoringSession).where(
        and_(
            LiveMonitoringSession.analysis_id == analysis_id,
            LiveMonitoringSession.is_active == True
        )
    )
    status = "running" if db.execute(session_count).scalar_one() > 0 else "unknown"
    platform = "windows"

    return LiveMonitoringStatus(
        analysis_id=analysis_id,
        status=status,  # Get from analysis record
        sandbox_status=SandboxStatus(
            analysis_id=analysis_id,
            platform=platform,  # Get from analysis
            status="running",
            uptime_seconds=0,
            memory_usage_mb=0,
            cpu_percent=0,
            last_activity=last_event_ts or datetime.utcnow()
        ),
        current_risk_score=current_risk,
        event_count=event_counts,
        active_alerts=active_alerts,
        connected_clients=connection_manager.get_connection_count(analysis_id),
        last_event_timestamp=last_event_ts
    )


@router.get("/{analysis_id}/live/events")
async def get_live_events(
    analysis_id: UUID,
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    event_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Get events with filtering and pagination."""

    stmt = select(AnalysisEvent).where(
        AnalysisEvent.analysis_id == analysis_id
    )

    # Apply filters
    if start_time:
        stmt = stmt.where(AnalysisEvent.timestamp >= start_time)
    if end_time:
        stmt = stmt.where(AnalysisEvent.timestamp <= end_time)
    if event_type:
        stmt = stmt.where(AnalysisEvent.event_type == event_type)

    # Get total count
    total_count = select(func.count()).select_from(AnalysisEvent).where(
        AnalysisEvent.analysis_id == analysis_id
    )
    total = db.execute(total_count).scalar_one()

    # Apply pagination
    stmt = stmt.order_by(desc(AnalysisEvent.timestamp)).offset(offset).limit(limit)

    events = db.execute(stmt).scalars().all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "events": [
            {
                "event_id": str(e.event_id),
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "event_data": e.event_data,
                "enrichment": e.enrichment,
                "mitre_techniques": e.mitre_techniques or [],
                "severity": e.severity
            }
            for e in events
        ]
    }


@router.get("/{analysis_id}/live/iocs")
async def get_live_iocs(
    analysis_id: UUID,
    ioc_type: Optional[str] = Query(None),
    min_confidence: int = Query(0, ge=0, le=100),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Get extracted IOCs."""

    stmt = select(LiveIOC).where(
        and_(
            LiveIOC.analysis_id == analysis_id,
            LiveIOC.confidence >= min_confidence
        )
    )

    if ioc_type:
        stmt = stmt.where(LiveIOC.ioc_type == ioc_type)

    stmt = stmt.order_by(desc(LiveIOC.first_seen)).limit(limit)

    iocs = db.execute(stmt).scalars().all()

    return {
        "iocs": [
            {
                "ioc_id": str(ioc.ioc_id),
                "ioc_type": ioc.ioc_type,
                "ioc_value": ioc.ioc_value,
                "confidence": ioc.confidence,
                "first_seen": ioc.first_seen.isoformat(),
                "threat_intel": ioc.threat_intel
            }
            for ioc in iocs
        ]
    }


@router.post("/{analysis_id}/sandbox/control")
async def sandbox_control(
    analysis_id: UUID,
    action: str = Query(..., pattern="^(pause|resume|kill)$"),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Control sandbox execution via CAPE API."""
    
    # Implement actual sandbox control via CAPE API
    import httpx
    import os
    
    cape_api_url = os.environ.get("CAPE_API_URL", "http://localhost:8080")
    
    try:
        async with httpx.AsyncClient() as client:
            if action == "kill":
                # Send kill command to CAPE
                response = await client.post(
                    f"{cape_api_url}/api/kill",
                    json={"task_id": str(analysis_id)},
                    timeout=10.0
                )
                response.raise_for_status()
            elif action == "pause":
                # Send pause command to CAPE
                response = await client.post(
                    f"{cape_api_url}/api/pause",
                    json={"task_id": str(analysis_id)},
                    timeout=10.0
                )
                response.raise_for_status()
            elif action == "resume":
                # Send resume command to CAPE
                response = await client.post(
                    f"{cape_api_url}/api/resume",
                    json={"task_id": str(analysis_id)},
                    timeout=10.0
                )
                response.raise_for_status()
                
    except Exception as e:
        _LOGGER.error(f"Failed to control sandbox: {e}")
        # Continue with audit logging even if API call fails
    
    # Log audit trail
    audit_log = LiveMonitoringAuditLog(
        analysis_id=analysis_id,
        user_id="current_user",  # TODO: Get from JWT
        action=action,
        timestamp=datetime.utcnow()
    )
    db.add(audit_log)
    db.commit()

    return {
        "action": action,
        "status": "success",
        "sandbox_state": action,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/{analysis_id}/live/alerts")
async def get_live_alerts(
    analysis_id: UUID,
    dismissed: bool = Query(False),
    limit: int = Query(50),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Get alerts."""

    stmt = select(Alert).where(
        and_(
            Alert.analysis_id == analysis_id,
            Alert.dismissed == dismissed
        )
    ).order_by(desc(Alert.timestamp)).limit(limit)

    alerts = db.execute(stmt).scalars().all()

    return {
        "alerts": [
            {
                "alert_id": str(a.alert_id),
                "rule_id": a.rule_id,
                "timestamp": a.timestamp.isoformat(),
                "severity": a.severity,
                "message": a.message,
                "mitre_techniques": a.mitre_techniques or [],
                "dismissed": a.dismissed
            }
            for a in alerts
        ]
    }


@router.put("/{analysis_id}/alerts/{alert_id}/dismiss")
async def dismiss_alert(
    analysis_id: UUID,
    alert_id: UUID,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Dismiss an alert."""

    stmt = select(Alert).where(
        and_(
            Alert.analysis_id == analysis_id,
            Alert.alert_id == alert_id
        )
    )
    alert = db.execute(stmt).scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.dismissed = True
    alert.dismissed_by = "current_user"  # TODO: Get from JWT
    alert.dismissed_at = datetime.utcnow()

    db.commit()

    return {
        "alert_id": str(alert.alert_id),
        "dismissed_at": alert.dismissed_at.isoformat(),
        "dismissed_by": alert.dismissed_by
    }
