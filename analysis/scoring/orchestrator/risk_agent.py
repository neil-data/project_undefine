"""
Risk Scoring Agent — LangGraph node that consumes events and updates risk score.

Integrates with the live monitoring system to provide real-time risk scoring.
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from uuid import UUID
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, desc

from backend.app.models.db_models import AnalysisEvent, RiskScore as RiskScoreDB
from backend.app.models.live_monitoring import (
    RiskScore, RiskScoreBand, SignalBreakdown, EventType
)

_LOGGER = logging.getLogger(__name__)


class RiskScoringRules:
    """Risk scoring rule set."""

    # File operations scoring
    FILE_RULES = {
        "system32_write": {"pattern": "system32", "points": 15, "technique": "T1112"},
        "temp_exe": {"pattern": "temp", "points": 20, "technique": "T1140"},
        "startup_write": {"pattern": "startup", "points": 25, "technique": "T1547"},
        "appdata_exe": {"pattern": "appdata.*\\.exe", "points": 20, "technique": "T1547"},
        "program_files_write": {"pattern": "program files", "points": 15, "technique": "T1574"},
    }

    # Network operations scoring
    NETWORK_RULES = {
        "c2_connection": {"pattern": "known_c2", "points": 50, "technique": "T1071.001"},
        "dns_tunneling": {"pattern": "dns", "points": 30, "technique": "T1071.004"},
        "high_volume_post": {"pattern": "post", "points": 20, "technique": "T1030"},
        "outbound_to_suspicious": {"pattern": "reputation_score", "points": 25, "technique": "T1020"},
    }

    # API call scoring
    API_RULES = {
        "credential_theft": {
            "apis": ["readprocessmemory", "queryregistryvalue", "getclipboarddata"],
            "points": 40,
            "technique": "T1005",
        },
        "screen_capture": {
            "apis": ["bitblt", "getdibits", "createcompatibledc"],
            "points": 35,
            "technique": "T1113",
        },
        "sms_access": {
            "apis": ["querysms", "deletesms", "sendsms"],
            "points": 30,
            "technique": "T1412",
        },
        "gps_location": {
            "apis": ["getlocation", "getgps"],
            "points": 25,
            "technique": "T1418",
        },
        "privilege_escalation": {
            "apis": ["createremotethread", "writeprocessmemory", "setwindowshookex"],
            "points": 45,
            "technique": "T1055",
        },
        "persistence": {
            "apis": ["regsetvalueex", "createservicew", "setfilesecurity"],
            "points": 35,
            "technique": "T1547",
        },
    }

    # Registry operations scoring (Windows)
    REGISTRY_RULES = {
        "run_key_write": {"pattern": "run", "points": 25, "technique": "T1547.001"},
        "software_write": {"pattern": "software", "points": 15, "technique": "T1112"},
        "services_write": {"pattern": "services", "points": 20, "technique": "T1547.001"},
    }


class RiskScoringAgent:
    """LangGraph agent node for real-time risk scoring."""

    def __init__(self, db_session: Session, config: Dict[str, Any]):
        self.db = db_session
        self.config = config
        self.rules = RiskScoringRules()
        # Expose rules directly for test compatibility
        self.API_RULES = self.rules.API_RULES
        self.REGISTRY_RULES = self.rules.REGISTRY_RULES
        self.FILE_RULES = self.rules.FILE_RULES
        self.NETWORK_RULES = self.rules.NETWORK_RULES

    async def score_events(self, analysis_id: UUID, events: List[AnalysisEvent]) -> RiskScore:
        """Score a batch of events and return updated risk score."""

        # Get last risk score
        last_score = await self._get_last_score(analysis_id)
        points = last_score.score if last_score else 0
        signal_breakdown = last_score.signal_breakdown if last_score else SignalBreakdown()

        # Track contributing event IDs
        contributing_events = []

        # Score each event
        for event in events:
            event_points, technique = self._score_event(event)

            if event_points > 0:
                points += event_points
                contributing_events.append(event.id)

                # Update signal breakdown
                self._update_signal_breakdown(signal_breakdown, event, event_points)

        # Apply decay if no new signals
        time_since_last = self._get_time_since_last_score(analysis_id)
        if time_since_last and time_since_last > timedelta(seconds=30):
            decay_factor = 0.98 ** (time_since_last.total_seconds() / 300)  # Decay every 5 minutes
            points = int(points * decay_factor)

        # Clamp score to 0-100
        points = max(0, min(100, points))

        # Determine band and trend
        band = self._get_band(points)
        trend = self._get_trend(points, last_score.score if last_score else 0)

        # Generate reasoning
        reasoning = self._generate_reasoning(signal_breakdown, points, band)

        # Create risk score object
        risk_score = RiskScore(
            analysis_id=analysis_id,
            timestamp=datetime.utcnow(),
            score=points,
            band=band,
            reasoning=reasoning,
            signal_breakdown=signal_breakdown,
            trend=trend,
            contributing_event_ids=[UUID(int=eid) for eid in contributing_events[:10]],  # Top 10
        )

        # Save to database
        await self._save_risk_score(risk_score)

        return risk_score

    def _score_event(self, event: AnalysisEvent) -> tuple[int, Optional[str]]:
        """Score a single event."""
        event_type = event.event_type
        event_data = event.event_data or {}
        points = 0
        technique = None

        if event_type == EventType.FILE:
            points, technique = self._score_file_event(event_data)
        elif event_type == EventType.NETWORK:
            points, technique = self._score_network_event(event_data, event.enrichment)
        elif event_type == EventType.API:
            points, technique = self._score_api_event(event_data)
        elif event_type == EventType.REGISTRY:
            points, technique = self._score_registry_event(event_data)
        elif event_type == EventType.PROCESS:
            points, technique = self._score_process_event(event_data)

        return points, technique

    def _score_file_event(self, event_data: Dict[str, Any]) -> tuple[int, Optional[str]]:
        """Score file operation."""
        path = event_data.get("path", "").lower()
        operation = event_data.get("operation", "").lower()

        # Check against file rules
        for rule_name, rule in self.FILE_RULES.items():
            if rule.get("pattern") in path:
                return rule.get("points", 0), rule.get("technique")

        return 0, None

    def _score_network_event(
        self, event_data: Dict[str, Any], enrichment: Dict[str, Any] = None
    ) -> tuple[int, Optional[str]]:
        """Score network operation."""
        dst_ip = event_data.get("dst_ip", "")
        bytes_sent = event_data.get("bytes_sent", 0)

        # Check if known C2
        if enrichment and enrichment.get("known_c2"):
            return 50, "T1071.001"

        # Check for high-volume transfer
        if bytes_sent > 10_000_000:  # > 10 MB
            return 20, "T1030"

        # Check IP reputation
        if enrichment:
            reputation = enrichment.get("reputation_score", 0)
            if reputation > 70:
                return 25, "T1020"

        return 0, None

    def _score_api_event(self, event_data: Dict[str, Any]) -> tuple[int, Optional[str]]:
        """Score API call."""
        api_name = event_data.get("api_name", "").lower()

        # Check against API rules
        for rule_name, rule in self.API_RULES.items():
            apis = rule.get("apis", [])
            for api in apis:
                if api in api_name:
                    return rule.get("points", 0), rule.get("technique")

        return 0, None

    def _score_registry_event(self, event_data: Dict[str, Any]) -> tuple[int, Optional[str]]:
        """Score registry operation."""
        key_path = event_data.get("key_path", "").lower()

        # Check against registry rules
        for rule_name, rule in self.REGISTRY_RULES.items():
            pattern = rule.get("pattern", "").lower()
            if pattern in key_path:
                return rule.get("points", 0), rule.get("technique")

        return 0, None

    def _score_process_event(self, event_data: Dict[str, Any]) -> tuple[int, Optional[str]]:
        """Score process operation."""
        action = event_data.get("action", "").lower()

        # Privilege escalation
        if "privilege" in action:
            return 45, "T1055"

        # Suspicious process names
        suspicious_names = ["cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe"]
        process_name = event_data.get("process_name", "").lower()
        if any(name in process_name for name in suspicious_names):
            return 20, "T1086"

        return 0, None

    def _update_signal_breakdown(
        self, breakdown: SignalBreakdown, event: AnalysisEvent, points: int
    ):
        """Update signal breakdown."""
        event_type = event.event_type

        if event_type == EventType.FILE:
            key = event.event_data.get("path", "unknown")
            breakdown.files[key] = breakdown.files.get(key, 0) + points

        elif event_type == EventType.NETWORK:
            key = f"{event.event_data.get('dst_ip', 'unknown')}:{event.event_data.get('dst_port', 'unknown')}"
            breakdown.network[key] = breakdown.network.get(key, 0) + points

        elif event_type == EventType.API:
            key = event.event_data.get("api_name", "unknown")
            breakdown.api_calls[key] = breakdown.api_calls.get(key, 0) + points

        elif event_type == EventType.REGISTRY:
            key = event.event_data.get("key_path", "unknown")
            breakdown.registry[key] = breakdown.registry.get(key, 0) + points

        elif event_type == EventType.PROCESS:
            key = event.event_data.get("process_name", "unknown")
            breakdown.process[key] = breakdown.process.get(key, 0) + points

    def _get_band(self, score: int) -> RiskScoreBand:
        """Get risk band for score."""
        if score <= 30:
            return RiskScoreBand.GREEN
        elif score <= 60:
            return RiskScoreBand.YELLOW
        elif score <= 85:
            return RiskScoreBand.ORANGE
        else:
            return RiskScoreBand.RED

    def _get_trend(self, current_score: int, last_score: int) -> str:
        """Determine trend."""
        diff = current_score - last_score

        if diff > 10:
            return "increasing"
        elif diff < -10:
            return "decreasing"
        else:
            return "stable"

    def _generate_reasoning(self, breakdown: SignalBreakdown, score: int, band: RiskScoreBand) -> str:
        """Generate human-readable reasoning for score."""
        reasons = []

        if breakdown.api_calls:
            reasons.append(f"Detected {len(breakdown.api_calls)} suspicious API calls")

        if breakdown.network:
            reasons.append(f"Network activity to {len(breakdown.network)} suspicious destinations")

        if breakdown.files:
            reasons.append(f"File operations in {len(breakdown.files)} sensitive locations")

        if breakdown.registry:
            reasons.append(f"Registry modifications in {len(breakdown.registry)} critical keys")

        # Add band-specific message
        band_messages = {
            RiskScoreBand.GREEN: "No immediate threats detected",
            RiskScoreBand.YELLOW: "Suspicious behavior detected, requires manual review",
            RiskScoreBand.ORANGE: "High-risk behavior detected, recommend investigator review",
            RiskScoreBand.RED: "CRITICAL: Confirmed malicious behavior, recommend sandbox termination",
        }

        base_message = band_messages.get(band, "Risk assessment in progress")

        if reasons:
            return f"{base_message}. {'; '.join(reasons)}"
        else:
            return base_message

    async def _get_last_score(self, analysis_id: UUID) -> Optional[RiskScore]:
        """Get last risk score from database."""
        try:
            stmt = select(RiskScoreDB).where(
                RiskScoreDB.analysis_id == analysis_id
            ).order_by(desc(RiskScoreDB.timestamp)).limit(1)

            result = self.db.execute(stmt).scalar_one_or_none()

            if result:
                return RiskScore(
                    analysis_id=result.analysis_id,
                    timestamp=result.timestamp,
                    score=result.score,
                    band=self._get_band(result.score),
                    reasoning=result.reasoning,
                    signal_breakdown=SignalBreakdown.model_validate(result.signal_breakdown or {}),
                    trend=result.trend or "stable",
                )

            return None

        except Exception as e:
            _LOGGER.error(f"Error getting last score: {e}")
            return None

    def _get_time_since_last_score(self, analysis_id: UUID) -> Optional[timedelta]:
        """Get time since last score."""
        try:
            stmt = select(RiskScoreDB.timestamp).where(
                RiskScoreDB.analysis_id == analysis_id
            ).order_by(desc(RiskScoreDB.timestamp)).limit(1)

            result = self.db.execute(stmt).scalar_one_or_none()

            if result:
                return datetime.utcnow() - result

            return None

        except Exception as e:
            _LOGGER.error(f"Error getting time since last score: {e}")
            return None

    async def _save_risk_score(self, risk_score: RiskScore):
        """Save risk score to database."""
        try:
            db_score = RiskScoreDB(
                analysis_id=risk_score.analysis_id,
                timestamp=risk_score.timestamp,
                score=risk_score.score,
                reasoning=risk_score.reasoning,
                signal_breakdown=risk_score.signal_breakdown.model_dump(),
                trend=risk_score.trend,
                contributing_events=[int(eid) for eid in risk_score.contributing_event_ids],
            )

            self.db.add(db_score)
            self.db.commit()

            _LOGGER.debug(f"Saved risk score {risk_score.score} for {risk_score.analysis_id}")

        except Exception as e:
            _LOGGER.error(f"Error saving risk score: {e}")
            self.db.rollback()
