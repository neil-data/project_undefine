"""
Alert Engine — Real-time rule-based alerting system for live monitoring.

Watches event stream and triggers alerts based on configurable rules.
"""

import logging
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from uuid import UUID, uuid4
from dataclasses import dataclass
import redis.asyncio as redis
from sqlalchemy.orm import Session

from .models.live_monitoring import (
    Alert, AlertSeverity, EnrichedEvent, AlertRule, EventType
)
from .models.db_models import Alert as AlertDB

_LOGGER = logging.getLogger(__name__)


@dataclass
class AlertRuleConfig:
    """Alert rule configuration."""
    rule_id: str
    name: str
    description: str
    severity: AlertSeverity
    trigger_event_types: List[EventType]
    condition_lambda: Callable[[Dict[str, Any]], bool]
    mitre_techniques: List[str]


class AlertEngine:
    """Real-time alert rule processor."""

    def __init__(self, redis_client: redis.Redis, db_session: Session, config: Dict[str, Any]):
        self.redis = redis_client
        self.db = db_session
        self.config = config
        self.rules = self._init_rules()
        self.alert_history: Dict[str, datetime] = {}  # For deduplication

    def _init_rules(self) -> List[AlertRuleConfig]:
        """Initialize alert rules."""
        rules = [
            AlertRuleConfig(
                rule_id="c2_connection",
                name="Known C2 Connection",
                description="Connection to known C2 server",
                severity=AlertSeverity.CRITICAL,
                trigger_event_types=[EventType.NETWORK],
                condition_lambda=lambda e: e.get("enrichment", {}).get("known_c2", False),
                mitre_techniques=["T1071.001"],
            ),
            AlertRuleConfig(
                rule_id="exfil_threshold",
                name="High-Volume Data Exfiltration",
                description="More than 10MB data sent in 1 minute",
                severity=AlertSeverity.WARNING,
                trigger_event_types=[EventType.NETWORK],
                condition_lambda=lambda e: e.get("event_data", {}).get("bytes_sent", 0) > 10_000_000,
                mitre_techniques=["T1030"],
            ),
            AlertRuleConfig(
                rule_id="ransomware_pattern",
                name="Ransomware-Like Behavior",
                description="Mass file operations suggesting ransomware",
                severity=AlertSeverity.CRITICAL,
                trigger_event_types=[EventType.FILE],
                condition_lambda=self._check_ransomware_pattern,
                mitre_techniques=["T1486"],
            ),
            AlertRuleConfig(
                rule_id="credential_theft",
                name="Credential Theft Detected",
                description="API calls indicating credential theft",
                severity=AlertSeverity.CRITICAL,
                trigger_event_types=[EventType.API],
                condition_lambda=lambda e: self._check_credential_theft(e.get("event_data", {})),
                mitre_techniques=["T1005"],
            ),
            AlertRuleConfig(
                rule_id="privilege_escalation",
                name="Privilege Escalation Attempt",
                description="Suspicious privilege elevation patterns",
                severity=AlertSeverity.CRITICAL,
                trigger_event_types=[EventType.API, EventType.PROCESS],
                condition_lambda=lambda e: self._check_privilege_escalation(e.get("event_data", {})),
                mitre_techniques=["T1055", "T1134"],
            ),
            AlertRuleConfig(
                rule_id="screen_capture",
                name="Screen Capture Detected",
                description="Attempts to capture screen content",
                severity=AlertSeverity.WARNING,
                trigger_event_types=[EventType.API],
                condition_lambda=lambda e: self._check_screen_capture(e.get("event_data", {})),
                mitre_techniques=["T1113"],
            ),
            AlertRuleConfig(
                rule_id="persistence_mechanism",
                name="Persistence Mechanism Installed",
                description="Registry/startup modifications for persistence",
                severity=AlertSeverity.WARNING,
                trigger_event_types=[EventType.REGISTRY, EventType.FILE],
                condition_lambda=lambda e: self._check_persistence(e),
                mitre_techniques=["T1547"],
            ),
            AlertRuleConfig(
                rule_id="sms_access",
                name="SMS/SMS Access Detected (Android)",
                description="Unauthorized SMS or message access",
                severity=AlertSeverity.CRITICAL,
                trigger_event_types=[EventType.API],
                condition_lambda=lambda e: self._check_sms_access(e.get("event_data", {})),
                mitre_techniques=["T1412"],
            ),
            AlertRuleConfig(
                rule_id="gps_location_access",
                name="GPS/Location Access (Android)",
                description="Attempt to access device location",
                severity=AlertSeverity.WARNING,
                trigger_event_types=[EventType.API],
                condition_lambda=lambda e: self._check_gps_access(e.get("event_data", {})),
                mitre_techniques=["T1418"],
            ),
        ]

        return rules

    async def process_event(self, analysis_id: UUID, event: EnrichedEvent) -> List[Alert]:
        """Process event against all rules, return triggered alerts."""
        alerts = []

        for rule in self.rules:
            # Check if this rule applies to this event type
            if event.event_type not in rule.trigger_event_types:
                continue

            # Evaluate rule condition
            try:
                event_dict = {
                    "event_type": event.event_type,
                    "event_data": event.event_data,
                    "enrichment": event.enrichment.model_dump() if event.enrichment else {},
                    "mitre_techniques": event.mitre_techniques,
                }

                if rule.condition_lambda(event_dict):
                    # Rule triggered
                    alert = await self._create_alert(
                        analysis_id, rule, event
                    )

                    if alert:
                        alerts.append(alert)

            except Exception as e:
                _LOGGER.error(f"Error evaluating rule {rule.rule_id}: {e}")

        return alerts

    async def _create_alert(
        self, analysis_id: UUID, rule: AlertRuleConfig, event: EnrichedEvent
    ) -> Optional[Alert]:
        """Create and save alert."""
        try:
            # Check for deduplication (same rule within 10 seconds)
            dedup_key = f"alert:{analysis_id}:{rule.rule_id}"

            if dedup_key in self.alert_history:
                last_alert_time = self.alert_history[dedup_key]
                if datetime.utcnow() - last_alert_time < timedelta(seconds=10):
                    _LOGGER.debug(f"Alert deduped: {rule.rule_id}")
                    return None

            # Update dedup history
            self.alert_history[dedup_key] = datetime.utcnow()

            # Create alert object
            alert = Alert(
                alert_id=uuid4(),
                analysis_id=analysis_id,
                rule_id=rule.rule_id,
                timestamp=datetime.utcnow(),
                severity=rule.severity,
                message=rule.description,
                event_id=event.event_id,
                mitre_techniques=rule.mitre_techniques,
            )

            # Save to database
            db_alert = AlertDB(
                analysis_id=alert.analysis_id,
                alert_id=alert.alert_id,
                rule_id=alert.rule_id,
                timestamp=alert.timestamp,
                severity=alert.severity,
                message=alert.message,
                event_id=event.event_id,
                mitre_techniques=alert.mitre_techniques,
            )

            self.db.add(db_alert)
            self.db.commit()

            _LOGGER.info(f"Alert triggered: {rule.rule_id} for {analysis_id}")

            return alert

        except Exception as e:
            _LOGGER.error(f"Error creating alert: {e}")
            self.db.rollback()
            return None

    def _check_credential_theft(self, event_data: Dict[str, Any]) -> bool:
        """Check for credential theft indicators."""
        api_name = event_data.get("api_name", "").lower()
        suspicious_apis = [
            "readprocessmemory",
            "queryregistryvalue",
            "getclipboarddata",
            "dumpmemory",
            "readlsasecrets",
        ]
        return any(api in api_name for api in suspicious_apis)

    def _check_ransomware_pattern(self, event_data: Dict[str, Any]) -> bool:
        """Check for ransomware patterns."""
        # In production, would track file operation counts over time
        # For now, check for specific patterns
        path = event_data.get("path", "").lower()
        operation = event_data.get("operation", "").lower()

        # Mass file operations to user directories
        user_paths = ["documents", "pictures", "desktop", "downloads"]
        return (
            operation in ["delete", "modify"]
            and any(user_path in path for user_path in user_paths)
        )

    def _check_privilege_escalation(self, event_data: Dict[str, Any]) -> bool:
        """Check for privilege escalation."""
        api_name = event_data.get("api_name", "").lower()
        action = event_data.get("action", "").lower()

        escalation_apis = [
            "createremotethread",
            "writeprocessmemory",
            "setwindowshookex",
            "createtoken",
            "impersonateloggedonuser",
        ]

        return (
            any(api in api_name for api in escalation_apis)
            or "privilege" in action
        )

    def _check_screen_capture(self, event_data: Dict[str, Any]) -> bool:
        """Check for screen capture APIs."""
        api_name = event_data.get("api_name", "").lower()
        capture_apis = [
            "bitblt",
            "getdibits",
            "createcompatibledc",
            "screencapture",
            "gethdc",
        ]
        return any(api in api_name for api in capture_apis)

    def _check_persistence(self, event: Any) -> bool:
        """Check for persistence mechanisms (supports both dict and EnrichedEvent)."""
        if isinstance(event, dict):
            event_type = event.get("event_type")
            event_data = event.get("event_data", {})
        else:
            event_type = getattr(event, "event_type", None)
            event_data = getattr(event, "event_data", {}) or {}

        # Normalize EventType enum vs string
        event_type_val = event_type.value if hasattr(event_type, "value") else str(event_type)

        if event_type_val in (EventType.REGISTRY.value, "registry"):
            key_path = str(event_data.get("key_path", "")).lower().replace("/", "\\")
            persistence_keys = [
                "\\run",
                "\\runonce",
                "\\services\\",
                "\\shellexecute",
                "\\userinit",
            ]
            return any(key in key_path for key in persistence_keys)

        elif event_type_val in (EventType.FILE.value, "file"):
            path = str(event_data.get("path", "")).lower().replace("/", "\\")
            startup_paths = [
                "startup",
                "programdata\\microsoft\\windows\\start menu",
                "appdata\\roaming\\microsoft\\windows\\start menu",
            ]
            return any(needle in path for needle in startup_paths)

        return False

    def _check_sms_access(self, event_data: Dict[str, Any]) -> bool:
        """Check for SMS/message access (Android)."""
        api_name = event_data.get("api_name", "").lower()
        sms_apis = [
            "querysms",
            "deletesms",
            "sendsms",
            "getmessages",
            "readmessages",
        ]
        return any(api in api_name for api in sms_apis)

    def _check_gps_access(self, event_data: Dict[str, Any]) -> bool:
        """Check for GPS/location access (Android)."""
        api_name = event_data.get("api_name", "").lower()
        location_apis = [
            "getlocation",
            "getgps",
            "getlastknownlocation",
            "requestlocationupdates",
        ]
        return any(api in api_name for api in location_apis)

    async def dismiss_alert(self, alert_id: UUID, user_id: str):
        """Dismiss an alert."""
        try:
            stmt = select(AlertDB).where(AlertDB.alert_id == alert_id)
            db_alert = self.db.execute(stmt).scalar_one_or_none()

            if db_alert:
                db_alert.dismissed = True
                db_alert.dismissed_by = user_id
                db_alert.dismissed_at = datetime.utcnow()
                self.db.commit()

        except Exception as e:
            _LOGGER.error(f"Error dismissing alert: {e}")
            self.db.rollback()


# Import at bottom to avoid circular dependency
from sqlalchemy import select
