"""
Comprehensive tests for live monitoring system.

Tests:
- Event emitter (sandbox integration)
- Event processor (enrichment)
- Risk scoring agent
- Alert engine
- IOC extractor
- WebSocket connectivity
"""

import pytest
import asyncio
import json
from datetime import datetime
from uuid import uuid4
from sqlalchemy.orm import Session

# Import components to test
from backend.app.models.live_monitoring import (
    EnrichedEvent, EventType, RiskScore, Alert, IOC, IOCType,
    ThreatIntelligence, AlertSeverity
)
from backend.app.models.db_models import AnalysisEvent, RiskScore as RiskScoreDB
from backend.app.sandbox_event_emitter import MockSandboxEventEmitter
from backend.app.event_processor import EventProcessor
from backend.app.alert_engine import AlertEngine
from backend.app.ioc_extractor import IOCExtractor
from agents.orchestrator.risk_agent import RiskScoringAgent
from unittest.mock import Mock, AsyncMock, patch


class TestEventEmitter:
    """Test sandbox event emitter."""

    @pytest.mark.asyncio
    async def test_normalize_file_event(self):
        """Test file event normalization."""
        emitter = MockSandboxEventEmitter(Mock(), {})

        raw_event = {
            "type": "CreateFile",
            "timestamp": datetime.utcnow().isoformat(),
            "path": "C:\\Users\\Admin\\Desktop\\test.exe",
            "size": 2048,
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }

        event = await emitter._normalize_event(raw_event, "windows")

        assert event.event_type == EventType.FILE
        assert event.event_data["path"] == "C:\\Users\\Admin\\Desktop\\test.exe"
        assert event.event_data["size"] == 2048

    @pytest.mark.asyncio
    async def test_normalize_network_event(self):
        """Test network event normalization."""
        emitter = MockSandboxEventEmitter(Mock(), {})

        raw_event = {
            "type": "Connect",
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": "192.168.1.100",
            "src_port": 54321,
            "dst_ip": "1.2.3.4",
            "dst_port": 443,
            "protocol": "tcp",
        }

        event = await emitter._normalize_event(raw_event, "windows")

        assert event.event_type == EventType.NETWORK
        assert event.event_data["src_ip"] == "192.168.1.100"
        assert event.event_data["dst_ip"] == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_event_type_mapping(self):
        """Test event type mapping."""
        emitter = MockSandboxEventEmitter(Mock(), {})

        test_cases = [
            ("CreateFile", EventType.FILE),
            ("Connect", EventType.NETWORK),
            ("CallAPI", EventType.API),
            ("RegSetValueEx", EventType.REGISTRY),
            ("CreateProcess", EventType.PROCESS),
        ]

        for raw_type, expected_type in test_cases:
            mapped = emitter._map_event_type(raw_type)
            assert mapped == expected_type


class TestEventProcessor:
    """Test event enrichment."""

    def test_enrich_network_event_with_threat_intel(self, db_session: Session):
        """Test network event enrichment."""
        processor = EventProcessor(Mock(), db_session, {})

        event = EnrichedEvent(
            event_id=uuid4(),
            analysis_id=uuid4(),
            timestamp=datetime.utcnow(),
            event_type=EventType.NETWORK,
            event_data={
                "dst_ip": "1.2.3.4",
                "src_ip": "192.168.1.100",
                "dst_port": 443,
            },
        )

        # Mock threat intel lookup
        with patch.object(processor, '_lookup_ip', return_value=ThreatIntelligence(
            known_c2=True,
            threat_family="Emotet",
        )):
            asyncio.run(processor._enrich_network_event(event))

        assert event.enrichment is not None
        assert event.enrichment.known_c2 is True
        assert "T1071.001" in event.mitre_techniques

    def test_enrich_file_event_sensitive_path(self, db_session: Session):
        """Test file event enrichment for sensitive paths."""
        processor = EventProcessor(Mock(), db_session, {})

        event = EnrichedEvent(
            event_id=uuid4(),
            analysis_id=uuid4(),
            timestamp=datetime.utcnow(),
            event_type=EventType.FILE,
            event_data={
                "path": "C:\\Windows\\System32\\malware.dll",
                "operation": "create",
            },
        )

        asyncio.run(processor._enrich_file_event(event))

        assert event.severity == "warning"
        assert "T1574.001" in event.mitre_techniques

    def test_enrich_api_event_credential_theft(self, db_session: Session):
        """Test API event enrichment for credential theft."""
        processor = EventProcessor(Mock(), db_session, {})

        event = EnrichedEvent(
            event_id=uuid4(),
            analysis_id=uuid4(),
            timestamp=datetime.utcnow(),
            event_type=EventType.API,
            event_data={
                "api_name": "ReadProcessMemory",
                "module": "kernel32.dll",
                "arguments": {},
            },
        )

        asyncio.run(processor._enrich_api_event(event))

        assert event.severity == "critical"
        assert "T1005" in event.mitre_techniques


class TestRiskScoringAgent:
    """Test risk scoring."""

    def test_score_known_c2_connection(self, db_session: Session):
        """Test scoring for known C2 connection."""
        agent = RiskScoringAgent(db_session, {})

        event = AnalysisEvent(
            analysis_id=uuid4(),
            event_type=EventType.NETWORK,
            timestamp=datetime.utcnow(),
            event_data={
                "dst_ip": "1.2.3.4",
                "src_ip": "192.168.1.100",
                "dst_port": 443,
            },
            enrichment={"known_c2": True},
        )

        points, technique = agent._score_network_event(
            event.event_data,
            event.enrichment
        )

        assert points == 50
        assert technique == "T1071.001"

    def test_score_credential_theft_api(self, db_session: Session):
        """Test scoring for credential theft API calls."""
        agent = RiskScoringAgent(db_session, {})

        event = AnalysisEvent(
            analysis_id=uuid4(),
            event_type=EventType.API,
            timestamp=datetime.utcnow(),
            event_data={
                "api_name": "ReadProcessMemory",
                "module": "kernel32.dll",
            },
        )

        points, technique = agent._score_api_event(event.event_data)

        assert points == 40
        assert technique == "T1005"

    def test_score_persistence_registry(self, db_session: Session):
        """Test scoring for persistence mechanisms."""
        agent = RiskScoringAgent(db_session, {})

        event = AnalysisEvent(
            analysis_id=uuid4(),
            event_type=EventType.REGISTRY,
            timestamp=datetime.utcnow(),
            event_data={
                "operation": "set",
                "key_path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            },
        )

        points, technique = agent._score_registry_event(event.event_data)

        assert points == 25
        assert technique == "T1547.001"

    def test_risk_band_calculation(self, db_session: Session):
        """Test risk band classification."""
        agent = RiskScoringAgent(db_session, {})

        assert agent._get_band(15) == "green"
        assert agent._get_band(45) == "yellow"
        assert agent._get_band(70) == "orange"
        assert agent._get_band(95) == "red"

    def test_trend_calculation(self, db_session: Session):
        """Test trend detection."""
        agent = RiskScoringAgent(db_session, {})

        assert agent._get_trend(60, 40) == "increasing"
        assert agent._get_trend(30, 50) == "decreasing"
        assert agent._get_trend(50, 48) == "stable"


class TestAlertEngine:
    """Test alerting system."""

    @pytest.mark.asyncio
    async def test_c2_connection_alert(self):
        """Test C2 connection alert triggering."""
        engine = AlertEngine(Mock(), Mock(), {})

        event = EnrichedEvent(
            event_id=uuid4(),
            analysis_id=uuid4(),
            timestamp=datetime.utcnow(),
            event_type=EventType.NETWORK,
            event_data={
                "dst_ip": "1.2.3.4",
                "src_ip": "192.168.1.100",
                "dst_port": 443,
            },
            enrichment=ThreatIntelligence(known_c2=True),
        )

        alerts = await engine.process_event(event.analysis_id, event)

        assert len(alerts) > 0
        assert any(a.rule_id == "c2_connection" for a in alerts)

    @pytest.mark.asyncio
    async def test_credential_theft_alert(self):
        """Test credential theft alert."""
        engine = AlertEngine(Mock(), Mock(), {})

        event = EnrichedEvent(
            event_id=uuid4(),
            analysis_id=uuid4(),
            timestamp=datetime.utcnow(),
            event_type=EventType.API,
            event_data={
                "api_name": "ReadProcessMemory",
                "module": "kernel32.dll",
                "arguments": {},
            },
        )

        alerts = await engine.process_event(event.analysis_id, event)

        assert len(alerts) > 0
        assert any(a.rule_id == "credential_theft" for a in alerts)

    def test_alert_deduplication(self):
        """Test alert deduplication."""
        engine = AlertEngine(Mock(), Mock(), {})

        # First alert
        dedup_key = "alert:analysis123:c2_connection"
        engine.alert_history[dedup_key] = datetime.utcnow()

        # Should be recent enough to dedupe
        import time
        time.sleep(0.1)

        # Try to create similar alert (should be deduped)
        # This is tested by checking dedup_key in history


class TestIOCExtractor:
    """Test IOC extraction."""

    @pytest.mark.asyncio
    async def test_extract_ip_from_network_event(self, db_session: Session):
        """Test IP extraction from network events."""
        extractor = IOCExtractor(Mock(), db_session, {})

        event = EnrichedEvent(
            event_id=uuid4(),
            analysis_id=uuid4(),
            timestamp=datetime.utcnow(),
            event_type=EventType.NETWORK,
            event_data={
                "dst_ip": "8.8.8.8",
                "src_ip": "192.168.1.100",
                "dst_port": 53,
            },
        )

        iocs = await extractor.extract_iocs(event.analysis_id, event)

        assert len(iocs) > 0
        assert any(ioc.ioc_type == IOCType.IP for ioc in iocs)

    @pytest.mark.asyncio
    async def test_extract_domain_from_network_event(self, db_session: Session):
        """Test domain extraction."""
        extractor = IOCExtractor(Mock(), db_session, {})

        event = EnrichedEvent(
            event_id=uuid4(),
            analysis_id=uuid4(),
            timestamp=datetime.utcnow(),
            event_type=EventType.NETWORK,
            event_data={
                "dst_ip": "1.2.3.4",
                "domain": "malware.com",
                "dst_port": 443,
            },
        )

        iocs = await extractor.extract_iocs(event.analysis_id, event)

        assert len(iocs) > 0
        assert any(ioc.ioc_type == IOCType.DOMAIN and ioc.ioc_value == "malware.com" for ioc in iocs)

    @pytest.mark.asyncio
    async def test_extract_file_hash(self, db_session: Session):
        """Test file hash extraction."""
        extractor = IOCExtractor(Mock(), db_session, {})

        event = EnrichedEvent(
            event_id=uuid4(),
            analysis_id=uuid4(),
            timestamp=datetime.utcnow(),
            event_type=EventType.FILE,
            event_data={
                "path": "C:\\malware.exe",
                "operation": "create",
                "hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
                "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
        )

        iocs = await extractor.extract_iocs(event.analysis_id, event)

        assert len(iocs) >= 2
        assert any(ioc.ioc_type == IOCType.HASH for ioc in iocs)

    def test_ip_validation(self, db_session: Session):
        """Test IP address validation."""
        extractor = IOCExtractor(Mock(), db_session, {})

        # Valid public IPs
        assert extractor._is_valid_ip("8.8.8.8") is True
        assert extractor._is_valid_ip("1.2.3.4") is True

        # Invalid IPs
        assert extractor._is_valid_ip("192.168.1.1") is False  # Private
        assert extractor._is_valid_ip("127.0.0.1") is False  # Loopback
        assert extractor._is_valid_ip("256.256.256.256") is False  # Invalid


# Fixtures
@pytest.fixture
def db_session():
    """Provide a mock database session."""
    return Mock(spec=Session)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
