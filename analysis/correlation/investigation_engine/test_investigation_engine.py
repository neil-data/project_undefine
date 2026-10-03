"""
test_investigation_engine.py — Tests for Phase 10 AI Investigation Engine.
"""

import pytest
from datetime import datetime
from agents.investigation_engine.investigation_schema import (
    InvestigationState,
    TimelineEvent,
    MalwareExplanation,
    VictimImpact,
    ExfiltrationAnalysis,
    Recommendation,
    InvestigationSummary,
)
from agents.investigation_engine.investigation_engine import InvestigationEngine, run_investigation_workflow


@pytest.fixture
def sample_investigation_state():
    """Sample investigation state for testing."""
    return {
        "sample_id": "test_sample_001",
        "static_output": {
            "sha256": "a" * 64,
            "platform": "android",
            "file_type": "apk",
            "yara_matches": [
                {
                    "rule_name": "android_spyware",
                    "category": "spyware",
                    "severity": "high",
                    "description": "Known Android spyware signature"
                }
            ],
            "extracted_strings": {
                "urls": ["http://malicious-server.com"],
                "ips": ["192.168.1.100"],
                "suspicious_keywords": ["password", "login", "steal"]
            }
        },
        "dynamic_output": {
            "process_tree": [
                {"name": "malware.exe", "pid": 1234}
            ],
            "network_connections": [
                {
                    "dest_ip": "192.168.1.100",
                    "dest_port": 443,
                    "protocol": "https",
                    "flagged_c2": True,
                    "interval_seconds": 60
                }
            ],
            "files_written": ["/data/data/malware/cache.dat"],
            "registry_changes": [],
            "api_calls": ["CryptEncrypt", "InternetConnect"]
        },
        "mitre_techniques": [
            {"technique_id": "T1112", "technique_name": "Modify Registry", "confidence": 0.8},
            {"technique_id": "T1055", "technique_name": "Process Injection", "confidence": 0.9}
        ],
        "capability_tags": [
            {"capability": "sms_theft", "confidence": 0.85, "evidence": ["READ_SMS permission"]},
            {"capability": "gps_tracking", "confidence": 0.75, "evidence": ["ACCESS_FINE_LOCATION permission"]},
            {"capability": "keylogging", "confidence": 0.7, "evidence": ["keyboard hook API"]}
        ],
        "risk_score": 75,
    }


class TestInvestigationEngine:
    """Test suite for InvestigationEngine."""
    
    def test_load_all_evidence(self, sample_investigation_state):
        """Test that evidence is loaded correctly."""
        engine = InvestigationEngine()
        state = engine._load_all_evidence(sample_investigation_state)
        
        assert state["sample_id"] == "test_sample_001"
        assert state["static_output"] is not None
        assert state["dynamic_output"] is not None
        assert len(state["mitre_techniques"]) == 2
        assert len(state["capability_tags"]) == 3
    
    def test_generate_timeline(self, sample_investigation_state):
        """Test timeline generation."""
        engine = InvestigationEngine()
        state = engine._generate_timeline(sample_investigation_state)
        
        assert "timeline_events" in state
        assert len(state["timeline_events"]) > 0
        
        # Check that we have different event types
        event_types = set(event.event_type for event in state["timeline_events"])
        assert "static" in event_types
        assert "network" in event_types
        assert "file" in event_types
        
        # Check that critical events are marked correctly
        critical_events = [e for e in state["timeline_events"] if e.severity == "critical"]
        assert len(critical_events) > 0  # C2 connection should be critical
    
    def test_explain_malware(self, sample_investigation_state):
        """Test malware explanation generation."""
        engine = InvestigationEngine()
        state = engine._explain_malware(sample_investigation_state)
        
        assert "malware_explanation" in state
        assert state["malware_explanation"] is not None
        
        explanation = state["malware_explanation"]
        assert explanation.summary is not None
        assert explanation.technical_details is not None
        assert len(explanation.capabilities_identified) > 0
        assert 0 <= explanation.confidence_level <= 1
    
    def test_explain_victim_impact(self, sample_investigation_state):
        """Test victim impact analysis."""
        engine = InvestigationEngine()
        state = engine._explain_victim_impact(sample_investigation_state)
        
        assert "victim_impact" in state
        assert state["victim_impact"] is not None
        
        impact = state["victim_impact"]
        assert impact.overall_impact in ["low", "medium", "high", "critical"]
        assert impact.explanation is not None
        
        # With SMS theft and GPS tracking, should be at least medium
        assert impact.overall_impact in ["medium", "high", "critical"]
    
    def test_explain_exfiltration(self, sample_investigation_state):
        """Test exfiltration analysis."""
        engine = InvestigationEngine()
        state = engine._explain_exfiltration(sample_investigation_state)
        
        assert "exfiltration_analysis" in state
        assert state["exfiltration_analysis"] is not None
        
        exfil = state["exfiltration_analysis"]
        assert exfil.data_types is not None
        assert exfil.destinations is not None
        assert exfil.risk_assessment in ["Low", "Medium", "High", "Critical"]
        
        # Should have detected C2 connection
        assert len(exfil.destinations) > 0
    
    def test_generate_recommendations(self, sample_investigation_state):
        """Test recommendation generation."""
        engine = InvestigationEngine()
        state = engine._generate_recommendations(sample_investigation_state)
        
        assert "recommendations" in state
        assert len(state["recommendations"]) > 0
        
        # Check that recommendations are sorted by priority
        priorities = [r.priority for r in state["recommendations"]]
        priority_order = {"immediate": 0, "high": 1, "medium": 2, "low": 3}
        sorted_priorities = sorted(priorities, key=lambda p: priority_order.get(p, 99))
        assert priorities == sorted_priorities
        
        # Check that we have different categories
        categories = set(r.category for r in state["recommendations"])
        assert len(categories) > 0
    
    def test_generate_summary(self, sample_investigation_state):
        """Test final summary generation."""
        engine = InvestigationEngine()
        
        # First ensure we have all required data
        state = engine._generate_timeline(sample_investigation_state)
        state = engine._explain_victim_impact(state)
        state = engine._explain_exfiltration(state)
        state = engine._generate_recommendations(state)
        
        state = engine._generate_summary(state)
        
        assert "investigation_summary" in state
        assert state["investigation_summary"] is not None
        
        summary = state["investigation_summary"]
        assert summary.executive_summary is not None
        assert len(summary.key_findings) > 0
        assert summary.timeline_summary is not None
        assert summary.risk_assessment is not None
        assert len(summary.next_steps) > 0
    
    def test_full_investigation_workflow(self, sample_investigation_state):
        """Test the complete investigation workflow."""
        engine = InvestigationEngine()
        final_state = engine.run_investigation(sample_investigation_state)
        
        # Check all components are present
        assert "timeline_events" in final_state
        assert "malware_explanation" in final_state
        assert "victim_impact" in final_state
        assert "exfiltration_analysis" in final_state
        assert "recommendations" in final_state
        assert "investigation_summary" in final_state
        
        # Verify data integrity
        assert len(final_state["timeline_events"]) > 0
        assert final_state["malware_explanation"] is not None
        assert final_state["victim_impact"] is not None
        assert final_state["exfiltration_analysis"] is not None
        assert len(final_state["recommendations"]) > 0
        assert final_state["investigation_summary"] is not None
    
    def test_investigation_without_dynamic_data(self):
        """Test investigation with only static data."""
        state = {
            "sample_id": "static_only_001",
            "static_output": {
                "sha256": "b" * 64,
                "platform": "windows",
                "file_type": "exe",
                "yara_matches": [],
                "extracted_strings": {"urls": [], "ips": [], "suspicious_keywords": []}
            },
            "dynamic_output": None,
            "mitre_techniques": [],
            "capability_tags": [],
            "risk_score": 25,
        }
        
        engine = InvestigationEngine()
        final_state = engine.run_investigation(state)
        
        # Should still complete without errors
        assert "timeline_events" in final_state
        assert "malware_explanation" in final_state
        assert "victim_impact" in final_state


def test_run_investigation_workflow_convenience(sample_investigation_state):
    """Test the convenience function."""
    final_state = run_investigation_workflow(sample_investigation_state)
    
    assert "investigation_summary" in final_state
    assert final_state["investigation_summary"] is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
