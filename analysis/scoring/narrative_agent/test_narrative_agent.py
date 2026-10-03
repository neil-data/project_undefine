"""
test_narrative_agent.py — Tests for the narrative agent's fallback
behavior and error handling. Does NOT make real Groq API calls (no
network in test environment / no key required) — validates that the
degradation path works correctly, which is the part most likely to
break silently in production.
"""

import os
import pytest

from agents.narrative_agent.narrative import generate_narrative, _fallback_summary
from agents.mitre_mapper.mitre_rules import map_to_mitre
from agents.capability_classifier.capability_rules import classify_capabilities
from agents.orchestrator.risk_scoring import compute_risk_score


class TestFallbackBehavior:
    def test_falls_back_when_no_api_key(self, monkeypatch, android_malicious_static, android_malicious_dynamic):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)

        mitre = map_to_mitre(android_malicious_static, android_malicious_dynamic)
        caps = classify_capabilities(android_malicious_static, android_malicious_dynamic)
        score = compute_risk_score(android_malicious_static, android_malicious_dynamic, mitre, caps)

        result = generate_narrative(android_malicious_static, android_malicious_dynamic, mitre, caps, score)
        assert "FALLBACK" in result
        assert str(score) in result

    def test_fallback_never_crashes_on_empty_capabilities(self, monkeypatch, benign_static):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        result = generate_narrative(benign_static, None, [], [], 0)
        assert "FALLBACK" in result
        assert "no confirmed malicious capability" in result

    def test_fallback_handles_invalid_api_key_gracefully(self, monkeypatch, android_malicious_static, android_malicious_dynamic):
        """
        Simulates a bad/expired key. Real network call would fail —
        we're checking the exception path doesn't propagate and crash
        the whole pipeline, it should degrade to fallback instead.
        """
        monkeypatch.setenv("GROQ_API_KEY", "invalid_key_deliberately_wrong")

        mitre = map_to_mitre(android_malicious_static, android_malicious_dynamic)
        caps = classify_capabilities(android_malicious_static, android_malicious_dynamic)
        score = compute_risk_score(android_malicious_static, android_malicious_dynamic, mitre, caps)

        # This will attempt a real call and fail (invalid key / no network
        # in CI) — must not raise, must return a string.
        result = generate_narrative(android_malicious_static, android_malicious_dynamic, mitre, caps, score)
        assert isinstance(result, str)
        assert len(result) > 0


class TestFallbackSummaryContent:
    def test_includes_all_capability_names(self, android_malicious_static):
        from agents.orchestrator.schema import CapabilityTag
        caps = [
            CapabilityTag(capability="sms_otp_theft", confidence=0.9, evidence=["x"]),
            CapabilityTag(capability="gps_tracking", confidence=0.8, evidence=["y"]),
        ]
        summary = _fallback_summary(android_malicious_static, caps, 75)
        assert "sms otp theft" in summary
        assert "gps tracking" in summary
        assert "75" in summary

    def test_handles_zero_capabilities(self, benign_static):
        summary = _fallback_summary(benign_static, [], 0)
        assert "no confirmed malicious capability" in summary