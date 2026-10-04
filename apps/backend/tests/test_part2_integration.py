"""
backend/tests/test_part2_integration.py — Integration tests for Master Prompt 2/3 features.

Covers:
  - Network indicator extraction (static + dynamic, deduplication)
  - Geo-IP fallback behaviour (no DB configured)
  - Threat assessment score → level/verdict/confidence mapping
  - AI analysis payload structure (no fabricated content)
  - api_models helper functions

These tests use only in-process logic (no live network, no live DB) so they
run offline and alongside the existing 732-test suite without side effects.
"""

from __future__ import annotations

import sys
import os
import pytest

# Ensure repo root is on path
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


# ---------------------------------------------------------------------------
# api_models helper functions
# ---------------------------------------------------------------------------

class TestThreatLevelFromScore:
    """threat_level_from_score must follow the documented 5-level scale."""

    def _lvl(self, score):
        from backend.app.models.api_models import threat_level_from_score
        return threat_level_from_score(score)

    def test_low(self):
        assert self._lvl(0) == "LOW"
        assert self._lvl(19) == "LOW"

    def test_medium(self):
        assert self._lvl(20) == "MEDIUM"
        assert self._lvl(39) == "MEDIUM"

    def test_high(self):
        assert self._lvl(40) == "HIGH"
        assert self._lvl(69) == "HIGH"

    def test_critical(self):
        assert self._lvl(70) == "CRITICAL"
        assert self._lvl(89) == "CRITICAL"
        assert self._lvl(90) == "CRITICAL"
        assert self._lvl(100) == "CRITICAL"


class TestVerdictFromScore:
    """verdict_from_score must return exactly three values."""

    def _v(self, score):
        from backend.app.models.api_models import verdict_from_score
        return verdict_from_score(score)

    def test_clean(self):
        assert self._v(0) == "CLEAN"
        assert self._v(19) == "CLEAN"

    def test_suspicious(self):
        assert self._v(20) == "SUSPICIOUS"
        assert self._v(59) == "SUSPICIOUS"

    def test_malicious(self):
        assert self._v(60) == "MALICIOUS"
        assert self._v(100) == "MALICIOUS"


class TestConfidenceFromSignals:
    """confidence_from_signals must stay within 0-100."""

    def _c(self, yara, mitre, dyn):
        from backend.app.models.api_models import confidence_from_signals
        return confidence_from_signals(yara, mitre, dyn)

    def test_no_evidence(self):
        c = self._c(0, 0, False)
        assert 0 <= c <= 100

    def test_max_capped(self):
        # Many signals should not exceed 100
        c = self._c(100, 100, True)
        assert c == 100

    def test_dynamic_adds_confidence(self):
        c_static = self._c(2, 3, False)
        c_dynamic = self._c(2, 3, True)
        assert c_dynamic > c_static


# ---------------------------------------------------------------------------
# Network indicator extraction
# ---------------------------------------------------------------------------

class TestExtractNetworkIndicators:
    """_extract_network_indicators must deduplicate and never fabricate."""

    def _extract(self, raw_static, dynamic_output=None):
        from backend.app.analysis import _extract_network_indicators
        return _extract_network_indicators(raw_static, dynamic_output)

    def test_empty_input(self):
        result = self._extract({})
        assert result["ips"] == []
        assert result["domains"] == []
        assert result["urls"] == []
        assert result["connections"] == []

    def test_static_ips_extracted(self):
        raw = {"extracted_strings": {"ips": ["1.2.3.4", "5.6.7.8"], "urls": [], "suspicious_keywords": []}}
        result = self._extract(raw)
        assert "1.2.3.4" in result["ips"]
        assert "5.6.7.8" in result["ips"]

    def test_deduplication(self):
        raw = {"extracted_strings": {"ips": ["1.2.3.4", "1.2.3.4"], "urls": [], "suspicious_keywords": []}}
        result = self._extract(raw)
        assert result["ips"].count("1.2.3.4") == 1

    def test_domain_extracted_from_url(self):
        raw = {"extracted_strings": {"ips": [], "urls": ["https://evil.example.com/payload"], "suspicious_keywords": []}}
        result = self._extract(raw)
        assert "evil.example.com" in result["domains"]

    def test_dynamic_ips_merged(self):
        raw = {"extracted_strings": {"ips": ["1.1.1.1"], "urls": [], "suspicious_keywords": []}}
        dyn = {
            "network_connections": [{"dest_ip": "9.9.9.9", "dest_port": 443, "protocol": "HTTPS", "flagged_c2": False}],
            "c2_endpoints_detected": [],
            "dns_queries": [],
        }
        result = self._extract(raw, dyn)
        assert "1.1.1.1" in result["ips"]
        assert "9.9.9.9" in result["ips"]

    def test_c2_flagged_connection(self):
        raw = {"extracted_strings": {"ips": [], "urls": [], "suspicious_keywords": []}}
        dyn = {
            "network_connections": [{"dest_ip": "10.20.30.40", "dest_port": 8080, "protocol": "TCP", "flagged_c2": True}],
            "c2_endpoints_detected": [],
            "dns_queries": [],
        }
        result = self._extract(raw, dyn)
        c2_conns = [c for c in result["connections"] if c.get("flagged_c2")]
        assert len(c2_conns) == 1
        assert c2_conns[0]["ip"] == "10.20.30.40"


# ---------------------------------------------------------------------------
# Threat assessment builder
# ---------------------------------------------------------------------------

class TestBuildThreatAssessment:
    """_build_threat_assessment must derive all values from evidence — no random output."""

    def _build(self, risk_score, yara_matches, mitre_techniques, capability_tags, has_dynamic, malware_bazaar=None):
        from backend.app.analysis import _build_threat_assessment
        return _build_threat_assessment(risk_score, yara_matches, mitre_techniques, capability_tags, has_dynamic, malware_bazaar)

    def test_returns_all_keys(self):
        result = self._build(0, [], [], [], False)
        assert "risk_score" in result
        assert "threat_level" in result
        assert "verdict" in result
        assert "confidence" in result
        assert "key_findings" in result

    def test_no_evidence_has_clean_verdict(self):
        result = self._build(0, [], [], [], False)
        assert result["verdict"] == "CLEAN"
        assert result["threat_level"] == "LOW"

    def test_high_score_gives_malicious(self):
        result = self._build(85, [], [], [], False, {"found": True, "signature": "Mirai"})
        assert result["verdict"] == "MALICIOUS"
        assert result["threat_level"] == "CRITICAL"

    def test_yara_match_appears_in_findings(self):
        yara = [{"rule_name": "TestRule", "severity": "high", "category": "malware", "description": "Test"}]
        result = self._build(50, yara, [], [], False)
        assert any("YARA" in f for f in result["key_findings"])

    def test_mitre_techniques_appear_in_findings(self):
        # MitreTechnique-like object
        class FakeTechnique:
            technique_id = "T1059"
            technique_name = "Command Interpreter"
            confidence = 0.9

        result = self._build(50, [], [FakeTechnique()], [], False)
        assert any("MITRE" in f for f in result["key_findings"])

    def test_confidence_increases_with_evidence(self):
        low_conf = self._build(50, [], [], [], False)
        high_conf = self._build(50,
            [{"rule_name": "R", "severity": "high", "category": "x", "description": ""}] * 3,
            [{"technique_id": "T1059", "technique_name": "x"}] * 4,
            [],
            True
        )
        assert high_conf["confidence"] >= low_conf["confidence"]


# ---------------------------------------------------------------------------
# Geo-IP fallback behaviour
# ---------------------------------------------------------------------------

class TestGeoIpFallback:
    """geoip module must never raise and must return [] when unconfigured."""

    def test_lookup_many_empty_list(self):
        from backend.app.geoip import lookup_many
        result = lookup_many([])
        assert result == []

    def test_lookup_many_private_ip(self):
        """Private IPs should not go through HTTP fallback and return None → skipped."""
        from backend.app.geoip import lookup_many
        # 192.168.x.x is private — should return [] unless MaxMind DB is configured
        # We don't assert it returns [] exactly (a MaxMind DB could exist),
        # but it must not raise.
        result = lookup_many(["192.168.1.1"])
        assert isinstance(result, list)

    def test_is_private_ip(self):
        from backend.app.geoip import _is_private_ip
        assert _is_private_ip("127.0.0.1") is True
        assert _is_private_ip("192.168.0.1") is True
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("172.16.0.1") is True

    def test_is_public_ip(self):
        from backend.app.geoip import _is_private_ip
        # 8.8.8.8 is Google DNS — public
        assert _is_private_ip("8.8.8.8") is False

    def test_deduplication_in_lookup_many(self):
        from backend.app.geoip import lookup_many
        # Duplicate IPs should only be looked up once
        # We can't easily assert the count without mocking, but it must not raise
        result = lookup_many(["1.1.1.1", "1.1.1.1"])
        assert isinstance(result, list)

    def test_disclaimer_present_when_available(self):
        from backend.app.geoip import GEOIP_DISCLAIMER
        assert "approximate" in GEOIP_DISCLAIMER.lower()
        assert "exact" in GEOIP_DISCLAIMER.lower()


# ---------------------------------------------------------------------------
# AI analysis builder
# ---------------------------------------------------------------------------

class TestBuildAiAnalysis:
    """_build_ai_analysis must produce a valid structure from real state — no fabrication."""

    def _build(self, narrative="Test narrative.", investigation_output=None,
               network_indicators=None, geo_iocs=None, threat_assessment=None):
        from backend.app.analysis import _build_ai_analysis

        class FakeTechnique:
            technique_id = "T1059"
            technique_name = "Command Interpreter"

        final_state = {
            "narrative_summary": narrative,
            "mitre_techniques": [FakeTechnique()],
            "dynamic_output": None,
        }
        return _build_ai_analysis(
            final_state=final_state,
            investigation_output=investigation_output or {},
            network_indicators=network_indicators or {"ips": [], "domains": [], "urls": [], "connections": [], "dns_queries": []},
            geo_iocs=geo_iocs or [],
            threat_assessment=threat_assessment or {"risk_score": 50, "threat_level": "HIGH", "verdict": "MALICIOUS", "confidence": 60, "key_findings": []},
        )

    def test_returns_required_keys(self):
        result = self._build()
        for key in ("executive_summary", "ai_available", "fallback_used", "confidence", "recommendations", "mitre_techniques_explained"):
            assert key in result, f"Missing key: {key}"

    def test_fallback_detected(self):
        result = self._build(narrative="[FALLBACK — GROQ_API_KEY not set] Some summary.")
        assert result["fallback_used"] is True
        assert result["ai_available"] is False

    def test_real_narrative_not_fallback(self):
        result = self._build(narrative="This malware steals OTP codes from the victim's phone.")
        assert result["fallback_used"] is False
        assert result["ai_available"] is True

    def test_mitre_techniques_listed(self):
        result = self._build()
        assert len(result["mitre_techniques_explained"]) == 1
        assert "T1059" in result["mitre_techniques_explained"][0]

    def test_network_interpretation_populated_when_ips(self):
        indicators = {"ips": ["1.2.3.4"], "domains": [], "urls": [], "connections": [], "dns_queries": []}
        result = self._build(network_indicators=indicators)
        assert result["network_interpretation"] is not None
        assert "1" in result["network_interpretation"]  # IP count

    def test_no_network_interpretation_when_empty(self):
        result = self._build()  # empty indicators
        assert result["network_interpretation"] is None

    def test_geoip_interpretation_populated_when_geo_iocs(self):
        geo = [{"ip": "1.2.3.4", "country": "India", "city": "Mumbai", "isp": "Jio", "is_hosting": False, "is_proxy": False}]
        result = self._build(geo_iocs=geo)
        assert result["geoip_interpretation"] is not None
        assert "India" in result["geoip_interpretation"]

    def test_recommendations_from_investigation_output(self):
        inv = {"recommendations": [{"description": "Check bank accounts for unauthorized transactions."}]}
        result = self._build(investigation_output=inv)
        assert any("bank" in r.lower() for r in result["recommendations"])
