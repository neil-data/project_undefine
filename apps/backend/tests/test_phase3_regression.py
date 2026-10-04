"""
backend/tests/test_phase3_regression.py — TDD Regression Tests for Phase 3 (A11–A16).

Phase 3 Scope:
- A11: Duplicate dynamic failure prefix and "nulls" duration in sandbox / report rendering.
- A12: Recommendation deduplication (isolation), filtering filenames like index.html from DNS sinkholing, structured perimeter firewall rules, and static persistence hunting.
- A13: Evidence timeline layout: distinct timestamps for ingestion vs static completion, clean timestamp cell (no massive sequence sentence), and separate Seq #.
- A14: PDF page 2 static analysis explained strings truncation/pagination guard.
- A15: Malware family normalization from raw MalwareBazaar YARA rules (e.g. Linux_Trojan_Gafgyt_0cd591cd -> Gafgyt) preventing false disagreement and raw rule exposure.
- A16: GeoIP unconfigured database vs unmapped IP distinction.
"""

from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

# A11 Imports
from backend.app.sandbox import run_dynamic_analysis, DynamicAnalysisOutput

# A12 & A13 & A15 Imports
from backend.app.analysis import (
    _generate_recommendations,
    _build_evidence_timeline,
    _build_threat_assessment,
)
try:
    from backend.app.analysis import normalize_malware_family
except ImportError:
    normalize_malware_family = None

# A16 Imports
from backend.app import geoip


# ===========================================================================
# A11: Duplicate dynamic failure string & duration nulls
# ===========================================================================

class TestA11DynamicFailureAndDuration:
    """A11: Ensure dynamic failure reason has no duplicate prefix and null duration is safe."""

    @pytest.mark.asyncio
    async def test_a11_unconfigured_sandbox_failure_reason_no_redundant_prefix(self, monkeypatch, tmp_path):
        dummy_file = tmp_path / "sample.bin"
        dummy_file.write_bytes(b"\x7fELF\x02\x01\x01\x00")
        monkeypatch.delenv("SANDBOX_API_URL", raising=False)

        output = await run_dynamic_analysis(dummy_file)
        assert output.dynamic_status == "unavailable"
        # The failure reason must NOT repeat "Dynamic analysis not performed: "
        assert not output.failure_reason.startswith("Dynamic analysis not performed: Dynamic analysis not performed:")
        assert "Dynamic analysis not performed: Dynamic analysis not performed:" not in output.failure_reason
        assert output.failure_reason == "SANDBOX_API_URL is not configured"

    def test_a11_null_duration_seconds_is_none(self):
        output = DynamicAnalysisOutput(
            sample_id="test.bin",
            available=False,
            execution_mode="real",
            status="unavailable",
            dynamic_status="unavailable",
            failure_reason="SANDBOX_API_URL is not configured",
            duration_seconds=None,
        )
        assert output.duration_seconds is None


# ===========================================================================
# A12: Recommendations correctness, deduplication, firewall & persistence
# ===========================================================================

class TestA12RecommendationsCorrectness:
    """A12: Verify recommendation deduplication, filename filtering, firewall rules, and persistence hunting."""

    def test_a12_deduplicates_isolation_advice(self):
        existing = ["Isolate the affected device from the network"]
        recs = _generate_recommendations(
            verdict="MALICIOUS",
            risk_score=90,
            capabilities=[],
            mitre=[],
            network_indicators={"connections": [], "domains": []},
            dynamic_output=None,
            existing_recommendations=existing,
            platform="linux",
        )
        # Should NOT contain multiple variations of isolation advice
        isolation_recs = [r for r in recs if "isolate" in r.lower()]
        assert len(isolation_recs) == 1, f"Expected 1 isolation recommendation, got {isolation_recs}"

    def test_a12_does_not_sinkhole_index_html_or_non_domains(self):
        recs = _generate_recommendations(
            verdict="MALICIOUS",
            risk_score=90,
            capabilities=[],
            mitre=[],
            network_indicators={
                "connections": [],
                "domains": ["index.html", "rc.local", "evil-c2.attacker.com"],
            },
            dynamic_output=None,
            existing_recommendations=[],
            platform="linux",
        )
        for r in recs:
            assert "index.html" not in r, f"index.html must not be sinkholed in recommendations: {r}"
            assert "rc.local" not in r, f"rc.local must not be sinkholed in recommendations: {r}"
        
        # Valid domain evil-c2.attacker.com SHOULD be included in sinkhole rec
        sinkhole_recs = [r for r in recs if "sinkhole" in r.lower() or "dns" in r.lower()]
        assert any("evil-c2.attacker.com" in r for r in sinkhole_recs)

    def test_a12_structured_perimeter_firewall_rules_for_c2_ips(self):
        recs = _generate_recommendations(
            verdict="MALICIOUS",
            risk_score=85,
            capabilities=[],
            mitre=[],
            network_indicators={
                "connections": [
                    {"ip": "198.51.100.2", "dest_port": 4444, "flagged_c2": True, "evidence_state": "OBSERVED"},
                    {"ip": "203.0.113.5", "dest_port": 80, "flagged_c2": True, "evidence_state": "OBSERVED"},
                ],
                "domains": [],
            },
            dynamic_output=None,
            existing_recommendations=[],
            platform="linux",
        )
        # Should include structured firewall block rules (e.g. iptables rule or structured rule syntax)
        firewall_recs = [r for r in recs if "firewall" in r.lower() or "iptables" in r.lower()]
        assert len(firewall_recs) > 0, f"Expected perimeter firewall recommendation in {recs}"
        assert any("198.51.100.2" in r for r in firewall_recs)
        assert any("iptables -A OUTPUT -d 198.51.100.2 -j DROP" in r or "Block outbound traffic to confirmed C2 IP" in r for r in firewall_recs)

    def test_a12_static_persistence_hunt_when_dynamic_absent(self):
        recs = _generate_recommendations(
            verdict="SUSPICIOUS",
            risk_score=60,
            capabilities=[{"capability": "cron_persistence", "evidence": ["/etc/cron.d/qv3b"]}],
            mitre=[{"technique_id": "T1053.003", "technique_name": "Cron"}],
            network_indicators={"connections": [], "domains": []},
            dynamic_output=None,
            existing_recommendations=[],
            platform="linux",
            static_persistence_paths=["/etc/cron.d/qv3b", "/etc/init.d/qv3b"],
        )
        persistence_recs = [r for r in recs if "/etc/cron.d/qv3b" in r or "persistence" in r.lower()]
        assert len(persistence_recs) > 0, f"Expected persistence hunt recommendation for static paths in {recs}"
        assert any("/etc/cron.d/qv3b" in r for r in persistence_recs)


# ===========================================================================
# A13: Evidence timeline layout and timestamps
# ===========================================================================

class TestA13EvidenceTimelineLayout:
    """A13: Distinct timestamps, clean timestamp cells, and separate sequence numbering."""

    def test_a13_sample_received_and_static_analysis_timestamps_distinguishable(self):
        submitted_at = "2026-10-03T12:00:00Z"
        timeline = _build_evidence_timeline(submitted_at, dynamic_output=None, correlations=[], stage_timestamps={"ingestion": submitted_at, "static": "2026-10-03T12:00:01Z"})

        assert len(timeline) >= 2
        ev1 = timeline[0]
        ev2 = timeline[1]
        assert ev1["event"] == "Sample received"
        assert ev2["event"] == "Static analysis completed"
        # The timestamps should NOT be identical strings
        assert ev1["timestamp"] != ev2["timestamp"], "Ingestion and static completion must have distinguishable timestamps"

    def test_a13_timestamp_cell_is_clean_not_long_sentence(self):
        submitted_at = "2026-10-03T12:00:00Z"
        dynamic_out = {
            "network_connections": [{"dest_ip": "1.2.3.4", "dest_port": 80, "flagged_c2": False}],
            "dns_queries": ["c2.example.com"],
        }
        timeline = _build_evidence_timeline(submitted_at, dynamic_output=dynamic_out, correlations=[])

        for item in timeline:
            ts = item.get("timestamp_display", "")
            assert isinstance(ts, str)
            # Must NOT contain the 80-character explanation sentence in the cell
            assert "Approximate relative execution sequence (event timestamps unrecorded)" not in ts, (
                f"Timeline cell contains sentence: {ts}"
            )
            # Must have a separate seq field
            assert "seq" in item
            assert isinstance(item["seq"], int)
            if item.get("timestamp") is None:
                assert ts == "not recorded"


# ===========================================================================
# A14: PDF Unit 5 Explained Strings Truncation Guard
# ===========================================================================

class TestA14StaticStringsTruncation:
    """A14: Ensure explained strings list is capped/truncated with an overflow count."""

    def test_a14_explained_strings_capped(self):
        from backend.app.analysis import _format_pdf_static_strings
        explained = [{"value": f"/tmp/string_{i}", "explanation": f"Explanation {i}"} for i in range(120)]
        
        truncated, overflow_count = _format_pdf_static_strings(explained, max_items=20)
        assert len(truncated) == 20
        assert overflow_count == 100


# ===========================================================================
# A15: Malware Family Normalization from MalwareBazaar YARA Rules
# ===========================================================================

class TestA15MalwareFamilyNormalization:
    """A15: Extract normalized malware family name from raw MalwareBazaar community YARA rules."""

    def test_a15_normalize_malware_family_names(self):
        assert normalize_malware_family("Linux_Trojan_Gafgyt_0cd591cd") == "Gafgyt"
        assert normalize_malware_family("[MalwareBazaar] Linux_Trojan_Gafgyt_0cd591cd") == "Gafgyt"
        assert normalize_malware_family("ELF.Mirai.Variant_1") == "Mirai"
        assert normalize_malware_family("Win32.Trojan.Mozi_b") == "Mozi"
        assert normalize_malware_family("ELF_Tsunami_1") == "Tsunami"
        assert normalize_malware_family("Linux_Backdoor_Qbot_abc") == "Qbot"
        assert normalize_malware_family("Community_Yara") == "Community_Yara"

    def test_a15_no_false_family_disagreement_when_normalized_names_match(self):
        yara_matches = [
            {"rule_name": "[MalwareBazaar] Linux_Trojan_Gafgyt_0cd591cd", "severity": "high"}
        ]
        malware_bazaar = {
            "found": True,
            "signature": "Gafgyt",
            "tags": ["gafgyt", "elf"],
        }
        assessment = _build_threat_assessment(
            risk_score=85,
            yara_matches=yara_matches,
            mitre_techniques=[],
            capability_tags=[],
            has_dynamic=False,
            malware_bazaar=malware_bazaar,
        )
        findings = assessment.get("key_findings", [])
        disagreement = [f for f in findings if "disagree" in f.lower()]
        assert len(disagreement) == 0, f"Should not flag disagreement when normalized families match: {disagreement}"

    def test_a15_flags_family_disagreement_with_normalized_name_when_truly_different(self):
        yara_matches = [
            {"rule_name": "[MalwareBazaar] Linux_Trojan_Mozi_0cd591cd", "severity": "high"}
        ]
        malware_bazaar = {
            "found": True,
            "signature": "Mirai",
            "tags": ["mirai", "elf"],
        }
        assessment = _build_threat_assessment(
            risk_score=85,
            yara_matches=yara_matches,
            mitre_techniques=[],
            capability_tags=[],
            has_dynamic=False,
            malware_bazaar=malware_bazaar,
        )
        findings = assessment.get("key_findings", [])
        disagreement = [f for f in findings if "disagree" in f.lower()]
        assert len(disagreement) == 1
        # The disagreement should mention normalized family names rather than raw rule string if possible
        assert "Mozi" in disagreement[0]
        assert "Mirai" in disagreement[0]


# ===========================================================================
# A16: GeoIP Missing Database Handling vs Unmapped IP
# ===========================================================================

class TestA16GeoIPStatusDistinction:
    """A16: Distinguish unconfigured MaxMind DB from unmapped IP and provide explicit status."""

    def test_a16_lookup_ip_unconfigured_database(self, monkeypatch):
        # Force DB not loaded/unconfigured
        monkeypatch.delenv("GEOIP_DB_PATH", raising=False)
        monkeypatch.delenv("GEOIP_ASN_DB_PATH", raising=False)
        monkeypatch.setattr(geoip, "_city_reader", None)
        monkeypatch.setattr(geoip, "_asn_reader", None)
        monkeypatch.setattr(geoip, "_load_attempted", True)

        res = geoip.lookup_ip("45.33.32.156")
        assert res is not None
        assert res.get("status") == "database_not_configured"
        assert res.get("database_configured") is False
        assert "database not configured" in res.get("message", "").lower()

    def test_a16_lookup_ip_private_ip(self):
        res = geoip.lookup_ip("192.168.1.1")
        assert res is not None
        assert res.get("status") == "private"
        assert res.get("country_iso") == "PRIVATE"

    def test_a16_get_status(self, monkeypatch):
        monkeypatch.delenv("GEOIP_DB_PATH", raising=False)
        monkeypatch.setattr(geoip, "_city_reader", None)
        monkeypatch.setattr(geoip, "_load_attempted", True)

        status = geoip.get_status()
        assert status["available"] is False
        assert status["city_db_configured"] is False
