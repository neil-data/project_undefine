"""
Unit tests for Day 2 — B1 Evidence Model & Source Separation.
Asserts that findings carry canonical fields and adhere to strict separation invariants.
"""
import pytest
from pydantic import ValidationError

from analysis.scoring.orchestrator.schema import (
    EvidenceFinding,
    EvidenceState,
    SourceType,
    CapabilityTag,
    MitreTechnique,
    StaticAnalysisOutput,
    DynamicAnalysisOutput,
    YaraMatch,
    ExtractedStrings,
)
from analysis.correlation.capability_classifier.capability_rules import (
    _cap_c2_communication,
    _cap_network_communication,
    classify_capabilities,
)


class TestEvidenceModelInvariants:
    def test_evidence_finding_creation_and_fields(self):
        finding = EvidenceFinding(
            source_type=SourceType.STATIC,
            source="yara",
            evidence_state=EvidenceState.STATIC,
            confidence=0.75,
            provenance="rules/elf/network.yar:c2_regex",
            description="Hardcoded C2 pattern identified",
        )
        assert finding.source_type == SourceType.STATIC
        assert finding.source == "yara"
        assert finding.evidence_state == EvidenceState.STATIC
        assert finding.confidence == 0.75
        assert finding.provenance == "rules/elf/network.yar:c2_regex"

    def test_static_finding_cannot_claim_observed_or_dynamic_state(self):
        with pytest.raises(ValueError, match="cannot have OBSERVED or DYNAMIC"):
            EvidenceFinding(
                source_type=SourceType.STATIC,
                source="yara",
                evidence_state=EvidenceState.OBSERVED,
                confidence=0.75,
                provenance="test",
                description="Invalid state",
            )

    def test_static_rule_match_cannot_claim_intel_state(self):
        with pytest.raises(ValueError, match="Static rule match.*cannot claim INTEL"):
            EvidenceFinding(
                source_type=SourceType.STATIC,
                source="yara",
                evidence_state=EvidenceState.INTEL,
                confidence=0.75,
                provenance="builtin.rule",
                description="Invalid intel state",
            )

    def test_yara_source_must_be_static_with_bounded_confidence(self):
        with pytest.raises(ValueError, match="YARA matches are strictly STATIC"):
            EvidenceFinding(
                source_type=SourceType.INTEL,
                source="yara",
                evidence_state=EvidenceState.STATIC,
                confidence=0.75,
                provenance="builtin.yara",
                description="Yara cannot be INTEL source type",
            )

        with pytest.raises(ValueError, match="YARA match confidence must be <= 0.80"):
            EvidenceFinding(
                source_type=SourceType.STATIC,
                source="yara",
                evidence_state=EvidenceState.STATIC,
                confidence=0.95,
                provenance="builtin.yara",
                description="Yara cannot have >=0.85 confidence",
            )

    def test_intel_source_finding(self):
        finding = EvidenceFinding(
            source_type=SourceType.INTEL,
            source="malwarebazaar",
            evidence_state=EvidenceState.INTEL,
            confidence=0.95,
            provenance="MalwareBazaar API SHA256 query",
            description="Malware family signature hit: Mirai",
        )
        assert finding.source_type == SourceType.INTEL
        assert finding.evidence_state == EvidenceState.INTEL
        assert finding.confidence == 0.95


class TestCapabilitySourceSeparation:
    def test_static_yara_network_hit_is_not_c2_communication(self):
        static_out = StaticAnalysisOutput(
            sample_id="test_c2_static",
            submitted_at="2026-10-04T00:00:00Z",
            file_path="/tmp/c2.elf",
            file_size_bytes=1024,
            file_type="elf",
            platform="linux",
            sha256="b" * 64,
            extracted_strings=ExtractedStrings(),
            yara_matches=[
                YaraMatch(
                    rule_name="builtin.network_indicators",
                    category="threat_intel",
                    description="Hardcoded C2 pattern",
                    severity="medium",
                )
            ],
        )
        assert _cap_c2_communication(static_out, None) is None
        res = _cap_network_communication(static_out, None)
        assert res is not None
        assert res.capability == "network_communication"
        assert res.evidence_state == "STATIC"

    def test_c2_communication_observed_when_flagged_in_dynamic(self):
        static_out = StaticAnalysisOutput(
            sample_id="test_c2_dyn",
            submitted_at="2026-10-04T00:00:00Z",
            file_path="/tmp/clean.elf",
            file_size_bytes=1024,
            file_type="elf",
            platform="linux",
            sha256="c" * 64,
            extracted_strings=ExtractedStrings(),
            yara_matches=[],
        )
        dyn_out = DynamicAnalysisOutput(
            status="completed",
            execution_mode="real",
            network_connections=[
                {"dest_ip": "185.220.101.5", "dest_port": 443, "flagged_c2": True, "interval_seconds": 30}
            ],
            c2_endpoints_detected=["185.220.101.5:443"],
        )
        res = _cap_c2_communication(static_out, dyn_out)
        assert res is not None
        assert res.evidence_state == "OBSERVED"
        assert res.source_type == "DYNAMIC"
        assert res.confidence == 0.90
        assert res.confidence_level == "confirmed"

