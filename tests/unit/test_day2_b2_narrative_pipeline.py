"""
Unit tests for Day 2 — B2 Narrative Pipeline.
Asserts contract validation, exact-token grounding, refusal/truncation detection, and fallback safety.
"""
import pytest

from analysis.scoring.orchestrator.schema import (
    StaticAnalysisOutput,
    DynamicAnalysisOutput,
    YaraMatch,
    ExtractedStrings,
    CapabilityTag,
    MitreTechnique,
)
from analysis.scoring.narrative_agent.narrative import (
    _validate_narrative,
    _render_narrative,
    _claims_are_evidence_scoped,
    generate_narrative,
)


@pytest.fixture
def sample_static():
    return StaticAnalysisOutput(
        sample_id="test_sample_123",
        submitted_at="2026-10-04T00:00:00Z",
        file_path="/tmp/sample.elf",
        file_size_bytes=2048,
        file_type="elf",
        platform="linux",
        sha256="a" * 64,
        extracted_strings=ExtractedStrings(
            urls=["http://192.0.2.1:8080/c2"],
            ips=["192.0.2.1"],
            suspicious_keywords=[],
        ),
        yara_matches=[
            YaraMatch(
                rule_name="elf_trojan_downloader",
                category="trojan",
                description="Hardcoded C2 IP reference",
                severity="medium",
            )
        ],
    )


@pytest.fixture
def sample_dynamic():
    return DynamicAnalysisOutput(
        status="completed",
        execution_mode="real",
        process_tree=[{"pid": 100, "name": "sample.elf", "cmdline": "./sample.elf"}],
        network_connections=[
            {"dest_ip": "192.0.2.1", "dest_port": 8080, "flagged_c2": True}
        ],
        files_written=["/tmp/dropped.sh"],
    )


class TestNarrativeValidation:
    @pytest.mark.parametrize("claim", [
        "The sample established C2 communications and beaconing.",
        "The sample persisted and captured screenshots.",
        "The sample modified registry keys and executed a process.",
        "Sandbox traffic showed outbound network activity.",
    ])
    def test_fabricated_runtime_claims_rejected_without_observed_dynamic_evidence(self, claim, sample_static):
        static_only = DynamicAnalysisOutput(
            status="not_supported", dynamic_status="unavailable", execution_mode="real",
            failure_reason="Static only",
        )
        assert not _claims_are_evidence_scoped(
            {"executive_summary": claim, "technical_steps": []},
            sample_static, static_only, None,
        )

    def test_static_fallback_uses_indicator_wording(self, sample_static):
        result = generate_narrative(sample_static, None, [], [], 30)
        assert "Static analysis" in result
        assert "exhibits" not in result
        assert "runtime behavior" in result

    def test_valid_json_with_grounded_evidence_passes(self, sample_static, sample_dynamic):
        raw_json = """{
            "executive_summary": "The sample executed in sandbox and initiated outbound connection to 192.0.2.1:8080.",
            "technical_steps": [
                {"step": "1", "action": "Connects to C2 server at 192.0.2.1", "evidence": "Network connection to 192.0.2.1:8080 observed."}
            ]
        }"""
        valid, violations, parsed = _validate_narrative(
            raw_text=raw_json,
            static=sample_static,
            dynamic=sample_dynamic,
            mitre=[],
            capabilities=[],
            risk_score=70,
            victim_impact="medium",
        )
        assert valid, f"Expected valid narrative, got violations: {violations}"
        assert parsed is not None
        assert "192.0.2.1" in parsed["executive_summary"]

    def test_refusal_phrase_detected(self, sample_static, sample_dynamic):
        raw_json = """{
            "executive_summary": "I am sorry, but I cannot assist with analyzing this malware binary.",
            "technical_steps": []
        }"""
        valid, violations, _ = _validate_narrative(
            raw_text=raw_json,
            static=sample_static,
            dynamic=sample_dynamic,
            mitre=[],
            capabilities=[],
            risk_score=70,
            victim_impact="medium",
        )
        assert not valid
        assert any("refusal" in v.lower() for v in violations)

    def test_truncation_missing_punctuation_detected(self, sample_static, sample_dynamic):
        raw_json = """{
            "executive_summary": "The sample contacts 192.0.2.1 and drops file",
            "technical_steps": []
        }"""
        valid, violations, _ = _validate_narrative(
            raw_text=raw_json,
            static=sample_static,
            dynamic=sample_dynamic,
            mitre=[],
            capabilities=[],
            risk_score=70,
            victim_impact="medium",
        )
        assert not valid
        assert any("truncated" in v.lower() for v in violations)

    def test_ungrounded_ip_detected(self, sample_static, sample_dynamic):
        raw_json = """{
            "executive_summary": "The sample connects to ungrounded IP 203.0.113.55.",
            "technical_steps": []
        }"""
        valid, violations, _ = _validate_narrative(
            raw_text=raw_json,
            static=sample_static,
            dynamic=sample_dynamic,
            mitre=[],
            capabilities=[],
            risk_score=70,
            victim_impact="medium",
        )
        assert not valid
        assert any("203.0.113.55" in v for v in violations)

    def test_ungrounded_cve_detected(self, sample_static, sample_dynamic):
        raw_json = """{
            "executive_summary": "The malware exploits CVE-2024-1234 to gain root privileges.",
            "technical_steps": []
        }"""
        valid, violations, _ = _validate_narrative(
            raw_text=raw_json,
            static=sample_static,
            dynamic=sample_dynamic,
            mitre=[],
            capabilities=[],
            risk_score=70,
            victim_impact="medium",
        )
        assert not valid
        assert any("cve-2024-1234" in v.lower() for v in violations), f"Violations: {violations}"

    def test_exact_token_grounding_substring_mismatch(self, sample_static, sample_dynamic):
        """'xor' is in 'extractor', but exact-token mechanism 'xor' must NOT match."""
        # Evidence has 'extractor'
        sample_static.yara_matches[0].description = "Metadata extractor module"
        raw_json = """{
            "executive_summary": "The malware employs xor encryption on strings.",
            "technical_steps": []
        }"""
        valid, violations, _ = _validate_narrative(
            raw_text=raw_json,
            static=sample_static,
            dynamic=sample_dynamic,
            mitre=[],
            capabilities=[],
            risk_score=70,
            victim_impact="medium",
        )
        assert not valid
        assert any("xor" in v.lower() for v in violations)

    def test_rendered_steps_no_raw_tables_or_br(self):
        summary = "Executive summary of forensic analysis."
        steps = [
            {"step": "1", "action": "Connects to remote server", "evidence": "Connection to 1.2.3.4:80"}
        ]
        rendered = _render_narrative(summary, steps)
        assert "| Step" not in rendered
        assert "|---" not in rendered
        assert "<br>" not in rendered
        assert "Step 1: Connects to remote server (Evidence: Connection to 1.2.3.4:80)" in rendered
