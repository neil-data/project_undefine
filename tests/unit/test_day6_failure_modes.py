"""Unit tests for Day 6 failure modes.

Explicitly asserts safe degradation without fabricating evidence:
1. Provider unavailable
2. Timeout
3. Invalid provider response
4. Rate limited
5. No intel hit
6. Static-only path
7. AI failure -> deterministic fallback
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from analysis.scoring.narrative_agent.narrative import generate_narrative
from analysis.scoring.orchestrator.schema import (
    DynamicAnalysisOutput,
    ExtractedStrings,
    StaticAnalysisOutput,
)
from apps.backend.app.analysis import (
    _build_threat_assessment,
    _build_risk_explanation,
    _build_threat_intelligence_summary,
)
from providers.dynamic.base import DynamicState, NormalizedProviderResult
from providers.dynamic.hybrid_analysis import HybridAnalysisAdapter
from providers.dynamic.pipeline import (
    DynamicAnalysisPipeline,
    render_dynamic_result,
    unsupported_platform_result,
)
from providers.dynamic.trust_boundary import normalize_provider_result


def make_dummy_static(platform="linux", file_type="elf", sha256=None):
    sha = sha256 or ("1" * 64)
    return StaticAnalysisOutput(
        sample_id=f"sample-{sha[:8]}",
        sha256=sha,
        platform=platform,
        file_type=file_type,
        file_size_bytes=2048,
        submitted_at="2026-10-05T00:00:00Z",
        extracted_strings=ExtractedStrings(urls=[], ips=[], suspicious_keywords=[]),
        yara_matches=[],
    )


class TestDay6FailureModes:

    def test_provider_unavailable_degrades_safely_with_zero_evidence(self):
        """Provider unavailable emits clean unavailable line and zero dynamic findings."""
        adapter = HybridAnalysisAdapter(api_key="mock-key")
        pipeline = DynamicAnalysisPipeline(providers={"hybrid_analysis": adapter})

        with patch.object(adapter, "lookup_by_hash", side_effect=ConnectionError("Could not connect to provider")):
            res = pipeline.run("a" * 64, platform="ELF", architecture="x86_64")

            assert res.state == DynamicState.PROVIDER_UNAVAILABLE
            assert "Dynamic analysis not performed: provider unavailable" in res.report_line
            assert len(res.findings) == 0
            assert not res.observation.has_behavior()
            assert res.verdict is None

    def test_provider_timeout_degrades_safely_with_zero_evidence(self):
        """Provider timeout emits explicit timeout line and zero dynamic findings."""
        adapter = HybridAnalysisAdapter(api_key="mock-key")
        pipeline = DynamicAnalysisPipeline(providers={"hybrid_analysis": adapter})

        with patch.object(adapter, "lookup_by_hash", return_value={"state": "TIMEOUT"}):
            res = pipeline.run("b" * 64, platform="ELF", architecture="x86_64")

            assert res.state == DynamicState.TIMEOUT
            assert "Dynamic analysis not performed: timeout" in res.report_line
            assert len(res.findings) == 0
            assert not res.observation.has_behavior()

    def test_provider_invalid_response_rejects_atomically(self):
        """Malformed or schema-violating provider payloads are rejected with zero findings."""
        adapter = HybridAnalysisAdapter(api_key="mock-key")

        # 1. Hostile extra root keys
        hostile_payload = {
            "behavior": {"processes": ["/bin/sh"]},
            "unexpected_hostile_key": "injected_data",
        }
        res = normalize_provider_result(adapter, hostile_payload, "task-1", "test-env")
        assert res.state == DynamicState.INVALID_RESPONSE
        assert "Dynamic analysis not performed: invalid response" in render_dynamic_result(res)
        assert len(res.findings) == 0

        # 2. Hostile behavior field
        invalid_behavior = {
            "behavior": {"invalid_subfield": [{"evil": "true"}]},
        }
        res2 = normalize_provider_result(adapter, invalid_behavior, "task-1", "test-env")
        assert res2.state == DynamicState.INVALID_RESPONSE
        assert len(res2.findings) == 0

    def test_provider_rate_limited_degrades_safely(self):
        """Provider rate limit emits clean rate limited report line and zero findings."""
        adapter = HybridAnalysisAdapter(api_key="mock-key")
        pipeline = DynamicAnalysisPipeline(providers={"hybrid_analysis": adapter})

        with patch.object(adapter, "lookup_by_hash", return_value={"state": "RATE_LIMITED"}):
            res = pipeline.run("c" * 64, platform="ELF", architecture="x86_64")

            assert res.state == DynamicState.RATE_LIMITED
            assert "Dynamic analysis not performed: rate limited" in res.report_line
            assert len(res.findings) == 0
            assert not res.observation.has_behavior()

    def test_no_intel_hit_leaves_assessment_clean_and_unrated(self):
        """Absence of threat intel hit creates no false positive C2, intel floor, or inflated score."""
        mb_empty = None
        sha = "d" * 64

        assessment = _build_threat_assessment(
            risk_score=0,
            yara_matches=[],
            mitre_techniques=[],
            capability_tags=[],
            has_dynamic=False,
            malware_bazaar=mb_empty,
        )

        assert assessment["verdict"] == "CLEAN"
        assert assessment["confidence"] == 50
        assert not any("c2" in f.lower() for f in assessment["key_findings"])

        ti_summary = _build_threat_intelligence_summary(sha, mb_empty)
        assert ti_summary["found"] is False
        assert ti_summary["signature"] is None
        assert ti_summary["status"] == "unqueried"

        explanation = _build_risk_explanation(
            {"yara_matches": []}, [], [], 0, malware_bazaar=mb_empty
        )
        assert not any("floor" in line["label"].lower() for line in explanation["contributions"])

    def test_static_only_paths_for_macho_and_unsupported_arch(self):
        """Mach-O and unsupported architectures route strictly to static-only with exact line."""
        # 1. Mach-O
        macho_res = unsupported_platform_result("Mach-O", "x86_64")
        assert macho_res.state == DynamicState.NOT_SUPPORTED_PLATFORM
        assert macho_res.report_line == "Dynamic analysis: not performed (static-only)"
        assert len(macho_res.findings) == 0

        # 2. Unsupported ELF arch
        arm_res = unsupported_platform_result("ELF", "mips")
        assert arm_res.state == DynamicState.NOT_SUPPORTED_PLATFORM
        assert "unsupported platform (mips)" in arm_res.report_line
        assert len(arm_res.findings) == 0

    def test_ai_failure_produces_clean_grounded_deterministic_fallback(self, monkeypatch):
        """AI safety refusal or failure cleanly triggers deterministic fallback without refusal leak."""
        monkeypatch.setenv("GROQ_API_KEY", "mock-groq-key")
        static = make_dummy_static(platform="linux", file_type="elf")

        mock_choice = MagicMock()
        mock_choice.message.content = "I'm sorry, but I can't help with analyzing this malicious software."
        mock_completion = MagicMock()
        mock_completion.choices = [mock_choice]
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_completion

        with patch("groq.Groq", return_value=mock_client):
            narrative = generate_narrative(
                static=static,
                dynamic=None,
                mitre=[],
                capabilities=[],
                risk_score=25,
            )

            # Refusal string must never leak into narrative text
            assert "i'm sorry" not in narrative.lower()
            assert "can't help" not in narrative.lower()
            # Markdown table syntax must not be present
            assert "| Step" not in narrative
            assert "<br>" not in narrative
            # Deterministic fallback is populated
            assert len(narrative) > 20
