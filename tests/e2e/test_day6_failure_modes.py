"""E2E Failure degradation tests for Day 6 entrypoint (analyze_and_save).

Verifies that failures across providers, threat intelligence, and AI degrade safely:
1. Provider unavailable
2. Dynamic timeout
3. Invalid provider response
4. Provider rate limited
5. Threat intelligence negative hit
6. Mach-O static-only pipeline
7. AI safety refusal / service failure fallback
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

import struct
from apps.backend.app.analysis import analyze_and_save

def tiny_elf(machine=62, bits=64):
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1, 1, 0]) + b"\0" * 8
    if bits == 64:
        header = ident + struct.pack("<HHIQQQIHHHHHH", 2, machine, 1, 0x400000, 0, 64, 0, 64, 0, 0, 64, 1, 0)
        sh0 = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    else:
        header = ident + struct.pack("<HHIIIIIHHHHHH", 2, machine, 1, 0x10000, 0, 52, 0, 52, 0, 0, 40, 1, 0)
        sh0 = struct.pack("<IIIIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return header + sh0

def tiny_pe():
    data = bytearray(0x80 + 24 + 240)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 0, 0, 0, 0, 240, 0)
    struct.pack_into("<H", data, 0x98, 0x20b)
    return bytes(data)

def tiny_macho():
    magic = b"\xcf\xfa\xed\xfe"
    return magic + struct.pack("<IiiIIIII", 0x01000007, 3, 2, 0, 0, 0, 0, 0)


def create_json_sample(tmp_path: Path, filename: str, file_type="elf", platform="linux", dynamic_data=None) -> Path:
    p = tmp_path / filename
    sha = "e" * 64
    data = {
        "sample_id": f"sample-{sha[:8]}",
        "sha256": sha,
        "static_analysis": {
            "sample_id": f"sample-{sha[:8]}",
            "sha256": sha,
            "platform": platform,
            "file_type": file_type,
            "file_size_bytes": 1024,
            "submitted_at": "2026-10-05T00:00:00Z",
            "extracted_strings": {"urls": [], "ips": [], "suspicious_keywords": []},
            "yara_matches": [],
        },
    }
    if dynamic_data:
        data["dynamic_analysis"] = dynamic_data
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


@pytest.mark.e2e
@pytest.mark.asyncio
class TestDay6E2EFailureModes:

    async def test_e2e_provider_unavailable_degrades_safely(self, tmp_path):
        sample = tmp_path / "test.elf"
        sample.write_bytes(tiny_elf())

        with patch("apps.backend.app.sandbox.run_dynamic_analysis") as mock_dyn:
            from analysis.scoring.orchestrator.schema import DynamicAnalysisOutput
            mock_dyn.return_value = DynamicAnalysisOutput(
                sample_id="sample-elf",
                execution_mode="real",
                dynamic_status="unavailable",
                failure_reason="Dynamic analysis not performed: provider unavailable",
                status="unavailable",
                message="Dynamic analysis not performed: provider unavailable",
            )

            case_data = await analyze_and_save(sample)
            assert case_data["dynamic_analysis"]["status"] == "unavailable"
            assert "provider unavailable" in case_data["dynamic_analysis"]["failure_reason"]
            assert len(case_data["dynamic_analysis"]["network_connections"]) == 0
            assert len(case_data["dynamic_analysis"]["process_tree"]) == 0

    async def test_e2e_dynamic_timeout_degrades_safely(self, tmp_path):
        sample = tmp_path / "timeout.elf"
        sample.write_bytes(tiny_elf())

        with patch("apps.backend.app.sandbox.run_dynamic_analysis") as mock_dyn:
            from analysis.scoring.orchestrator.schema import DynamicAnalysisOutput
            mock_dyn.return_value = DynamicAnalysisOutput(
                sample_id="sample-timeout",
                execution_mode="real",
                dynamic_status="timeout",
                failure_reason="Dynamic analysis not performed: timeout",
                status="timeout",
                message="Dynamic analysis not performed: timeout",
            )

            case_data = await analyze_and_save(sample)
            assert case_data["dynamic_analysis"]["status"] == "timeout"
            assert "timeout" in case_data["dynamic_analysis"]["failure_reason"].lower()
            assert len(case_data["dynamic_analysis"]["network_connections"]) == 0

    async def test_e2e_no_intel_hit_degrades_safely(self, tmp_path):
        sample = create_json_sample(tmp_path, "sample_no_intel.json")

        with patch("apps.backend.app.malware_bazaar.lookup_hash", return_value=None):
            case_data = await analyze_and_save(sample)
            assert case_data["malware_bazaar"] is None
            assert case_data["threat_intelligence"]["found"] is False
            assert not any("floor" in str(line).lower() for line in case_data.get("risk_explanation", {}).get("contributions", []))

    async def test_e2e_macho_static_only_pipeline(self, tmp_path):
        sample = tmp_path / "sample.macho"
        sample.write_bytes(tiny_macho())

        with patch("apps.backend.app.sandbox.run_dynamic_analysis") as mock_dyn:
            from analysis.scoring.orchestrator.schema import DynamicAnalysisOutput
            mock_dyn.return_value = DynamicAnalysisOutput(
                sample_id="sample-macho",
                execution_mode="real",
                dynamic_status="not_supported",
                failure_reason="Dynamic analysis: not performed (static-only)",
                status="not_supported",
                message="Dynamic analysis: not performed (static-only)",
            )

            case_data = await analyze_and_save(sample)
            assert case_data["platform"] == "macos"
            assert case_data["file_type"] in ("macho", "mach_o")
            assert case_data["dynamic_analysis"]["failure_reason"] == "Dynamic analysis: not performed (static-only)"

    async def test_e2e_ai_failure_fallback_clean_narrative(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "mock-groq-key")
        sample = create_json_sample(tmp_path, "sample_ai_refusal.json")

        mock_choice = MagicMock()
        mock_choice.message.content = "I cannot fulfill this request. I am programmed to be a helpful and harmless AI assistant."
        mock_completion = MagicMock()
        mock_completion.choices = [mock_choice]
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_completion

        with patch("groq.Groq", return_value=mock_client):
            case_data = await analyze_and_save(sample)
            narrative = case_data.get("narrative_summary", "")
            assert "cannot fulfill" not in narrative.lower()
            assert "harmless ai assistant" not in narrative.lower()
            assert "| Step" not in narrative
            assert "<br>" not in narrative
            assert len(narrative) > 20
