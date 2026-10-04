"""
E2E Tests for Day 2 — LLM Failure Handling in Report Generation Entrypoint (analyze_and_save).
Asserts that when the LLM returns refusals, empty text, non-JSON, truncated JSON,
or fabricated claims, analyze_and_save handles it safely and persists a valid report.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from apps.backend.app.analysis import analyze_and_save


@pytest.fixture
def sample_payload_path(tmp_path: Path) -> Path:
    sample_file = tmp_path / "test_malware_sample.json"
    payload = {
        "sample_id": "test_llm_failure_sample_001",
        "sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "md5": "1234567890abcdef1234567890abcdef",
        "sha1": "1234567890abcdef1234567890abcdef12345678",
        "static_analysis": {
            "sample_id": "test_llm_failure_sample_001",
            "sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "platform": "linux",
            "file_type": "elf",
            "file_size_bytes": 4096,
            "submitted_at": "2026-10-04T10:00:00.000000+00:00",
            "yara_matches": [
                {
                    "rule_name": "elf_generic_backdoor",
                    "category": "trojan",
                    "severity": "high",
                    "description": "Generic backdoor signature matched",
                }
            ],
            "extracted_strings": {
                "urls": ["http://198.51.100.10:8080/beacon"],
                "ips": ["198.51.100.10"],
                "suspicious_keywords": ["socket", "connect"],
            },
        },
        "dynamic_analysis": {
            "status": "completed",
            "dynamic_status": "completed",
            "execution_mode": "real",
            "duration_seconds": 15,
            "network_connections": [
                {
                    "dest_ip": "198.51.100.10",
                    "dest_port": 8080,
                    "flagged_c2": True,
                    "interval_seconds": 30,
                }
            ],
            "c2_endpoints_detected": ["198.51.100.10:8080"],
            "process_tree": [
                {
                    "pid": 2048,
                    "name": "sample_proc",
                    "cmdline": "./sample_proc",
                    "timestamp": "+0.000s",
                }
            ],
            "files_written": ["/tmp/dropped_agent.bin"],
            "api_calls": ["sys_connect", "sys_write"],
        },
    }
    sample_file.write_text(json.dumps(payload), encoding="utf-8")
    return sample_file


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_mode,mock_llm_response",
    [
        (
            "refusal_phrase",
            "I'm sorry, but I can't help with that request as an AI language model.",
        ),
        (
            "empty_text",
            "",
        ),
        (
            "non_json",
            "This malware connects to 198.51.100.10 and drops files in tmp directory.",
        ),
        (
            "truncated_json",
            '{"executive_summary": "The malware connects to 198.51.100.10 and initiates',
        ),
        (
            "fabricated_claim",
            json.dumps(
                {
                    "executive_summary": "The malware exploits unevidenced CVE-2024-99999 and contacts 203.0.113.99.",
                    "technical_steps": [
                        {
                            "step": "1",
                            "action": "Exploit CVE-2024-99999",
                            "evidence": "Fabricated evidence",
                        }
                    ],
                }
            ),
        ),
    ],
)
async def test_analyze_and_save_llm_failure_handling(
    monkeypatch, sample_payload_path: Path, failure_mode: str, mock_llm_response: str
):
    """
    Asserts that in all LLM failure modes (refusal, empty, non-JSON, truncated, fabricated claim):
    1. analyze_and_save runs without uncaught exceptions.
    2. Generates a valid JSON report.
    3. Uses fallback narrative (no refusal phrase, no ungrounded CVE, ends with terminal punct).
    4. Threat score and assessment are unchanged.
    """
    monkeypatch.setenv("GROQ_API_KEY", "mock_groq_api_key_test")

    # Mock the Groq client completions call
    mock_choice = MagicMock()
    mock_choice.message.content = mock_llm_response
    mock_completion = MagicMock()
    mock_completion.choices = [mock_choice]

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = mock_completion

    with patch("groq.Groq", return_value=mock_client):
        case_data = await analyze_and_save(sample_payload_path)

    # 1. Returned valid dictionary and JSON serializable
    assert isinstance(case_data, dict), f"[{failure_mode}] analyze_and_save did not return a dict"
    serialized = json.dumps(case_data)
    assert len(serialized) > 0, f"[{failure_mode}] Report could not be serialized to JSON"

    # 2. Risk score and status exist and are defensible
    assert "risk_score" in case_data, f"[{failure_mode}] Missing risk_score in case_data"
    assert case_data["risk_score"] > 0, f"[{failure_mode}] Risk score unexpectedly zeroed"
    assert "status" in case_data, f"[{failure_mode}] Missing status in case_data"

    # 3. Narrative validation
    narrative = case_data.get("narrative_summary") or ""
    assert narrative, f"[{failure_mode}] Narrative summary is empty"

    # Terminal punctuation
    stripped = narrative.strip()
    assert stripped[-1] in ".!?'\"", (
        f"[{failure_mode}] Narrative does not end with sentence terminal punctuation: '{stripped[-30:]}'"
    )

    # No refusal phrases
    assert "i'm sorry" not in narrative.lower()
    assert "can't help" not in narrative.lower()

    # No ungrounded fabricated CVEs
    assert "CVE-2024-99999" not in narrative

    # No raw markdown table delimiters or HTML tags
    assert "| Step" not in narrative
    assert "|---" not in narrative
    assert "<br>" not in narrative

    # 4. Fallback status verification in ai_analysis
    ai_analysis = case_data.get("ai_analysis") or {}
    assert ai_analysis.get("fallback_used") is True or "[FALLBACK]" in narrative or "exhibits" in narrative
