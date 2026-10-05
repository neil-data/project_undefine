"""Unit tests for provider scripts, config loading, and secret redaction.

Uses mocked HTTP only. Tests never touch the live network.
"""
import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from packages.config import (
    load_config,
    redact_sensitive,
    redact_structure,
)
import scripts.provider_selfcheck as selfcheck
import scripts.record_provider_responses as recorder

ROOT = Path(__file__).resolve().parents[1]


def test_redact_sensitive_replaces_known_secrets_and_headers():
    fake_key = "fake_ha_key_abcdef123456"
    sample_text = (
        f"Request failed with api-key: {fake_key} and Authorization: Bearer token_secret_998877\n"
        f"Header X-Mobsf-Api-Key: mobsf_secret_token_123\n"
        f"Direct key appearance: {fake_key}"
    )
    redacted = redact_sensitive(sample_text, extra_secrets=[fake_key])

    assert fake_key not in redacted
    assert "token_secret_998877" not in redacted
    assert "mobsf_secret_token_123" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_structure_recursively_redacts_nested_structures():
    fake_key = "super_secret_payload_key_123"
    raw_data = {
        "status": "ok",
        "api_key": fake_key,
        "nested": {
            "token": "sensitive_jwt_token_456",
            "message": f"Contacted using {fake_key}",
        },
        "items": [
            {"authorization": "Basic abcdef"},
            {"clean": "public_data"},
        ],
    }
    cleaned = redact_structure(raw_data, extra_secrets=[fake_key])

    assert cleaned["api_key"] == "[REDACTED]"
    assert cleaned["nested"]["token"] == "[REDACTED]"
    assert fake_key not in cleaned["nested"]["message"]
    assert cleaned["items"][0]["authorization"] == "[REDACTED]"
    assert cleaned["items"][1]["clean"] == "public_data"


def test_selfcheck_fails_when_nothing_configured(monkeypatch, capsys):
    monkeypatch.delenv("HYBRID_ANALYSIS_API_KEY", raising=False)
    monkeypatch.delenv("MOBSF_URL", raising=False)
    monkeypatch.delenv("MOBSF_API_KEY", raising=False)

    rc = selfcheck.main()
    assert rc == 1
    out = capsys.readouterr().out
    assert "NOTHING CONFIGURED: 0 providers checked" in out


def test_selfcheck_ha_success_mocked(monkeypatch, capsys):
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "mocked-valid-key-abcdef")
    monkeypatch.delenv("MOBSF_URL", raising=False)

    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("requests.get", return_value=mock_resp):
        rc = selfcheck.main()
        assert rc == 0

    out = capsys.readouterr().out
    assert "PASS Hybrid Analysis: key present" in out
    assert "PASS Hybrid Analysis: known public hash lookup succeeded (status 200)" in out
    assert "mocked-valid-key-abcdef" not in out


def test_selfcheck_ha_auth_failure_mocked(monkeypatch, capsys):
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "mocked-invalid-key-abcdef")
    monkeypatch.delenv("MOBSF_URL", raising=False)

    mock_resp = MagicMock()
    mock_resp.status_code = 401

    with patch("requests.get", return_value=mock_resp):
        rc = selfcheck.main()
        assert rc == 1

    out = capsys.readouterr().out
    assert "FAIL Hybrid Analysis: hash lookup authentication rejected (status 401)" in out
    assert "mocked-invalid-key-abcdef" not in out


def test_selfcheck_mobsf_success_and_warn_floating_tag(monkeypatch, capsys):
    monkeypatch.delenv("HYBRID_ANALYSIS_API_KEY", raising=False)
    monkeypatch.setenv("MOBSF_URL", "http://localhost:8003")
    monkeypatch.setenv("MOBSF_API_KEY", "mock-mobsf-key")

    mock_post_resp = MagicMock()
    mock_post_resp.status_code = 400

    mock_get_resp = MagicMock()
    mock_get_resp.status_code = 200

    with patch("requests.post", return_value=mock_post_resp), patch("requests.get", return_value=mock_get_resp):
        rc = selfcheck.main()
        assert rc == 0

    out = capsys.readouterr().out
    assert "WARN MobSF: compose image tag is floating (latest) or unpinned" in out
    assert "PASS MobSF: URL reachable and API key accepted" in out
    assert "mock-mobsf-key" not in out


def test_record_provider_responses_mocked(tmp_path, monkeypatch):
    fake_ha_key = "secret_ha_key_test_123456"
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", fake_ha_key)
    monkeypatch.delenv("MOBSF_URL", raising=False)

    mock_lookup_resp = MagicMock()
    mock_lookup_resp.status_code = 200
    mock_lookup_resp.json.return_value = {
        "response": {"sha256": "4faccd95d23724469122505b90cdfd280ff552528be38e73e2b969be90eb7380"},
        "verdict": "malicious",
        "key_echo": fake_ha_key,
    }

    mock_env_resp = MagicMock()
    mock_env_resp.status_code = 200
    mock_env_resp.json.return_value = [{"id": 100, "name": "Windows 10 64-bit"}]

    def mock_get(url, *args, **kwargs):
        if "search/hash" in url:
            return mock_lookup_resp
        elif "system/environments" in url:
            return mock_env_resp
        res = MagicMock()
        res.status_code = 404
        return res

    with patch("requests.get", side_effect=mock_get):
        ops, files = recorder.record_responses(tmp_path)
        recorder.generate_manifest_and_summary(tmp_path, ops, files)

    # Verify files created
    manifest_file = tmp_path / "MANIFEST.sha256"
    summary_file = tmp_path / "RECORDING_SUMMARY.md"
    assert manifest_file.exists()
    assert summary_file.exists()

    # Verify secrets are redacted from files
    for json_file in tmp_path.glob("**/*.json"):
        text = json_file.read_text(encoding="utf-8")
        assert fake_ha_key not in text

    # The lookup file that echoed the key should have [REDACTED]
    lookup_file = tmp_path / "hybrid_analysis" / "lookup_4faccd95.json"
    assert lookup_file.exists()
    assert "[REDACTED]" in lookup_file.read_text(encoding="utf-8")

    # Verify summary has field names and no secrets
    summary_text = summary_file.read_text(encoding="utf-8")
    assert fake_ha_key not in summary_text
    assert "Top-level fields" in summary_text
