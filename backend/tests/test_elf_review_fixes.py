import pytest
import asyncio
from pathlib import Path
from unittest.mock import Mock

from backend.app import sandbox, geoip
from backend.app.analysis import (
    _is_valid_ipv4,
    _is_valid_domain,
    _extract_network_indicators,
    _build_ioc_intelligence,
    _build_risk_explanation,
    _build_threat_assessment,
)
from backend.app.ioc_extractor import IOCExtractor
from agents.narrative_agent.narrative import _is_grounded, _fallback_summary
from agents.orchestrator.schema import StaticAnalysisOutput, ExtractedStrings, DynamicAnalysisOutput, YaraMatch


def test_zero_fixture_ips_in_production_code():
    """Verify that production code contains NO hardcoded test IPs, domains, or canned PIDs."""
    app_dir = Path(__file__).resolve().parent.parent / "app"
    forbidden_strings = [
        "185.220.101.5",
        "c2-backend.darknet.in",
        "2048",
        "2049",
        "2055",
    ]
    py_files = list(app_dir.glob("*.py"))
    for py_file in py_files:
        content = py_file.read_text(encoding="utf-8")
        for bad in forbidden_strings:
            assert bad not in content, f"Found forbidden fixture string '{bad}' in production file {py_file.name}"


@pytest.mark.asyncio
async def test_simulation_mode_never_reports_clean(tmp_path):
    """An un-detonated benign sample must report 'no behavior observed (simulated)', never 'clean'."""
    dummy_elf = tmp_path / "hello_benign"
    dummy_elf.write_bytes(b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 50)
    
    result = await sandbox.run_dynamic_analysis(
        dummy_elf,
        platform="linux",
        file_type="elf",
        static_data={"extracted_strings": {}, "yara_matches": []}
    )
    assert result.execution_mode == "simulated"
    assert "no behavior observed (simulated)" in result.message.lower()
    assert result.network_connections == []
    assert result.c2_endpoints_detected == []
    assert result.files_written == []


@pytest.mark.asyncio
async def test_dynamic_independence(tmp_path):
    """Different binaries must produce distinct simulated runtime behavior based strictly on their evidence."""
    sample_a = tmp_path / "sample_a"
    sample_a.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 50)

    static_a = {
        "extracted_strings": {
            "ips": ["45.33.2.1"],
            "urls": [],
            "suspicious_keywords": ["/bin/sh", "crontab"],
        },
        "yara_matches": [{"rule_name": "Linux_Mirai", "category": "trojan", "severity": "high"}],
    }

    res_a = await sandbox.run_dynamic_analysis(
        sample_a,
        platform="linux",
        file_type="elf",
        static_data=static_a,
    )
    assert res_a.execution_mode == "simulated"
    assert len(res_a.network_connections) == 1
    assert res_a.network_connections[0]["dest_ip"] == "45.33.2.1"
    assert any("cron" in p for p in res_a.persistence_artifacts)

    # Sample B with zero network indicators
    sample_b = tmp_path / "sample_b"
    sample_b.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 50)
    static_b = {
        "extracted_strings": {"ips": [], "urls": [], "suspicious_keywords": []},
        "yara_matches": [],
    }

    res_b = await sandbox.run_dynamic_analysis(
        sample_b,
        platform="linux",
        file_type="elf",
        static_data=static_b,
    )
    assert res_b.execution_mode == "simulated"
    assert res_b.network_connections == []
    assert res_b.c2_endpoints_detected == []


def test_ioc_sanitizer_extensions_and_ips():
    """Sanitizer rejects non-domain binary extensions and non-routable IPs."""
    assert _is_valid_domain("bad-c2.com") is True
    assert _is_valid_domain("update.evil-domain.org") is True

    # Rejection of binary / archive artifacts
    assert _is_valid_domain("sample.out") is False
    assert _is_valid_domain("payload.bin") is False
    assert _is_valid_domain("classes.dex") is False
    assert _is_valid_domain("classes.dexPK") is False
    assert _is_valid_domain("script.sh") is False
    assert _is_valid_domain("malware.exe") is False
    assert _is_valid_domain("data.dat") is False
    assert _is_valid_domain("module.p") is False

    # IP rejection
    assert _is_valid_ipv4("8.8.8.8") is True
    assert _is_valid_ipv4("127.0.0.1") is False  # Loopback
    assert _is_valid_ipv4("10.0.0.1") is False   # Private
    assert _is_valid_ipv4("192.168.1.5") is False # Private
    assert _is_valid_ipv4("169.254.1.1") is False # Link local
    assert _is_valid_ipv4("0.0.0.0") is False


def test_dual_tier_tor_checks():
    """Tor checks distinguish confirmed exit nodes from Tor hosting ASNs."""
    # ASN 60729 is a known Tor relay provider
    is_tor, label = geoip.check_tor_status("185.220.101.5", asn=60729)
    assert is_tor is True
    assert "Hosting ASN associated with Tor relay infrastructure" in label
    assert "Confirmed Tor exit node" not in label


def test_risk_explanation_and_vendor_confidence():
    """MalwareBazaar floor is explicitly reported and vendor confidence uses agreement."""
    static_out = StaticAnalysisOutput(
        sample_id="test",
        sha256="test",
        platform="linux",
        file_type="elf",
        file_size_bytes=1000,
        submitted_at="2026-10-02T00:00:00Z",
        yara_matches=[],
        extracted_strings=ExtractedStrings(urls=[], ips=[], suspicious_keywords=[]),
    )
    mb_data = {
        "found": True,
        "signature": "Mirai",
        "vendor_intel": {
            "VendorA": {"verdict": "malicious"},
            "VendorB": {"verdict": "malicious"},
            "VendorC": {"verdict": "clean"},
            "VendorD": {"verdict": "not_supported"},
        }
    }
    # Risk score raised to 85 by MB
    explanation = _build_risk_explanation(static_out, [], [], 85, malware_bazaar=mb_data)
    assert any("MalwareBazaar intelligence floor" in c["label"] for c in explanation["contributions"])
    assert "intel_floor_note" in explanation

    threat = _build_threat_assessment(85, [], [], [], True, malware_bazaar=mb_data)
    # Counted = VendorA, VendorB, VendorC, MalwareBazaar (4). Agreeing = 3. 95 * 3/4 = 71.
    assert threat["confidence"] == 71
    assert threat["verdict"] == "MALICIOUS"


def test_narrative_grounding_and_term_allowlist():
    """Narrative agent flags ungrounded technical mechanisms."""
    static = StaticAnalysisOutput(
        sample_id="test",
        sha256="test",
        platform="linux",
        file_type="elf",
        file_size_bytes=1000,
        submitted_at="2026-10-02T00:00:00Z",
        yara_matches=[],
        extracted_strings=ExtractedStrings(urls=[], ips=[], suspicious_keywords=["curl"]),
    )
    dynamic = DynamicAnalysisOutput(sample_id="test")

    # Hallucinating 'systemd' when absent from raw evidence
    hallucinated = "The malware establishes persistence via systemd service units."
    assert _is_grounded(hallucinated, static, dynamic) is False

    # Grounded statement
    grounded = "The malware downloads additional components using curl."
    assert _is_grounded(grounded, static, dynamic) is True
