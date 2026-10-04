from unittest.mock import Mock
from backend.app.analysis import (
    _generate_recommendations,
    _is_valid_ipv4,
    _is_valid_url,
)
from backend.app.ioc_extractor import IOCExtractor


def test_is_valid_ipv4():
    assert _is_valid_ipv4("8.8.8.8") is True
    assert _is_valid_ipv4("45.13.223.9") is True
    # False positives to reject
    assert _is_valid_ipv4("1.3.6.1") is False       # ASN.1 OID
    assert _is_valid_ipv4("1.3.6.1.4.1") is False   # ASN.1 OID
    assert _is_valid_ipv4("1.2.840.113549") is False
    assert _is_valid_ipv4("0.0.0.0") is False       # Unspecified
    assert _is_valid_ipv4("0.1.2.3") is False       # 0.x.x.x
    assert _is_valid_ipv4("255.255.255.255") is False # Broadcast
    assert _is_valid_ipv4("999.999.999.999") is False


def test_is_valid_url():
    assert _is_valid_url("http://c2.badactor.in/gate.php") is True
    assert _is_valid_url("https://malware-drop.xyz/stage2.bin") is True
    # Garbled fragments to reject
    assert _is_valid_url(">httpu") is False
    assert _is_valid_url(":httpu\"") is False
    assert _is_valid_url("*http2.TH9") is False
    assert _is_valid_url("httponlyL") is False
    assert _is_valid_url("9http") is False
    assert _is_valid_url("8httpu3A") is False
    assert _is_valid_url("http/1.1H9") is False
    assert _is_valid_url("http://") is False
    assert _is_valid_url("http://a") is False


def test_backend_ioc_extractor_helpers():
    extractor = IOCExtractor(Mock(), Mock(), {})

    # IP validation tests
    assert extractor._is_valid_ip("45.13.223.9") is True
    assert extractor._is_valid_ip("1.3.6.1") is False
    assert extractor._is_valid_ip("1.3.6.1.4.1") is False
    assert extractor._is_valid_ip("0.0.0.0") is False
    assert extractor._is_valid_ip("255.255.255.255") is False

    # URL validation tests
    assert extractor._is_valid_url("http://c2.evil-corp.com/payload") is True
    assert extractor._is_valid_url(">httpu") is False
    assert extractor._is_valid_url(":httpu\"") is False
    assert extractor._is_valid_url("*http2.TH9") is False
    assert extractor._is_valid_url("httponlyL") is False
    assert extractor._is_valid_url("9http") is False
    assert extractor._is_valid_url("http/1.1H9") is False


def test_recommendations_synthesis_high_risk():
    recs = _generate_recommendations(
        verdict="MALICIOUS",
        risk_score=85,
        capabilities=[{"capability": "persistence_registry"}, {"capability": "credential_dumping", "evidence_state": "OBSERVED"}],
        mitre=[{"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"}],
        network_indicators={"ips": ["45.13.223.9"], "domains": ["c2.evil.com"], "urls": ["http://c2.evil.com/beacon"]},
        dynamic_output={
            "c2_endpoints_detected": ["45.13.223.9:443"],
            "persistence_artifacts": ["HKCU\\...\\Run\\malware"],
        },
    )
    assert len(recs) >= 3
    rec_text = " ".join(recs).lower()
    assert "isolate" in rec_text
    assert "firewall" in rec_text or "block" in rec_text or "c2" in rec_text
    assert "persistence" in rec_text or "registry" in rec_text
    assert "credential" in rec_text


def test_recommendations_synthesis_benign():
    recs = _generate_recommendations(
        verdict="BENIGN",
        risk_score=10,
        capabilities=[],
        mitre=[],
        network_indicators={"ips": [], "domains": [], "urls": []},
        dynamic_output=None,
    )
    assert len(recs) >= 1
    assert any("baseline" in r.lower() or "monitor" in r.lower() for r in recs)
