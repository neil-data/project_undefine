from backend.app.analysis import (
    _build_evidence_correlations,
    _build_ioc_intelligence,
    _build_risk_explanation,
)


def test_matching_static_and_dynamic_ip_is_corroborated():
    static = {"extracted_strings": {"ips": ["198.51.100.10"], "urls": []}, "submitted_at": "2026-01-01T00:00:00Z"}
    dynamic = {"network_connections": [{"dest_ip": "198.51.100.10", "dest_port": 443, "protocol": "tcp"}]}
    indicators = {"ips": ["198.51.100.10"], "domains": [], "urls": []}

    correlations = _build_evidence_correlations(static, dynamic, indicators, [])
    iocs = _build_ioc_intelligence(static, dynamic, indicators)

    assert correlations[0]["evidence_state"] == "CORROBORATED"
    assert iocs[0]["source"] == "Static + Dynamic"


def test_static_only_endpoint_is_not_claimed_as_c2():
    static = {"extracted_strings": {"ips": ["203.0.113.5"], "urls": []}, "submitted_at": "2026-01-01T00:00:00Z"}
    iocs = _build_ioc_intelligence(static, None, {"ips": ["203.0.113.5"], "domains": [], "urls": []})

    assert iocs[0]["classification"] == "UNKNOWN"
    assert iocs[0]["evidence_state"] == "OBSERVED"


def test_known_android_domain_is_classified_benign():
    static = {"extracted_strings": {"ips": [], "urls": []}, "submitted_at": "2026-01-01T00:00:00Z"}
    iocs = _build_ioc_intelligence(static, None, {"ips": [], "domains": ["schemas.android.com"], "urls": []})

    assert iocs[0]["classification"] == "BENIGN"


def test_risk_explanation_accounts_for_unallocated_score():
    explanation = _build_risk_explanation({"yara_matches": []}, [], [], 42)

    assert explanation["score"] == 42
    assert explanation["contributions"][0]["label"] == "Other deterministic behavior rules"
    assert explanation["contributions"][0]["points"] == 42
