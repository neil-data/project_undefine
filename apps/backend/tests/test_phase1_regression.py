"""
test_phase1_regression.py — Mandatory regression tests for Phase 1 (Issues A1–A5).
Written BEFORE fixing production code to establish baseline failures.
"""

from unittest.mock import MagicMock, patch
import pytest

from agents.capability_classifier.capability_rules import classify_capabilities
from agents.investigation_engine.investigation_engine import InvestigationEngine
from agents.investigation_engine.investigation_schema import InvestigationState
from agents.narrative_agent.narrative import generate_narrative
from agents.orchestrator.risk_scoring import compute_risk_score, SCORE_STATIC_CAP
from agents.orchestrator.schema import (
    CapabilityTag,
    DynamicAnalysisOutput,
    ExtractedStrings,
    MitreTechnique,
    StaticAnalysisOutput,
    YaraMatch,
)
from backend.app.analysis import (
    _build_evidence_correlations,
    _build_ioc_intelligence,
    _build_risk_explanation,
    _build_threat_assessment,
)


# =====================================================================
# A1: Evidence-State Correctness
# =====================================================================

def test_a1_static_only_yara_is_labeled_static():
    """Static YARA matches must carry evidence_state='STATIC', never 'OBSERVED'."""
    raw_static = {
        "yara_matches": [
            {"rule_name": "Mirai_Botnet", "category": "trojan", "severity": "high", "description": "Mirai payload"}
        ],
        "extracted_strings": {"ips": [], "urls": []},
        "submitted_at": "2026-01-01T00:00:00Z",
    }
    correlations = _build_evidence_correlations(raw_static, None, {"ips": [], "domains": [], "urls": []}, [])
    assert len(correlations) >= 1
    yara_corr = [c for c in correlations if "YARA" in c["finding"]][0]
    assert yara_corr["evidence_state"] == "STATIC"


def test_a1_threat_intel_yara_is_labeled_intel():
    """MalwareBazaar/intel YARA matches must carry evidence_state='INTEL'."""
    raw_static = {
        "yara_matches": [
            {
                "rule_name": "[MalwareBazaar] Community_Yara",
                "category": "threat_intel",
                "severity": "high",
                "description": "Community rule match",
            }
        ],
        "extracted_strings": {"ips": [], "urls": []},
        "submitted_at": "2026-01-01T00:00:00Z",
    }
    correlations = _build_evidence_correlations(raw_static, None, {"ips": [], "domains": [], "urls": []}, [])
    intel_corr = correlations[0]
    assert intel_corr["evidence_state"] == "INTEL"


def test_a1_static_only_mitre_is_labeled_static():
    """Static-only MITRE technique must be labeled 'STATIC'."""
    raw_static = {"yara_matches": [], "extracted_strings": {"ips": [], "urls": []}}
    techniques = [MitreTechnique(technique_id="T1071", technique_name="Application Layer Protocol", confidence=0.65)]
    correlations = _build_evidence_correlations(raw_static, None, {"ips": [], "domains": [], "urls": []}, techniques)
    mitre_corr = [c for c in correlations if "MITRE" in c["finding"]][0]
    assert mitre_corr["evidence_state"] == "STATIC"


def test_a1_empty_or_unavailable_dynamic_produces_zero_observed():
    """When dynamic analysis is unavailable/empty, NO correlation or IoC finding may be 'OBSERVED'."""
    raw_static = {
        "yara_matches": [
            {"rule_name": "Trojan_Rule", "category": "trojan", "severity": "high", "description": "Trojan"}
        ],
        "extracted_strings": {"ips": ["1.2.3.4"], "urls": []},
        "submitted_at": "2026-01-01T00:00:00Z",
    }
    dyn_unavailable = DynamicAnalysisOutput(
        available=False,
        dynamic_status="unavailable",
        network_connections=[],
        files_written=[],
        process_tree=[],
    )
    indicators = {"ips": ["1.2.3.4"], "domains": [], "urls": []}
    techniques = [MitreTechnique(technique_id="T1071", technique_name="Application Layer Protocol", confidence=0.65)]

    correlations = _build_evidence_correlations(raw_static, dyn_unavailable, indicators, techniques)
    iocs = _build_ioc_intelligence(raw_static, dyn_unavailable, indicators)

    assert all(c["evidence_state"] != "OBSERVED" for c in correlations)
    assert all(i["evidence_state"] != "OBSERVED" for i in iocs)


def test_a1_real_dynamic_connection_is_observed():
    """Real dynamic execution network connection must carry evidence_state='OBSERVED'."""
    raw_static = {"yara_matches": [], "extracted_strings": {"ips": []}}
    dyn_completed = DynamicAnalysisOutput(
        available=True,
        dynamic_status="completed",
        network_connections=[{"dest_ip": "198.51.100.10", "dest_port": 80, "protocol": "tcp"}],
    )
    correlations = _build_evidence_correlations(raw_static, dyn_completed, {"ips": ["198.51.100.10"], "domains": [], "urls": []}, [])
    conn_corr = correlations[0]
    assert conn_corr["evidence_state"] == "OBSERVED"


def test_a1_correlation_never_uses_correlated_as_evidence_state():
    """'CORRELATED' is not a valid evidence state; must be OBSERVED, STATIC, or INTEL."""
    raw_static = {"yara_matches": [], "extracted_strings": {"ips": ["198.51.100.10"]}}
    dyn_completed = DynamicAnalysisOutput(
        available=True,
        dynamic_status="completed",
        network_connections=[{"dest_ip": "198.51.100.10", "dest_port": 80, "protocol": "tcp"}],
    )
    correlations = _build_evidence_correlations(raw_static, dyn_completed, {"ips": ["198.51.100.10"], "domains": [], "urls": []}, [])
    for c in correlations:
        assert c["evidence_state"] in ("OBSERVED", "STATIC", "INTEL")
        assert c["evidence_state"] != "CORRELATED"


def test_a1_dynamic_evidence_column_text_when_not_run():
    """When dynamic analysis is unavailable, dynamic evidence column must state dynamic analysis not performed."""
    raw_static = {"yara_matches": [], "extracted_strings": {"ips": []}}
    dyn_unavailable = DynamicAnalysisOutput(available=False, dynamic_status="unavailable")
    techniques = [MitreTechnique(technique_id="T1071", technique_name="Application Layer Protocol", confidence=0.65)]
    correlations = _build_evidence_correlations(raw_static, dyn_unavailable, {"ips": [], "domains": [], "urls": []}, techniques)
    mitre_corr = correlations[0]
    assert "not performed" in mitre_corr["dynamic_evidence"].lower()
    assert "See correlated runtime findings" not in mitre_corr["dynamic_evidence"]


# =====================================================================
# A2: LLM Refusal Handling
# =====================================================================

def test_a2_valid_llm_response_preserved():
    """Valid analytical LLM response must be preserved in investigation output."""
    engine = InvestigationEngine(groq_api_key="mock_key")
    state: InvestigationState = {
        "sample_id": "test_sample",
        "static_output": {"platform": "linux", "file_type": "elf", "yara_matches": []},
        "dynamic_output": {},
        "capability_tags": [],
        "mitre_techniques": [],
    }

    mock_resp = MagicMock()
    mock_resp.choices = [MagicMock(message=MagicMock(content="The sample is a Linux backdoor that establishes outbound connections."))]

    with patch("groq.Groq") as mock_groq:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_resp
        mock_groq.return_value = mock_client
        res = engine._explain_malware(state)

    explanation = res["malware_explanation"]
    assert "Linux backdoor" in explanation.technical_details


@pytest.mark.parametrize("refusal_phrase", [
    "I'm sorry, but I can't help with that.",
    "I cannot assist with analyzing malware or malicious software.",
    "I can't assist with this request.",
    "I am unable to help with reverse engineering this file.",
])
def test_a2_refusal_detected_and_retried_or_fallback(refusal_phrase):
    """Refusal strings must be detected; if retry also fails/refuses, fallback is used."""
    engine = InvestigationEngine(groq_api_key="mock_key")
    state: InvestigationState = {
        "sample_id": "test_sample",
        "static_output": {"platform": "linux", "file_type": "elf", "yara_matches": []},
        "dynamic_output": {},
        "capability_tags": [{"capability": "network_communication"}],
        "mitre_techniques": [],
    }

    refusal_resp = MagicMock()
    refusal_resp.choices = [MagicMock(message=MagicMock(content=refusal_phrase))]

    with patch("groq.Groq") as mock_groq:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = refusal_resp
        mock_groq.return_value = mock_client
        res = engine._explain_malware(state)

    explanation = res["malware_explanation"]
    assert refusal_phrase not in explanation.technical_details
    assert "I'm sorry" not in explanation.technical_details
    assert "cannot assist" not in explanation.technical_details
    assert "can't assist" not in explanation.technical_details
    assert "unable to help" not in explanation.technical_details
    # Fallback provides useful neutral forensic text
    assert "linux elf" in explanation.technical_details.lower() or "linux elf" in explanation.summary.lower()


def test_a2_refusal_retry_success_uses_valid_retry():
    """If initial attempt returns a refusal but neutral retry succeeds, use the retry result."""
    engine = InvestigationEngine(groq_api_key="mock_key")
    state: InvestigationState = {
        "sample_id": "test_sample",
        "static_output": {"platform": "linux", "file_type": "elf", "yara_matches": []},
        "dynamic_output": {},
        "capability_tags": [],
        "mitre_techniques": [],
    }

    refusal_resp = MagicMock()
    refusal_resp.choices = [MagicMock(message=MagicMock(content="I'm sorry, but I can't help with that."))]

    success_resp = MagicMock()
    success_resp.choices = [MagicMock(message=MagicMock(content="Forensic assessment: The binary contains routine network socket operations."))]

    with patch("groq.Groq") as mock_groq:
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = [refusal_resp, success_resp]
        mock_groq.return_value = mock_client
        res = engine._explain_malware(state)

    explanation = res["malware_explanation"]
    assert "Forensic assessment" in explanation.technical_details
    assert "I'm sorry" not in explanation.technical_details


def test_a2_narrative_agent_refusal_falls_back():
    """Narrative agent must not return refusal text in executive summary."""
    static = StaticAnalysisOutput(
        sample_id="test",
        sha256="abc",
        platform="linux",
        file_type="elf",
        file_size_bytes=100,
        submitted_at="2026-01-01T00:00:00Z",
        extracted_strings=ExtractedStrings(),
    )
    refusal_resp = MagicMock()
    refusal_resp.choices = [MagicMock(message=MagicMock(content="I'm sorry, but I can't help with that."))]

    with patch.dict("os.environ", {"GROQ_API_KEY": "mock_key"}):
        with patch("groq.Groq") as mock_groq:
            mock_client = MagicMock()
            mock_client.chat.completions.create.return_value = refusal_resp
            mock_groq.return_value = mock_client
            narrative = generate_narrative(static, None, [], [], 50)

    assert "I'm sorry" not in narrative
    assert "can't help" not in narrative
    assert "This linux elf binary" in narrative or "FALLBACK" in narrative


# =====================================================================
# A3: Capability Confirmation Must Be Evidence-Gated
# =====================================================================

def test_a3_static_urls_and_ips_do_not_confirm_c2_communication():
    """Static URLs/IPs must NOT emit c2_communication without intel or observed beacon."""
    static = StaticAnalysisOutput(
        sample_id="test",
        sha256="abc",
        platform="linux",
        file_type="elf",
        file_size_bytes=100,
        submitted_at="2026-01-01T00:00:00Z",
        extracted_strings=ExtractedStrings(urls=["http://example.com/bot"], ips=["198.51.100.1"]),
        static_risk_flags=["hardcoded_c2_ip"],
    )
    tags = classify_capabilities(static, None)
    tag_names = [t.capability for t in tags]
    assert "c2_communication" not in tag_names


def test_a3_static_strings_do_not_confirm_data_exfiltration():
    """Static strings/endpoints alone must NOT emit data_exfiltration."""
    static = StaticAnalysisOutput(
        sample_id="test",
        sha256="abc",
        platform="linux",
        file_type="elf",
        file_size_bytes=100,
        submitted_at="2026-01-01T00:00:00Z",
        extracted_strings=ExtractedStrings(urls=["http://example.com/upload"], ips=["198.51.100.1"]),
    )
    tags = classify_capabilities(static, None)
    tag_names = [t.capability for t in tags]
    assert "data_exfiltration" not in tag_names


def test_a3_network_communication_allowed_from_static_as_static():
    """Static endpoints may emit network_communication labeled STATIC."""
    static = StaticAnalysisOutput(
        sample_id="test",
        sha256="abc",
        platform="linux",
        file_type="elf",
        file_size_bytes=100,
        submitted_at="2026-01-01T00:00:00Z",
        extracted_strings=ExtractedStrings(urls=["http://example.com"]),
    )
    tags = classify_capabilities(static, None)
    net_tag = [t for t in tags if t.capability == "network_communication"]
    assert len(net_tag) == 1
    assert net_tag[0].evidence_state == "STATIC"


def test_a3_dynamic_beacon_confirms_c2_as_observed():
    """Observed dynamic beaconing confirms c2_communication with evidence_state='OBSERVED'."""
    static = StaticAnalysisOutput(
        sample_id="test",
        sha256="abc",
        platform="linux",
        file_type="elf",
        file_size_bytes=100,
        submitted_at="2026-01-01T00:00:00Z",
        extracted_strings=ExtractedStrings(),
    )
    dyn = DynamicAnalysisOutput(
        network_connections=[{"dest_ip": "1.2.3.4", "dest_port": 443, "interval_seconds": 60}],
    )
    tags = classify_capabilities(static, dyn)
    c2_tag = [t for t in tags if t.capability == "c2_communication"]
    assert len(c2_tag) == 1
    assert c2_tag[0].evidence_state == "OBSERVED"


def test_a3_threat_assessment_wording_capabilities_identified():
    """Threat assessment must say 'Capabilities identified' with confirmed vs static counts."""
    caps = [
        CapabilityTag(capability="network_communication", confidence=0.65, evidence=["url"], evidence_state="STATIC"),
    ]
    assessment = _build_threat_assessment(
        risk_score=50,
        yara_matches=[],
        mitre_techniques=[],
        capability_tags=caps,
        has_dynamic=False,
    )
    kf = " ".join(assessment["key_findings"])
    assert "Capabilities identified" in kf
    assert "Malicious capabilities confirmed" not in kf
    assert "0 confirmed capabilities (OBSERVED/INTEL), 1 static indicators" in kf


# =====================================================================
# A4: Reputation Confidence & "Legit File" Handling
# =====================================================================

def test_a4_legit_file_counted_as_benign_disagreement_produces_71():
    """YOROI 'Legit File' with 3 malicious sources produces counted=4, agreeing=3 -> confidence 71."""
    mb_data = {
        "found": True,
        "signature": "Mirai",
        "vendor_intel": {
            "CERT-PL": {"detection": "Mirai"},
            "YOROI": {"verdict": "Legit File"},
            "vxCube": {"verdict": "Malicious"},
        },
    }
    assessment = _build_threat_assessment(
        risk_score=85,
        yara_matches=[],
        mitre_techniques=[],
        capability_tags=[],
        has_dynamic=False,
        malware_bazaar=mb_data,
    )
    # counted = 4 (CERT-PL, YOROI, vxCube, MalwareBazaar)
    # agreeing = 3 (CERT-PL, vxCube, MalwareBazaar)
    # max(50, round(95 * 3 / 4)) = 71
    assert assessment["confidence"] == 71
    kf = " ".join(assessment["key_findings"])
    assert "Vendor disagreement observed (3/4 agree)" in kf


@pytest.mark.parametrize("benign_verdict", [
    "Legit File",
    "legit file",
    "Clean",
    "benign",
    "Safe",
    "Whitelist",
    "Legitimate",
])
def test_a4_various_benign_verdicts_not_counted_as_agreeing(benign_verdict):
    """Benign labels must not be counted as agreeing with malware."""
    mb_data = {
        "found": True,
        "signature": "Mirai",
        "vendor_intel": {
            "CERT-PL": {"detection": "Mirai"},
            "VendorX": {"verdict": benign_verdict},
        },
    }
    assessment = _build_threat_assessment(
        risk_score=85,
        yara_matches=[],
        mitre_techniques=[],
        capability_tags=[],
        has_dynamic=False,
        malware_bazaar=mb_data,
    )
    # counted = 3 (CERT-PL, VendorX, MalwareBazaar), agreeing = 2
    # max(50, round(95 * 2 / 3)) = 63
    assert assessment["confidence"] == 63


def test_a4_unrated_and_unknown_are_not_counted():
    """not_supported, unknown, unrated, none must be excluded from counted vendors."""
    mb_data = {
        "found": True,
        "signature": "Mirai",
        "vendor_intel": {
            "CERT-PL": {"detection": "Mirai"},
            "UnkVendor": {"verdict": "not_supported"},
            "NoneVendor": {"verdict": "None"},
            "UnratedVendor": {"verdict": "unrated"},
        },
    }
    assessment = _build_threat_assessment(
        risk_score=85,
        yara_matches=[],
        mitre_techniques=[],
        capability_tags=[],
        has_dynamic=False,
        malware_bazaar=mb_data,
    )
    # counted = 2 (CERT-PL, MalwareBazaar), agreeing = 2 -> 95
    assert assessment["confidence"] == 95


def test_a4_fully_agreeing_vendors_produce_95():
    """All agreeing vendors produce confidence 95."""
    mb_data = {
        "found": True,
        "signature": "Mirai",
        "vendor_intel": {
            "CERT-PL": {"detection": "Mirai"},
            "vxCube": {"verdict": "Malicious"},
        },
    }
    assessment = _build_threat_assessment(
        risk_score=85,
        yara_matches=[],
        mitre_techniques=[],
        capability_tags=[],
        has_dynamic=False,
        malware_bazaar=mb_data,
    )
    assert assessment["confidence"] == 95


# =====================================================================
# A5: Combined Static-Derived Score Cap
# =====================================================================

@pytest.mark.parametrize("yara_pts,mitre_count,cap_conf,expected_static", [
    (15, 0, 0.2, 18),  # 15 + 0 + int(0.2*15=3) = 18 -> 18
    (15, 0, 0.27, 19), # 15 + 0 + int(0.27*15=4) = 19 -> 19
    (15, 0, 0.35, 20), # 15 + 0 + 5 = 20 -> 20
    (15, 1, 0.0, 20),  # 15 + 8 = 23 -> capped to 20
    (15, 2, 0.6, 20),  # 15 + 16 + 9 = 40 -> capped to 20
])
def test_a5_compute_risk_score_static_cap_boundaries(yara_pts, mitre_count, cap_conf, expected_static):
    """Static-derived points for ELF (YARA + MITRE + Cap) must be combined and capped at 20."""
    static = StaticAnalysisOutput(
        sample_id="test",
        sha256="abc",
        platform="linux",
        file_type="elf",
        file_size_bytes=100,
        submitted_at="2026-01-01T00:00:00Z",
        yara_matches=[YaraMatch(rule_name="Trojan_Rule", category="trojan", severity="high", description="match")] if yara_pts > 0 else [],
        extracted_strings=ExtractedStrings(),
    )
    mitre = [
        MitreTechnique(technique_id=f"T100{i}", technique_name=f"Tech{i}", confidence=0.7)
        for i in range(mitre_count)
    ]
    caps = [
        CapabilityTag(capability="network_communication", confidence=cap_conf, evidence=["endpoint"], evidence_state="STATIC")
    ] if cap_conf > 0 else []

    score = compute_risk_score(static, None, mitre, caps)
    assert score == expected_static


def test_a5_dynamic_and_intel_applied_on_top_of_static_cap():
    """Dynamic behavior and threat intel floor are NOT swallowed by the static cap."""
    static = StaticAnalysisOutput(
        sample_id="test",
        sha256="abc",
        platform="linux",
        file_type="elf",
        file_size_bytes=100,
        submitted_at="2026-01-01T00:00:00Z",
        yara_matches=[YaraMatch(rule_name="Trojan_Rule", category="trojan", severity="high", description="match")],
        extracted_strings=ExtractedStrings(),
    )
    mitre = [MitreTechnique(technique_id="T1071", technique_name="C2", confidence=0.7)]
    caps = [CapabilityTag(capability="network_communication", confidence=0.8, evidence_state="STATIC")]

    # Dynamic run with download and exec (+20 dynamic points)
    dyn = DynamicAnalysisOutput(
        available=True,
        dynamic_status="completed",
        process_tree=[{"name": "/bin/sh"}],
        api_calls=["wget"],
    )
    # Static contribution capped at 20 + dynamic 20 = 40
    score = compute_risk_score(static, dyn, mitre, caps)
    assert score == 40


def test_a5_risk_explanation_sums_exactly_with_cap_line():
    """In _build_risk_explanation, static contribution is capped with a {kind: 'cap'} line."""
    static = {
        "yara_matches": [{"rule_name": "Trojan_Rule", "category": "trojan", "severity": "high", "description": "match"}],
    }
    # YARA 15 + MITRE 16 + Cap 23 = 54 -> capped to 20 -> diff = -34
    mitre = [
        {"technique_id": "T1071", "technique_name": "C2"},
        {"technique_id": "T1059", "technique_name": "Shell"},
    ]
    caps = [
        {"capability": "network_communication", "confidence": 0.8, "evidence_state": "STATIC"},
        {"capability": "persistence_cron", "confidence": 0.7, "evidence_state": "STATIC"},
    ]
    explanation = _build_risk_explanation(static, mitre, caps, risk_score=20)
    assert explanation["score"] == 20
    assert sum(c["points"] for c in explanation["contributions"]) == 20
    cap_items = [c for c in explanation["contributions"] if c.get("kind") == "cap"]
    assert len(cap_items) >= 1
    assert cap_items[0]["points"] < 0
