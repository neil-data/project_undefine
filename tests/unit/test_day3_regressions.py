from __future__ import annotations

from analysis.rules.mitre.mitre_rules import _rule_c2_comms
from analysis.scoring.orchestrator.orchestrator import compute_risk_score as orchestrate_score
from analysis.scoring.orchestrator.risk_scoring import _is_generic_yara_rule
from analysis.scoring.orchestrator.schema import ExtractedStrings, MitreTechnique, StaticAnalysisOutput
from apps.backend.app.analysis import _build_evidence_timeline, _build_risk_explanation, _generate_recommendations


def test_report_risk_explanation_caps_static_points_and_reconciles_total():
    caps = [{"capability": f"static_{i}", "confidence": 1.0, "evidence_state": "STATIC"} for i in range(5)]
    techniques = [{"technique_id": f"T{i}", "evidence_state": "STATIC"} for i in range(4)]
    explanation = _build_risk_explanation({}, techniques, caps, 35)
    contributions = explanation["contributions"]
    assert sum(c["points"] for c in contributions) == 35
    assert sum(c["points"] for c in contributions if c["rule"] in {"mitre", "capabilities"}) <= 20


def test_unverified_critical_score_is_gated():
    static = StaticAnalysisOutput(
        sample_id="score-gate", submitted_at="2026-10-04T00:00:00Z", file_path="sample.exe",
        file_size_bytes=12, file_type="exe", platform="windows", sha256="d" * 64,
        extracted_strings=ExtractedStrings(), yara_matches=[],
    )
    techniques = [MitreTechnique(technique_id=f"T10{i}", technique_name="Static technique", confidence=1) for i in range(12)]
    result = orchestrate_score({"static_output": static, "dynamic_output": None, "mitre_techniques": techniques, "capability_tags": []})
    assert result["risk_score"] == 84
    assert result["victim_impact"] != "critical"


def test_timeline_preserves_sequence_without_invented_or_duplicate_unlabeled_times():
    ts = "2026-10-04T00:00:00+00:00"
    timeline = _build_evidence_timeline(ts, {
        "network_connections": [{"dest_ip": "203.0.113.9", "timestamp": ts}],
        "dns_queries": ["sample.example"],
    }, [{"evidence_state": "STATIC"}])
    assert not any("approx" in str(event) for event in timeline)
    assert all(event.get("seq") is not None for event in timeline)
    duplicate_times = [event["timestamp"] for event in timeline if event.get("timestamp")]
    assert len(duplicate_times) != len(set(duplicate_times))  # duplicated source time is explicitly sequenced


def test_credential_advice_requires_credential_capability_evidence():
    recs = _generate_recommendations(
        verdict="MALICIOUS", risk_score=90, capabilities=[], mitre=[], network_indicators={},
        platform="windows", existing_recommendations=["Rotate all domain passwords and OAuth tokens immediately."],
    )
    assert not any(any(word in r.lower() for word in ("password", "oauth", "kerberos", "credential", "token rotation")) for r in recs)


def test_static_c2_ip_does_not_map_to_t1071():
    static = StaticAnalysisOutput(
        sample_id="mitre-static", submitted_at="2026-10-04T00:00:00Z", file_path="sample.elf",
        file_size_bytes=12, file_type="elf", platform="linux", sha256="e" * 64,
        extracted_strings=ExtractedStrings(), yara_matches=[], static_risk_flags=["hardcoded_c2_ip"],
    )
    assert _rule_c2_comms(static, None) is None


def test_generic_compiler_and_hash_constant_rules_are_zero_weight():
    for name in ("generic_network_rule", "compiler_stub_rule", "sha256_hash_constant"):
        assert _is_generic_yara_rule(name, "misc")
