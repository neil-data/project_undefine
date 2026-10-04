"""Day 3b raw-input contracts against production report builders."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from apps.backend.app.analysis import (
    _build_evidence_timeline,
    _build_risk_explanation,
    _build_threat_assessment,
    _generate_recommendations,
    _format_file_size,
    _finalize_report_quality,
)
from analysis.correlation.capability_classifier.capability_rules import classify_capabilities
from analysis.rules.mitre.mitre_rules import map_to_mitre
from analysis.scoring.orchestrator.schema import AndroidManifestInfo, DynamicAnalysisOutput, ExtractedStrings, StaticAnalysisOutput
from packages.shared.ioc_classifier import truncate_display_value

RAW = json.loads((Path(__file__).parent / "inputs" / "day3b_cases.json").read_text(encoding="utf-8"))


def _assessment(score: int, vendors: dict | None = None, mb: dict | None = None, yara: list | None = None, dynamic: bool = False) -> dict:
    return _build_threat_assessment(score, yara or [], [], [], dynamic, {"vendor_intel": vendors or {}, **(mb or {})})


def test_score_verdict_raw_cases():
    compiler = RAW["score_verdict"]["compiler_generic"]
    out = _assessment(compiler["risk_score"], compiler["vendors"], yara=compiler["yara_matches"])
    assert out["verdict"] not in {"MALICIOUS", "CRITICAL"}
    generic_explanation = _build_risk_explanation({"yara_matches": compiler["yara_matches"]}, [], [], 0)
    assert not any(line["rule"] == "yara" and line["points"] for line in generic_explanation["contributions"])

    family = RAW["score_verdict"]["family_only"]
    out = _assessment(family["risk_score"], family["vendors"], yara=family["yara_matches"])
    assert out["threat_level"] == "HIGH"
    assert out["verdict"] != "CRITICAL"
    assert any("static rules only" in line.lower() for line in out["key_findings"])

    intel = RAW["score_verdict"]["intel_floor"]
    explanation = _build_risk_explanation({"yara_matches": []}, [], [], intel["risk_score"], intel["malware_bazaar"])
    assert any("floor" in line["label"].lower() for line in explanation["contributions"])
    assert sum(line["points"] for line in explanation["contributions"]) == explanation["score"]

    unverified = _assessment(94)
    assert unverified["risk_score"] == 84
    capped = _build_risk_explanation({"yara_matches": []}, [], [], unverified["risk_score"], score_cap_reason="capped at 84")
    assert any(line.get("kind") == "cap" and "84" in line["label"] for line in capped["contributions"])


@pytest.mark.parametrize("case,expected", [("not_supported", 50), ("single", 70), ("mixed", 50), ("yoroi_vxcube_mb", 63)])
def test_vendor_confidence_raw_cases(case: str, expected: int):
    raw = RAW["vendor_confidence"][case]
    mb = {"vendor_intel": raw["vendor_intel"]}
    if "signature" in raw:
        mb.update(found=True, signature=raw["signature"])
    assessment = _assessment(45, mb=mb)
    assert assessment["confidence"] == expected
    if case == "not_supported":
        assert any("static rules only" in line.lower() for line in assessment["key_findings"])
    else:
        assert any("(" in line and "/" in line and ")" in line for line in assessment["key_findings"])


def test_timeline_raw_case_uses_real_or_null_times_and_sequence_labels():
    raw = RAW["timeline"]
    timeline = _build_evidence_timeline(raw["submitted_at"], raw["dynamic"], raw["correlations"])
    assert all(event.get("seq") for event in timeline)
    assert not any("approx" in str(event).lower() for event in timeline)
    same_time = [event for event in timeline if event.get("timestamp") == raw["submitted_at"]]
    assert len(same_time) == 3
    assert len({event["seq"] for event in same_time}) == 3
    assert any(event.get("timestamp") is None for event in timeline)


def test_recommendations_raw_case_limits_dedupes_and_scopes_static_paths():
    raw = RAW["recommendations"]
    recs = _generate_recommendations(
        verdict=raw["verdict"], risk_score=raw["risk_score"], capabilities=[], mitre=[],
        network_indicators={"connections": [{"ip": ip, "flagged_c2": True} for ip in raw["ips"]], "domains": raw["domains"]},
        existing_recommendations=raw["existing_recommendations"], platform=raw["platform"],
        static_persistence_paths=raw["static_paths"],
    )
    assert len([r for r in recs if "isolate" in r.lower()]) <= 1
    assert len(recs) == len({r.casefold() for r in recs})
    assert any("15" in r and "and 5 more (see ioc table)" in r.lower() for r in recs)
    assert any("check hosts for these paths" in r.lower() for r in recs)
    assert not any("sinkhole" in r.lower() for r in recs)
    assert not any(word in r.lower() for r in recs for word in ("password", "oauth", "credential", "kerberos"))
    family_recs = _generate_recommendations(verdict="MALICIOUS", risk_score=80, capabilities=[], mitre=[], network_indicators={}, intel_family="Amos")
    assert any("based on intel family match: Amos" in r for r in family_recs)
    observed_recs = _generate_recommendations(verdict="MALICIOUS", risk_score=80, capabilities=[{"capability":"credential_access","evidence_state":"OBSERVED"}], mitre=[], network_indicators={})
    assert any("credential" in r.lower() for r in observed_recs)


def test_mitre_raw_case_rejects_static_c2_mapping():
    raw = RAW["mitre"]["linux_static"]
    linux = StaticAnalysisOutput(sample_id="l", sha256="b" * 64, platform=raw["platform"], file_type="elf", file_size_bytes=1, submitted_at="2026-10-04T00:00:00Z", extracted_strings=ExtractedStrings(), static_risk_flags=["hardcoded_c2_ip"])
    assert raw["evidence_state"] == "STATIC"
    assert raw["technique_id"] not in {t.technique_id for t in map_to_mitre(linux, None)}
    yara_only = linux.model_copy(update={"yara_matches":[{"rule_name":"builtin.c2_indicator","category":"network_indicator","severity":"high"}]})
    assert not any(c.capability == "c2_communication" for c in classify_capabilities(yara_only, None))


def test_mitre_platform_provider_and_static_provenance():
    android = StaticAnalysisOutput(sample_id="a", sha256="a" * 64, platform="android", file_type="apk", file_size_bytes=1, submitted_at="2026-10-04T00:00:00Z", extracted_strings=ExtractedStrings(), android_manifest=AndroidManifestInfo(package_name="test", permissions=["android.permission.RECEIVE_SMS"]))
    android_ids = {t.technique_id for t in map_to_mitre(android, None)}
    assert "T1517" in android_ids and all(tid.startswith(("T14", "T15", "T16")) for tid in android_ids)
    windows = android.model_copy(update={"platform": "windows", "file_type": "exe"})
    assert "T1517" not in {t.technique_id for t in map_to_mitre(windows, None)}

    linux = StaticAnalysisOutput(sample_id="l", sha256="b" * 64, platform="linux", file_type="elf", file_size_bytes=1, submitted_at="2026-10-04T00:00:00Z", extracted_strings=ExtractedStrings(), static_risk_flags=["hardcoded_c2_ip"])
    provider = DynamicAnalysisOutput(source_type="DYNAMIC", evidence_state="DYNAMIC", provider="hosted sandbox", execution_mode="hosted", network_connections=[{"dest_ip":"203.0.113.8","flagged_c2":True}])
    c2 = next(t for t in map_to_mitre(linux, provider) if t.technique_id == "T1071")
    assert c2.source_type == "DYNAMIC" and "provider" in c2.source
    static_only = map_to_mitre(linux, None)
    assert all(t.confidence <= 0.5 and t.evidence_state == "STATIC" for t in static_only)

    linux_strings = linux.model_copy(update={"extracted_strings": ExtractedStrings(suspicious_keywords=["/etc/cron.d/persist"])})
    persistence = [c for c in classify_capabilities(linux_strings, None) if c.capability.startswith("persistence_") or c.capability == "persistence"]
    assert all(c.evidence_state == "STATIC" and c.confidence <= 0.5 for c in persistence)


def test_report_quality_runtime_timestamps_sizes_truncation_and_string_cap():
    timestamps = {"ingestion":"2026-10-04T10:00:00Z", "static":"2026-10-04T10:00:01Z", "intel":None}
    report = {"file_size_bytes": 1, "explained_strings": [str(i) for i in range(23)], "evidence_timeline": [{"seq":1,"timestamp":None}]}
    _finalize_report_quality(report, timestamps)
    assert report["file_size_formatted"] == "1 B"
    assert len(report["explained_strings"]) == 20 and "3 additional" in report["explained_strings_note"]
    assert report["evidence_timeline"][0]["timestamp_display"] == "not recorded"
    assert report["stage_timestamps"]["report"]
    assert _format_file_size(100) != "0.0 MB"
    long_value = "x" * 100
    display = truncate_display_value(long_value)
    assert len(display) <= 95 and display.endswith("...(20 more)")
