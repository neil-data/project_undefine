"""Layer 1: frozen bad reports must still trip their named validator."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests.e2e.conftest import is_rejected_path, is_valid_domain

FIXTURES = Path(__file__).parent / "fixtures"
EXPECTED_VIOLATIONS = {
    "base64_and_system_libs_as_paths": "invalid_path_ioc",
    "benign_hosts_suspicious": "benign_host_overstated_risk",
    "credential_advice_no_evidence": "credential_advice_without_evidence",
    "critical_all_vendors_clean": "critical_without_supporting_evidence",
    "duplicate_timestamps_synthetic_offset": "ambiguous_duplicate_timestamp",
    "fabricated_narrative": "ungrounded_or_malformed_narrative",
    "go_symbols_as_domains": "non_domain_go_symbols",
    "llm_refusal": "refusal_disclosed_as_analysis",
    "random_fragment_domains": "invalid_fragment_domain",
    "static_cap_exceeded": "static_score_cap_exceeded",
    "static_rule_labeled_intel": "static_rule_claimed_as_intel",
    "synthetic_mirai_droppee": "static_hit_claimed_as_c2_communication",
}


def validate_report(report: dict) -> set[str]:
    found: set[str] = set()
    for domain in (report.get("network_indicators") or {}).get("domains", []):
        ok, _ = is_valid_domain(str(domain))
        if not ok:
            found.add("non_domain_go_symbols" if str(domain).split(".")[0] in {"fmt", "go", "io", "os", "runtime"} else "invalid_fragment_domain")
    for ioc in report.get("ioc_intelligence", []):
        value = str(ioc.get("indicator", ""))
        rejected, _ = is_rejected_path(value)
        if rejected and ioc.get("type") in {"FILE_PATH", "PERSISTENCE_PATH", "INSTALL_PATH"}:
            found.add("invalid_path_ioc")
    if report.get("threat_level") in {"MEDIUM", "HIGH", "CRITICAL"} and set((report.get("network_indicators") or {}).get("domains", [])) <= {"go.dev", "microsoft.com", "android.googlesource.com"}:
        found.add("benign_host_overstated_risk")
    recs = report.get("recommendations", [])
    caps = {c.get("capability") for c in report.get("capability_tags", [])}
    if any(re.search(r"password|oauth|kerberos|credential|token rotation", str(r), re.I) for r in recs) and not caps.intersection({"credential_access", "credential_dumping", "password_theft", "keylogging"}):
        found.add("credential_advice_without_evidence")
    if report.get("threat_level") == "CRITICAL" and not report.get("ioc_intelligence") and not report.get("dynamic_analysis", {}).get("network_connections"):
        found.add("critical_without_supporting_evidence")
    timeline = report.get("evidence_timeline", [])
    stamps = [e.get("timestamp") for e in timeline if e.get("timestamp")]
    if len(stamps) != len(set(stamps)) or any("+" in str(s) and "approx" in str(s) for s in stamps):
        found.add("ambiguous_duplicate_timestamp")
    narrative = str(report.get("narrative_summary", ""))
    if "| Step" in narrative or "<br>" in narrative or "CVE-" in narrative and "CVE-" not in json.dumps(report.get("extracted_strings", {})):
        found.add("ungrounded_or_malformed_narrative")
    if any(p in narrative.lower() for p in ("i'm sorry", "can't help", "as an ai")):
        found.add("refusal_disclosed_as_analysis")
    if any(c.get("capability") == "c2_communication" and c.get("evidence_state") == "STATIC" for c in report.get("capability_tags", [])):
        found.add("static_hit_claimed_as_c2_communication")
    if any(c.get("evidence_state") == "INTEL" and any(w in " ".join(c.get("evidence", [])).lower() for w in ("static", "yara")) for c in report.get("capability_tags", [])):
        found.add("static_rule_claimed_as_intel")
    score = report.get("risk_explanation", {}).get("contributions", [])
    if sum(x.get("points", 0) for x in score if x.get("rule") in {"mitre", "capabilities"}) > 20:
        found.add("static_score_cap_exceeded")
    return found


@pytest.mark.parametrize("fixture,violation_id", EXPECTED_VIOLATIONS.items())
def test_original_bad_fixture_trips_expected_validator(fixture: str, violation_id: str) -> None:
    report = json.loads((FIXTURES / f"{fixture}.json").read_text(encoding="utf-8"))
    assert violation_id in validate_report(report), f"{fixture}: expected detector {violation_id} did not fire"


def test_clean_control_has_no_detected_violations() -> None:
    report = json.loads((FIXTURES / "clean_control.json").read_text(encoding="utf-8"))
    assert validate_report(report) == set()
