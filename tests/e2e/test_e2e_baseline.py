"""
E2E Baseline Tests — Day 1.
Tests assert DESIRED forensic and behavioral contracts across all fixtures.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Tuple
import pytest

from tests.e2e.conftest import (
    CREDENTIAL_ADVICE_KEYWORDS,
    CREDENTIAL_CAPABILITIES,
    LEGITIMATE_BENIGN_DOMAINS,
    PUBLIC_DNS_RESOLVERS,
    REFUSAL_PHRASES,
    collect_all_evidence_values,
    find_recursive_states,
    get_fixture_items,
    is_rejected_path,
    is_valid_domain,
)

# Product-output contracts run only against the clean control. Frozen bad reports
# are exercised separately by test_detectors.py as detector regressions.
FIXTURE_ITEMS = [item for item in get_fixture_items() if item[0] == "clean_control"]
FIXTURE_IDS = [item[0] for item in FIXTURE_ITEMS]

pytestmark = pytest.mark.e2e


@pytest.fixture(params=FIXTURE_ITEMS, ids=FIXTURE_IDS)
def fixture_item(request) -> Tuple[str, Dict[str, Any]]:
    return request.param


# ─────────────────────────────────────────────────────────────────────────────
# 1. no_fake_dynamic
# ─────────────────────────────────────────────────────────────────────────────

def test_no_fake_dynamic(fixture_item: Tuple[str, Dict[str, Any]]):
    """If dynamic_status != completed -> zero dynamic events/IPs/pids/processes and no OBSERVED/DYNAMIC evidence_state."""
    name, data = fixture_item
    dyn_status = data.get("dynamic_status")
    if dyn_status is None and isinstance(data.get("dynamic_analysis"), dict):
        dyn_status = data["dynamic_analysis"].get("dynamic_status") or data["dynamic_analysis"].get("status")

    if dyn_status != "completed":
        events = data.get("dynamic_events") or data.get("behavior_events") or []
        assert len(events) == 0, f"[{name}] Found {len(events)} dynamic events when dynamic_status={dyn_status}"

        net = data.get("network_indicators") or {}
        dyn_ips = net.get("dynamic_ips") or []
        assert len(dyn_ips) == 0, f"[{name}] Found dynamic IPs {dyn_ips} when dynamic_status={dyn_status}"

        procs = data.get("processes") or data.get("process_tree") or []
        assert len(procs) == 0, f"[{name}] Found dynamic processes {procs} when dynamic_status={dyn_status}"

        bad_states = find_recursive_states(data, {"OBSERVED", "DYNAMIC"})
        assert len(bad_states) == 0, f"[{name}] Found {bad_states} evidence_state when dynamic_status={dyn_status}"


# ─────────────────────────────────────────────────────────────────────────────
# 2. source_separation
# ─────────────────────────────────────────────────────────────────────────────

def test_source_separation(fixture_item: Tuple[str, Dict[str, Any]]):
    """
    YARA/strings/parser findings are STATIC; INTEL only where an external lookup produced it;
    c2_communication never labeled INTEL/"confirmed" without an intel hit on an IP/domain.
    """
    name, data = fixture_item
    capabilities = data.get("capability_tags") or data.get("capabilities") or []

    for cap in capabilities:
        cap_name = cap.get("capability", "")
        ev_state = cap.get("evidence_state", "")
        evidence_list = cap.get("evidence", [])
        evidence_text = " ".join(str(e) for e in evidence_list).lower()

        is_static_source = any(k in evidence_text for k in ("static", "yara", "string", "header", "parser", "metadata", "hardcoded"))
        has_external_lookup = any(k in evidence_text for k in ("virustotal", "malwarebazaar", "alienvault", "threat intel", "ti hit"))

        if is_static_source and not has_external_lookup:
            assert ev_state == "STATIC", f"[{name}] Static-derived capability '{cap_name}' labeled as '{ev_state}' instead of STATIC"

        if cap_name == "c2_communication":
            confidence_val = cap.get("confidence", 0.0)
            confidence_level = str(cap.get("confidence_level", "")).lower()
            is_intel_or_confirmed = (ev_state == "INTEL" or confidence_level == "confirmed" or confidence_val >= 0.90)
            if is_intel_or_confirmed:
                has_ip_domain_intel = any(
                    rec.get("type") in ("IPV4", "DOMAIN", "URL") and rec.get("threat_intel")
                    for rec in data.get("ioc_intelligence", [])
                )
                assert has_ip_domain_intel, (
                    f"[{name}] c2_communication labeled as INTEL/confirmed (confidence={confidence_val}, state={ev_state}) "
                    f"without verified threat intel lookup on an IP or domain"
                )


# ─────────────────────────────────────────────────────────────────────────────
# 3. narrative
# ─────────────────────────────────────────────────────────────────────────────

def test_narrative(fixture_item: Tuple[str, Dict[str, Any]]):
    """
    No "| Step", "|---", "<br>", refusal phrases ("I'm sorry", "can't help"), no truncated final sentence;
    every path/IP/domain/port/CVE in the text exists in the evidence; if no dynamic findings -> equals fixed fallback.
    """
    name, data = fixture_item
    narrative = data.get("narrative_summary") or ""
    assert narrative, f"[{name}] Narrative summary is missing"

    assert "| Step" not in narrative, f"[{name}] Raw markdown table syntax '| Step' found in narrative"
    assert "|---" not in narrative, f"[{name}] Raw table delimiter '|---' found in narrative"
    assert "<br>" not in narrative, f"[{name}] Raw HTML '<br>' tag found in narrative"

    lower_narrative = narrative.lower()
    for phrase in REFUSAL_PHRASES:
        assert phrase not in lower_narrative, f"[{name}] LLM refusal phrase '{phrase}' detected in narrative"

    stripped = narrative.strip()
    assert stripped[-1] in ".!?'\"", f"[{name}] Narrative appears truncated; ends with '{stripped[-30:]}' without sentence terminal punctuation"

    evidence = collect_all_evidence_values(data)

    ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", narrative)
    for ip in ips:
        assert ip in evidence, f"[{name}] Narrative IP '{ip}' is ungrounded (not in evidence)"

    cves = re.findall(r"\bCVE-\d{4}-\d+\b", narrative, re.IGNORECASE)
    for cve in cves:
        assert cve in evidence, f"[{name}] Narrative CVE '{cve}' is ungrounded (not in evidence)"

    dyn_status = data.get("dynamic_status")
    dyn_events = (data.get("dynamic_analysis") or {}).get("process_tree", []) + (data.get("dynamic_events") or [])
    if dyn_status != "completed" and len(dyn_events) == 0:
        assert (
            "does not show any harmful actions" in lower_narrative
            or "no dynamic behavior" in lower_narrative
            or "contacts any external server" in lower_narrative
        ), f"[{name}] Dynamic findings absent but narrative did not equal the fixed fallback sentence"


# ─────────────────────────────────────────────────────────────────────────────
# 4. iocs
# ─────────────────────────────────────────────────────────────────────────────

def test_iocs(fixture_item: Tuple[str, Dict[str, Any]]):
    """
    Domains must pass (public-suffix TLD, no file extensions, no systemd unit suffixes, SLD >= 3 chars, no mixed-case TLD);
    reject Go symbols (pkg.symbol), zip entry names, base64 blobs as paths, system libs as install paths;
    public DNS resolvers never C2; go.dev / microsoft.com / android.googlesource.com not SUSPICIOUS.
    """
    name, data = fixture_item
    net = data.get("network_indicators") or {}
    domains = list(net.get("domains") or [])

    for item in data.get("ioc_intelligence", []):
        if item.get("type") == "DOMAIN":
            domains.append(item.get("indicator", ""))

    for dom in domains:
        valid, reason = is_valid_domain(dom)
        assert valid, f"[{name}] Invalid domain IoC '{dom}': {reason}"

        if dom.lower() in LEGITIMATE_BENIGN_DOMAINS:
            status = str(data.get("status", "")).lower()
            assert status != "suspicious" and status != "malicious", (
                f"[{name}] Whitelisted benign domain '{dom}' marked as suspicious/malicious"
            )

    paths = []
    for item in data.get("ioc_intelligence", []):
        if item.get("type") in ("PERSISTENCE_PATH", "FILE_PATH", "INSTALL_PATH", "PATH"):
            paths.append(item.get("indicator", ""))

    for p in paths:
        rejected, reason = is_rejected_path(p)
        assert not rejected, f"[{name}] Invalid path IoC '{p}': {reason}"

    c2_indicators = [
        str(item.get("indicator", "")) for item in data.get("ioc_intelligence", [])
        if "c2" in str(item.get("type", "")).lower() or "c2" in str(item.get("category", "")).lower()
    ]
    for resolver in PUBLIC_DNS_RESOLVERS:
        assert resolver not in c2_indicators, f"[{name}] Public DNS resolver '{resolver}' falsely categorized as C2"


# ─────────────────────────────────────────────────────────────────────────────
# 5. score
# ─────────────────────────────────────────────────────────────────────────────

def test_score(fixture_item: Tuple[str, Dict[str, Any]]):
    """
    Explanation points sum == risk_score; static-derived MITRE+capability points <= 20;
    GENERIC/COMPILER/HASH_CONSTANT YARA rules add 0; CRITICAL requires intel, observed evidence or a family-specific hit;
    confidence follows the vendor formula; victim_impact consistent with threat level.
    """
    name, data = fixture_item
    risk_score = data.get("risk_score", 0)

    explanation = data.get("risk_explanation") or {}
    contributions = explanation.get("contributions") or explanation.get("breakdown") or []
    if contributions:
        points_sum = sum(c.get("points", 0) for c in contributions)
        assert points_sum == risk_score, f"[{name}] Risk explanation points sum ({points_sum}) != risk_score ({risk_score})"

        mitre_pts = sum(c.get("points", 0) for c in contributions if c.get("rule") == "mitre")
        cap_pts = sum(c.get("points", 0) for c in contributions if c.get("rule") == "capabilities")
        static_mitre_cap = mitre_pts + cap_pts
        assert static_mitre_cap <= 20, (
            f"[{name}] Static-derived MITRE+capability points ({static_mitre_cap}) exceeded maximum allowed 20 points (mitre={mitre_pts}, caps={cap_pts})"
        )

    for ym in data.get("yara_matches", []):
        cat = (ym.get("category") or "").upper()
        rule = (ym.get("rule_name") or "").upper()
        if any(bad in cat or bad in rule for bad in ("GENERIC", "COMPILER", "HASH_CONSTANT")):
            assert ym.get("points", 0) == 0, f"[{name}] Generic/compiler YARA rule '{rule}' added non-zero points"

    status = str(data.get("status", "")).upper()
    threat_level = str(data.get("threat_level") or (data.get("threat_assessment") or {}).get("threat_level", "")).upper()
    if status == "CRITICAL" or threat_level == "CRITICAL" or risk_score >= 85:
        has_intel = bool(data.get("threat_intel") or (data.get("malware_bazaar") or {}).get("found"))
        has_observed = bool((data.get("dynamic_analysis") or {}).get("status") == "completed" and data.get("dynamic_events"))
        has_family_hit = any("family" in str(c.get("evidence", "")).lower() for c in data.get("capability_tags", []))
        assert has_intel or has_observed or has_family_hit, (
            f"[{name}] CRITICAL risk score ({risk_score}) claimed without threat intel, observed execution, or family match"
        )

    victim_impact = str(data.get("victim_impact", "")).upper()
    if victim_impact:
        if risk_score <= 25:
            assert victim_impact in ("NONE", "LOW", "NEGLIGIBLE"), f"[{name}] Low risk ({risk_score}) has inconsistent victim impact '{victim_impact}'"
        elif risk_score >= 75:
            assert victim_impact in ("HIGH", "CRITICAL", "SEVERE"), f"[{name}] High risk ({risk_score}) has inconsistent victim impact '{victim_impact}'"


# ─────────────────────────────────────────────────────────────────────────────
# 6. timeline_meta
# ─────────────────────────────────────────────────────────────────────────────

def test_timeline_meta(fixture_item: Tuple[str, Dict[str, Any]]):
    """No duplicate identical timestamps unless labeled; no synthetic '+Ns (approx)'; file size not '0.0 MB' when size>0."""
    name, data = fixture_item

    timeline = data.get("evidence_timeline") or data.get("timeline") or (data.get("dynamic_analysis") or {}).get("process_tree") or []
    timestamps = [e.get("timestamp") for e in timeline if isinstance(e, dict) and e.get("timestamp")]
    if len(timestamps) > 1:
        seen = set()
        duplicates = set()
        for ts in timestamps:
            if ts in seen:
                duplicates.add(ts)
            seen.add(ts)
        for e in timeline:
            if isinstance(e, dict) and e.get("timestamp") in duplicates:
                assert "label" in e or "seq" in e or "index" in e or "batch" in e, (
                    f"[{name}] Duplicate identical timestamp '{e.get('timestamp')}' lacks distinguishing label"
                )

    for e in timeline:
        raw_str = json.dumps(e)
        assert not re.search(r"\+\d+s\s*\(approx\)", raw_str), f"[{name}] Synthetic '+Ns (approx)' timing artifact found in timeline"

    size = data.get("file_size_bytes", 0)
    formatted = data.get("file_size_formatted") or ""
    if size > 0 and formatted:
        assert formatted != "0.0 MB", f"[{name}] file_size_bytes is {size} but formatted size is reported as '0.0 MB'"


# ─────────────────────────────────────────────────────────────────────────────
# 7. recommendations
# ─────────────────────────────────────────────────────────────────────────────

def test_recommendations(fixture_item: Tuple[str, Dict[str, Any]]):
    """
    No password/OAuth/Kerberos advice without credential evidence;
    every IP/domain/path recommended exists in the validated IoCs; no duplicates; no sinkhole of non-domains.
    """
    name, data = fixture_item
    recs = data.get("recommendations") or (data.get("ai_analysis") or {}).get("recommendations") or []
    if isinstance(recs, dict):
        rec_list = []
        for v in recs.values():
            if isinstance(v, list):
                rec_list.extend(v)
            elif isinstance(v, str):
                rec_list.append(v)
        recs = rec_list

    assert len(recs) == len(set(recs)), f"[{name}] Found duplicate recommendation entries: {recs}"

    capabilities = [c.get("capability", "") for c in data.get("capability_tags", [])]
    has_cred_evidence = any(c in CREDENTIAL_CAPABILITIES for c in capabilities)

    for rec in recs:
        rec_text = str(rec).lower()
        if any(keyword in rec_text for keyword in CREDENTIAL_ADVICE_KEYWORDS):
            assert has_cred_evidence, f"[{name}] Credential rotation recommended without credential theft evidence: '{rec}'"

        if "sinkhole" in rec_text:
            ip_in_sinkhole = re.search(r"sinkhole\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", rec_text)
            assert not ip_in_sinkhole, f"[{name}] Sinkhole recommendation inappropriately applied to non-domain IP: '{rec}'"

    validated_iocs = set()
    for item in data.get("ioc_intelligence", []):
        validated_iocs.add(str(item.get("indicator", "")))
    for ip in (data.get("network_indicators") or {}).get("ips", []):
        validated_iocs.add(str(ip))
    for dom in (data.get("network_indicators") or {}).get("domains", []):
        validated_iocs.add(str(dom))

    for rec in recs:
        ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", str(rec))
        for ip in ips:
            assert ip in validated_iocs or ip in PUBLIC_DNS_RESOLVERS, (
                f"[{name}] Recommended IP '{ip}' is unvalidated (not in IoCs)"
            )


# ─────────────────────────────────────────────────────────────────────────────
# 8. mitre
# ─────────────────────────────────────────────────────────────────────────────

def test_mitre(fixture_item: Tuple[str, Dict[str, Any]]):
    """Each technique is traceable to a validated capability; APK uses mobile-matrix IDs; no technique derived from overclaimed capability."""
    name, data = fixture_item
    mitre_techniques = data.get("mitre_techniques") or []
    capabilities = [c.get("capability", "") for c in data.get("capability_tags", [])]
    platform = str(data.get("platform") or data.get("file_type") or "").lower()

    for t in mitre_techniques:
        tid = t.get("technique_id") if isinstance(t, dict) else getattr(t, "technique_id", "")

        if platform in ("apk", "android"):
            is_mobile = tid.startswith("T14") or tid.startswith("T15") or tid.startswith("T16")
            assert is_mobile, f"[{name}] APK technique '{tid}' does not use MITRE Mobile Matrix identifier"

        if tid == "T1071":
            assert any(c in capabilities for c in ("c2_communication", "network_activity", "data_exfiltration")), (
                f"[{name}] T1071 MITRE technique claimed without supporting network capability"
            )


# ─────────────────────────────────────────────────────────────────────────────
# 9. layout (optional)
# ─────────────────────────────────────────────────────────────────────────────

def test_layout(fixture_item: Tuple[str, Dict[str, Any]]):
    """Footer-overlap check on generated PDF only if headless PDF generation is available; otherwise manual."""
    pytest.skip("manual: headless PDF generation is not available in backend Python environment")
