import pytest
from unittest.mock import patch
from uuid import uuid4
from datetime import datetime, timezone

from backend.app.malware_bazaar import lookup_hash, _MEMORY_CACHE
from backend.app.ioc_extractor import IOCExtractor
from backend.app.models.live_monitoring import EnrichedEvent, EventType
from backend.app.analysis import (
    _build_threat_assessment,
    _build_ioc_intelligence,
)
try:
    from backend.app.analysis import _build_threat_intelligence_summary
except ImportError:
    _build_threat_intelligence_summary = None
from agents.narrative_agent.narrative import generate_narrative
from agents.orchestrator.schema import StaticAnalysisOutput, DynamicAnalysisOutput, ExtractedStrings


# ─────────────────────────────────────────────────────────────────────────────
# B4: Threat Intelligence
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_b4_malware_bazaar_cache_preserves_negative_status():
    """Verify that cached negative/offline results are returned as structured dict, not swallowed to None."""
    test_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    cache_key = f"malware_bazaar:hash:{test_hash}"
    negative_entry = {
        "found": False,
        "query_status": "hash_not_found",
        "hash": test_hash,
        "classification": "UNKNOWN",
        "confidence": "LOW",
        "threat_level": "LOW",
        "intel_note": "Sample hash not present in threat feed",
        "evidence_state": "INTEL",
    }
    _MEMORY_CACHE[cache_key] = negative_entry
    try:
        res = await lookup_hash(test_hash)
        assert res is not None, "Negative cache hit should return structured dict, not None"
        assert res.get("found") is False
        assert res.get("query_status") == "hash_not_found"
    finally:
        _MEMORY_CACHE.pop(cache_key, None)


@pytest.mark.asyncio
async def test_b4_vendor_intel_parsing_covers_malware_family():
    """Verify parsing vendor verdicts that contain malware_family or status fields."""
    test_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    mock_api_res = {
        "query_status": "ok",
        "data": [{
            "sha256_hash": test_hash,
            "signature": "Mirai",
            "tags": ["mirai", "iot"],
            "vendor_intel": {
                "Triage": {"malware_family": "mirai"},
                "Kaspersky": {"status": "HEUR:Trojan.Linux.Mirai.b"},
                "ClamAV": {"threat_name": "Unix.Trojan.Mirai-1"},
            },
            "yara_rules": [],
        }]
    }
    with patch("backend.app.malware_bazaar._query_api_sync", return_value=mock_api_res), \
         patch("backend.app.malware_bazaar._get_redis_client", return_value=None):
        _MEMORY_CACHE.pop(f"malware_bazaar:hash:{test_hash}", None)
        res = await lookup_hash(test_hash)
        assert res is not None
        assert res.get("found") is True
        vendor_verdicts = res.get("vendor_verdicts", [])
        # Triage and Kaspersky verdicts must be extracted
        assert any("Triage: mirai" in v for v in vendor_verdicts), f"Missing Triage malware_family in {vendor_verdicts}"
        assert any("Kaspersky: HEUR:Trojan.Linux.Mirai.b" in v for v in vendor_verdicts), f"Missing Kaspersky status in {vendor_verdicts}"
        assert any("ClamAV: Unix.Trojan.Mirai-1" in v for v in vendor_verdicts), f"Missing ClamAV threat_name in {vendor_verdicts}"


def test_b4_threat_assessment_surfaces_unavailable_or_unmatched_ti():
    """Verify that _build_threat_assessment explicitly states when TI was offline or novel/not found."""
    # Case 1: TI is offline
    offline_assessment = _build_threat_assessment(
        risk_score=75,
        yara_matches=[],
        mitre_techniques=[],
        capability_tags=[],
        has_dynamic=False,
        malware_bazaar={"found": False, "query_status": "offline"},
    )
    findings = " ".join(offline_assessment["key_findings"])
    assert any("offline" in findings.lower() or "unreachable" in findings.lower() or "feed unavailable" in findings.lower() for _ in [1]), (
        f"Threat assessment should mention offline TI feed; got: {findings}"
    )

    # Case 2: TI returned hash_not_found
    novel_assessment = _build_threat_assessment(
        risk_score=50,
        yara_matches=[],
        mitre_techniques=[],
        capability_tags=[],
        has_dynamic=False,
        malware_bazaar={"found": False, "query_status": "hash_not_found"},
    )
    novel_findings = " ".join(novel_assessment["key_findings"])
    assert any("not present" in novel_findings.lower() or "unreported" in novel_findings.lower() or "novel" in novel_findings.lower() or "no matching" in novel_findings.lower() for _ in [1]), (
        f"Threat assessment should mention sample not found in TI feeds; got: {novel_findings}"
    )


def test_b4_structured_threat_intelligence_summary():
    """Verify _build_threat_intelligence_summary returns complete structured TI metadata."""
    assert _build_threat_intelligence_summary is not None, "_build_threat_intelligence_summary must be implemented"
    # Positive hit
    pos_ti = _build_threat_intelligence_summary(
        sha256="1111111111111111111111111111111111111111111111111111111111111111",
        malware_bazaar={
            "found": True,
            "signature": "Gafgyt",
            "tags": ["gafgyt", "botnet"],
            "vendor_intel": {"VendorA": {"verdict": "Malicious"}},
            "vendor_verdicts": ["VendorA: Malicious"],
            "bazaar_url": "https://bazaar.abuse.ch/sample/1111/",
        }
    )
    assert pos_ti["found"] is True
    assert pos_ti["signature"] == "Gafgyt"
    assert pos_ti["evidence_state"] == "INTEL"
    assert pos_ti["provider"] == "MalwareBazaar (abuse.ch)"

    # Negative / offline hit
    neg_ti = _build_threat_intelligence_summary(
        sha256="2222222222222222222222222222222222222222222222222222222222222222",
        malware_bazaar={"found": False, "query_status": "offline"}
    )
    assert neg_ti["found"] is False
    assert neg_ti["status"] == "offline"
    assert neg_ti["signature"] is None


@pytest.mark.asyncio
async def test_b4_no_fabricated_emotet_in_ioc_extractor():
    """Verify IOCExtractor does NOT inject unevidenced Emotet / Google LLC threat intelligence."""
    extractor = IOCExtractor(redis_client=None, db_session=None, config={})
    c2_ip = "45.33.32.156"
    c2_domain = "evil-c2-domain.com"
    extractor.KNOWN_C2_IPS.add(c2_ip)
    extractor.KNOWN_C2_DOMAINS.add(c2_domain)

    event = EnrichedEvent(
        event_id=uuid4(),
        timestamp=datetime.now(timezone.utc),
        event_type=EventType.NETWORK,
        event_data={"dst_ip": c2_ip, "domain": c2_domain},
    )
    iocs = await extractor._extract_network_iocs(uuid4(), event)
    assert len(iocs) == 2, f"Expected 2 IOCs extracted, got {len(iocs)}"
    for ioc in iocs:
        assert ioc.threat_intel is not None, "Threat intel should be attached for known C2"
        # Emotet and Google LLC should NOT be hardcoded
        assert ioc.threat_intel.threat_family != "Emotet", "Fabricated threat_family 'Emotet' detected"
        assert ioc.threat_intel.organization != "Google LLC", "Fabricated organization 'Google LLC' detected"


# ─────────────────────────────────────────────────────────────────────────────
# B5: Narrative, IoC & Detection-Rule Coverage
# ─────────────────────────────────────────────────────────────────────────────

def test_b5_file_hashes_always_in_ioc_intelligence():
    """Verify that sample file hashes (SHA256, MD5, SHA1) are always surfaced in ioc_intelligence."""
    raw_static = {
        "sha256": "4faccd957fba308b4ea1d9326e7bba891d243e8bbdbef9ea84d284fc4a0bb206",
        "md5": "338be6e9fa2ea293c66f68c2cfbbfb16",
        "sha1": "71383ea36f4521dd9857d4b29bbca0fb7383794b",
        "submitted_at": "2026-10-03T12:00:00Z",
        "is_malware": True,
    }
    # Test with TI negative / offline
    records = _build_ioc_intelligence(
        raw_static=raw_static,
        dynamic_output=None,
        indicators={"ips": [], "domains": [], "urls": []},
        malware_bazaar={"found": False, "query_status": "offline"},
    )
    sha256_records = [r for r in records if r.get("type") == "HASH_SHA256"]
    assert len(sha256_records) >= 1, "SHA-256 hash must be included in ioc_intelligence even if TI is offline"
    assert sha256_records[0]["indicator"] == raw_static["sha256"]
    assert sha256_records[0]["evidence_state"] == "STATIC"

    md5_records = [r for r in records if r.get("type") == "HASH_MD5"]
    assert len(md5_records) >= 1, "MD5 hash should be included in ioc_intelligence"
    assert md5_records[0]["indicator"] == raw_static["md5"]


def test_b5_persistence_artifacts_surfaced_in_ioc_intelligence():
    """Verify persistence paths from static or dynamic analysis appear in ioc_intelligence."""
    raw_static = {
        "sha256": "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
        "extracted_strings": {"suspicious_keywords": ["/etc/cron.d/malicious_cron"]},
    }
    dyn_data = {
        "network_connections": [],
        "dns_queries": [],
        "files_written": [],
        "persistence_artifacts": ["/etc/init.d/bot_startup"],
    }
    records = _build_ioc_intelligence(
        raw_static=raw_static,
        dynamic_output=dyn_data,
        indicators={"ips": [], "domains": [], "urls": []},
        malware_bazaar=None,
    )
    persistence_iocs = [r for r in records if r.get("type") == "PERSISTENCE_PATH"]
    indicators = [p["indicator"] for p in persistence_iocs]
    assert "/etc/init.d/bot_startup" in indicators, f"Dynamic persistence path missing from IoCs: {indicators}"
    assert "/etc/cron.d/malicious_cron" in indicators, f"Static persistence path missing from IoCs: {indicators}"


def test_b5_process_indicators_in_ioc_intelligence():
    """Verify process execution events from dynamic sandbox appear in ioc_intelligence."""
    raw_static = {"sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}
    dyn_data = {
        "network_connections": [],
        "dns_queries": [],
        "files_written": [],
        "process_tree": [
            {"pid": 1234, "cmdline": "/tmp/dropper -d", "process_name": "dropper", "is_suspicious": True}
        ],
    }
    records = _build_ioc_intelligence(
        raw_static=raw_static,
        dynamic_output=dyn_data,
        indicators={"ips": [], "domains": [], "urls": []},
        malware_bazaar=None,
    )
    proc_iocs = [r for r in records if r.get("type") == "PROCESS"]
    assert len(proc_iocs) >= 1, "Dynamic process execution must be surfaced in ioc_intelligence"
    assert "/tmp/dropper -d" in proc_iocs[0]["indicator"]
    assert proc_iocs[0]["evidence_state"] == "OBSERVED"


def test_b5_quiet_run_narrative_does_not_claim_unclassified_ti_match():
    """Verify that when dynamic run is quiet and TI is absent or unmatched, narrative does not invent TI matches."""
    static = StaticAnalysisOutput(
        sample_id="4faccd957fba308b4ea1d9326e7bba891d243e8bbdbef9ea84d284fc4a0bb206",
        file_path="/tmp/sample",
        sha256="4faccd957fba308b4ea1d9326e7bba891d243e8bbdbef9ea84d284fc4a0bb206",
        file_size_bytes=1024,
        file_type="ELF",
        platform="linux",
        submitted_at="2026-10-03T12:00:00Z",
        extracted_strings=ExtractedStrings(ips=[], urls=[], suspicious_keywords=[]),
    )
    dynamic = DynamicAnalysisOutput(
        execution_id="quiet-exec-1",
        sample_path="/tmp/sample",
        duration_seconds=5.0,
        dynamic_status="no_behavior_observed",
        network_connections=[],
        files_written=[],
        process_tree=[],
        persistence_artifacts=[],
    )
    # With no TI match
    narrative_unmatched = generate_narrative(
        static=static,
        dynamic=dynamic,
        mitre=[],
        capabilities=[],
        risk_score=75,
        malware_bazaar=None,
    )
    assert "(unclassified)" not in narrative_unmatched, (
        f"Narrative should not state '(unclassified)' threat-intelligence match when no TI match exists: {narrative_unmatched}"
    )
    assert "strictly on static rule hits" in narrative_unmatched or "no external threat-intelligence" in narrative_unmatched or "threat-intelligence matches" not in narrative_unmatched, (
        f"Narrative should indicate static rule basis without fabricating TI matches: {narrative_unmatched}"
    )
