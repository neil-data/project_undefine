"""
capability_rules.py — Real capability classification logic.

Same rule-engine pattern as mitre_rules.py: each rule inspects
combined static + dynamic signals and emits a CapabilityTag with
confidence + human-readable evidence (the evidence list feeds
directly into the narrative agent's prompt later).
"""

from __future__ import annotations
from typing import Optional

from agents.orchestrator.schema import StaticAnalysisOutput, DynamicAnalysisOutput, CapabilityTag


def _cap_sms_otp_theft(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[CapabilityTag]:
    perms = static.android_manifest.permissions if static.android_manifest else []
    evidence = []
    score = 0.0

    if any("READ_SMS" in p for p in perms):
        evidence.append("READ_SMS permission declared")
        score += 0.4
    if any(y.category == "india_scam_rules" for y in static.yara_matches):
        evidence.append("matches India-specific scam YARA rule")
        score += 0.3
    if dynamic and any("sms" in c.lower() for c in dynamic.api_calls):
        evidence.append("observed live SMS content access during detonation")
        score += 0.3

    if score >= 0.4:
        return CapabilityTag(capability="sms_otp_theft", confidence=min(score, 1.0), evidence=evidence)
    return None


def _cap_gps_tracking(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[CapabilityTag]:
    perms = static.android_manifest.permissions if static.android_manifest else []
    evidence = []
    score = 0.0

    if any("LOCATION" in p for p in perms):
        evidence.append("ACCESS_FINE_LOCATION permission declared")
        score += 0.4
    if dynamic and any("LocationManager" in c for c in dynamic.api_calls):
        evidence.append("observed live location API calls during detonation")
        score += 0.4

    if score >= 0.4:
        return CapabilityTag(capability="gps_tracking", confidence=min(score, 1.0), evidence=evidence)
    return None


def _cap_overlay_phishing(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[CapabilityTag]:
    perms = static.android_manifest.permissions if static.android_manifest else []
    if any("SYSTEM_ALERT_WINDOW" in p for p in perms):
        return CapabilityTag(
            capability="overlay_phishing",
            confidence=0.65,
            evidence=["SYSTEM_ALERT_WINDOW permission — can draw fake UI over legitimate apps"],
        )
    return None


def _cap_device_admin_persistence(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[CapabilityTag]:
    if dynamic and any("DevicePolicyManager" in c for c in dynamic.api_calls):
        return CapabilityTag(
            capability="uninstall_resistance",
            confidence=0.8,
            evidence=["requested device admin privileges during detonation — resists uninstall"],
        )
    return None


def _cap_data_exfiltration(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[CapabilityTag]:
    evidence = []
    score = 0.0

    if static.extracted_strings.urls or static.extracted_strings.ips:
        evidence.append("hardcoded network endpoint(s) found in static strings")
        score += 0.3
    if dynamic and any(conn.get("flagged_c2") for conn in dynamic.network_connections):
        evidence.append("confirmed live connection to flagged C2 endpoint")
        score += 0.5
    if dynamic:
        for conn in dynamic.network_connections:
            interval = conn.get("interval_seconds")
            if interval and interval < 120:
                evidence.append(f"periodic beaconing every {interval}s — consistent with automated exfiltration")
                score += 0.2
                break

    if score >= 0.3:
        return CapabilityTag(capability="data_exfiltration", confidence=min(score, 1.0), evidence=evidence)
    return None


def _cap_keylogging(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[CapabilityTag]:
    evidence = []
    score = 0.0

    keylog_apis = ("GetKeyboardState", "SetWindowsHookEx", "GetAsyncKeyState")
    if dynamic and any(api in c for c in dynamic.api_calls for api in keylog_apis):
        evidence.append("observed keyboard-hooking API calls during detonation")
        score += 0.6
    if "keylog" in static.extracted_strings.suspicious_keywords:
        evidence.append("'keylog' string found in static analysis")
        score += 0.3

    if score >= 0.3:
        return CapabilityTag(capability="keylogging", confidence=min(score, 1.0), evidence=evidence)
    return None


def _cap_persistence(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[CapabilityTag]:
    if dynamic and dynamic.registry_changes:
        run_key = any("Run" in rc or "Startup" in rc for rc in dynamic.registry_changes)
        if run_key:
            return CapabilityTag(
                capability="persistence_registry",
                confidence=0.85,
                evidence=["writes to registry Run key — survives reboot"],
            )
    return None


def _cap_cron_persistence(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[CapabilityTag]:
    """Linux — persistence via cron."""
    if dynamic and any("cron" in a.lower() for a in dynamic.persistence_artifacts):
        return CapabilityTag(
            capability="persistence_cron",
            confidence=0.85,
            evidence=["installs a cron job — survives reboot on Linux"],
        )
    return None


def _cap_launchd_persistence(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[CapabilityTag]:
    """macOS — persistence via LaunchAgents/LaunchDaemons."""
    if dynamic and any(
        "launchd" in a.lower() or "launchagent" in a.lower() or "launchdaemon" in a.lower()
        for a in dynamic.persistence_artifacts
    ):
        return CapabilityTag(
            capability="persistence_launchd",
            confidence=0.85,
            evidence=["installs a LaunchAgent/LaunchDaemon — survives reboot on macOS"],
        )
    return None


def _cap_privilege_escalation(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[CapabilityTag]:
    """Linux/macOS — setuid/setgid privilege escalation."""
    binary_imports = static.binary_analysis.imports if static.binary_analysis else []
    static_hit = any("setuid" in imp.lower() or "setgid" in imp.lower() for imp in binary_imports)
    dynamic_hit = dynamic and any("setuid" in c.lower() or "setgid" in c.lower() for c in dynamic.api_calls)
    if static_hit or dynamic_hit:
        confidence = 0.8 if dynamic_hit else 0.5
        evidence = []
        if static_hit:
            evidence.append("setuid/setgid import found in binary")
        if dynamic_hit:
            evidence.append("observed setuid/setgid call during detonation — privilege escalation")
        return CapabilityTag(capability="privilege_escalation", confidence=confidence, evidence=evidence)
    return None


def _cap_reverse_shell(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[CapabilityTag]:
    """Cross-platform — remote shell access capability."""
    shell_spawn = dynamic and any(
        proc in str(dynamic.process_tree).lower() for proc in ("/bin/sh", "/bin/bash", "cmd.exe", "powershell")
    )
    has_network = dynamic and len(dynamic.network_connections) > 0
    if shell_spawn and has_network:
        return CapabilityTag(
            capability="remote_shell_access",
            confidence=0.8,
            evidence=["spawned a command shell with an active network connection — remote control capability"],
        )
    return None


def _cap_library_hijack(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[CapabilityTag]:
    """Linux — LD_PRELOAD hijacking for stealth/persistence."""
    static_hit = any("LD_PRELOAD" in kw for kw in static.extracted_strings.suspicious_keywords)
    dynamic_hit = dynamic and any("LD_PRELOAD" in c for c in dynamic.api_calls)
    if static_hit or dynamic_hit:
        confidence = 0.75 if dynamic_hit else 0.5
        return CapabilityTag(
            capability="library_hijacking",
            confidence=confidence,
            evidence=["uses LD_PRELOAD to hijack library loading — stealth/persistence technique"],
        )
    return None


def _cap_downloader(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[CapabilityTag]:
    """Ingress tool transfer / dropper capability."""
    tools = ("curl", "wget", "ftpget", "tftp", "busybox wget")
    dynamic_hit = dynamic and any(
        tool in str(dynamic.process_tree).lower() or tool in str(dynamic.api_calls).lower()
        for tool in tools
    )
    static_hit = any(
        tool in kw.lower() for kw in static.extracted_strings.suspicious_keywords for tool in tools
    )
    if dynamic_hit or static_hit:
        return CapabilityTag(
            capability="downloader",
            confidence=0.85 if dynamic_hit else 0.65,
            evidence=["downloads external payloads / tools via command-line utilities"],
        )
    return None


def _cap_cryptomining(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[CapabilityTag]:
    """Cryptomining / resource hijacking capability."""
    mining_indicators = ("stratum", "cryptonight", "xmrig", "monero", "minergate", "pool.mine")
    static_hit = any(
        m in kw.lower() for kw in static.extracted_strings.suspicious_keywords for m in mining_indicators
    )
    dynamic_conn_hit = dynamic and any(
        c.get("dest_port") in (3333, 8888, 9999, 14444) for c in dynamic.network_connections
    )
    if static_hit or dynamic_conn_hit:
        return CapabilityTag(
            capability="cryptomining",
            confidence=0.85 if (static_hit and dynamic_conn_hit) else 0.7,
            evidence=["exhibits cryptocurrency mining configuration or mining pool communication"],
        )
    return None


def _cap_anti_debug(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[CapabilityTag]:
    """Anti-debugging / debugger evasion capability."""
    anti_debug_terms = ("ptrace", "ptrace_traceme", "tracerpid", "isdebuggerpresent")
    static_hit = any(
        term in kw.lower() for kw in static.extracted_strings.suspicious_keywords for term in anti_debug_terms
    )
    dynamic_hit = dynamic and any(
        term in c.lower() for c in dynamic.api_calls for term in anti_debug_terms
    )
    if static_hit or dynamic_hit:
        return CapabilityTag(
            capability="anti_debug",
            confidence=0.85 if dynamic_hit else 0.65,
            evidence=["implements debugger evasion checks (ptrace/TracerPid/anti-debugging APIs)"],
        )
    return None


def _cap_c2_communication(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[CapabilityTag]:
    """Command & Control beaconing capability."""
    has_c2_conn = dynamic and any(c.get("flagged_c2") for c in dynamic.network_connections)
    has_c2_ep = dynamic and len(dynamic.c2_endpoints_detected) > 0
    static_c2 = "hardcoded_c2_ip" in static.static_risk_flags
    if has_c2_conn or has_c2_ep or static_c2:
        return CapabilityTag(
            capability="c2_communication",
            confidence=0.9 if (has_c2_conn or has_c2_ep) else 0.7,
            evidence=["communicates with confirmed or flagged command-and-control infrastructure"],
        )
    return None


CAPABILITY_RULES = [
    _cap_sms_otp_theft,
    _cap_gps_tracking,
    _cap_overlay_phishing,
    _cap_device_admin_persistence,
    _cap_data_exfiltration,
    _cap_keylogging,
    _cap_persistence,
    _cap_cron_persistence,
    _cap_launchd_persistence,
    _cap_privilege_escalation,
    _cap_reverse_shell,
    _cap_library_hijack,
    _cap_downloader,
    _cap_cryptomining,
    _cap_anti_debug,
    _cap_c2_communication,
]


def classify_capabilities(
    static: StaticAnalysisOutput,
    dynamic: Optional[DynamicAnalysisOutput],
) -> list[CapabilityTag]:
    results: list[CapabilityTag] = []
    for rule in CAPABILITY_RULES:
        match = rule(static, dynamic)
        if match:
            results.append(match)
    return results