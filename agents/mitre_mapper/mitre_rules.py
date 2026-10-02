"""
mitre_rules.py — Real MITRE ATT&CK mapping logic.

Rule-based engine: each rule checks a condition against combined
static + dynamic signals and, if matched, emits a MitreTechnique.
This replaces the Week 2 hardcoded stub with something that actually
scales as more signal types come in (add a rule = add a dict entry,
no graph changes needed).

To extend: add a new entry to MITRE_RULES. Each rule is a function
that takes (static, dynamic) and returns a MitreTechnique or None.
"""

from __future__ import annotations
from typing import Optional
from pathlib import Path

from agents.orchestrator.schema import StaticAnalysisOutput, DynamicAnalysisOutput, MitreTechnique


def _rule_sms_access(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    perms = static.android_manifest.permissions if static.android_manifest else []
    sms_perm = any("SMS" in p for p in perms)
    sms_api = dynamic and any("SmsManager" in c or "sms" in c.lower() for c in dynamic.api_calls)
    if sms_perm or sms_api:
        confidence = 0.9 if (sms_perm and sms_api) else 0.7
        return MitreTechnique(technique_id="T1517", technique_name="Access Notifications", confidence=confidence)
    return None


def _rule_c2_comms(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    static_c2 = "hardcoded_c2_ip" in static.static_risk_flags
    dynamic_c2 = dynamic and any(conn.get("flagged_c2") for conn in dynamic.network_connections)
    if static_c2 or dynamic_c2:
        confidence = 0.9 if (static_c2 and dynamic_c2) else 0.65
        return MitreTechnique(technique_id="T1071", technique_name="Application Layer Protocol (C2)", confidence=confidence)
    return None


def _rule_overlay_ui(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    perms = static.android_manifest.permissions if static.android_manifest else []
    if any("SYSTEM_ALERT_WINDOW" in p for p in perms):
        return MitreTechnique(technique_id="T1417", technique_name="Input Capture (Overlay)", confidence=0.75)
    return None


def _rule_device_admin_abuse(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    dynamic_admin = dynamic and any("DevicePolicyManager" in c for c in dynamic.api_calls)
    if dynamic_admin:
        return MitreTechnique(technique_id="T1626", technique_name="Abuse Elevation Control Mechanism (Device Admin)", confidence=0.8)
    return None


def _rule_location_tracking(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    perms = static.android_manifest.permissions if static.android_manifest else []
    location_perm = any("LOCATION" in p for p in perms)
    location_api = dynamic and any("LocationManager" in c for c in dynamic.api_calls)
    if location_perm or location_api:
        confidence = 0.85 if (location_perm and location_api) else 0.6
        return MitreTechnique(technique_id="T1430", technique_name="Location Tracking", confidence=confidence)
    return None


def _rule_data_encoded_exfil(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    persistent_write = dynamic and len(dynamic.files_written) > 0
    exfil_conn = dynamic and len(dynamic.network_connections) > 0
    if persistent_write and exfil_conn:
        return MitreTechnique(technique_id="T1005", technique_name="Data from Local System", confidence=0.55)
    return None


def _rule_registry_persistence(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    if dynamic and dynamic.registry_changes:
        run_key_persistence = any("Run" in rc or "Startup" in rc for rc in dynamic.registry_changes)
        if run_key_persistence:
            return MitreTechnique(
                technique_id="T1547.001",
                technique_name="Boot or Logon Autostart Execution: Registry Run Keys",
                confidence=0.85,
            )
    return None


def _rule_keylogging(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    keylog_api = dynamic and any(
        api in c for c in dynamic.api_calls
        for api in ("GetKeyboardState", "SetWindowsHookEx", "GetAsyncKeyState")
    )
    keylog_string = "keylog" in static.extracted_strings.suspicious_keywords
    if keylog_api or keylog_string:
        confidence = 0.85 if keylog_api else 0.6
        return MitreTechnique(technique_id="T1056.001", technique_name="Input Capture: Keylogging", confidence=confidence)
    return None


def _rule_cron_persistence(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    """Linux — persistence via cron/crontab."""
    if dynamic and any("cron" in a.lower() for a in dynamic.persistence_artifacts):
        return MitreTechnique(technique_id="T1053.003", technique_name="Scheduled Task/Job: Cron", confidence=0.85)
    return None


def _rule_launchd_persistence(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    """macOS — persistence via LaunchAgents/LaunchDaemons (launchd)."""
    if dynamic and any(
        "launchd" in a.lower() or "launchagent" in a.lower() or "launchdaemon" in a.lower()
        for a in dynamic.persistence_artifacts
    ):
        return MitreTechnique(
            technique_id="T1543.001",
            technique_name="Create or Modify System Process: Launch Agent",
            confidence=0.85,
        )
    return None


def _rule_ld_preload_hijack(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    """Linux — library injection via LD_PRELOAD."""
    static_hit = "LD_PRELOAD" in static.extracted_strings.suspicious_keywords or any(
        "LD_PRELOAD" in kw for kw in static.extracted_strings.suspicious_keywords
    )
    dynamic_hit = dynamic and any("LD_PRELOAD" in c for c in dynamic.api_calls)
    if static_hit or dynamic_hit:
        return MitreTechnique(
            technique_id="T1574.006",
            technique_name="Hijack Execution Flow: Dynamic Linker Hijacking (LD_PRELOAD)",
            confidence=0.75 if dynamic_hit else 0.55,
        )
    return None


def _rule_setuid_privilege_escalation(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    """Linux/macOS — setuid/setgid abuse for privilege escalation."""
    binary_imports = static.binary_analysis.imports if static.binary_analysis else []
    static_hit = any("setuid" in imp.lower() or "setgid" in imp.lower() for imp in binary_imports)
    dynamic_hit = dynamic and any("setuid" in c.lower() or "setgid" in c.lower() for c in dynamic.api_calls)
    if static_hit or dynamic_hit:
        return MitreTechnique(
            technique_id="T1548.001",
            technique_name="Abuse Elevation Control Mechanism: Setuid and Setgid",
            confidence=0.8 if dynamic_hit else 0.55,
        )
    return None


def _rule_reverse_shell(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    """
    Cross-platform (ELF/Mach-O/PE) — classic reverse-shell pattern:
    spawning a shell/command interpreter combined with a live network
    connection.
    """
    shell_spawn = dynamic and any(
        proc in str(dynamic.process_tree).lower() for proc in ("/bin/sh", "/bin/bash", "cmd.exe", "powershell")
    )
    has_network = dynamic and len(dynamic.network_connections) > 0
    if shell_spawn and has_network:
        return MitreTechnique(technique_id="T1059", technique_name="Command and Scripting Interpreter", confidence=0.85)
    return None


def _rule_unix_shell(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    """T1059.004 — Command and Scripting Interpreter: Unix Shell."""
    shell_spawn = dynamic and any(
        proc in str(dynamic.process_tree).lower() for proc in ("/bin/sh", "/bin/bash")
    )
    has_network = dynamic and len(dynamic.network_connections) > 0
    if shell_spawn and has_network:
        return MitreTechnique(technique_id="T1059.004", technique_name="Command and Scripting Interpreter: Unix Shell", confidence=0.85)
    return None


def _rule_ingress_tool_transfer(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    """T1105 — Ingress Tool Transfer (curl, wget, ftpget, tftp)."""
    tools = ("curl", "wget", "ftpget", "tftp", "busybox wget")
    dynamic_hit = dynamic and any(
        tool in str(dynamic.process_tree).lower() or tool in str(dynamic.api_calls).lower()
        for tool in tools
    )
    static_hit = any(
        tool in kw.lower() for kw in static.extracted_strings.suspicious_keywords for tool in tools
    )
    if dynamic_hit or static_hit:
        return MitreTechnique(
            technique_id="T1105",
            technique_name="Ingress Tool Transfer",
            confidence=0.85 if dynamic_hit else 0.65,
        )
    return None


def _rule_resource_hijacking(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    """T1496 — Resource Hijacking (Cryptomining)."""
    mining_indicators = ("stratum", "cryptonight", "xmrig", "monero", "minergate", "pool.mine")
    static_hit = any(
        m in kw.lower() for kw in static.extracted_strings.suspicious_keywords for m in mining_indicators
    )
    dynamic_conn_hit = dynamic and any(
        c.get("dest_port") in (3333, 8888, 9999, 14444) for c in dynamic.network_connections
    )
    if static_hit or dynamic_conn_hit:
        return MitreTechnique(
            technique_id="T1496",
            technique_name="Resource Hijacking: Cryptomining",
            confidence=0.85 if (static_hit and dynamic_conn_hit) else 0.7,
        )
    return None


def _rule_hidden_files(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    """T1564.001 — Hide Artifacts: Hidden Files and Directories."""
    hidden_path = dynamic and any(
        any(part.startswith(".") and len(part) > 1 for part in Path(f).parts)
        for f in (dynamic.files_written + dynamic.persistence_artifacts)
    )
    if hidden_path:
        return MitreTechnique(
            technique_id="T1564.001",
            technique_name="Hide Artifacts: Hidden Files and Directories",
            confidence=0.8,
        )
    return None


def _rule_debugger_evasion(static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> Optional[MitreTechnique]:
    """T1622 — Debugger Evasion (ptrace / TracerPid only)."""
    anti_debug_terms = ("ptrace", "ptrace_traceme", "tracerpid", "isdebuggerpresent")
    static_hit = any(
        term in kw.lower() for kw in static.extracted_strings.suspicious_keywords for term in anti_debug_terms
    )
    dynamic_hit = dynamic and any(
        term in c.lower() for c in dynamic.api_calls for term in anti_debug_terms
    )
    if static_hit or dynamic_hit:
        return MitreTechnique(
            technique_id="T1622",
            technique_name="Debugger Evasion",
            confidence=0.85 if dynamic_hit else 0.65,
        )
    return None



MITRE_RULES = [
    _rule_sms_access,
    _rule_c2_comms,
    _rule_overlay_ui,
    _rule_device_admin_abuse,
    _rule_location_tracking,
    _rule_data_encoded_exfil,
    _rule_registry_persistence,
    _rule_keylogging,
    _rule_cron_persistence,
    _rule_launchd_persistence,
    _rule_ld_preload_hijack,
    _rule_setuid_privilege_escalation,
    _rule_reverse_shell,
    _rule_unix_shell,
    _rule_ingress_tool_transfer,
    _rule_resource_hijacking,
    _rule_hidden_files,
    _rule_debugger_evasion,
]


def map_to_mitre(
    static: StaticAnalysisOutput,
    dynamic: Optional[DynamicAnalysisOutput],
) -> list[MitreTechnique]:
    """Run every rule against the combined signal set, return all matches."""
    results: list[MitreTechnique] = []
    for rule in MITRE_RULES:
        match = rule(static, dynamic)
        if match:
            results.append(match)
    return results