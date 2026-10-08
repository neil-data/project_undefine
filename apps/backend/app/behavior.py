"""Evidence-bound static behavior inference for uploaded binaries.

This module describes capabilities indicated by collected artifacts. It never
turns a static indicator into a runtime event.
"""
from __future__ import annotations

import re
from typing import Any


_RULES = [
    ("Execution", r"createprocess|shellexecute|execve|execveat|system\(|runtime\.exec|processbuilder|loadlibrary|dlopen", "Process or program-launch API/import"),
    ("Command/Scripting", r"powershell|cmd\.exe|/bin/(?:ba)?sh|\bbusybox\b|wscript|cscript|python[23]?\.exe|\bsh -c\b", "Command interpreter or script-engine string"),
    ("Network/C2", r"winhttp|wininet|ws2_32|internetopen|https?://|\bsocket\b|connect\(|getaddrinfo|okhttp|httpurlconnection", "Network API/import or embedded endpoint indicator"),
    ("File System", r"createfile|writefile|fopen|open\(|write\(|filesdir|external_storage|/tmp/|/var/tmp/|\\users\\public\\", "File access API or file-path indicator"),
    ("Persistence", r"currentversion\\run|\\runonce|schtasks|create service|systemd|/etc/cron|init\.d|boot_completed|device_admin|startup", "Persistence-related path, command, component, or API"),
    ("Discovery", r"whoami|ipconfig|systeminfo|uname|/proc/(?:self|version|cpuinfo)|gethostbyname|querydisplayconfig|enumprocess|installed_packages", "Host or environment discovery indicator"),
    ("Credential/Data Access", r"credential|password|keylog|cookie|wallet|keystore|clipboard|accounts|sms|contacts|querycontentprovider|lsass", "Credential, account, or user-data access indicator"),
    ("Privilege/Access", r"se_debug_privilege|uac|\bsudo\b|setuid|setgid|request_.*permission|accessibility_service|device_admin", "Privilege or sensitive-access indicator"),
    ("Payload Dropping", r"writeprocessmemory|urlmon|downloadfile|downloadmanager|dexclassloader|payload|dropper|\.dll\b|\.so\b", "Payload-related API or artifact string"),
    ("Injection", r"virtualalloc(?:ex)?|writeprocessmemory|createremotethread|ptrace|process_vm_writev|inject", "Process-injection API or syscall indicator"),
    ("Defense Evasion", r"amsi.?scan|etw.?event|ntqueryinformationprocess|isdebuggerpresent|anti.?debug|anti.?analysis", "Anti-analysis or defense-evasion indicator"),
    ("Anti-VM/Anti-Sandbox", r"vmware|virtualbox| vbox|qemu|sandbox|wine_get|hypervisor|rdtsc", "Virtualization or sandbox detection indicator"),
    ("Obfuscation", r"obfuscat|upx|packed|packer|confuser|.?net reactor|control.?flow flatten", "Packing or obfuscation evidence"),
    ("Encryption", r"cryptencrypt|cryptdecrypt|bcrypt|aes|rsa|chacha|encrypt|decrypt", "Cryptographic API or algorithm string"),
    ("Communication", r"sendbroadcast|startservice|bindservice|ipc|named pipe|\bd-bus\b|binder", "IPC or inter-process communication indicator"),
]


def infer_static_behaviors(static: dict[str, Any], dynamic: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return sample-specific behavior findings with evidence and provenance."""
    details = static.get("format_details") or {}
    strings = static.get("extracted_strings") or {}
    evidence: list[str] = []
    for key in ("imports", "symbols", "libraries", "services", "activities", "receivers", "providers", "requested_permissions", "permissions", "components", "sections", "native_libraries"):
        value = details.get(key, []) if isinstance(details, dict) else []
        if value:
            evidence.extend(str(item) for item in value)
    for key in ("all", "keywords", "suspicious_keywords", "urls", "domains", "ips", "paths", "commands", "registry", "services", "libraries", "symbols"):
        value = strings.get(key, []) if isinstance(strings, dict) else []
        if isinstance(value, list):
            evidence.extend(str(item) for item in value)
    for item in static.get("yara_matches", []) or []:
        evidence.extend(str(item.get(k, "")) for k in ("rule_name", "category", "description"))
    evidence.extend(str(item) for item in static.get("explained_strings", []) or [])
    packing = static.get("packing") or {}
    if isinstance(packing, dict) and (packing.get("is_packed") or packing.get("packed")):
        evidence.extend(["packing detected", str(packing)])
    intel = static.get("malware_bazaar") or {}
    if isinstance(intel, dict) and intel.get("found"):
        evidence.append("Threat intelligence hash match")

    findings = []
    for category, pattern, reason in _RULES:
        matches = []
        for item in evidence:
            # Keep evidence snippets bounded and tied to actual extracted data.
            if re.search(pattern, item, re.IGNORECASE):
                snippet = item.strip()
                if snippet and snippet not in matches:
                    matches.append(snippet[:240])
                if len(matches) == 5:
                    break
        if matches:
            findings.append({
                "behavior": category,
                "assessment": "High" if len(matches) >= 3 else "Medium" if len(matches) >= 2 else "Low",
                "evidence": matches,
                "reason": reason + ("; this indicates capability, not proof of execution."),
                "source": "Static Inference",
                "runtime_verified": False,
                "evidence_state": "STATIC",
            })
    dyn = dynamic or {}
    status = str(dyn.get("dynamic_status") or dyn.get("status") or "unavailable").lower()
    observed_sources = (
        ("Process Activity", "process_tree"), ("Network/C2", "network_connections"),
        ("Network/C2", "dns_queries"), ("File System", "files_written"),
        ("Persistence", "registry_changes"), ("Persistence", "persistence_artifacts"),
        ("Command/Scripting", "api_calls"),
    )
    observed = []
    runtime_completed = status in {"completed", "no_behavior_observed"}
    for category, key in (observed_sources if runtime_completed else ()):
        items = dyn.get(key) or []
        if isinstance(items, list) and items:
            snippets = [str(item)[:240] for item in items[:5]]
            observed.append({
                "behavior": category, "assessment": "Observed", "evidence": snippets,
                "reason": f"{len(items)} runtime artifact(s) returned by dynamic analysis.",
                "source": "Dynamic Analysis", "runtime_verified": True,
                "evidence_state": "OBSERVED",
            })
    return {
        "status": "available" if findings else "insufficient_evidence",
        "dynamic_status": status,
        "fallback_reason": dyn.get("failure_reason") if status in {"failed", "timed_out", "unavailable", "not_configured", "unsupported"} else None,
        "findings": findings,
        "observed_findings": observed,
        "message": "Static evidence supports the listed capabilities; these are not runtime observations." if findings else "Insufficient evidence to infer specific behavior from the available static artifacts.",
    }
