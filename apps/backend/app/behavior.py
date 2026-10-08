"""Evidence-bound behavior fusion for Android, PE, ELF, and related samples.

Static findings describe capabilities indicated by artifacts; runtime findings
are emitted only from completed dynamic-analysis telemetry. This module never
turns a prediction into a forensic event.
"""
from __future__ import annotations

import re
from typing import Any, Iterable


def _values(value: Any) -> Iterable[str]:
    """Flatten parser output while retaining concrete strings, not repr(dict)."""
    if isinstance(value, str):
        text = value.strip()
        if text:
            yield text[:300]
    elif isinstance(value, dict):
        for key, item in value.items():
            # Metadata and long explanations are not direct behavior evidence.
            if key.lower() in {"description", "explanation", "timestamp", "offset", "address"}:
                continue
            yield from _values(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _values(item)


def _collect_static_evidence(static: dict[str, Any]) -> list[dict[str, str]]:
    evidence: list[dict[str, str]] = []

    def add(source: str, value: Any) -> None:
        for item in _values(value):
            evidence.append({"source": source, "value": item})

    details = static.get("format_details") or {}
    # All are parser-backed fields; nested APK manifest entries, PE imports,
    # ELF symbols/libraries, and section metadata are flattened consistently.
    if isinstance(details, dict):
        for key in (
            "imports", "symbols", "libraries", "needed_libraries", "services",
            "activities", "receivers", "providers", "requested_permissions",
            "permissions", "components", "sections", "native_libraries",
            "exports", "indicators", "security", "suspicious_imports",
            "anti_analysis_indicators", "file_paths", "commands",
        ):
            if details.get(key):
                add(f"format_details.{key}", details[key])

    strings = static.get("extracted_strings") or {}
    if isinstance(strings, dict):
        for key, values in strings.items():
            add(f"extracted_strings.{key}", values)

    add("behavior_evidence", static.get("behavior_evidence"))

    for item in static.get("explained_strings") or []:
        if isinstance(item, dict):
            # The explanation is generated prose, so only use extracted value
            # and its parser-assigned type/category as evidence.
            add("explained_strings", item.get("value"))
            add("explained_strings.type", item.get("type"))
            add("explained_strings.category", item.get("category"))

    for match in static.get("yara_matches") or []:
        if not isinstance(match, dict):
            continue
        # Rule identifiers/categories and captured strings are evidence.
        # Free-form descriptions are deliberately excluded from rule matching.
        add("yara.rule_name", match.get("rule_name"))
        add("yara.category", match.get("category"))
        add("yara.matched_strings", match.get("matched_strings"))
        add("yara.mitre", match.get("mitre"))

    packing = static.get("packing") or {}
    if isinstance(packing, dict):
        if packing.get("is_packed") or packing.get("packed"):
            add("packing", "packer detected")
            add("packing", packing.get("packer_name"))
            add("packing.evidence", packing.get("evidence"))
        add("packing.high_entropy_sections", packing.get("high_entropy_sections"))

    # Explicit external-intelligence behavior fields can corroborate static
    # indicators. A family/signature name or vendor verdict alone cannot
    # create a behavior claim.
    for key in ("malware_bazaar", "threat_intelligence"):
        intel = static.get(key) or {}
        if isinstance(intel, dict) and intel.get("found"):
            for behavior_key in ("behaviors", "capabilities", "tags", "mitre"):
                add(f"{key}.{behavior_key}", intel.get(behavior_key))

    for item in static.get("_static_capability_tags") or []:
        if isinstance(item, dict) and str(item.get("evidence_state") or item.get("state") or "").upper() == "STATIC":
            add("static_capability", item.get("capability"))
            add("static_capability.evidence", item.get("evidence"))

    # Deduplicate while preserving provenance and extraction order.
    seen: set[tuple[str, str]] = set()
    result = []
    for item in evidence:
        identity = (item["source"], item["value"].casefold())
        if identity not in seen:
            seen.add(identity)
            result.append(item)
    return result


# (category, behavioral label, evidence expressions, rationale)
# Import/API evidence can indicate capability; paths and indicator strings are
# explicitly described as potential behavior rather than execution.
_RULES = [
    ("execution", "Process Activity", [r"createprocess", r"shellexecute", r"execve", r"execveat", r"processbuilder", r"runtime\.exec", r"loadlibrary", r"dlopen", r"startprocess", r"fork\("], "Process-launch API, syscall, or command evidence indicates execution capability."),
    ("command", "Command/Scripting", [r"powershell(?:\.exe)?", r"pwsh(?:\.exe)?", r"cmd\.exe", r"/bin/(?:ba)?sh", r"\bsh -c\b", r"wscript", r"cscript", r"schtasks\.exe", r"\bbusybox\b", r"-enc(?:odedcommand)?\b"], "A command interpreter or script-engine indicator is present; no command execution is implied."),
    ("network", "Network/C2", [r"winhttp", r"wininet", r"ws2_32", r"internetopen", r"internetconnect", r"http[s]?://", r"\bsocket\b", r"connect\(", r"getaddrinfo", r"gethostbyname", r"okhttp", r"httpurlconnection", r"curl_easy_", r"libcurl", r"network_communication", r"c2_communication"], "Network API, endpoint, or explicit network capability evidence indicates potential communication."),
    ("dns_http", "DNS/HTTP Indicators", [r"http[s]?://", r"dnsquery", r"getaddrinfo", r"gethostbyname", r"dns_lookup", r"host(?:name)?\s*[:=]"], "An embedded URL, DNS API, or host indicator is present; no DNS query or HTTP request is claimed."),
    ("file_activity", "File Activity", [r"createfile", r"writefile", r"deletefile", r"movefile", r"copyfile", r"fopen", r"fwrite", r"open\(", r"write\(", r"/tmp/", r"/var/tmp/", r"/etc/", r"\\users\\public\\", r"%appdata%", r"%temp%", r"filesdir", r"external_storage", r"\.docx\b", r"\.pdf\b"], "A file API or concrete filesystem path is present; this does not establish that a file was created or modified."),
    ("payload", "Payload/Dropper", [r"urlmon", r"urldownloadtofile", r"downloadfile", r"downloadmanager", r"dexclassloader", r"writeprocessmemory", r"dropper", r"payload"], "A download, payload-loading, or payload-related indicator is present."),
    ("persistence", "Persistence", [r"regsetvalue", r"regcreatekey", r"currentversion\\run", r"\\runonce", r"createservice", r"change service config", r"schtasks(?:\.exe)?", r"systemd", r"/etc/cron(?:\.d)?/", r"/etc/init\.d/", r"boot_completed", r"device_admin", r"startup"], "A persistence-specific API, autorun location, scheduled-task, service, or boot component is present."),
    ("discovery", "Discovery", [r"getcomputername", r"getusername", r"getversionex", r"globalmemorystatusex", r"enumprocess", r"process32first", r"querydisplayconfig", r"systeminfo", r"ipconfig", r"whoami", r"uname", r"/proc/(?:self|version|cpuinfo)", r"installed_packages", r"build\.\w+"], "A host, process, operating-system, or installed-software discovery indicator is present."),
    ("credential_data", "Credential/Data Access", [r"credential", r"credenumerate", r"credread", r"cryptunprotectdata", r"vaultopenvault", r"password", r"keylog", r"cookie", r"wallet", r"keystore", r"clipboard", r"lsass", r"samdatabase", r"credentialmanager", r"accounts", r"sms", r"contacts", r"querycontentprovider", r"token"], "A credential, account, or user-data indicator is present; access or theft is not confirmed."),
    ("privilege", "Privilege/Access", [r"sedebugprivilege", r"openprocesstoken", r"gettokeninformation", r"token_elevation", r"adjusttokenprivileges", r"uac", r"\bsudo\b", r"setuid", r"setgid", r"accessibility_service", r"device_admin", r"request_.*permission"], "A privilege query, elevation, or sensitive-access indicator is present."),
    ("defense_evasion", "Defense Evasion", [r"amsi.?scan", r"etw.?event", r"ntqueryinformationprocess", r"anti.?analysis", r"defense.?evasion", r"disable.?defender", r"exclusionpath"], "An anti-analysis or defense-evasion indicator is present."),
    ("anti_debug", "Anti-Debugging", [r"isdebuggerpresent", r"checkremotedebuggerpresent", r"ntqueryinformationprocess", r"outputdebugstring", r"anti.?debug", r"debuggercheck", r"debugport", r"beingdebugged", r"ptrace_traceme"], "A debugger-detection API, flag, or explicit anti-debug indicator is present."),
    ("anti_vm", "Anti-VM/Sandbox", [r"vmware", r"virtualbox", r"vbox", r"qemu", r"sandbox", r"wine_get", r"hypervisor", r"rdtsc", r"anti.?vm", r"virtual.?machine"], "A virtualization or sandbox detection indicator is present."),
    ("injection", "Injection", [r"virtualallocex", r"writeprocessmemory", r"createremotethread", r"ntmapviewofsection", r"queueuserapc", r"ptrace", r"process_vm_writev", r"process injection"], "A process-injection API or syscall indicator is present; injection is not observed."),
    ("obfuscation", "Obfuscation", [r"packer detected", r"high_entropy", r"upx", r"packed", r"obfuscat", r"confuser", r".net reactor", r"control.?flow flatten"], "Packing, high-entropy section, or obfuscation evidence is present."),
    ("encryption", "Encryption", [r"cryptencrypt", r"cryptdecrypt", r"bcrypt", r"cryptacquirecontext", r"aes", r"rsa", r"chacha", r"encrypt", r"decrypt"], "A cryptographic API, algorithm, or explicit encryption indicator is present; ransomware is not inferred."),
    ("communication", "IPC/Communication", [r"sendbroadcast", r"startservice", r"bindservice", r"named pipe", r"d-bus", r"binder", r"ipc"], "An inter-process or platform communication indicator is present."),
]


def _matches(rule: tuple[str, str, list[str], str], evidence: list[dict[str, str]]) -> list[str]:
    _, _, patterns, _ = rule
    matches: list[str] = []
    for artifact in evidence:
        value = artifact["value"]
        source = artifact["source"]
        # YARA identifiers/categories and captured strings are fair evidence;
        # generic category labels alone are too broad to establish a behavior.
        if source in {"yara.category", "yara.rule_name"} and not re.search(
            r"anti.?debug|anti.?vm|anti.?sandbox|persistence|credential|process.?inject|powershell|c2|network.?communication",
            value,
            re.IGNORECASE,
        ):
            continue
        if source == "static_capability" and not re.search(
            r"network|c2|execution|command|process|file|persistence|discovery|credential|data.?access|privilege|injection|evasion|anti.?debug|anti.?vm|encrypt|obfuscat|communication",
            value,
            re.IGNORECASE,
        ):
            continue
        if any(re.search(pattern, value, re.IGNORECASE) for pattern in patterns):
            snippet = f"{value} [{source}]"
            if snippet not in matches:
                matches.append(snippet[:360])
        if len(matches) >= 8:
            break
    return matches


def _confidence(category: str, matches: list[str]) -> str:
    joined = " ".join(matches).lower()
    direct = {
        "command": r"powershell|pwsh|cmd\.exe|/bin/(?:ba)?sh|wscript|cscript",
        "anti_debug": r"isdebuggerpresent|checkremotedebuggerpresent|anti.?debug|debuggercheck",
        "anti_vm": r"anti.?vm|anti.?sandbox|vmware|virtualbox|qemu",
        "injection": r"writeprocessmemory|createremotethread|ptrace|process_vm_writev|process injection",
        "persistence": r"currentversion\\run|\\runonce|regsetvalue|createservice|/etc/cron|systemd|boot_completed",
    }
    if category in direct and re.search(direct[category], joined):
        return "HIGH"
    if len(matches) >= 3:
        return "HIGH"
    if len(matches) >= 2:
        return "MEDIUM"
    return "LOW"


def _static_findings(static: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = _collect_static_evidence(static)
    file_type = str(static.get("file_type") or "").lower()
    platform = str(static.get("platform") or "").lower()
    findings = []
    for rule in _RULES:
        category, label, _, rationale = rule
        matches = _matches(rule, evidence)
        if not matches:
            continue
        confidence = _confidence(category, matches)
        if category in {"network", "dns_http", "file_activity"} and confidence == "HIGH":
            behavior = {
                "network": "Potential network communication",
                "dns_http": "DNS/HTTP indicators",
                "file_activity": "Potential file activity",
            }[category]
        else:
            behavior = label
        findings.append({
            "behavior": behavior,
            "category": category,
            "confidence": confidence,
            "assessment": confidence.title(),
            "evidence": matches,
            "source": "static_assessment",
            "runtime_verified": False,
            "evidence_state": "STATIC",
            "rationale": f"{rationale} Evidence is from {file_type or 'the analyzed sample'} static artifacts on {platform or 'an unknown platform'}; this is not a runtime observation.",
            "reason": rationale,
        })
    return findings


def _observed_findings(dynamic: dict[str, Any], status: str) -> list[dict[str, Any]]:
    if status not in {"completed", "no_behavior_observed", "incomplete"}:
        return []
    categories = (
        ("Process Activity", "execution", "process_tree"),
        ("Command Execution", "command", "commands"),
        ("Network/C2", "network", "http_requests"),
        ("Network/C2", "network", "network_connections"),
        ("DNS/HTTP Activity", "dns_http", "dns_queries"),
        ("File Activity", "file_activity", "files_written"),
        ("File Activity", "file_activity", "files_created"),
        ("File Activity", "file_activity", "files_modified"),
        ("File Activity", "file_activity", "files_deleted"),
        ("Persistence", "persistence", "registry_changes"),
        ("Persistence", "persistence", "persistence_artifacts"),
        ("Services", "persistence", "services"),
        ("IPC/Communication", "communication", "ipc_events"),
        ("Runtime API Activity", "runtime_api", "api_calls"),
    )
    observed = []
    for label, category, key in categories:
        values = dynamic.get(key) or []
        if isinstance(values, list) and values:
            serialized = [str(value)[:360] for value in values[:8]]
            observed.append({
                "behavior": label,
                "category": category,
                "confidence": "HIGH",
                "assessment": "Observed",
                "evidence": serialized,
                "source": "dynamic_analysis",
                "runtime_verified": True,
                "evidence_state": "OBSERVED",
                "rationale": f"{len(values)} artifact(s) were returned by completed dynamic analysis.",
                "reason": "Observed during the analyzed runtime; details are limited to the returned telemetry.",
            })
    command_lines = [
        item.get("cmdline") or item.get("command_line") or item.get("command")
        for item in dynamic.get("process_tree", [])
        if isinstance(item, dict) and (item.get("cmdline") or item.get("command_line") or item.get("command"))
    ]
    if command_lines:
        observed.append({
            "behavior": "Command Execution", "category": "command", "confidence": "HIGH",
            "assessment": "Observed", "evidence": [str(value)[:360] for value in command_lines[:8]],
            "source": "dynamic_analysis", "runtime_verified": True, "evidence_state": "OBSERVED",
            "rationale": f"{len(command_lines)} command line(s) were returned with observed process telemetry.",
            "reason": "Observed during dynamic analysis.",
        })
    return observed


def infer_static_behaviors(static: dict[str, Any], dynamic: dict[str, Any] | None = None) -> dict[str, Any]:
    """Fuse observed runtime evidence with sample-specific static assessment."""
    dyn = dynamic or {}
    status = str(dyn.get("dynamic_status") or dyn.get("status") or "unavailable").lower()
    static_context = dict(static)
    static_context["_static_capability_tags"] = [
        tag for tag in static.get("capability_tags", [])
        if isinstance(tag, dict) and str(tag.get("evidence_state") or tag.get("state") or "").upper() == "STATIC"
    ]
    static_findings = _static_findings(static_context)
    observed = _observed_findings(dyn, status)
    failure_states = {
        "failed", "timed_out", "timeout", "unavailable", "sandbox_unavailable",
        "provider_unavailable", "not_configured", "not_supported", "not_supported_platform",
        "unsupported", "unsupported_architecture", "error", "http_error", "http_404",
        "http_5xx", "http_4xx", "http_5xx_error", "submission_failed",
    }
    fallback = not observed and (status in failure_states or bool(dyn.get("failure_reason")))
    for finding in static_findings:
        finding["source"] = "behavioral_simulation" if fallback else "static_assessment"
    observed_categories = {finding["category"] for finding in observed}
    static_categories = {finding["category"] for finding in static_findings}
    if observed and static_findings:
        mode = "MIXED EVIDENCE"
    elif observed:
        mode = "RUNTIME VERIFIED"
    elif fallback and static_findings:
        mode = "BEHAVIORAL SIMULATION"
    elif static_findings:
        mode = "STATIC ASSESSMENT"
    else:
        mode = "INSUFFICIENT EVIDENCE"

    # Record where independent sources support the same category. We retain
    # separate findings/provenance instead of overwriting either source.
    for finding in observed:
        if finding["category"] in static_categories:
            finding["corroborated_by_static"] = True
    for finding in static_findings:
        if finding["category"] in observed_categories:
            finding["corroborated_by_runtime"] = True

    findings = observed + static_findings
    fallback_reason = dyn.get("failure_reason") if fallback else None
    return {
        "status": "available" if findings else "insufficient_evidence",
        "mode": mode,
        "dynamic_status": status,
        "fallback_reason": fallback_reason,
        "message": (
            "Runtime findings and sample-specific static indicators are shown with separate provenance."
            if mode == "MIXED EVIDENCE" else
            "Genuine runtime telemetry is shown; no static-only claims were added."
            if mode == "RUNTIME VERIFIED" else
            "Sandbox execution was unavailable. The listed behaviors are evidence-based static inferences, not executed events."
            if mode == "BEHAVIORAL SIMULATION" else
            "The listed capabilities are supported by static artifacts; execution was not verified."
            if mode == "STATIC ASSESSMENT" else
            "Insufficient evidence to infer specific behavior from the available artifacts."
        ),
        "findings": findings,
        # Keep these fields during migration for existing clients.
        "observed_findings": observed,
        "static_findings": static_findings,
        "evidence_categories": sorted({finding["category"] for finding in findings}),
    }
