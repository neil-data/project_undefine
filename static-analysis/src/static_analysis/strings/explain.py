"""Plain-language explanations for extracted strings and embedded indicators.

`StringExtractionService` and the format analyzers find *what* strings are
present; this module explains *why an investigator should care* — the same
"no jargon, explain victim impact" philosophy already used by the narrative
agent (`agents/narrative_agent/narrative.py`), applied one level down at the
individual-string level so the evidence behind a finding is legible on its
own, not just the finding's headline.

Single source of truth: `rules/builtin.py::SuspiciousStringsRule` imports
`KEYWORD_EXPLANATIONS` from here instead of keeping its own separate keyword
list, so the two can never drift apart.
"""

from static_analysis.strings.models import ExtractedString, StringExplanation, StringType

# keyword -> (category, severity, explanation). Order matters: checked in this
# order, first match wins, so more specific substrings should precede shorter
# ones they contain (e.g. "invoke-expression" before a hypothetical "invoke").
KEYWORD_EXPLANATIONS: tuple[tuple[str, str, str, str], ...] = (
    ("cmd.exe", "shell_execution", "medium",
     "Spawns the Windows command interpreter — often used to run attacker-supplied commands."),
    ("powershell", "living_off_the_land", "medium",
     "Invokes PowerShell, commonly used for fileless execution or to download a second-stage payload."),
    ("invoke-expression", "living_off_the_land", "high",
     "PowerShell 'Invoke-Expression' — executes a string as code, a common way to run obfuscated commands."),
    ("downloadstring", "download_primitive", "high",
     "Downloads and often immediately executes remote content — a classic dropper pattern."),
    ("/bin/sh", "shell_execution", "medium",
     "Spawns a Unix shell — indicates the sample can execute arbitrary commands."),
    ("/bin/bash", "shell_execution", "medium",
     "Spawns a Unix shell — indicates the sample can execute arbitrary commands."),
    ("wget ", "download_primitive", "medium",
     "Uses 'wget' to fetch a remote file — a common way to pull down a second-stage payload."),
    ("curl ", "download_primitive", "medium",
     "Uses 'curl' to fetch or transmit data over the network — may be used for download or exfiltration."),
    ("base64 -d", "obfuscation", "medium",
     "Decodes Base64 data — often used to deobfuscate a hidden payload at runtime."),
    ("chmod +x", "execution_prep", "medium",
     "Marks a file executable — typically a step just before running a dropped payload."),
    ("rundll32", "living_off_the_land", "high",
     "Uses the trusted Windows 'rundll32' utility to execute code — a common defense-evasion technique."),
    ("regsvr32", "living_off_the_land", "high",
     "Uses 'regsvr32' to run code via a registered COM/script handler — a known AppLocker/defense bypass."),
    ("mshta", "living_off_the_land", "high",
     "Uses 'mshta' to execute HTML Application (.hta) code — commonly abused to run scripts while evading detection."),
    ("certutil", "living_off_the_land", "high",
     "Uses 'certutil', a trusted Windows tool, to decode or download files — a well-known evasion trick."),
    ("iex(", "living_off_the_land", "high",
     "PowerShell 'IEX' (Invoke-Expression) shorthand — executes a string as code, often obfuscated."),
    ("eval(", "obfuscation", "medium",
     "Evaluates a string as code at runtime — a common way to hide the sample's real logic from static scanning."),
    ("system(", "shell_execution", "medium",
     "Calls the C library 'system()' function to run an arbitrary shell command."),
    ("ptrace", "anti_analysis", "medium",
     "Uses 'ptrace' — commonly used for anti-debugging checks or to inject into another process."),
    ("/proc/self/", "anti_analysis", "low",
     "Reads its own process information — often used to detect debuggers or sandboxing."),
    ("vfork", "process_injection", "low",
     "Creates a child process without fully copying the parent — sometimes paired with code injection."),
    ("reverse shell", "remote_access", "critical",
     "Indicates a reverse-shell pattern, granting an attacker interactive remote control of the device."),
    ("nc -e", "remote_access", "critical",
     "Uses netcat with command execution ('-e') — a classic way to open a reverse shell to an attacker."),
)

# Per-indicator-type explanations for strings the extraction service already
# classified as a network/filesystem/registry indicator (StringType != plain
# ASCII/UTF text) rather than matched against the keyword table above.
_INDICATOR_EXPLANATIONS: dict[StringType, tuple[str, str, str]] = {
    StringType.URL: ("network_indicator", "medium",
                      "Embedded URL — a potential command-and-control (C2) or data-exfiltration destination."),
    StringType.IPV4: ("network_indicator", "medium",
                       "Embedded IP address — a potential C2 server or exfiltration destination hardcoded into the sample."),
    StringType.IPV6: ("network_indicator", "medium",
                       "Embedded IPv6 address — a potential C2 server or exfiltration destination hardcoded into the sample."),
    StringType.DOMAIN: ("network_indicator", "medium",
                         "Embedded domain name — a potential C2 or exfiltration destination; worth a threat-intel lookup."),
    StringType.EMAIL: ("network_indicator", "low",
                        "Embedded email address — may be used for exfiltration, C2 registration, or attacker attribution."),
    StringType.REGISTRY_PATH: ("persistence", "medium",
                                "Windows registry path — may indicate persistence via a Run key or other autostart location."),
    StringType.WINDOWS_PATH: ("filesystem_indicator", "low",
                               "Windows filesystem path — shows where the sample reads, writes, or installs itself."),
    StringType.UNIX_PATH: ("filesystem_indicator", "low",
                            "Unix filesystem path — shows where the sample reads, writes, or installs itself."),
}


def _is_valid_unix_path(value: str) -> bool:
    if len(value) < 5 or not value.startswith("/"):
        return False
    parts = [p for p in value.split("/") if p]
    if not parts or all(len(p) <= 1 for p in parts):
        return False
    common_roots = (
        "bin", "boot", "dev", "etc", "home", "lib", "lib64", "media", "mnt",
        "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr",
        "var", "data", "system", "sdcard"
    )
    if parts[0].lower() in common_roots:
        return True
    return len(parts) >= 2 and len(value) >= 6


def explain_string(item: ExtractedString) -> StringExplanation | None:
    """Return a plain-language explanation for one extracted string, if any.

    Checks the keyword table first (covers command/shell/obfuscation
    literals regardless of what `StringType` they were tagged with), then
    falls back to the per-indicator-type table for URLs, IPs, domains, etc.
    Returns `None` for strings that aren't independently notable — most
    extracted strings are ordinary program text and shouldn't be flagged.
    """
    lowered = item.value.lower()
    for keyword, category, severity, explanation in KEYWORD_EXPLANATIONS:
        if keyword in lowered:
            return StringExplanation(
                value=item.value,
                string_type=item.string_type,
                category=category,
                explanation=explanation,
                severity=severity,
            )

    if item.string_type is StringType.UNIX_PATH and not _is_valid_unix_path(item.value):
        return None

    indicator = _INDICATOR_EXPLANATIONS.get(item.string_type)
    if indicator is not None:
        category, severity, explanation = indicator
        return StringExplanation(
            value=item.value,
            string_type=item.string_type,
            category=category,
            explanation=explanation,
            severity=severity,
        )

    return None
