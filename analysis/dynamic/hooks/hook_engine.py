"""
hook_engine.py — Turns a stream of API calls into behaviors.

THE CORE PROBLEM
----------------
Individual API calls are almost worthless as evidence. VirtualAlloc fires
thousands of times in a benign process. CryptEncrypt is what a password manager
does. GetProcAddress is ordinary dynamic linking.

What distinguishes malware is *ordering*:

    VirtualAlloc(RWX) → NtWriteVirtualMemory(other proc) → CreateRemoteThread
        = process injection, and essentially nothing else

    CreateFile(doc) → ReadFile → CryptEncrypt → WriteFile → DeleteFile
        repeated across hundreds of user documents
        = ransomware, not a backup tool

So this engine keeps a bounded sliding window of recent calls per process and
matches ordered chains against it. Individual calls are scored near zero; the
chains carry the weight.

WHY WINDOWS ARE BOUNDED
-----------------------
A 30-minute Stage 7 run at a few hundred calls per second would exhaust memory
if every call were retained. Each process keeps a capped deque, and chain
matching only ever looks backwards within a time horizon, so cost stays flat
regardless of run length.
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Deque, Dict, List, Optional, Set, Tuple
from uuid import UUID, uuid4

from .api_catalog import (
    ACCESSIBILITY_TEXT_CHANGED,
    ACCESSIBILITY_WINDOW_STATE_CHANGED,
    API_CATALOG,
    AUDIO_SOURCES,
    ApiCategory,
    ApiHook,
    BaselineRisk,
    FLAG_NOT_FOCUSABLE,
    FLAG_NOT_TOUCHABLE,
    VIDEO_SOURCES,
    WINDOW_TYPES,
    classify_content_uri,
    dangerous_permissions,
    decode_flags,
    has_credential_search_term,
    is_covert_audio_source,
    is_dangerous_permission,
    is_executable,
    is_overlay_window,
    is_rwx,
    resolve_api,
    PAGE_PROTECTION,
    PROCESS_CREATION_FLAGS,
)

_LOGGER = logging.getLogger(__name__)


# ============================================================================
# Events
# ============================================================================

@dataclass
class ApiCallEvent:
    """One observed API call, normalized from the guest hook."""
    call_id: UUID
    analysis_id: UUID

    api_name: str                      # Canonical catalog name
    raw_name: str                      # As hooked (CreateFileW, VirtualAllocEx)
    module: str

    timestamp: datetime
    pid: int
    tid: int

    args: Dict[str, Any] = field(default_factory=dict)
    decoded_args: Dict[str, Any] = field(default_factory=dict)
    return_value: Optional[Any] = None

    # Stage attribution — filled by the pipeline so the dashboard can show
    # which of the eight stages provoked this call.
    stage_id: Optional[str] = None

    # Populated by the engine
    category: Optional[ApiCategory] = None
    baseline_risk: Optional[BaselineRisk] = None
    mitre: List[str] = field(default_factory=list)

    # True when this call is a link in a matched chain. Standalone noisy calls
    # stay False and get filtered out of the default dashboard view.
    part_of_chain: bool = False

    @property
    def target_pid(self) -> Optional[int]:
        """Foreign process this call operates on, if any."""
        return self.decoded_args.get("target_pid")


class ChainSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class BehaviorChain:
    """A matched sequence of calls that together constitute a behavior."""
    chain_id: UUID
    analysis_id: UUID
    rule_id: str

    name: str
    description: str          # Plain language, for the investigator
    severity: ChainSeverity

    pid: int
    started_at: datetime
    completed_at: datetime

    call_ids: List[UUID] = field(default_factory=list)
    api_sequence: List[str] = field(default_factory=list)
    mitre: List[str] = field(default_factory=list)

    risk_points: int = 0
    stage_id: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration_sec(self) -> float:
        return (self.completed_at - self.started_at).total_seconds()


# ============================================================================
# Chain rules
# ============================================================================

@dataclass
class ChainRule:
    """
    An ordered sequence of APIs that, seen together within a time window,
    constitutes a named behavior.

    `sequence` is ordered but not necessarily contiguous — unrelated calls may
    interleave, which they always do in practice.
    """
    rule_id: str
    name: str
    description: str
    severity: ChainSeverity
    sequence: List[str]
    window_sec: float
    risk_points: int
    mitre: List[str] = field(default_factory=list)

    # Extra conditions beyond ordering, evaluated against the matched calls.
    # Keyed by API name; value is a predicate over the ApiCallEvent.
    conditions: Dict[str, str] = field(default_factory=dict)

    # All calls must come from one process (injection) vs. may span (delivery)
    same_process: bool = True

    # Rules whose sequence is a superset of this one. When a superseding rule
    # matches the same triggering call, this rule stays silent.
    #
    # Without this, one injection reports twice: once as the full
    # alloc→write→thread chain and again as the write→thread subset, which are
    # the same event described at two levels of detail. Two findings for one
    # behavior inflates the apparent severity and wastes the investigator's
    # attention.
    superseded_by: List[str] = field(default_factory=list)


CHAIN_RULES: List[ChainRule] = [

    # ---- Process injection ------------------------------------------------
    ChainRule(
        rule_id="classic_injection",
        name="Process injection",
        description=(
            "The program reserved executable memory inside another running "
            "program, wrote code into it, and then started that code running. "
            "This is how malware hides inside trusted software so that "
            "security tools and the user see only the legitimate program."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["VirtualAlloc", "NtWriteVirtualMemory", "CreateRemoteThread"],
        window_sec=30.0,
        risk_points=55,
        mitre=["T1055.002"],
        conditions={"VirtualAlloc": "rwx_or_exec", "NtWriteVirtualMemory": "foreign_process"},
    ),

    ChainRule(
        rule_id="injection_no_alloc",
        name="Process injection into existing memory",
        description=(
            "The program wrote code directly into another running program's "
            "memory and started it, reusing memory that was already there. "
            "This is a quieter variant of process injection that avoids the "
            "memory allocation that monitoring tools usually watch for."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["NtWriteVirtualMemory", "CreateRemoteThread"],
        window_sec=15.0,
        risk_points=50,
        mitre=["T1055.002"],
        conditions={"NtWriteVirtualMemory": "foreign_process"},
        # Both of these describe the same event in more detail. Only report
        # this narrower form when neither fuller chain was observed.
        superseded_by=["classic_injection", "process_hollowing"],
    ),

    ChainRule(
        rule_id="process_hollowing",
        name="Process hollowing",
        description=(
            "The program started a legitimate application in a frozen state, "
            "replaced its contents with different code, and then let it run. "
            "Anyone inspecting the system sees the name of the trusted "
            "application while entirely different code executes."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["CreateProcess", "NtWriteVirtualMemory", "CreateRemoteThread"],
        window_sec=60.0,
        risk_points=60,
        mitre=["T1055.012"],
        conditions={"CreateProcess": "suspended"},
    ),

    # ---- Unpacking --------------------------------------------------------
    ChainRule(
        rule_id="runtime_unpacking",
        name="Code unpacked at runtime",
        description=(
            "The program decoded hidden instructions into memory and then made "
            "that memory executable. This means its real behavior was "
            "concealed inside the file and only assembled once running, which "
            "is why file-based scanning would not have revealed it."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["VirtualAlloc", "VirtualProtect"],
        window_sec=20.0,
        risk_points=35,
        mitre=["T1027.002"],
        conditions={"VirtualProtect": "becomes_executable"},
    ),

    ChainRule(
        rule_id="decrypt_then_execute",
        name="Payload decrypted then executed",
        description=(
            "The program decrypted data and immediately made it executable. "
            "The working code was stored in encrypted form specifically so it "
            "could not be read by inspecting the file."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["CryptDecrypt", "VirtualProtect"],
        window_sec=30.0,
        risk_points=40,
        mitre=["T1140", "T1027"],
        conditions={"VirtualProtect": "becomes_executable"},
    ),

    # ---- Ransomware -------------------------------------------------------
    ChainRule(
        rule_id="ransomware_cycle",
        name="File encryption cycle",
        description=(
            "The program opened a document, read its contents, encrypted them, "
            "wrote the result back, and deleted the original. Repeated across "
            "many files this is the mechanism of a ransomware attack — the "
            "user's own files are made unreadable."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["ReadFile", "CryptEncrypt", "WriteFile"],
        window_sec=10.0,
        risk_points=50,
        mitre=["T1486"],
    ),

    ChainRule(
        rule_id="destructive_delete",
        name="Read then delete cycle",
        description=(
            "The program read files and then deleted them. Repeated in volume "
            "this indicates either data destruction or removal of originals "
            "after copies were taken."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["ReadFile", "DeleteFile"],
        window_sec=10.0,
        risk_points=30,
        mitre=["T1485", "T1070.004"],
    ),

    # ---- Persistence ------------------------------------------------------
    ChainRule(
        rule_id="drop_and_persist",
        name="Payload dropped and set to auto-start",
        description=(
            "The program wrote a file to disk and then registered it to launch "
            "automatically. The infection is designed to survive a restart and "
            "will run again every time the device is switched on."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["WriteFile", "RegCreateKey", "RegSetValue"],
        window_sec=120.0,
        risk_points=45,
        mitre=["T1547.001", "T1105"],
        conditions={"RegSetValue": "autostart_key"},
    ),

    ChainRule(
        rule_id="registry_persistence",
        name="Auto-start entry created",
        description=(
            "The program added an entry that makes it launch automatically "
            "when the device starts."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["RegCreateKey", "RegSetValue"],
        window_sec=30.0,
        risk_points=30,
        mitre=["T1547.001"],
        conditions={"RegSetValue": "autostart_key"},
    ),

    # ---- Exfiltration -----------------------------------------------------
    ChainRule(
        rule_id="collect_and_exfiltrate",
        name="Data collected and sent out",
        description=(
            "The program read files from the device and then transmitted data "
            "to an external server. This is the pattern of information theft — "
            "documents, credentials or personal data leaving the device."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["ReadFile", "InternetConnect", "WinHttpSendRequest"],
        window_sec=120.0,
        risk_points=50,
        mitre=["T1041", "T1005"],
    ),

    ChainRule(
        rule_id="encrypt_then_exfiltrate",
        name="Data encrypted before being sent",
        description=(
            "The program encrypted data and then transmitted it. Encrypting "
            "before sending is done to prevent network monitoring from "
            "revealing what was taken."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["CryptEncrypt", "WinHttpSendRequest"],
        window_sec=60.0,
        risk_points=45,
        mitre=["T1041", "T1027"],
    ),

    # ---- Concealment ------------------------------------------------------
    ChainRule(
        rule_id="dynamic_api_resolution",
        name="Capabilities hidden until runtime",
        description=(
            "The program loaded system components and looked up their "
            "functions while running, rather than declaring them in the file. "
            "This is done specifically so that inspecting the file does not "
            "reveal what the program is capable of."
        ),
        severity=ChainSeverity.MEDIUM,
        sequence=["LoadLibrary", "GetProcAddress"],
        window_sec=5.0,
        risk_points=20,
        mitre=["T1027"],
    ),

    ChainRule(
        rule_id="download_and_execute",
        name="Downloaded content executed",
        description=(
            "The program contacted an external server, saved what it received "
            "to disk, and then ran it. This is a downloader: the file examined "
            "here is only a delivery mechanism, and the actual payload arrives "
            "afterwards from the internet."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["WinHttpSendRequest", "WriteFile", "ShellExecute"],
        window_sec=180.0,
        risk_points=55,
        mitre=["T1105", "T1204"],
    ),

    ChainRule(
        rule_id="driver_communication",
        name="Direct communication with a driver",
        description=(
            "The program sent commands directly to a low-level system driver, "
            "bypassing normal operating system protections. This is associated "
            "with rootkits and with attacks that abuse legitimate drivers to "
            "gain deeper access to the device."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["CreateFile", "DeviceIoControl"],
        window_sec=30.0,
        risk_points=35,
        mitre=["T1211"],
        conditions={"CreateFile": "device_path"},
    ),

    # ---- Services (5.1) ---------------------------------------------------
    ChainRule(
        rule_id="service_persistence_install",
        name="Service installed for persistence",
        description=(
            "The program opened the Windows service manager, registered a new "
            "service, and started it. Services run automatically at boot and "
            "typically as SYSTEM, making this one of the most durable and "
            "privileged persistence mechanisms on Windows."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["OpenSCManager", "CreateService", "StartService"],
        window_sec=60.0,
        risk_points=55,
        mitre=["T1543.003"],
        conditions={"CreateService": "service_auto_start"},
    ),

    ChainRule(
        rule_id="service_hijack",
        name="Existing service hijacked",
        description=(
            "The program opened the service manager and modified an existing "
            "service's binary path. Replacing a legitimate service's executable "
            "redirects system-level code execution to the attacker's binary "
            "while retaining the original service name, making it harder to detect."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["OpenSCManager", "ChangeServiceConfig"],
        window_sec=30.0,
        risk_points=50,
        mitre=["T1543.003", "T1574"],
        conditions={"ChangeServiceConfig": "suspicious_binary_path"},
    ),

    ChainRule(
        rule_id="drop_and_install_service",
        name="File dropped and installed as service",
        description=(
            "The program wrote a file to disk and then installed it as a "
            "Windows service. This is the complete dropper-plus-persistence "
            "sequence: the payload arrives as a dropped file and is immediately "
            "registered for automatic execution on every boot."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["WriteFile", "OpenSCManager", "CreateService"],
        window_sec=120.0,
        risk_points=60,
        mitre=["T1543.003", "T1105"],
    ),

    # ---- Drivers (5.2) ----------------------------------------------------
    ChainRule(
        rule_id="driver_load_from_nonstandard_path",
        name="Driver loaded from non-system path",
        description=(
            "The program loaded a kernel driver from outside the standard "
            "Windows driver directory. Kernel drivers have unrestricted access "
            "to the entire system. Loading one from AppData, Temp, or a "
            "removable drive is the signature of a rootkit or a BYOVD attack."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["NtLoadDriver"],
        window_sec=5.0,
        risk_points=65,
        mitre=["T1014", "T1068", "T1543.003"],
        conditions={"NtLoadDriver": "nonstandard_driver_path"},
    ),

    ChainRule(
        rule_id="drop_and_load_driver",
        name="File dropped and loaded as kernel driver",
        description=(
            "The program wrote a file to disk and then loaded it into the "
            "kernel as a driver. This is the complete rootkit installation "
            "sequence: the malicious kernel module arrives as a dropped file "
            "and is immediately given unrestricted kernel-level access."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["WriteFile", "CreateService", "NtLoadDriver"],
        window_sec=120.0,
        risk_points=70,
        mitre=["T1014", "T1068", "T1543.003"],
        conditions={"NtLoadDriver": "nonstandard_driver_path"},
    ),

    ChainRule(
        rule_id="byovd_attack",
        name="Bring Your Own Vulnerable Driver (BYOVD)",
        description=(
            "The program loaded a driver and immediately communicated with it "
            "via low-level device control commands. Loading a signed but "
            "exploitable driver to then abuse it for privileged operations — "
            "such as disabling security software or writing to kernel memory — "
            "is a BYOVD (Bring Your Own Vulnerable Driver) attack."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["NtLoadDriver", "DeviceIoControl"],
        window_sec=30.0,
        risk_points=70,
        mitre=["T1068", "T1211"],
    ),

    # ---- Privilege Escalation (5.3) ---------------------------------------
    ChainRule(
        rule_id="token_impersonation_full",
        name="Privilege escalation via token impersonation",
        description=(
            "The program opened another process's security token, duplicated "
            "it with elevated permissions, and used it to spawn a new process. "
            "This steals the identity of a higher-privileged process — typically "
            "SYSTEM — and runs code under that identity without any kernel "
            "exploit, entirely in user space."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["OpenProcessToken", "DuplicateTokenEx", "CreateProcessWithToken"],
        window_sec=30.0,
        risk_points=60,
        mitre=["T1134.001", "T1134.002", "T1134.003"],
        conditions={"DuplicateTokenEx": "token_primary_type"},
    ),

    ChainRule(
        rule_id="token_impersonation_basic",
        name="Thread impersonating a privileged user",
        description=(
            "The program opened a security token and used it to impersonate "
            "a different user on the current thread. If the impersonated token "
            "belongs to a higher-privileged account this effectively elevates "
            "the thread's access rights for the duration of the impersonation."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["OpenProcessToken", "ImpersonateLoggedOnUser"],
        window_sec=15.0,
        risk_points=40,
        mitre=["T1134.003", "T1134"],
        superseded_by=["token_impersonation_full"],
    ),

    ChainRule(
        rule_id="privilege_enable_debug",
        name="SeDebugPrivilege enabled (credential dump precondition)",
        description=(
            "The program enabled the SeDebugPrivilege, which grants the ability "
            "to open and read the memory of any process including the OS "
            "credential store (lsass.exe). This privilege is almost exclusively "
            "used by debuggers and credential-dumping tools."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["OpenProcessToken", "AdjustTokenPrivileges"],
        window_sec=10.0,
        risk_points=55,
        mitre=["T1134.001", "T1003"],
        conditions={"AdjustTokenPrivileges": "debug_privilege_enabled"},
    ),

    ChainRule(
        rule_id="escalate_and_exec",
        name="Privilege escalated then process spawned",
        description=(
            "The program elevated its privileges and then started a new process. "
            "Elevating first then launching ensures the child process inherits "
            "the elevated security context, which is the pattern of lateral "
            "movement and UAC bypass payloads."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["AdjustTokenPrivileges", "CreateProcess"],
        window_sec=30.0,
        risk_points=50,
        mitre=["T1134", "T1548.002"],
        conditions={"AdjustTokenPrivileges": "any_privilege_enabled"},
    ),

    # ---- Defense Evasion (5.4) -----------------------------------------------
    ChainRule(
        rule_id="security_process_termination",
        name="Security software process terminated",
        description=(
            "The program terminated one or more processes. When targeted at "
            "antivirus, EDR, or security tools this is a defense evasion "
            "technique designed to disable protections before proceeding "
            "with malicious activities."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["OpenProcess", "TerminateProcess"],
        window_sec=15.0,
        risk_points=55,
        mitre=["T1562.001", "T1489"],
        conditions={"OpenProcess": "suspicious_target_process"},
    ),

    ChainRule(
        rule_id="security_service_disabled",
        name="Security service stopped or disabled",
        description=(
            "The program stopped a running Windows service. When the target "
            "is antivirus, firewall, or other security services this is a "
            "defense evasion technique to disable protection mechanisms."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["OpenSCManager", "ControlService"],
        window_sec=30.0,
        risk_points=50,
        mitre=["T1562.001", "T1543.003"],
        conditions={"ControlService": "service_stop"},
    ),

    ChainRule(
        rule_id="security_service_deleted",
        name="Security service configuration deleted",
        description=(
            "The program deleted a service entry from the service control "
            "manager. Deleting security services removes protection "
            "mechanisms and is a common defense evasion technique."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["OpenSCManager", "DeleteService"],
        window_sec=30.0,
        risk_points=50,
        mitre=["T1562.001", "T1070.006"],
    ),

    ChainRule(
        rule_id="registry_security_disabled",
        name="Security registry keys deleted or modified",
        description=(
            "The program deleted or modified registry keys used by security "
            "software or system policies. This disables security features, "
            "removes security tool configurations, or alters system policies "
            "to allow malicious activities."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["RegOpenKey", "RegDeleteValue"],
        window_sec=30.0,
        risk_points=40,
        mitre=["T1112", "T1562.001"],
        conditions={"RegOpenKey": "security_registry_key"},
    ),

    # ---- Process Reconnaissance (5.5) ---------------------------------------
    ChainRule(
        rule_id="process_enumeration_high_frequency",
        name="High-frequency process enumeration",
        description=(
            "The program repeatedly enumerated running processes. High-frequency "
            "process enumeration suggests the sample is monitoring for security "
            "tools, virtualization artifacts, or specific target processes to "
            "evade or attack."
        ),
        severity=ChainSeverity.MEDIUM,
        sequence=["EnumProcesses"],
        window_sec=60.0,
        risk_points=25,
        mitre=["T1057"],
        same_process=False,  # Multiple calls from same process indicate monitoring
    ),

    ChainRule(
        rule_id="module_enumeration_suspicious_target",
        name="Module enumeration of suspicious processes",
        description=(
            "The program enumerated loaded modules in one or more processes. "
            "When targeting system processes or security software this indicates "
            "reconnaissance for API addresses, security product detection, or "
            "injection target analysis."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["OpenProcess", "EnumProcessModules"],
        window_sec=30.0,
        risk_points=35,
        mitre=["T1057", "T1014"],
        conditions={"OpenProcess": "suspicious_target_process"},
    ),

    # ---- File System Reconnaissance (5.6) -----------------------------------
    ChainRule(
        rule_id="document_directory_enumeration",
        name="User document directory enumeration",
        description=(
            "The program searched through user document directories looking "
            "for files. This is the reconnaissance phase of ransomware or data "
            "theft, where the sample discovers what files exist before encrypting "
            "or exfiltrating them."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["FindFirstFile", "FindNextFile"],
        window_sec=30.0,
        risk_points=35,
        mitre=["T1083", "T1005"],
        conditions={"FindFirstFile": "document_pattern"},
    ),

    ChainRule(
        rule_id="system_directory_enumeration",
        name="System directory enumeration",
        description=(
            "The program searched through Windows system directories. This "
            "indicates reconnaissance for system files to replace, security "
            "tools to locate, or system configurations to modify."
        ),
        severity=ChainSeverity.MEDIUM,
        sequence=["FindFirstFile", "FindNextFile"],
        window_sec=30.0,
        risk_points=25,
        mitre=["T1083", "T1014"],
        conditions={"FindFirstFile": "system_pattern"},
    ),

    ChainRule(
        rule_id="file_replacement_attack",
        name="Legitimate file replaced with malicious copy",
        description=(
            "The program copied a file to a system directory. Replacing "
            "legitimate system binaries with malicious ones is a persistence "
            "and privilege escalation technique known as DLL search order "
            "hijacking or binary replacement."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["CopyFile"],
        window_sec=5.0,
        risk_points=40,
        mitre=["T1574.001", "T1547.001"],
        conditions={"CopyFile": "system_directory_destination"},
    ),

    # ---- Network C2 Patterns (5.7) ------------------------------------------
    ChainRule(
        rule_id="socket_based_c2",
        name="Custom socket-based C2 communication",
        description=(
            "The program established a raw socket connection and sent data. "
            "Custom TCP-based protocols that don't use HTTP are often used by "
            "malware for C2 communication to bypass HTTP inspection and proxy "
            "filtering."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["connect", "send"],
        window_sec=30.0,
        risk_points=40,
        mitre=["T1071.004", "T1041"],
    ),

    ChainRule(
        rule_id="high_frequency_beaconing",
        name="High-frequency network beaconing",
        description=(
            "The program sent repeated small requests to the same external "
            "server at regular intervals. This pattern is characteristic of "
            "C2 beaconing, where malware maintains contact with its command "
            "server for instructions and to indicate it's still active."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["WinHttpSendRequest"],
        window_sec=60.0,
        risk_points=35,
        mitre=["T1071.001", "T1102"],
        same_process=False,
    ),

    ChainRule(
        rule_id="direct_url_c2",
        name="Direct URL-based C2 communication",
        description=(
            "The program opened a full URL and sent data. Using high-level "
            "URL APIs like InternetOpenUrl is common in simple malware for "
            "C2 communication and payload delivery due to its simplicity."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["InternetOpenUrl"],
        window_sec=30.0,
        risk_points=35,
        mitre=["T1071.001", "T1105"],
    ),

    # ---- Advanced Persistence (5.8) -----------------------------------------
    ChainRule(
        rule_id="file_based_persistence",
        name="File copied to startup folder",
        description=(
            "The program copied a file to a user or system startup folder. "
            "Files in these directories are automatically executed at login, "
            "making this a simple but effective persistence mechanism."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["CopyFile"],
        window_sec=10.0,
        risk_points=40,
        mitre=["T1547.001"],
        conditions={"CopyFile": "startup_directory"},
    ),

    ChainRule(
        rule_id="file_moved_to_system_location",
        name="File moved to system directory for persistence",
        description=(
            "The program moved a file to a Windows system directory. Moving "
            "binaries to System32 or other system directories is a persistence "
            "technique that gives the file trusted location and makes it harder "
            "to detect."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["MoveFile"],
        window_sec=10.0,
        risk_points=40,
        mitre=["T1547.001", "T1074.001"],
        conditions={"MoveFile": "system_directory_destination"},
    ),

    ChainRule(
        rule_id="registry_run_key_persistence",
        name="Registry Run key persistence established",
        description=(
            "The program created or modified a registry Run key to execute "
            "a file at startup. Run keys are one of the most common persistence "
            "mechanisms on Windows and are widely used by malware."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["RegCreateKey", "RegSetValue"],
        window_sec=30.0,
        risk_points=35,
        mitre=["T1547.001"],
        conditions={"RegCreateKey": "run_key"},
    ),

    # ---- Lateral Movement Preparation (5.9) --------------------------------
    ChainRule(
        rule_id="credential_dumping_preparation",
        name="LSASS process opened for memory access",
        description=(
            "The program opened the LSASS process with access rights that "
            "allow reading its memory. LSASS contains cached credentials, and "
            "opening it with VM_READ rights is the first step of credential "
            "dumping attacks used for lateral movement."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["OpenProcess"],
        window_sec=5.0,
        risk_points=55,
        mitre=["T1003.001", "T1055"],
        conditions={"OpenProcess": "lsass_target"},
    ),

    ChainRule(
        rule_id="network_discovery",
        name="Network reconnaissance activity",
        description=(
            "The program performed network operations that indicate reconnaissance, "
            "such as resolving hostnames or establishing connections to multiple "
            "systems. This is often the precursor to lateral movement."
        ),
        severity=ChainSeverity.MEDIUM,
        sequence=["InternetConnect"],
        window_sec=60.0,
        risk_points=25,
        mitre=["T1010", "T1016"],
        same_process=False,
    ),

    # ======================================================================
    # Android (Phase 6)
    # ======================================================================
    #
    # The same premise as the Windows rules, applied to a different resource
    # set. Every one of these individual calls has a legitimate app that makes
    # it: a messaging app reads SMS, a maps app subscribes to location, a
    # password manager reads the clipboard. What none of them do is read the
    # resource and immediately hand it to a network endpoint or an SMS
    # recipient — that pairing is the finding.
    #
    # Windows-named links (InternetConnect, WriteFile) appear here on purpose:
    # the Android agent reports java.net.URL.openConnection as InternetConnect,
    # so the network half of each chain is shared with the Windows rules.

    # ---- SMS interception and abuse --------------------------------------
    ChainRule(
        rule_id="android_sms_interception",
        name="Text messages read and forwarded",
        description=(
            "The app read the phone's text messages and then sent a text "
            "message itself. This is how one-time passwords are stolen: the "
            "bank's OTP arrives on the victim's phone, the app reads it "
            "before the owner does and forwards it to the attacker, who "
            "completes the transaction. The victim sees a normal message and "
            "no sign that it was intercepted."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["ReadSMS", "SendSMS"],
        window_sec=60.0,
        risk_points=55,
        mitre=["T1636.004", "T1582"],
    ),

    ChainRule(
        rule_id="android_sms_exfiltration",
        name="Text messages read and uploaded",
        description=(
            "The app read the phone's text messages and then opened a network "
            "connection. The message history — bank alerts, one-time "
            "passwords, personal conversations — was taken off the device."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["ReadSMS", "InternetConnect"],
        window_sec=120.0,
        risk_points=50,
        mitre=["T1636.004", "T1639"],
    ),

    # ---- Contacts --------------------------------------------------------
    ChainRule(
        rule_id="android_contact_exfiltration",
        name="Contact list read and uploaded",
        description=(
            "The app read the phone's contacts and then opened a network "
            "connection. Beyond the theft itself, a stolen contact list is "
            "what makes the harassment stage of loan-app extortion possible — "
            "the victim's family and employer are contacted directly."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["ReadContacts", "InternetConnect"],
        window_sec=120.0,
        risk_points=40,
        mitre=["T1636.003", "T1639"],
    ),

    ChainRule(
        rule_id="android_contact_smishing",
        name="Contact list read and messaged",
        description=(
            "The app read the phone's contacts and then sent text messages. "
            "The malware is spreading itself through the victim's own address "
            "book, which is why the recipients trust the link — it arrives "
            "from someone they know."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["ReadContacts", "SendSMS"],
        window_sec=120.0,
        risk_points=50,
        mitre=["T1636.003", "T1582", "T1643"],
    ),

    # ---- Location --------------------------------------------------------
    ChainRule(
        rule_id="android_location_exfiltration",
        name="Position tracked and reported",
        description=(
            "The app subscribed to the phone's position and then opened a "
            "network connection. The device's movements were being reported "
            "to a remote party."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["RequestLocationUpdates", "InternetConnect"],
        window_sec=180.0,
        risk_points=40,
        mitre=["T1430", "T1639"],
    ),

    ChainRule(
        rule_id="android_cached_location_exfiltration",
        name="Cached position read and reported",
        description=(
            "The app read the last known position from the system cache and "
            "then opened a network connection. Using the cache avoids waking "
            "the GPS, so no location indicator appears for the user."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["GetLastKnownLocation", "InternetConnect"],
        window_sec=180.0,
        risk_points=35,
        mitre=["T1430", "T1639"],
    ),

    # ---- Clipboard -------------------------------------------------------
    ChainRule(
        rule_id="android_crypto_clipper",
        name="Payment address substituted in the clipboard",
        description=(
            "The app read the clipboard, found something the length of a "
            "wallet or payment address, and immediately replaced it. The "
            "victim pastes what they believe is the intended recipient and "
            "the money goes to the attacker instead. Nothing on screen looks "
            "wrong at any point."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["ClipboardRead", "ClipboardWrite"],
        window_sec=5.0,
        risk_points=55,
        mitre=["T1414"],
        conditions={"ClipboardRead": "crypto_address_clipboard"},
    ),

    ChainRule(
        rule_id="android_clipboard_hijack",
        name="Clipboard read and immediately overwritten",
        description=(
            "The app read what the user had copied and replaced it within "
            "seconds. Substituting the clipboard behind the user is how "
            "payment details get redirected."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["ClipboardRead", "ClipboardWrite"],
        window_sec=5.0,
        risk_points=35,
        mitre=["T1414"],
        superseded_by=["android_crypto_clipper"],
    ),

    ChainRule(
        rule_id="android_clipboard_exfiltration",
        name="Clipboard contents uploaded",
        description=(
            "The app read the clipboard and then opened a network connection. "
            "Whatever the user last copied — a password, a one-time code, an "
            "account number — left the device."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["ClipboardRead", "InternetConnect"],
        window_sec=120.0,
        risk_points=40,
        mitre=["T1414", "T1639"],
    ),

    # ---- Microphone and camera -------------------------------------------
    ChainRule(
        rule_id="android_audio_surveillance",
        name="Microphone recorded and uploaded",
        description=(
            "The app started recording from the microphone and then opened a "
            "network connection. Audio from the phone's surroundings was "
            "captured and sent to a remote party."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["AudioRecordStart", "InternetConnect"],
        window_sec=300.0,
        risk_points=55,
        mitre=["T1429", "T1639"],
    ),

    ChainRule(
        rule_id="android_covert_audio_recording",
        name="Covert audio recording session",
        description=(
            "The app configured a recording to capture the microphone or the "
            "phone call itself and then started it. Call recording in "
            "particular has no legitimate background use on an unmodified "
            "device."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["MediaRecorderAudioSource", "MediaRecorderStart"],
        window_sec=60.0,
        risk_points=40,
        mitre=["T1429"],
        conditions={"MediaRecorderAudioSource": "covert_audio_source"},
    ),

    ChainRule(
        rule_id="android_camera_surveillance",
        name="Camera opened and contents uploaded",
        description=(
            "The app opened the camera and then opened a network connection, "
            "with no camera screen shown to the user. Images or video were "
            "captured and sent off the device."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["CameraOpen", "InternetConnect"],
        window_sec=300.0,
        risk_points=50,
        mitre=["T1512", "T1639"],
    ),

    ChainRule(
        rule_id="android_covert_photo_capture",
        name="Covert photo capture without UI",
        description=(
            "The app took pictures using the camera without showing a camera "
            "interface to the user. This is surveillance — capturing images of "
            "the user or their surroundings without their knowledge."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["CameraTakePicture"],
        window_sec=10.0,
        risk_points=55,
        mitre=["T1512"],
    ),

    ChainRule(
        rule_id="android_camera_without_permission_flow",
        name="Camera accessed without user permission flow",
        description=(
            "The app accessed camera functions without triggering the normal "
            "permission request flow, indicating it's using privileged access "
            "or exploiting a vulnerability to bypass user consent."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["CameraOpen", "CameraSetParameters"],
        window_sec=15.0,
        risk_points=40,
        mitre=["T1512", "T1068"],
    ),

    # ---- Permission escalation (Phase 4) ------------------------------------
    ChainRule(
        rule_id="android_permission_escalation",
        name="Runtime permission escalation without user consent",
        description=(
            "The app directly granted itself permissions using privileged APIs, "
            "bypassing the normal user consent flow. This indicates root access "
            "or exploitation of permission system vulnerabilities."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["GrantRuntimePermission"],
        window_sec=5.0,
        risk_points=60,
        mitre=["T1626", "T1068"],
    ),

    ChainRule(
        rule_id="android_permission_state_manipulation",
        name="Permission state directly modified",
        description=(
            "The app directly modified permission states using privileged APIs. "
            "This is how malware with root access silently grants itself "
            "sensitive permissions without user interaction."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["SetPackagePermission"],
        window_sec=5.0,
        risk_points=55,
        mitre=["T1626", "T1068"],
    ),

    ChainRule(
        rule_id="android_overlay_permission_request",
        name="Overlay permission requested for malicious purposes",
        description=(
            "The app requested SYSTEM_ALERT_WINDOW permission at runtime. "
            "This permission is specifically required for drawing over other apps "
            "and is a prerequisite for tapjacking and overlay attacks."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["SystemAlertWindowRequest"],
        window_sec=10.0,
        risk_points=35,
        mitre=["T1417.002", "T1626"],
        conditions={"SystemAlertWindowRequest": "permission_granted"},
    ),

    # ---- SMS evidence destruction (Phase 4) ------------------------------------
    ChainRule(
        rule_id="android_sms_evidence_destruction",
        name="SMS messages deleted after reading",
        description=(
            "The app read SMS messages and then deleted them. This is evidence "
            "destruction — removing OTP messages, bank alerts, or transaction "
            "confirmations to hide fraudulent activity."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["ReadSMS", "DeleteSMS"],
        window_sec=60.0,
        risk_points=50,
        mitre=["T1636.004", "T1070.004"],
    ),

    ChainRule(
        rule_id="android_sms_mass_deletion",
        name="Mass SMS deletion",
        description=(
            "The app deleted multiple SMS messages in bulk. This indicates "
            "systematic evidence destruction, likely to hide ongoing fraudulent "
            "activity or to disrupt the victim's communications."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["DeleteSMS"],
        window_sec=30.0,
        risk_points=40,
        mitre=["T1636.004", "T1070.004"],
        same_process=False,
    ),

    ChainRule(
        rule_id="android_mms_payload_delivery",
        name="MMS used for payload delivery",
        description=(
            "The app downloaded MMS content from a server. MMS can be used as a "
            "covert channel to deliver malicious payloads or configuration data "
            "to the malware."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["DownloadMMS"],
        window_sec=10.0,
        risk_points=35,
        mitre=["T1105", "T1582"],
    ),

    # ---- Contact manipulation (Phase 4) --------------------------------------
    ChainRule(
        rule_id="android_contact_manipulation",
        name="Contact list modified for smishing campaign",
        description=(
            "The app wrote to the contacts database, adding attacker-controlled "
            "entries. This enables smishing campaigns where SMS messages appear "
            "to come from trusted contacts."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["WriteContacts"],
        window_sec=10.0,
        risk_points=40,
        mitre=["T1636.003", "T1582"],
    ),

    ChainRule(
        rule_id="android_contact_destruction",
        name="Contact list destruction",
        description=(
            "The app deleted contacts from the database. This destroys evidence "
            "of contact-based attacks and can be used to disrupt the victim's "
            "personal communications."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["DeleteContacts"],
        window_sec=10.0,
        risk_points=35,
        mitre=["T1636.003", "T1070.004"],
    ),

    ChainRule(
        rule_id="android_contact_replacement",
        name="Legitimate contacts replaced with fraudulent ones",
        description=(
            "The app deleted legitimate contacts and added fraudulent ones, "
            "effectively replacing the victim's address book with attacker-"
            "controlled entries for ongoing scams."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["DeleteContacts", "WriteContacts"],
        window_sec=30.0,
        risk_points=50,
        mitre=["T1636.003", "T1582"],
    ),

    # ---- Location tracking enhancement (Phase 4) ------------------------------
    ChainRule(
        rule_id="android_geofencing_surveillance",
        name="Geofencing configured for tracking",
        description=(
            "The app registered geofences (virtual perimeters) to trigger "
            "actions when the victim enters or leaves specific areas. This is "
            "used by stalkerware to monitor the victim's movements."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["GeofencingAdd"],
        window_sec=30.0,
        risk_points=40,
        mitre=["T1430"],
    ),

    ChainRule(
        rule_id="android_high_accuracy_tracking",
        name="High-accuracy location tracking in background",
        description=(
            "The app requested high-accuracy GPS location updates, which "
            "significantly impacts battery and provides precise tracking. "
            "Background high-accuracy requests indicate surveillance."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["LocationRequestHighAccuracy"],
        window_sec=10.0,
        risk_points=35,
        mitre=["T1430"],
        conditions={"LocationRequestHighAccuracy": "high_accuracy_requested"},
    ),

    ChainRule(
        rule_id="android_location_geofence_exfiltration",
        name="Geofencing triggers reported to remote server",
        description=(
            "The app set up geofences and then opened network connections, "
            "likely to report when the victim enters or leaves monitored areas."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["GeofencingAdd", "InternetConnect"],
        window_sec=60.0,
        risk_points=45,
        mitre=["T1430", "T1639"],
    ),

    # ---- Accessibility automation (Phase 4) ----------------------------------
    ChainRule(
        rule_id="android_accessibility_automation",
        name="Accessibility service performing automated actions",
        description=(
            "The app used accessibility services to perform actions (clicks, "
            "scrolls) in other apps automatically. This is how banking trojans "
            "auto-fill forms or dismiss security dialogs."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["AccessibilityEvent", "AccessibilityPerformAction"],
        window_sec=30.0,
        risk_points=50,
        mitre=["T1417.001", "T1516"],
    ),

    ChainRule(
        rule_id="android_accessibility_credential_automation",
        name="Accessibility service automating credential input",
        description=(
            "The app found credential fields and performed actions on them, "
            "indicating automated credential theft or form-filling for fraudulent "
            "transactions."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["AccessibilityFindByText", "AccessibilityPerformAction"],
        window_sec=15.0,
        risk_points=55,
        mitre=["T1417.001", "T1516"],
        conditions={"AccessibilityFindByText": "credential_search"},
    ),

    ChainRule(
        rule_id="android_accessibility_navigate_and_act",
        name="Accessibility service systematically navigating UI",
        description=(
            "The app systematically found nodes and performed actions, indicating "
            "programmatic UI navigation for automated fraud or data theft."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["AccessibilityFindAccessibilityNodeInfo", "AccessibilityPerformAction"],
        window_sec=30.0,
        risk_points=40,
        mitre=["T1417.001"],
    ),

    # ---- Overlay enhancement (Phase 4) ---------------------------------------
    ChainRule(
        rule_id="android_overlay_without_permission",
        name="Overlay created without proper permission flow",
        description=(
            "The app created overlay windows using alternative APIs without "
            "triggering the normal SYSTEM_ALERT_WINDOW permission request, "
            "indicating bypass attempts or privileged access."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["WindowManagerAddView"],
        window_sec=10.0,
        risk_points=40,
        mitre=["T1417.002", "T1068"],
    ),

    ChainRule(
        rule_id="android_overlay_with_permission_escalation",
        name="Overlay permission escalated then used",
        description=(
            "The app escalated overlay permissions and immediately created "
            "overlay windows, showing a systematic approach to enabling "
            "overlay-based attacks."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["SystemAlertWindowRequest", "OverlayWindowAdded"],
        window_sec=30.0,
        risk_points=55,
        mitre=["T1417.002", "T1626"],
        conditions={"SystemAlertWindowRequest": "permission_granted"},
    ),

    ChainRule(
        rule_id="android_automated_overlay_attack",
        name="Accessibility combined with overlay for automated attack",
        description=(
            "The app used accessibility services to detect app switches and "
            "created overlays when target apps came to the front. This is the "
            "classic banking trojan pattern for overlay attacks."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["AccessibilityEvent", "OverlayWindowAdded"],
        window_sec=30.0,
        risk_points=60,
        mitre=["T1417.001", "T1417.002"],
        conditions={"AccessibilityEvent": "window_change_event"},
    ),

    ChainRule(
        rule_id="android_video_recording",
        name="Camera recording session",
        description=(
            "The app configured a recording to take video from the camera and "
            "then started it."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["MediaRecorderVideoSource", "MediaRecorderStart"],
        window_sec=60.0,
        risk_points=35,
        mitre=["T1512"],
        conditions={"MediaRecorderVideoSource": "camera_video_source"},
    ),

    # ---- Accessibility abuse ---------------------------------------------
    ChainRule(
        rule_id="android_accessibility_credential_theft",
        name="On-screen credential fields located and read",
        description=(
            "The app is registered as an accessibility service — which lets "
            "it see everything on screen in every other app — and used that "
            "position to search the display for password, PIN, OTP or CVV "
            "fields. This is credential theft from inside the banking app's "
            "own screen, where nothing the user sees is fake."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["AccessibilityEvent", "AccessibilityFindByText"],
        window_sec=60.0,
        risk_points=55,
        mitre=["T1417.001", "T1516"],
        conditions={"AccessibilityFindByText": "credential_search"},
    ),

    ChainRule(
        rule_id="android_accessibility_exfiltration",
        name="Screen contents captured and uploaded",
        description=(
            "The app read on-screen content through the accessibility service "
            "and then opened a network connection. What the user typed and "
            "saw in other apps was sent off the device."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["AccessibilityEvent", "InternetConnect"],
        window_sec=180.0,
        risk_points=40,
        mitre=["T1417.001", "T1639"],
        conditions={"AccessibilityEvent": "text_capture_event"},
    ),

    # ---- Overlay attacks --------------------------------------------------
    ChainRule(
        rule_id="android_targeted_overlay",
        name="Fake screen drawn over the app in the foreground",
        description=(
            "The app watched for another application to come to the front and "
            "then drew its own window on top of it. This is the banking "
            "overlay attack: the victim opens their bank, a copy of the login "
            "screen appears over it, and the credentials go to the attacker "
            "while the real app sits untouched underneath. The bank's own "
            "records show a normal, unremarkable session."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["AccessibilityEvent", "OverlayWindowAdded"],
        window_sec=30.0,
        risk_points=60,
        mitre=["T1417.002", "T1516"],
        conditions={
            "AccessibilityEvent": "window_change_event",
            "OverlayWindowAdded": "overlay_window",
        },
    ),

    ChainRule(
        rule_id="android_overlay_credential_theft",
        name="Overlay window built and its contents uploaded",
        description=(
            "The app drew a window over other applications, filled it with a "
            "crafted layout, and then opened a network connection. A fake "
            "screen collected input and forwarded it."
        ),
        severity=ChainSeverity.CRITICAL,
        sequence=["OverlayWindowAdded", "LayoutInflate", "InternetConnect"],
        window_sec=120.0,
        risk_points=50,
        mitre=["T1417.002", "T1639"],
        conditions={"OverlayWindowAdded": "overlay_window"},
    ),

    # ---- Runtime code loading ---------------------------------------------
    ChainRule(
        rule_id="android_dynamic_dex_then_network",
        name="Code loaded at runtime, then network contact",
        description=(
            "The app loaded executable code that was not part of the "
            "installed package and then contacted the network. The behaviour "
            "that matters was never in the file that was scanned, which is "
            "why the app passed store review and static inspection."
        ),
        severity=ChainSeverity.HIGH,
        sequence=["LoadLibrary", "InternetConnect"],
        window_sec=180.0,
        risk_points=40,
        mitre=["T1407", "T1027"],
        conditions={"LoadLibrary": "dynamic_dex"},
    ),
]


# ============================================================================
# Condition predicates
# ============================================================================

AUTOSTART_KEY_MARKERS = (
    r"\run", r"\runonce", r"\services\\", r"\winlogon",
    r"\shell folders", r"\userinit", r"\image file execution options",
    r"\currentversion\policies\explorer\run",
)

SENSITIVE_DIR_MARKERS = (
    r"\documents", r"\desktop", r"\pictures", r"\downloads",
    r"\onedrive", r"\videos", r"\music",
)


def _cond_rwx_or_exec(call: ApiCallEvent) -> bool:
    prot = call.args.get("flProtect")
    return is_rwx(prot) or is_executable(prot)


def _cond_becomes_executable(call: ApiCallEvent) -> bool:
    return is_executable(call.args.get("flNewProtect"))


def _cond_foreign_process(call: ApiCallEvent) -> bool:
    """
    True when the write targets a process other than the caller.

    Self-writes are how packers unpack and are comparatively unremarkable;
    writing into someone else's address space is the injection signal.
    """
    target = call.decoded_args.get("target_pid")
    return target is not None and target != call.pid


def _cond_suspended(call: ApiCallEvent) -> bool:
    flags = call.args.get("dwCreationFlags") or 0
    return bool(flags & 0x00000004)   # CREATE_SUSPENDED


def _cond_autostart_key(call: ApiCallEvent) -> bool:
    path = str(
        call.decoded_args.get("full_key_path")
        or call.args.get("lpSubKey")
        or ""
    ).lower()
    return any(marker in path for marker in AUTOSTART_KEY_MARKERS)


def _cond_device_path(call: ApiCallEvent) -> bool:
    path = str(call.args.get("lpFileName") or "").lower()
    return path.startswith("\\\\.\\") or path.startswith("\\device\\")


# ---- Service conditions (5.1) -----------------------------------------------

def _cond_service_auto_start(call: ApiCallEvent) -> bool:
    """
    True when a service is configured to start automatically.
    SERVICE_AUTO_START (0x2) runs at boot; SERVICE_BOOT_START (0x0) runs even
    earlier. Both represent persistent execution — demand-start (0x3) does not.
    """
    start_type = call.args.get("dwStartType")
    if start_type is None:
        return True   # Unknown = assume persistent (safe over-reporting direction)
    return int(start_type) in (0x0, 0x1, 0x2)  # BOOT, SYSTEM, AUTO


_SUSPICIOUS_PATH_MARKERS = (
    "\\appdata",
    "\\temp",
    "\\tmp",
    "\\users\\public",
    "\\programdata",
    "%temp%",
    "%appdata%",
)


def _cond_suspicious_binary_path(call: ApiCallEvent) -> bool:
    """
    Flags when a service binary path points to a non-system, writable location.
    Legitimate services live in System32, Program Files, or vendor directories;
    anything in Temp or AppData strongly indicates service hijacking.
    """
    path = str(call.args.get("lpBinaryPathName") or "").lower()
    if not path:
        return False
    return any(marker in path for marker in _SUSPICIOUS_PATH_MARKERS)


# ---- Driver conditions (5.2) -------------------------------------------------

_STANDARD_DRIVER_PATHS = (
    r"\registry\machine\system\currentcontrolset\services",
    r"system32\drivers",
    r"syswow64\drivers",
)


def _cond_nonstandard_driver_path(call: ApiCallEvent) -> bool:
    """
    True when a driver is loaded from a path that is not under the standard
    Windows driver directory. Legitimate signed drivers are distributed via
    INF and live in System32\\drivers; anything else is the BYOVD signal.
    """
    path = str(call.args.get("DriverServiceName") or "").lower()
    if not path:
        return False
    # Legitimate service keys point to standard driver paths in their ImagePath
    # value. Malicious service keys point to Temp/AppData/USB paths.
    return not any(marker in path for marker in _STANDARD_DRIVER_PATHS)


# ---- Privilege escalation conditions (5.3) -----------------------------------

# SeDebugPrivilege LUID on all modern Windows versions.
# Low part = 0x14 (20 decimal), High part = 0
_SE_DEBUG_PRIVILEGE_LUID_LOW = 20


def _cond_debug_privilege_enabled(call: ApiCallEvent) -> bool:
    """
    True when AdjustTokenPrivileges is enabling SeDebugPrivilege (LUID=20).
    SeDebug grants open-process access to lsass, which is the credential-dump
    precondition. Legitimate code that needs this declares it explicitly;
    malware often enables it silently as an early step.
    """
    if call.args.get("DisableAllPrivileges"):
        return False
    first_luid = call.args.get("FirstLuid")
    if first_luid is None:
        return False
    try:
        # FirstLuid captured as readU64 string — low 32 bits are the LUID low part
        luid_val = int(first_luid) & 0xFFFFFFFF
        return luid_val == _SE_DEBUG_PRIVILEGE_LUID_LOW
    except (ValueError, TypeError):
        return False


def _cond_any_privilege_enabled(call: ApiCallEvent) -> bool:
    """True when AdjustTokenPrivileges is enabling (not disabling) privileges."""
    return (
        not call.args.get("DisableAllPrivileges", True)
        and int(call.args.get("PrivilegeCount") or 0) > 0
    )


def _cond_token_primary_type(call: ApiCallEvent) -> bool:
    """
    True when DuplicateTokenEx produces a TokenPrimary token.
    Primary tokens can be used with CreateProcessWithToken; impersonation tokens
    cannot. If the result is primary, the intent is to spawn an elevated process.
    """
    return int(call.args.get("TokenType") or 0) == 1  # TokenPrimary


# ---- Defense Evasion conditions (5.4) ---------------------------------------

# Suspicious process names for termination/analysis
_SUSPICIOUS_PROCESS_NAMES = {
    "avguard.exe", "avastui.exe", "avgui.exe", "avp.exe",  # Antivirus
    "msmpeng.exe", "wscsvc.exe", "wdnisservice.exe",  # Windows Defender
    "csrss.exe", "lsass.exe", "services.exe", "winlogon.exe",  # System processes
    "vmwareuser.exe", "vmwareservice.exe", "vboxservice.exe",  # Virtualization
}

# Security-related registry key paths
_SECURITY_REGISTRY_KEYS = {
    "software\\microsoft\\windows defender",
    "software\\microsoft\\windows currentversion\\run",
    "software\\microsoft\\windows currentversion\\policies",
    "system\\currentcontrolset\\services\\windefend",
}


def _cond_suspicious_target_process(call: ApiCallEvent) -> bool:
    """True when targeting a security or system process."""
    process_id = call.args.get("dwProcessId")
    if process_id:
        # Check against known suspicious PIDs (lsass is typically 600-800 range)
        # This is a simplified check - in production would use process name lookup
        return int(process_id) < 1000  # System processes typically have low PIDs
    return False


def _cond_service_stop(call: ApiCallEvent) -> bool:
    """True when ControlService is called with SERVICE_CONTROL_STOP (0x1)."""
    return int(call.args.get("dwControl") or 0) == 1


def _cond_security_registry_key(call: ApiCallEvent) -> bool:
    """True when opening security-related registry keys."""
    subkey = str(call.args.get("lpSubKey") or "").lower()
    return any(marker in subkey for marker in _SECURITY_REGISTRY_KEYS)


# ---- File System conditions (5.6) -------------------------------------------

# Document file patterns for ransomware/data theft detection
_DOCUMENT_PATTERNS = {
    "*.doc", "*.docx", "*.xls", "*.xlsx", "*.ppt", "*.pptx",  # Office docs
    "*.pdf", "*.txt", "*.rtf",  # Other documents
    "*.jpg", "*.jpeg", "*.png", "*.bmp",  # Images
    "*.mp4", "*.avi", "*.mov",  # Videos
    "*.zip", "*.rar", "*.7z",  # Archives
}

# System directory paths
_SYSTEM_DIRECTORIES = {
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows",
    "c:\\program files",
    "c:\\program files (x86)",
}

_STARTUP_DIRECTORIES = {
    "c:\\users\\",
    "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup",
    "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup",
    "programdata\\microsoft\\windows\\start menu\\programs\\startup",
}


def _cond_document_pattern(call: ApiCallEvent) -> bool:
    """True when searching for document file types."""
    filename = str(call.args.get("lpFileName") or "").lower()
    return any(pattern.replace("*", "") in filename for pattern in _DOCUMENT_PATTERNS)


def _cond_system_pattern(call: ApiCallEvent) -> bool:
    """True when searching in system directories."""
    filename = str(call.args.get("lpFileName") or "").lower()
    return any(dir in filename for dir in _SYSTEM_DIRECTORIES)


def _cond_system_directory_destination(call: ApiCallEvent) -> bool:
    """True when copying/moving to system directories."""
    dest_path = str(call.args.get("lpNewFileName") or call.args.get("lpDestination") or "").lower()
    return any(dir in dest_path for dir in _SYSTEM_DIRECTORIES)


def _cond_startup_directory(call: ApiCallEvent) -> bool:
    """True when copying to startup directories."""
    dest_path = str(call.args.get("lpNewFileName") or "").lower()
    return any(dir in dest_path for dir in _STARTUP_DIRECTORIES)


def _cond_run_key(call: ApiCallEvent) -> bool:
    """True when creating/modifying Run registry keys."""
    subkey = str(call.args.get("lpSubKey") or "").lower()
    return "run" in subkey and ("currentversion\\run" in subkey or "currentversion\\runonce" in subkey)


# ---- Lateral Movement conditions (5.9) --------------------------------------

def _cond_lsass_target(call: ApiCallEvent) -> bool:
    """True when opening LSASS process with memory access rights."""
    # LSASS typically has PID in specific range, but checking access rights is more reliable
    # PROCESS_VM_READ (0x10) or PROCESS_ALL_ACCESS (0x1F0FFF)
    access = int(call.args.get("dwDesiredAccess") or 0)
    return (access & 0x10) == 0x10 or access == 0x1F0FFF


# ---- Android conditions (6.x) -----------------------------------------------
#
# These read from decoded_args first and fall back to the raw guest flag.
# The guest already computes some of them (highFrequency, sensitiveSearch)
# because the value needed to decide is one the agent deliberately does not
# transmit — the clipboard text, the searched string. Recomputing on the host
# where possible keeps the decision auditable; trusting the guest flag where
# not is the price of not shipping the victim's data to the control plane.

def _as_int(value: Any) -> Optional[int]:
    """Frida reports numbers as ints, strings or floats depending on the type."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_bool(value: Any) -> bool:
    """Truthiness for guest flags, which arrive as bool, int or 'true'/'false'."""
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return bool(value)


def _cond_dangerous_permission(call: ApiCallEvent) -> bool:
    if call.decoded_args.get("dangerous_permissions"):
        return True
    return bool(dangerous_permissions(call.args.get("permissions")))


def _cond_sms_uri(call: ApiCallEvent) -> bool:
    return call.decoded_args.get("content_family") == "sms"


def _cond_contacts_uri(call: ApiCallEvent) -> bool:
    return call.decoded_args.get("content_family") == "contacts"


def _cond_high_frequency_location(call: ApiCallEvent) -> bool:
    """
    True when position is requested often enough to constitute tracking.

    A maps app asks for a fix while its screen is up. Ten-second polling from
    the background is a movement log, and the interval is the only thing that
    separates the two at the API level.
    """
    if _as_bool(call.args.get("highFrequency")):
        return True
    interval = _as_int(call.args.get("minTimeMs")) or _as_int(call.args.get("intervalMs"))
    return interval is not None and 0 < interval < 10_000


def _cond_crypto_address_clipboard(call: ApiCallEvent) -> bool:
    return _as_bool(call.args.get("possibleCryptoAddress"))


def _cond_covert_audio_source(call: ApiCallEvent) -> bool:
    if _as_bool(call.args.get("isMic")):
        return True
    return is_covert_audio_source(_as_int(call.args.get("source")))


def _cond_camera_video_source(call: ApiCallEvent) -> bool:
    return _as_int(call.args.get("source")) == 1   # VideoSource.CAMERA


def _cond_credential_search(call: ApiCallEvent) -> bool:
    if _as_bool(call.args.get("sensitiveSearch")):
        return True
    return has_credential_search_term(call.args.get("searchText"))


def _cond_text_capture_event(call: ApiCallEvent) -> bool:
    """TYPE_VIEW_TEXT_CHANGED — the service is seeing keystrokes."""
    if _as_bool(call.args.get("isTextChange")):
        return True
    event_type = _as_int(call.args.get("eventType")) or 0
    return bool(event_type & ACCESSIBILITY_TEXT_CHANGED)


def _cond_window_change_event(call: ApiCallEvent) -> bool:
    """TYPE_WINDOW_STATE_CHANGED — the service is tracking which app is in front."""
    if _as_bool(call.args.get("isWindowChange")):
        return True
    event_type = _as_int(call.args.get("eventType")) or 0
    return bool(event_type & ACCESSIBILITY_WINDOW_STATE_CHANGED)


def _cond_overlay_window(call: ApiCallEvent) -> bool:
    """
    True only for window types that can be drawn over other applications.

    Every app calls addView constantly for its own UI. Without this check the
    rule fires on ordinary screen drawing and the overlay finding becomes
    worthless.
    """
    if is_overlay_window(_as_int(call.args.get("windowType"))):
        return True
    return _as_bool(call.args.get("isOverlay"))


def _cond_invisible_overlay(call: ApiCallEvent) -> bool:
    """NOT_FOCUSABLE|NOT_TOUCHABLE — a transparent sheet that logs taps."""
    if _as_bool(call.args.get("invisibleTapLogger")):
        return True
    flags = _as_int(call.args.get("flags")) or 0
    return bool(flags & FLAG_NOT_FOCUSABLE) and bool(flags & FLAG_NOT_TOUCHABLE)


def _cond_dynamic_dex(call: ApiCallEvent) -> bool:
    """DexClassLoader — code that was not in the scanned package."""
    return _as_bool(call.args.get("dynamic_dex"))


# ---- Android conditions (Phase 4) -------------------------------------------

def _cond_permission_granted(call: ApiCallEvent) -> bool:
    """True when permission was granted."""
    return _as_bool(call.args.get("granted"))


def _cond_high_accuracy_requested(call: ApiCallEvent) -> bool:
    """True when high-accuracy location is requested."""
    quality = _as_int(call.args.get("quality") or 0)
    return quality == 100  # HIGH_ACCURACY


def _cond_window_change_event(call: ApiCallEvent) -> bool:
    """True when accessibility event is a window state change."""
    if _as_bool(call.args.get("isWindowChange")):
        return True
    event_type = _as_int(call.args.get("eventType")) or 0
    return bool(event_type & ACCESSIBILITY_WINDOW_STATE_CHANGED)


# Update the CONDITIONS dictionary
CONDITIONS = {
    # Existing
    "rwx_or_exec": _cond_rwx_or_exec,
    "becomes_executable": _cond_becomes_executable,
    "foreign_process": _cond_foreign_process,
    "suspended": _cond_suspended,
    "autostart_key": _cond_autostart_key,
    "device_path": _cond_device_path,
    # Phase 5.1 — Services
    "service_auto_start": _cond_service_auto_start,
    "suspicious_binary_path": _cond_suspicious_binary_path,
    # Phase 5.2 — Drivers
    "nonstandard_driver_path": _cond_nonstandard_driver_path,
    # Phase 5.3 — Privilege Escalation
    "debug_privilege_enabled": _cond_debug_privilege_enabled,
    "any_privilege_enabled": _cond_any_privilege_enabled,
    "token_primary_type": _cond_token_primary_type,
    # Phase 5.4 — Defense Evasion
    "suspicious_target_process": _cond_suspicious_target_process,
    "service_stop": _cond_service_stop,
    "security_registry_key": _cond_security_registry_key,
    # Phase 5.5 — Process Reconnaissance
    # (Conditions handled by rule configuration, no specific condition functions)
    # Phase 5.6 — File System Reconnaissance
    "document_pattern": _cond_document_pattern,
    "system_pattern": _cond_system_pattern,
    "system_directory_destination": _cond_system_directory_destination,
    "startup_directory": _cond_startup_directory,
    "run_key": _cond_run_key,
    # Phase 5.9 — Lateral Movement
    "lsass_target": _cond_lsass_target,
    # Phase 6 — Android
    "dangerous_permission": _cond_dangerous_permission,
    "sms_uri": _cond_sms_uri,
    "contacts_uri": _cond_contacts_uri,
    "high_frequency_location": _cond_high_frequency_location,
    "crypto_address_clipboard": _cond_crypto_address_clipboard,
    "covert_audio_source": _cond_covert_audio_source,
    "camera_video_source": _cond_camera_video_source,
    "credential_search": _cond_credential_search,
    "text_capture_event": _cond_text_capture_event,
    "window_change_event": _cond_window_change_event,
    "overlay_window": _cond_overlay_window,
    "invisible_overlay": _cond_invisible_overlay,
    "dynamic_dex": _cond_dynamic_dex,
    # Phase 4 — Android Enhanced
    "permission_granted": _cond_permission_granted,
    "high_accuracy_requested": _cond_high_accuracy_requested,
}


# ============================================================================
# Engine
# ============================================================================

# Bounded per-process history. Sized to comfortably span the longest chain
# window at realistic call rates without unbounded growth over a 30-minute run.
MAX_WINDOW_CALLS = 2000

# Volume thresholds at which repeated behavior becomes its own finding.
RANSOMWARE_CYCLE_THRESHOLD = 25
MASS_DELETE_THRESHOLD = 100
DYNAMIC_RESOLUTION_THRESHOLD = 50

# Android volume thresholds. Deliberately well above what an ordinary app does
# in a 30-minute detonation: a messaging app sends a handful of texts on user
# action, a maps app polls position while its screen is up, a password manager
# reads the clipboard when the user asks it to. Sustained, unattended activity
# at these rates is the thing being detected — none of these fire on a single
# legitimate-looking call.
ANDROID_SMS_BURST_THRESHOLD = 10
ANDROID_LOCATION_POLL_THRESHOLD = 20
ANDROID_AUDIO_READ_THRESHOLD = 50
ANDROID_CLIPBOARD_POLL_THRESHOLD = 30
ANDROID_KEYLOG_EVENT_THRESHOLD = 50
ANDROID_DANGEROUS_PERMISSION_THRESHOLD = 5


class HookEngine:
    """
    Consumes API call events, emits behavior chains and aggregate findings.

    Stateful per analysis. One instance per running sandbox.
    """

    def __init__(self, analysis_id: UUID, rules: Optional[List[ChainRule]] = None):
        self.analysis_id = analysis_id
        self.rules = rules or CHAIN_RULES

        # pid -> recent calls
        self._window: Dict[int, Deque[ApiCallEvent]] = defaultdict(
            lambda: deque(maxlen=MAX_WINDOW_CALLS)
        )

        # Chains already reported, so a long-running injection loop does not
        # emit the same finding hundreds of times.
        self._emitted: Dict[str, datetime] = {}

        # Aggregate counters
        self.call_counts: Dict[str, int] = defaultdict(int)
        self.calls_by_category: Dict[str, int] = defaultdict(int)
        self.calls_by_stage: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self.chain_counts: Dict[str, int] = defaultdict(int)

        # Handle tables: CreateFile returns a handle, ReadFile only carries the
        # handle. Without this mapping the path is lost by the time the read
        # happens, which is most of what makes file activity interpretable.
        self._file_handles: Dict[int, str] = {}
        self._reg_handles: Dict[int, str] = {}

        self.chains: List[BehaviorChain] = []
        self.total_calls = 0
        self.suppressed_calls = 0

        # Android aggregates that a raw call count cannot express: how many
        # accessibility events actually carried text, how many overlays were
        # the invisible kind, how much audio was really read off the mic.
        self.android_signals: Dict[str, int] = defaultdict(int)
        self.android_permissions: Set[str] = set()
        self.sms_destinations: Set[str] = set()
        self.observed_packages: Set[str] = set()
        self.audio_bytes_read = 0

        # Rate limiting state: api -> (window_start, count)
        self._rate_state: Dict[str, Tuple[float, int]] = {}

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------

    def ingest(self, raw: Dict[str, Any], stage_id: Optional[str] = None
               ) -> Tuple[Optional[ApiCallEvent], List[BehaviorChain]]:
        """
        Process one raw hook event.

        Returns the normalized call (None if dropped by rate limiting) and any
        chains that completed as a result.
        """
        raw_name = raw.get("api") or raw.get("name") or ""
        hook = resolve_api(raw_name)
        if hook is None:
            return None, []

        if self._rate_limited(hook):
            self.suppressed_calls += 1
            # Counters still advance — volume-based detections depend on the
            # true count, not the logged count.
            self.call_counts[hook.name] += 1
            self.total_calls += 1
            return None, []

        call = self._normalize(raw, hook, raw_name, stage_id)

        self.total_calls += 1
        self.call_counts[hook.name] += 1
        self.calls_by_category[hook.category.value] += 1
        if stage_id:
            self.calls_by_stage[stage_id][hook.name] += 1

        self._track_handles(call, hook)
        self._track_android_signals(call, hook)
        self._window[call.pid].append(call)

        # _match_chains has already counted every match; what it returns is the
        # deduplicated subset worth surfacing as distinct findings.
        chains = self._match_chains(call)
        self.chains.extend(chains)

        return call, chains

    def ingest_batch(self, raw_calls: List[Dict[str, Any]], stage_id: Optional[str] = None
                    ) -> List[BehaviorChain]:
        """
        Process multiple raw hook events.

        Returns all chains that completed as a result of processing the batch.
        """
        all_chains = []
        for raw in raw_calls:
            # Handle both dict and ApiCallEvent objects for test compatibility
            if isinstance(raw, dict):
                _, chains = self.ingest(raw, stage_id)
            else:
                # Assume it's an ApiCallEvent object
                # Manually process it through the engine logic
                self.total_calls += 1
                self.call_counts[raw.api_name] += 1
                if raw.category:
                    self.calls_by_category[raw.category.value] += 1
                if stage_id:
                    self.calls_by_stage[stage_id][raw.api_name] += 1
                
                self._window[raw.pid].append(raw)
                chains = self._match_chains(raw)
                self.chains.extend(chains)
            all_chains.extend(chains)
        return all_chains

    def _rate_limited(self, hook: ApiHook) -> bool:
        """Sliding one-second budget per API."""
        now = time.monotonic()
        start, count = self._rate_state.get(hook.name, (now, 0))

        if now - start >= 1.0:
            self._rate_state[hook.name] = (now, 1)
            return False

        if count >= hook.rate_limit_per_sec:
            self._rate_state[hook.name] = (start, count + 1)
            return True

        self._rate_state[hook.name] = (start, count + 1)
        return False

    def _normalize(self, raw: Dict[str, Any], hook: ApiHook,
                   raw_name: str, stage_id: Optional[str]) -> ApiCallEvent:
        args = raw.get("args", {}) or {}

        ts = raw.get("timestamp")
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except ValueError:
                ts = datetime.utcnow()
        elif not isinstance(ts, datetime):
            ts = datetime.utcnow()

        call = ApiCallEvent(
            call_id=uuid4(),
            analysis_id=self.analysis_id,
            api_name=hook.name,
            raw_name=raw_name,
            module=hook.module,
            timestamp=ts,
            pid=int(raw.get("pid", 0)),
            tid=int(raw.get("tid", 0)),
            args=args,
            return_value=raw.get("return"),
            stage_id=stage_id,
            category=hook.category,
            baseline_risk=hook.baseline_risk,
            mitre=list(hook.mitre),
        )

        call.decoded_args = self._decode(call, hook, raw)
        return call

    def _decode(self, call: ApiCallEvent, hook: ApiHook,
                raw: Dict[str, Any]) -> Dict[str, Any]:
        """Human-readable flag names, resolved handles, derived fields."""
        decoded: Dict[str, Any] = {}

        for arg in hook.args:
            if arg.flag_map and arg.name in call.args:
                value = call.args.get(arg.name)
                if isinstance(value, int):
                    decoded[f"{arg.name}_decoded"] = decode_flags(value, arg.flag_map)

        # Guest reports the target pid for cross-process operations; it cannot
        # be derived from the handle on this side.
        if "target_pid" in raw:
            decoded["target_pid"] = raw["target_pid"]

        # Resolve handles back to the paths recorded at open time
        if hook.name in ("ReadFile", "WriteFile"):
            handle = call.args.get("hFile")
            if handle in self._file_handles:
                decoded["path"] = self._file_handles[handle]

        if hook.name == "RegSetValue":
            handle = call.args.get("hKey")
            base = self._reg_handles.get(handle, "")
            sub = call.args.get("lpValueName", "")
            decoded["full_key_path"] = f"{base}\\{sub}" if base else sub

        if hook.name == "VirtualAlloc":
            decoded["is_rwx"] = is_rwx(call.args.get("flProtect"))

        if hook.name == "VirtualProtect":
            decoded["becomes_executable"] = is_executable(call.args.get("flNewProtect"))

        path = decoded.get("path") or call.args.get("lpFileName")
        if path:
            lowered = str(path).lower()
            decoded["in_user_documents"] = any(
                m in lowered for m in SENSITIVE_DIR_MARKERS
            )

        # DexClassLoader arrives under the LoadLibrary identity — a Windows
        # catalog entry — so this cannot live behind the platform gate below.
        if hook.name == "LoadLibrary" and _as_bool(call.args.get("dynamic_dex")):
            decoded["dynamic_dex"] = True

        if hook.platform == "android":
            decoded.update(self._decode_android(call, hook))

        return decoded

    @staticmethod
    def _decode_android(call: ApiCallEvent, hook: ApiHook) -> Dict[str, Any]:
        """
        Android-specific derived fields.

        The guest sends raw values; the interpretation lives here so the rule
        conditions, the evidence block and the dashboard all read the same
        derivation rather than three slightly different ones.
        """
        decoded: Dict[str, Any] = {}
        args = call.args

        if hook.name == "RequestPermissions":
            requested = args.get("permissions") or args.get("dangerous")
            dangerous = dangerous_permissions(requested)
            if dangerous:
                decoded["dangerous_permissions"] = dangerous
            if isinstance(requested, (list, tuple)):
                decoded["permission_count"] = len(requested)

        elif hook.name == "CheckPermission":
            decoded["is_dangerous"] = is_dangerous_permission(args.get("permission"))
            decoded["granted"] = _as_int(args.get("result")) == 0

        elif hook.name in ("ReadSMS", "ReadContacts"):
            family = classify_content_uri(args.get("uri"))
            if family:
                decoded["content_family"] = family

        elif hook.name in ("SendSMS", "SendMultipartSMS"):
            destination = args.get("destinationAddress")
            if destination:
                decoded["destination"] = str(destination)
            parts = _as_int(args.get("numParts"))
            if parts:
                decoded["multipart"] = parts > 1

        elif hook.name in ("RequestLocationUpdates", "FusedLocationUpdates"):
            decoded["high_frequency"] = _cond_high_frequency_location(call)
            interval = _as_int(args.get("minTimeMs")) or _as_int(args.get("intervalMs"))
            if interval is not None:
                decoded["interval_ms"] = interval

        elif hook.name == "ClipboardRead":
            decoded["possible_crypto_address"] = _as_bool(
                args.get("possibleCryptoAddress")
            )

        elif hook.name == "MediaRecorderAudioSource":
            source = _as_int(args.get("source"))
            if source is not None:
                decoded["audio_source_name"] = AUDIO_SOURCES.get(source, str(source))
            decoded["covert_audio"] = _cond_covert_audio_source(call)
            # Recording the call itself, rather than the room, is a separate
            # and materially more serious finding.
            decoded["records_call"] = source in (2, 3, 4)

        elif hook.name == "MediaRecorderVideoSource":
            source = _as_int(args.get("source"))
            if source is not None:
                decoded["video_source_name"] = VIDEO_SOURCES.get(source, str(source))

        elif hook.name == "AccessibilityEvent":
            decoded["captures_text"] = _cond_text_capture_event(call)
            decoded["watches_foreground_app"] = _cond_window_change_event(call)
            package = args.get("packageName")
            if package:
                decoded["observed_package"] = str(package)

        elif hook.name == "AccessibilityFindByText":
            decoded["credential_search"] = _cond_credential_search(call)

        elif hook.name == "OverlayWindowAdded":
            window_type = _as_int(args.get("windowType"))
            if window_type is not None:
                decoded["window_type_name"] = WINDOW_TYPES.get(
                    window_type, str(window_type)
                )
            decoded["is_overlay"] = _cond_overlay_window(call)
            decoded["invisible_tap_logger"] = _cond_invisible_overlay(call)

        return decoded

    def _track_handles(self, call: ApiCallEvent, hook: ApiHook) -> None:
        if hook.name == "CreateFile" and call.return_value is not None:
            path = call.args.get("lpFileName")
            if path:
                self._file_handles[call.return_value] = path
                # Bound the table — a long run can open a great many handles
                if len(self._file_handles) > 10000:
                    for key in list(self._file_handles)[:2000]:
                        del self._file_handles[key]

        if hook.name == "RegCreateKey" and call.return_value is not None:
            hive = (call.decoded_args.get("hKey_decoded") or [""])[0]
            sub = call.args.get("lpSubKey", "")
            self._reg_handles[call.return_value] = f"{hive}\\{sub}" if hive else sub

    def _track_android_signals(self, call: ApiCallEvent, hook: ApiHook) -> None:
        """
        Aggregate the Android facts that only mean something in quantity.

        Deliberately narrower than call_counts: an accessibility service
        receives events constantly, and the number that matters is how many
        carried typed text, not how many arrived. The same distinction applies
        to overlays (was it drawable over other apps?) and to the microphone
        (was the buffer actually read, or only opened?).
        """
        if hook.platform != "android":
            return

        name = hook.name
        decoded = call.decoded_args

        if name == "RequestPermissions":
            self.android_permissions.update(decoded.get("dangerous_permissions", []))

        elif name == "CheckPermission" and decoded.get("is_dangerous"):
            self.android_signals["dangerous_permission_checks"] += 1

        elif name in ("SendSMS", "SendMultipartSMS"):
            self.android_signals["sms_sent"] += 1
            destination = decoded.get("destination")
            if destination and len(self.sms_destinations) < 1000:
                self.sms_destinations.add(destination)

        elif name in ("RequestLocationUpdates", "GetLastKnownLocation",
                      "FusedLocationUpdates"):
            self.android_signals["location_requests"] += 1
            if decoded.get("high_frequency"):
                self.android_signals["high_frequency_location_requests"] += 1

        elif name in ("ClipboardRead", "ClipboardCheck"):
            self.android_signals["clipboard_polls"] += 1

        elif name == "AudioRecordRead":
            size = _as_int(call.args.get("sizeBytes")) or 0
            self.audio_bytes_read += max(0, size)
            self.android_signals["audio_reads"] += 1

        elif name == "MediaRecorderAudioSource" and decoded.get("records_call"):
            self.android_signals["call_recording_sessions"] += 1

        elif name == "AccessibilityEvent":
            if decoded.get("captures_text"):
                self.android_signals["accessibility_text_events"] += 1
            if decoded.get("watches_foreground_app"):
                self.android_signals["foreground_app_checks"] += 1
            package = decoded.get("observed_package")
            if package and len(self.observed_packages) < 500:
                self.observed_packages.add(package)

        elif name == "AccessibilityFindByText" and decoded.get("credential_search"):
            self.android_signals["credential_field_searches"] += 1

        elif name == "OverlayWindowAdded":
            if decoded.get("is_overlay"):
                self.android_signals["overlay_windows"] += 1
            if decoded.get("invisible_tap_logger"):
                self.android_signals["invisible_overlays"] += 1

    # ------------------------------------------------------------------
    # Chain matching
    # ------------------------------------------------------------------

    def _match_chains(self, trigger: ApiCallEvent) -> List[BehaviorChain]:
        """
        Match rules whose final API is the call we just saw.

        Anchoring on the last element means each chain is evaluated exactly
        once, when it completes, rather than re-scanning on every call.

        Counting and emission are deliberately separated. Every match is
        counted; only the first within a rule's window is emitted as a distinct
        chain. Conflating the two was a bug: ransomware encrypts thousands of
        files within seconds, so window-based dedup swallowed all but the first
        cycle and the mass-encryption threshold could never be reached. The
        dedup exists to keep the findings list readable, not to lose the
        volume evidence that makes the finding true.
        """
        candidates: List[Tuple[ChainRule, BehaviorChain]] = []

        for rule in self.rules:
            if rule.sequence[-1] != trigger.api_name:
                continue

            chain = self._try_match(rule, trigger)
            if chain is None:
                continue

            # Always count — volume detections depend on the true tally.
            self.chain_counts[rule.rule_id] += 1
            candidates.append((rule, chain))

        # Drop narrower rules when a fuller chain matched the same call, so one
        # behavior yields one finding rather than one per level of detail.
        matched_ids = {rule.rule_id for rule, _ in candidates}
        candidates = [
            (rule, chain) for rule, chain in candidates
            if not (matched_ids & set(rule.superseded_by))
        ]

        emitted: List[BehaviorChain] = []
        for rule, chain in candidates:
            key = f"{rule.rule_id}:{trigger.pid}"
            last = self._emitted.get(key)
            if last and (trigger.timestamp - last).total_seconds() < rule.window_sec:
                continue

            self._emitted[key] = trigger.timestamp
            emitted.append(chain)

        return emitted

    def _try_match(self, rule: ChainRule, trigger: ApiCallEvent
                   ) -> Optional[BehaviorChain]:
        """Walk backwards through the window looking for the rule's sequence."""
        history = self._window.get(trigger.pid)
        if not history:
            return None

        horizon = trigger.timestamp - timedelta(seconds=rule.window_sec)

        # Walk backwards, matching the sequence in reverse
        needed = list(rule.sequence[:-1])
        found: List[ApiCallEvent] = [trigger]

        if not self._satisfies(rule, trigger):
            return None

        for call in reversed(history):
            if call.call_id == trigger.call_id:
                continue
            if call.timestamp < horizon:
                break
            if not needed:
                break

            if call.api_name == needed[-1] and self._satisfies(rule, call):
                found.append(call)
                needed.pop()

        if needed:
            return None

        found.reverse()
        for call in found:
            call.part_of_chain = True

        return BehaviorChain(
            chain_id=uuid4(),
            analysis_id=self.analysis_id,
            rule_id=rule.rule_id,
            name=rule.name,
            description=rule.description,
            severity=rule.severity,
            pid=trigger.pid,
            started_at=found[0].timestamp,
            completed_at=trigger.timestamp,
            call_ids=[c.call_id for c in found],
            api_sequence=[c.api_name for c in found],
            mitre=list(rule.mitre),
            risk_points=rule.risk_points,
            stage_id=trigger.stage_id,
            evidence=self._evidence(found),
        )

    def _satisfies(self, rule: ChainRule, call: ApiCallEvent) -> bool:
        predicate_name = rule.conditions.get(call.api_name)
        if not predicate_name:
            return True
        predicate = CONDITIONS.get(predicate_name)
        return bool(predicate and predicate(call))

    @staticmethod
    def _evidence(calls: List[ApiCallEvent]) -> Dict[str, Any]:
        """Compact, human-meaningful detail from the matched calls."""
        ev: Dict[str, Any] = {}
        for call in calls:
            path = call.decoded_args.get("path") or call.args.get("lpFileName")
            if path:
                ev.setdefault("paths", []).append(str(path))
            key = call.decoded_args.get("full_key_path")
            if key:
                ev.setdefault("registry_keys", []).append(str(key))
            host = call.args.get("lpszServerName")
            if host:
                ev.setdefault("hosts", []).append(str(host))
            target = call.decoded_args.get("target_pid")
            if target is not None:
                ev["target_pid"] = target
            prot = call.decoded_args.get("flProtect_decoded")
            if prot:
                ev["protection"] = prot

            # Android evidence — the specific numbers, providers and apps an
            # investigator needs to name in the report.
            destination = call.decoded_args.get("destination")
            if destination:
                ev.setdefault("sms_destinations", []).append(str(destination))
            uri = call.args.get("uri")
            if uri:
                ev.setdefault("content_uris", []).append(str(uri))
            package = call.decoded_args.get("observed_package")
            if package:
                ev.setdefault("observed_packages", []).append(str(package))
            window_type = call.decoded_args.get("window_type_name")
            if window_type:
                ev["window_type"] = window_type
            audio_source = call.decoded_args.get("audio_source_name")
            if audio_source:
                ev["audio_source"] = audio_source
            permissions = call.decoded_args.get("dangerous_permissions")
            if permissions:
                ev.setdefault("permissions", []).extend(permissions)
            if call.decoded_args.get("credential_search"):
                search_text = call.args.get("searchText")
                if search_text:
                    ev.setdefault("credential_searches", []).append(str(search_text))
            if call.decoded_args.get("interval_ms") is not None:
                ev["location_interval_ms"] = call.decoded_args["interval_ms"]

        for field_name in ("paths", "registry_keys", "hosts", "sms_destinations",
                           "content_uris", "observed_packages", "permissions",
                           "credential_searches"):
            if field_name in ev:
                ev[field_name] = sorted(set(ev[field_name]))[:10]
        return ev

    # ------------------------------------------------------------------
    # Volume-based findings
    # ------------------------------------------------------------------

    def volume_findings(self) -> List[Dict[str, Any]]:
        """
        Behaviors that only become visible in aggregate.

        A single encrypt-write cycle is a file being saved. Nine hundred of
        them is a ransomware attack, and no individual call in that sequence
        looks any different from the others.
        """
        findings: List[Dict[str, Any]] = []

        ransom_cycles = self.chain_counts.get("ransomware_cycle", 0)
        if ransom_cycles >= RANSOMWARE_CYCLE_THRESHOLD:
            findings.append({
                "rule_id": "ransomware_volume",
                "name": "Mass file encryption",
                "severity": ChainSeverity.CRITICAL.value,
                "description": (
                    f"The read-encrypt-write cycle was repeated {ransom_cycles} "
                    f"times across separate files. Encryption at this scale is "
                    f"not a feature of normal software — it is an attack that "
                    f"renders the user's own documents unreadable."
                ),
                "count": ransom_cycles,
                "mitre": ["T1486"],
                "risk_points": 40,
            })

        deletes = self.call_counts.get("DeleteFile", 0)
        if deletes >= MASS_DELETE_THRESHOLD:
            findings.append({
                "rule_id": "mass_deletion",
                "name": "Mass file deletion",
                "severity": ChainSeverity.CRITICAL.value,
                "description": (
                    f"{deletes} files were deleted. This indicates either "
                    f"deliberate destruction of data or removal of originals "
                    f"after copies were taken."
                ),
                "count": deletes,
                "mitre": ["T1485"],
                "risk_points": 35,
            })

        resolutions = self.call_counts.get("GetProcAddress", 0)
        if resolutions >= DYNAMIC_RESOLUTION_THRESHOLD:
            findings.append({
                "rule_id": "heavy_dynamic_resolution",
                "name": "Capabilities systematically concealed",
                "severity": ChainSeverity.MEDIUM.value,
                "description": (
                    f"The program looked up {resolutions} system functions "
                    f"while running rather than declaring them in the file. "
                    f"At this volume the program's entire capability set was "
                    f"deliberately hidden from file inspection."
                ),
                "count": resolutions,
                "mitre": ["T1027"],
                "risk_points": 25,
            })

        findings.extend(self._android_volume_findings())
        return findings

    def _android_volume_findings(self) -> List[Dict[str, Any]]:
        """
        Android behaviours that only become visible in aggregate.

        Counts come from call_counts and android_signals rather than from the
        emitted call list, so a sample that floods a hook past its rate limit
        is measured on what it actually did, not on what survived logging.
        """
        findings: List[Dict[str, Any]] = []

        sms_sent = (
            self.call_counts.get("SendSMS", 0)
            + self.call_counts.get("SendMultipartSMS", 0)
        )
        if sms_sent >= ANDROID_SMS_BURST_THRESHOLD:
            recipients = len(self.sms_destinations)
            findings.append({
                "rule_id": "android_sms_burst",
                "name": "Mass text messaging",
                "severity": ChainSeverity.CRITICAL.value,
                "description": (
                    f"{sms_sent} text messages were sent without the user "
                    f"opening a messaging app"
                    + (f", to {recipients} different numbers" if recipients else "")
                    + ". At this volume the messages are either premium-rate "
                    "billing fraud charged to the victim's account, or the "
                    "malware spreading itself to other people."
                ),
                "count": sms_sent,
                "recipients": sorted(self.sms_destinations)[:20],
                "mitre": ["T1582", "T1643"],
                "risk_points": 40,
            })

        location_polls = self.android_signals.get("location_requests", 0)
        if location_polls >= ANDROID_LOCATION_POLL_THRESHOLD:
            high_freq = self.android_signals.get("high_frequency_location_requests", 0)
            findings.append({
                "rule_id": "android_continuous_tracking",
                "name": "Continuous location tracking",
                "severity": ChainSeverity.HIGH.value,
                "description": (
                    f"The device's position was requested {location_polls} "
                    f"times during the run"
                    + (f", {high_freq} of them at intervals under ten seconds"
                       if high_freq else "")
                    + ". Sustained polling with no map or navigation screen "
                    "in front of the user is a movement log being built."
                ),
                "count": location_polls,
                "mitre": ["T1430"],
                "risk_points": 30,
            })

        audio_reads = self.call_counts.get("AudioRecordRead", 0)
        if audio_reads >= ANDROID_AUDIO_READ_THRESHOLD:
            kb = self.audio_bytes_read // 1024
            findings.append({
                "rule_id": "android_sustained_audio_capture",
                "name": "Sustained microphone recording",
                "severity": ChainSeverity.CRITICAL.value,
                "description": (
                    f"Audio was pulled from the microphone {audio_reads} times"
                    + (f" ({kb} KB captured)" if kb else "")
                    + ". This is an active recording session, not a permission "
                    "check — the microphone was listening to the room while "
                    "the app showed nothing to indicate it."
                ),
                "count": audio_reads,
                "bytes_captured": self.audio_bytes_read,
                "mitre": ["T1429"],
                "risk_points": 40,
            })

        clipboard_polls = self.android_signals.get("clipboard_polls", 0)
        if clipboard_polls >= ANDROID_CLIPBOARD_POLL_THRESHOLD:
            findings.append({
                "rule_id": "android_clipboard_monitoring",
                "name": "Clipboard monitored continuously",
                "severity": ChainSeverity.HIGH.value,
                "description": (
                    f"The clipboard was inspected {clipboard_polls} times. "
                    f"Polling at this rate is a watcher waiting for the user "
                    f"to copy something worth taking — a password, a one-time "
                    f"code, a payment address."
                ),
                "count": clipboard_polls,
                "mitre": ["T1414"],
                "risk_points": 30,
            })

        text_events = self.android_signals.get("accessibility_text_events", 0)
        if text_events >= ANDROID_KEYLOG_EVENT_THRESHOLD:
            packages = len(self.observed_packages)
            findings.append({
                "rule_id": "android_accessibility_keylogging",
                "name": "Keystrokes captured across other apps",
                "severity": ChainSeverity.CRITICAL.value,
                "description": (
                    f"{text_events} text-entry events were captured from "
                    f"other applications"
                    + (f" across {packages} apps" if packages else "")
                    + " through the accessibility service. Everything the "
                    "victim typed — in their bank, their messages, their "
                    "email — was readable by this app."
                ),
                "count": text_events,
                "packages": sorted(self.observed_packages)[:20],
                "mitre": ["T1417.001"],
                "risk_points": 45,
            })

        invisible = self.android_signals.get("invisible_overlays", 0)
        if invisible:
            findings.append({
                "rule_id": "android_tapjacking",
                "name": "Invisible window layered over the screen",
                "severity": ChainSeverity.CRITICAL.value,
                "description": (
                    f"{invisible} window(s) were placed over the display that "
                    f"the user cannot see and cannot interact with. A layer "
                    f"like this exists to record where the victim taps, or to "
                    f"pass their taps through to a hidden control they never "
                    f"agreed to press."
                ),
                "count": invisible,
                "mitre": ["T1417.002", "T1516"],
                "risk_points": 45,
            })

        call_recording = self.android_signals.get("call_recording_sessions", 0)
        if call_recording:
            findings.append({
                "rule_id": "android_call_recording",
                "name": "Phone calls recorded",
                "severity": ChainSeverity.CRITICAL.value,
                "description": (
                    f"{call_recording} recording session(s) were configured to "
                    f"capture the call audio itself rather than the "
                    f"microphone. Conversations with banks, family and "
                    f"employers were recorded."
                ),
                "count": call_recording,
                "mitre": ["T1429", "T1512"],
                "risk_points": 40,
            })

        if len(self.android_permissions) >= ANDROID_DANGEROUS_PERMISSION_THRESHOLD:
            findings.append({
                "rule_id": "android_permission_escalation",
                "name": "Broad sensitive-permission escalation",
                "severity": ChainSeverity.MEDIUM.value,
                "description": (
                    f"The app requested {len(self.android_permissions)} "
                    f"separate sensitive permissions at runtime: "
                    f"{', '.join(sorted(self.android_permissions)[:8])}. "
                    f"A single app needing messages, contacts, location, the "
                    f"camera and the microphone at once has a purpose other "
                    f"than the one it advertises."
                ),
                "count": len(self.android_permissions),
                "permissions": sorted(self.android_permissions),
                "mitre": ["T1626"],
                "risk_points": 20,
            })

        return findings

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def risk_contribution(self) -> int:
        """
        Total risk points from hook monitoring, capped at 100.

        Repeat occurrences of the same chain add sharply diminishing value —
        the second injection is not twice as bad as the first — so repeats are
        scored on a logarithmic curve.
        """
        total = 0
        for rule_id, count in self.chain_counts.items():
            rule = next((r for r in self.rules if r.rule_id == rule_id), None)
            if not rule:
                continue
            total += rule.risk_points + int(rule.risk_points * 0.2 * math.log2(count)) \
                if count > 1 else rule.risk_points

        for finding in self.volume_findings():
            total += finding["risk_points"]

        return min(100, total)

    def summary(self) -> Dict[str, Any]:
        """Snapshot for the live dashboard and the stage report."""
        by_severity: Dict[str, int] = defaultdict(int)
        for chain in self.chains:
            by_severity[chain.severity.value] += 1

        mitre: Set[str] = set()
        for chain in self.chains:
            mitre.update(chain.mitre)

        return {
            "analysis_id": str(self.analysis_id),
            "total_calls": self.total_calls,
            "logged_calls": self.total_calls - self.suppressed_calls,
            "suppressed_calls": self.suppressed_calls,
            "calls_by_api": dict(self.call_counts),
            "calls_by_category": dict(self.calls_by_category),
            "calls_by_stage": {k: dict(v) for k, v in self.calls_by_stage.items()},
            "chains_detected": len(self.chains),
            "chains_by_rule": dict(self.chain_counts),
            "chains_by_severity": dict(by_severity),
            "volume_findings": self.volume_findings(),
            "android_signals": dict(self.android_signals),
            "android_permissions_requested": sorted(self.android_permissions),
            "mitre_techniques": sorted(mitre),
            "risk_contribution": self.risk_contribution(),
            "chains": [
                {
                    "chain_id": str(c.chain_id),
                    "rule_id": c.rule_id,
                    "name": c.name,
                    "description": c.description,
                    "severity": c.severity.value,
                    "pid": c.pid,
                    "api_sequence": c.api_sequence,
                    "duration_sec": round(c.duration_sec, 3),
                    "stage_id": c.stage_id,
                    "mitre": c.mitre,
                    "evidence": c.evidence,
                }
                for c in self.chains
            ],
        }

    def stage_breakdown(self) -> Dict[str, Dict[str, Any]]:
        """
        Which APIs and chains each pipeline stage provoked.

        This is what ties hook monitoring to the eight-stage pipeline: seeing
        that injection chains only appeared during the reboot stage is a
        materially different finding from seeing them at boot.
        """
        out: Dict[str, Dict[str, Any]] = {}
        for stage_id, counts in self.calls_by_stage.items():
            stage_chains = [c for c in self.chains if c.stage_id == stage_id]
            out[stage_id] = {
                "total_calls": sum(counts.values()),
                "calls_by_api": dict(counts),
                "chains": [c.name for c in stage_chains],
                "critical_chains": len(
                    [c for c in stage_chains if c.severity == ChainSeverity.CRITICAL]
                ),
            }
        return out
