"""
api_catalog.py — The monitored Win32 API surface.

WHY A CATALOG RATHER THAN A LIST OF NAMES
-----------------------------------------
Hooking an API is easy. Knowing what a call *means* is the hard part, and it
cannot be decided from the function name alone:

  • VirtualAlloc is called constantly by every benign process. It only matters
    when the protection is RWX, and it only matters *a lot* when it targets
    another process and is followed by a write and a remote thread.
  • CryptEncrypt is how password managers work. It is also how ransomware
    works. The difference is what came before it and how many files followed.
  • LoadLibrary + GetProcAddress is ordinary dynamic linking, unless the
    library names arrive as runtime-decoded strings, which is how malware
    hides its imports from static analysis.

So each entry carries: the risk it represents *in isolation*, which arguments
actually need capturing, which arguments must never be logged verbatim, and
what MITRE technique the call maps to. The sequence engine in hook_engine.py
consumes this to decide when a chain of individually-boring calls is a
behavior worth alerting on.

ARGUMENT CAPTURE IS DELIBERATELY NARROW
---------------------------------------
Capturing every argument of every call produces gigabytes per minute and buries
the signal. Each API declares only the parameters that carry investigative
weight. Buffer *contents* are almost never captured — a hash and a length tell
us what we need without turning the evidence store into a copy of the victim's
documents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ============================================================================
# Classification
# ============================================================================

class ApiCategory(str, Enum):
    """Broad behavioral family. Drives dashboard grouping and per-stage rollups."""
    FILESYSTEM = "filesystem"
    REGISTRY = "registry"
    NETWORK = "network"
    PROCESS = "process"
    MEMORY = "memory"
    INJECTION = "injection"
    DYNAMIC_RESOLUTION = "dynamic_resolution"
    CRYPTO = "crypto"
    DEVICE = "device"
    EXECUTION = "execution"

    # Android-only families. These have no Windows counterpart because the
    # sensitive resource is the phone itself — the SIM, the GPS, the
    # microphone — rather than the filesystem or the registry.
    PERMISSIONS = "permissions"
    SMS = "sms"
    LOCATION = "location"
    CONTACTS = "contacts"
    CLIPBOARD = "clipboard"
    CAMERA = "camera"
    MICROPHONE = "microphone"
    MEDIA_CAPTURE = "media_capture"
    ACCESSIBILITY = "accessibility"
    OVERLAY = "overlay"


class BaselineRisk(str, Enum):
    """
    How suspicious a single call is with no surrounding context.

    Most of these are BENIGN or LOW on purpose. A monitoring system that
    alerts on VirtualAlloc produces an unusable flood; the value is in the
    sequences, not the individual calls.
    """
    BENIGN = "benign"       # Ubiquitous in normal software
    LOW = "low"             # Common, mildly notable
    MEDIUM = "medium"       # Uncommon in benign software
    HIGH = "high"           # Rare outside malicious or admin tooling


@dataclass
class ApiArg:
    """One captured parameter."""
    name: str
    index: int                      # Positional index in the native call
    kind: str                       # 'string'|'wstring'|'int'|'pointer'|'flags'|'handle'|'buffer'
    note: str = ""

    # Buffers get hashed and length-recorded rather than copied. This keeps
    # victim document contents and credential material out of the evidence
    # store while still proving "the same 4KB block was encrypted 900 times".
    hash_only: bool = False

    # Redacted values are replaced before the event ever leaves the guest.
    # Key material must not transit to the control plane in cleartext even
    # inside an isolated lab.
    redact: bool = False

    # Decode numeric flags into readable names (PAGE_EXECUTE_READWRITE etc.)
    flag_map: Optional[Dict[int, str]] = None


@dataclass
class ApiHook:
    """A single monitored API."""
    name: str
    module: str
    category: ApiCategory
    baseline_risk: BaselineRisk

    # What this call does, in one line, for the report and the UI tooltip.
    purpose: str

    # Why we watch it — the malicious use, not the textbook definition.
    why_monitored: str

    args: List[ApiArg] = field(default_factory=list)
    mitre: List[str] = field(default_factory=list)

    # Capture the return value (handles, allocation addresses) — needed to
    # correlate later calls back to this one.
    capture_return: bool = True

    # Calls per second above which we stop logging individual calls and switch
    # to aggregate counting. Ransomware issues CryptEncrypt tens of thousands
    # of times; logging each one buys nothing and costs everything.
    rate_limit_per_sec: int = 100

    # Android/Frida equivalent, where one exists. Empty means Windows-only.
    android_equivalent: str = ""

    # Which guest this hook is installed in. Windows entries are installed by
    # the Frida/CAPE Win32 agent; Android entries by the Java-layer agent.
    # The distinction matters downstream: the CAPE monitor config and the
    # Win32 agent must not be handed Java class names.
    platform: str = "windows"

    @property
    def qualified_name(self) -> str:
        return f"{self.module}!{self.name}"


# ============================================================================
# Flag decoding
# ============================================================================

# Memory protection constants. RWX is the one that matters: legitimate code
# almost never needs a page that is simultaneously writable and executable,
# because that is precisely what you need to drop in shellcode and run it.
PAGE_PROTECTION = {
    0x01: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",   # RWX — the interesting one
    0x80: "PAGE_EXECUTE_WRITECOPY",
}

RWX_PROTECTIONS = {0x40, 0x80}
EXECUTABLE_PROTECTIONS = {0x10, 0x20, 0x40, 0x80}

MEM_ALLOCATION = {
    0x1000: "MEM_COMMIT",
    0x2000: "MEM_RESERVE",
    0x80000: "MEM_RESET",
    0x100000: "MEM_TOP_DOWN",
}

FILE_ACCESS = {
    0x80000000: "GENERIC_READ",
    0x40000000: "GENERIC_WRITE",
    0x20000000: "GENERIC_EXECUTE",
    0x10000000: "GENERIC_ALL",
}

REG_HIVES = {
    0x80000000: "HKEY_CLASSES_ROOT",
    0x80000001: "HKEY_CURRENT_USER",
    0x80000002: "HKEY_LOCAL_MACHINE",
    0x80000003: "HKEY_USERS",
    0x80000005: "HKEY_CURRENT_CONFIG",
}

PROCESS_CREATION_FLAGS = {
    0x00000004: "CREATE_SUSPENDED",   # Hallmark of process hollowing
    0x08000000: "CREATE_NO_WINDOW",
    0x00000008: "DETACHED_PROCESS",
    0x00000200: "CREATE_NEW_PROCESS_GROUP",
}


# ============================================================================
# Android constants
# ============================================================================

# Permissions that give access to data an investigator would consider
# sensitive. Requesting one is not itself malicious — the point of tracking
# them is that a runtime request is proof the app *uses* the permission, which
# a manifest declaration alone never is. Manifests routinely over-declare.
ANDROID_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
}

# Substrings that identify the content provider behind a ContentResolver URI.
# The guest hook already routes sms/contacts reads to distinct events; these
# are used to confirm and to classify anything that arrives unrouted.
CONTENT_URI_MARKERS = {
    "sms": "sms",
    "mms": "sms",
    "contacts": "contacts",
    "call_log": "call_log",
    "calendar": "calendar",
}

# WindowManager.LayoutParams.type. Not a bitmask — exact values.
# TYPE_APPLICATION_OVERLAY is the only route to draw over other apps on
# API 26+, so a banking-overlay attack must pass through 2038 (or 2003 on
# older devices, where the legacy alert window still works).
WINDOW_TYPES = {
    2002: "TYPE_PHONE",
    2003: "TYPE_SYSTEM_ALERT",
    2005: "TYPE_TOAST",
    2006: "TYPE_SYSTEM_OVERLAY",
    2010: "TYPE_SYSTEM_ERROR",
    2038: "TYPE_APPLICATION_OVERLAY",
}

OVERLAY_WINDOW_TYPES = {2002, 2003, 2006, 2010, 2038}

# WindowManager.LayoutParams flags — a bitmask.
# NOT_FOCUSABLE|NOT_TOUCHABLE together produce a window the user cannot see
# reacting and cannot interact with, which is what a tap logger looks like.
WINDOW_FLAGS = {
    0x00000008: "FLAG_NOT_FOCUSABLE",
    0x00000010: "FLAG_NOT_TOUCHABLE",
    0x00000020: "FLAG_NOT_TOUCH_MODAL",
    0x00000200: "FLAG_WATCH_OUTSIDE_TOUCH",
    0x00040000: "FLAG_HARDWARE_ACCELERATED",
}

FLAG_NOT_FOCUSABLE = 0x08
FLAG_NOT_TOUCHABLE = 0x10

# AccessibilityEvent types — a genuine bitmask.
ACCESSIBILITY_EVENT_TYPES = {
    0x00000001: "TYPE_VIEW_CLICKED",
    0x00000002: "TYPE_VIEW_LONG_CLICKED",
    0x00000004: "TYPE_VIEW_SELECTED",
    0x00000008: "TYPE_VIEW_FOCUSED",
    0x00000010: "TYPE_VIEW_TEXT_CHANGED",       # keystroke-level capture
    0x00000020: "TYPE_WINDOW_STATE_CHANGED",    # which app is in front
    0x00000800: "TYPE_WINDOW_CONTENT_CHANGED",
    0x00008000: "TYPE_VIEW_TEXT_SELECTION_CHANGED",
}

ACCESSIBILITY_TEXT_CHANGED = 0x10
ACCESSIBILITY_WINDOW_STATE_CHANGED = 0x20

# MediaRecorder.AudioSource / VideoSource — exact values, not a bitmask.
AUDIO_SOURCES = {
    0: "DEFAULT",
    1: "MIC",
    2: "VOICE_UPLINK",
    3: "VOICE_DOWNLINK",
    4: "VOICE_CALL",
    5: "CAMCORDER",
    6: "VOICE_RECOGNITION",
    7: "VOICE_COMMUNICATION",
}

# Sources that capture the room or the call rather than deliberate input.
COVERT_AUDIO_SOURCES = {1, 2, 3, 4, 5, 7}

VIDEO_SOURCES = {
    0: "DEFAULT",
    1: "CAMERA",
    2: "SURFACE",
}

# Text an accessibility node search is looking for when the intent is to find
# a credential field rather than to assist a user.
CREDENTIAL_SEARCH_TERMS = (
    "password", "passwd", "pin", "cvv", "otp", "mpin", "upi",
    "card number", "account", "secret", "seed", "mnemonic",
)


# ============================================================================
# The catalog
# ============================================================================

API_CATALOG: Dict[str, ApiHook] = {}


def _register(hook: ApiHook) -> ApiHook:
    API_CATALOG[hook.name] = hook
    return hook


# --- Filesystem -------------------------------------------------------------

_register(ApiHook(
    name="CreateFile",
    module="kernel32.dll",
    category=ApiCategory.FILESYSTEM,
    baseline_risk=BaselineRisk.BENIGN,
    purpose="Opens or creates a file, directory, device, or pipe.",
    why_monitored=(
        "The entry point for nearly all file activity, including dropping "
        "payloads into startup folders and opening raw devices. Also opens "
        "named pipes, a common C2 and injection transport."
    ),
    args=[
        ApiArg("lpFileName", 0, "wstring", "Target path"),
        ApiArg("dwDesiredAccess", 1, "flags", "Read/write intent",
               flag_map=FILE_ACCESS),
        ApiArg("dwCreationDisposition", 4, "int", "Create vs open semantics"),
    ],
    mitre=["T1083", "T1106"],
    rate_limit_per_sec=200,
    android_equivalent="java.io.File.<init>",
))

_register(ApiHook(
    name="ReadFile",
    module="kernel32.dll",
    category=ApiCategory.FILESYSTEM,
    baseline_risk=BaselineRisk.BENIGN,
    purpose="Reads data from an open file or device handle.",
    why_monitored=(
        "Mass reads across user document directories are the collection phase "
        "of both ransomware and data theft. The handle correlates back to the "
        "CreateFile that opened it, which is where the path lives."
    ),
    args=[
        ApiArg("hFile", 0, "handle", "Correlates to originating CreateFile"),
        ApiArg("nNumberOfBytesToRead", 2, "int"),
        ApiArg("lpBuffer", 1, "buffer", "Content hashed, never stored",
               hash_only=True),
    ],
    mitre=["T1005"],
    rate_limit_per_sec=500,
))

_register(ApiHook(
    name="WriteFile",
    module="kernel32.dll",
    category=ApiCategory.FILESYSTEM,
    baseline_risk=BaselineRisk.LOW,
    purpose="Writes data to an open file or device handle.",
    why_monitored=(
        "Payload drops, encrypted-file writes, and staged exfiltration all "
        "surface here. A read-then-write cycle over the same path with high "
        "entropy in between is the ransomware signature."
    ),
    args=[
        ApiArg("hFile", 0, "handle"),
        ApiArg("nNumberOfBytesToWrite", 2, "int"),
        ApiArg("lpBuffer", 1, "buffer", "Hashed; entropy computed in-guest",
               hash_only=True),
    ],
    mitre=["T1105", "T1074.001"],
    rate_limit_per_sec=500,
))

_register(ApiHook(
    name="DeleteFile",
    module="kernel32.dll",
    category=ApiCategory.FILESYSTEM,
    baseline_risk=BaselineRisk.LOW,
    purpose="Deletes a file from disk.",
    why_monitored=(
        "Two distinct malicious uses: destroying originals after encrypting "
        "them, and self-deletion of the dropper to frustrate forensics. Mass "
        "deletion in user directories is a destructive-payload indicator."
    ),
    args=[ApiArg("lpFileName", 0, "wstring", "Target path")],
    mitre=["T1070.004", "T1485"],
    rate_limit_per_sec=200,
))

_register(ApiHook(
    name="MoveFile",
    module="kernel32.dll",
    category=ApiCategory.FILESYSTEM,
    baseline_risk=BaselineRisk.LOW,
    purpose="Moves an existing file or directory.",
    why_monitored=(
        "Used to relocate payloads to system directories, replace legitimate "
        "binaries with malicious ones (DLL search order hijacking), or clean "
        "up evidence. Moving into System32 or Windows directory is suspicious."
    ),
    args=[
        ApiArg("lpExistingFileName", 0, "wstring", "Source path"),
        ApiArg("lpNewFileName", 1, "wstring", "Destination path"),
    ],
    mitre=["T1574.001", "T1074.001"],
))

_register(ApiHook(
    name="CopyFile",
    module="kernel32.dll",
    category=ApiCategory.FILESYSTEM,
    baseline_risk=BaselineRisk.LOW,
    purpose="Copies an existing file to a new file.",
    why_monitored=(
        "Used to spread payloads across directories, backup legitimate binaries "
        "before replacement, or distribute components. Copying into startup "
        "folders or system directories indicates persistence attempts."
    ),
    args=[
        ApiArg("lpExistingFileName", 0, "wstring", "Source"),
        ApiArg("lpNewFileName", 1, "wstring", "Destination"),
    ],
    mitre=["T1105", "T1547.001"],
))

_register(ApiHook(
    name="FindFirstFile",
    module="kernel32.dll",
    category=ApiCategory.FILESYSTEM,
    baseline_risk=BaselineRisk.BENIGN,
    purpose="Searches a directory for a file or subdirectory.",
    why_monitored=(
        "Directory enumeration is how malware discovers files to encrypt, "
        "exfiltrate, or delete. Searching user document directories recursively "
        "is a strong indicator of ransomware or data theft."
    ),
    args=[
        ApiArg("lpFileName", 0, "wstring", "Search pattern - e.g. *.doc, *.pdf"),
        ApiArg("lpFindFileData", 1, "pointer", "Results with file attributes"),
    ],
    mitre=["T1083", "T1005"],
    rate_limit_per_sec=100,
))

_register(ApiHook(
    name="FindNextFile",
    module="kernel32.dll",
    category=ApiCategory.FILESYSTEM,
    baseline_risk=BaselineRisk.BENIGN,
    purpose="Continues a file search from a previous call to FindFirstFile.",
    why_monitored=(
        "Continuation of directory enumeration. High-frequency calls indicate "
        "recursive directory traversal, typically looking for specific file types "
        "to encrypt or steal."
    ),
    args=[
        ApiArg("hFindFile", 0, "handle", "Search handle from FindFirstFile"),
        ApiArg("lpFindFileData", 1, "pointer", "Next file found"),
    ],
    mitre=["T1083"],
    rate_limit_per_sec=200,
))


# --- Registry ---------------------------------------------------------------

_register(ApiHook(
    name="RegCreateKey",
    module="advapi32.dll",
    category=ApiCategory.REGISTRY,
    baseline_risk=BaselineRisk.LOW,
    purpose="Creates or opens a registry key.",
    why_monitored=(
        "Creating keys under Run, RunOnce, Services, or the Winlogon path is "
        "how persistence gets installed. The hive plus subkey together decide "
        "whether this is routine configuration or a foothold."
    ),
    args=[
        ApiArg("hKey", 0, "flags", "Root hive", flag_map=REG_HIVES),
        ApiArg("lpSubKey", 1, "wstring", "Key path"),
    ],
    mitre=["T1112", "T1547.001"],
))

_register(ApiHook(
    name="RegSetValue",
    module="advapi32.dll",
    category=ApiCategory.REGISTRY,
    baseline_risk=BaselineRisk.MEDIUM,
    purpose="Writes a value into a registry key.",
    why_monitored=(
        "The actual moment persistence is established. A value written under "
        "an autostart key whose data is a path into AppData or Temp is a "
        "foothold, and this call is where that becomes observable."
    ),
    args=[
        ApiArg("hKey", 0, "handle", "Correlates to originating RegCreateKey"),
        ApiArg("lpValueName", 1, "wstring"),
        ApiArg("lpData", 3, "wstring", "Value payload — often the dropped path"),
    ],
    mitre=["T1112", "T1547.001"],
))

_register(ApiHook(
    name="RegDeleteKey",
    module="advapi32.dll",
    category=ApiCategory.REGISTRY,
    baseline_risk=BaselineRisk.MEDIUM,
    purpose="Deletes a registry key and its values.",
    why_monitored=(
        "Malware deletes registry keys to disable security tools, remove "
        "evidence of its installation, or clean up after itself. Deletion "
        "under System Policies or security software keys is particularly "
        "suspicious."
    ),
    args=[
        ApiArg("hKey", 0, "handle"),
        ApiArg("lpSubKey", 1, "wstring", "Key being deleted"),
    ],
    mitre=["T1112", "T1562.001"],
))

_register(ApiHook(
    name="RegDeleteValue",
    module="advapi32.dll",
    category=ApiCategory.REGISTRY,
    baseline_risk=BaselineRisk.LOW,
    purpose="Deletes a value from a registry key.",
    why_monitored=(
        "Used to disable security configurations, remove persistence entries "
        "of competing malware, or clean up artifacts. Frequent deletions from "
        "security-related keys indicates defensive evasion."
    ),
    args=[
        ApiArg("hKey", 0, "handle"),
        ApiArg("lpValueName", 1, "wstring", "Value being deleted"),
    ],
    mitre=["T1112", "T1562.001"],
))

_register(ApiHook(
    name="RegEnumKey",
    module="advapi32.dll",
    category=ApiCategory.REGISTRY,
    baseline_risk=BaselineRisk.BENIGN,
    purpose="Enumerates subkeys of a registry key.",
    why_monitored=(
        "Registry enumeration is how malware discovers installed software, "
        "security tools, and configuration. Enumerating Run keys, services, "
        "or security software keys indicates reconnaissance for persistence or "
        "defense evasion."
    ),
    args=[
        ApiArg("hKey", 0, "handle"),
        ApiArg("dwIndex", 1, "int"),
        ApiArg("lpName", 2, "wstring", "Subkey name found"),
    ],
    mitre=["T1010", "T1112"],
    rate_limit_per_sec=100,
))

_register(ApiHook(
    name="RegOpenKey",
    module="advapi32.dll",
    category=ApiCategory.REGISTRY,
    baseline_risk=BaselineRisk.BENIGN,
    purpose="Opens a registry key.",
    why_monitored=(
        "The read analogue of RegCreateKey. Opening autostart keys, security "
        "software keys, or policy keys indicates the sample is looking for "
        "persistence opportunities or security configurations to subvert."
    ),
    args=[
        ApiArg("hKey", 0, "flags", "Root hive", flag_map=REG_HIVES),
        ApiArg("lpSubKey", 1, "wstring", "Key path"),
    ],
    mitre=["T1112"],
    rate_limit_per_sec=200,
))


# --- Network ----------------------------------------------------------------

_register(ApiHook(
    name="InternetConnect",
    module="wininet.dll",
    category=ApiCategory.NETWORK,
    baseline_risk=BaselineRisk.LOW,
    purpose="Opens an HTTP/FTP session to a named host.",
    why_monitored=(
        "Yields the C2 hostname *before* DNS and before TLS, so it produces "
        "the intended destination even when the lookup fails or the traffic is "
        "encrypted. That makes it one of the highest-value hooks for IOC "
        "extraction."
    ),
    args=[
        ApiArg("lpszServerName", 1, "wstring", "C2 host — primary IOC"),
        ApiArg("nServerPort", 2, "int"),
        ApiArg("lpszUserName", 3, "wstring", "Credentials if embedded",
               redact=True),
        ApiArg("lpszPassword", 4, "wstring", redact=True),
    ],
    mitre=["T1071.001"],
))

_register(ApiHook(
    name="WinHttpSendRequest",
    module="winhttp.dll",
    category=ApiCategory.NETWORK,
    baseline_risk=BaselineRisk.LOW,
    purpose="Sends an HTTP request over a WinHTTP handle.",
    why_monitored=(
        "Where beaconing and exfiltration become measurable. Request headers "
        "expose the user-agent, which is frequently a hardcoded family "
        "fingerprint, and the payload length reveals how much data is leaving."
    ),
    args=[
        ApiArg("hRequest", 0, "handle"),
        ApiArg("lpszHeaders", 1, "wstring", "User-agent often family-specific"),
        ApiArg("dwTotalLength", 5, "int", "Exfiltration volume"),
        ApiArg("lpOptional", 3, "buffer", "Body hashed, not stored",
               hash_only=True),
    ],
    mitre=["T1071.001", "T1041"],
))

_register(ApiHook(
    name="InternetOpenUrl",
    module="wininet.dll",
    category=ApiCategory.NETWORK,
    baseline_risk=BaselineRisk.LOW,
    purpose="Opens a resource specified by a complete FTP or HTTP URL.",
    why_monitored=(
        "A high-level API that combines connection and request opening. "
        "Frequently used by malware for simple C2 communication and payload "
        "delivery due to its simplicity."
    ),
    args=[
        ApiArg("lpszUrl", 1, "wstring", "Full C2 or payload URL"),
        ApiArg("lpszHeaders", 2, "wstring"),
    ],
    mitre=["T1071.001"],
))

_register(ApiHook(
    name="send",
    module="ws2_32.dll",
    category=ApiCategory.NETWORK,
    baseline_risk=BaselineRisk.LOW,
    purpose="Sends data on a connected socket.",
    why_monitored=(
        "The raw socket send call. Used by custom TCP-based C2 protocols that "
        "don't use HTTP. High-frequency sends to the same destination indicate "
        "beaconing or data exfiltration."
    ),
    args=[
        ApiArg("s", 0, "int", "Socket handle"),
        ApiArg("buf", 1, "buffer", "Data being sent", hash_only=True),
        ApiArg("len", 2, "int", "Data length"),
    ],
    mitre=["T1071.004", "T1041"],
    rate_limit_per_sec=200,
))

_register(ApiHook(
    name="recv",
    module="ws2_32.dll",
    category=ApiCategory.NETWORK,
    baseline_risk=BaselineRisk.LOW,
    purpose="Receives data from a connected socket.",
    why_monitored=(
        "Raw socket receive. Paired with send() this builds the full picture "
        "of custom protocol C2 communication. Large receives may indicate "
        "payload downloads."
    ),
    args=[
        ApiArg("s", 0, "int", "Socket handle"),
        ApiArg("buf", 1, "buffer", "Data received", hash_only=True),
        ApiArg("len", 2, "int", "Buffer length"),
    ],
    mitre=["T1071.004", "T1105"],
    rate_limit_per_sec=200,
))

_register(ApiHook(
    name="connect",
    module="ws2_32.dll",
    category=ApiCategory.NETWORK,
    baseline_risk=BaselineRisk.MEDIUM,
    purpose="Establishes a connection to a specified socket.",
    why_monitored=(
        "Where outbound TCP connections begin. The address structure contains "
        "the destination IP and port, which are critical IOCs for C2 servers."
    ),
    args=[
        ApiArg("s", 0, "int", "Socket handle"),
        ApiArg("name", 1, "pointer", "SocketAddress with destination IP:port"),
    ],
    mitre=["T1071.004"],
))


# --- Process / execution ----------------------------------------------------

_register(ApiHook(
    name="CreateProcess",
    module="kernel32.dll",
    category=ApiCategory.PROCESS,
    baseline_risk=BaselineRisk.LOW,
    purpose="Creates a new process and its primary thread.",
    why_monitored=(
        "Builds the process tree, and the creation flags carry a specific "
        "tell: CREATE_SUSPENDED means the process is being started only to be "
        "hollowed out and overwritten before it ever runs its own code."
    ),
    args=[
        ApiArg("lpApplicationName", 0, "wstring"),
        ApiArg("lpCommandLine", 1, "wstring", "Full command line"),
        ApiArg("dwCreationFlags", 5, "flags", "CREATE_SUSPENDED is notable",
               flag_map=PROCESS_CREATION_FLAGS),
    ],
    mitre=["T1106", "T1055.012"],
))

_register(ApiHook(
    name="OpenProcess",
    module="kernel32.dll",
    category=ApiCategory.PROCESS,
    baseline_risk=BaselineRisk.MEDIUM,
    purpose="Opens an existing local process object.",
    why_monitored=(
        "The prerequisite for process injection, code injection, and credential "
        "theft. Opening a process with PROCESS_VM_WRITE or PROCESS_ALL_ACCESS "
        "rights is the first step of most injection attacks. Opening lsass.exe "
        "specifically indicates credential dumping."
    ),
    args=[
        ApiArg("dwDesiredAccess", 0, "flags", "VM_WRITE, VM_OPERATION, ALL_ACCESS are high-risk"),
        ApiArg("dwProcessId", 1, "int", "Target process ID"),
    ],
    mitre=["T1055", "T1003.001"],
))

_register(ApiHook(
    name="TerminateProcess",
    module="kernel32.dll",
    category=ApiCategory.PROCESS,
    baseline_risk=BaselineRisk.HIGH,
    purpose="Terminates a specified process and all of its threads.",
    why_monitored=(
        "Killing security software processes (antivirus, EDR) is defense "
        "evasion. Terminating system processes or other applications can be "
        "destructive behavior or anti-analysis."
    ),
    args=[
        ApiArg("hProcess", 0, "handle", "Target process handle"),
        ApiArg("uExitCode", 1, "int", "Exit code"),
    ],
    mitre=["T1562.001", "T1489"],
))

_register(ApiHook(
    name="EnumProcesses",
    module="psapi.dll",
    category=ApiCategory.PROCESS,
    baseline_risk=BaselineRisk.BENIGN,
    purpose="Retrieves the process identifier for each process object.",
    why_monitored=(
        "Process enumeration is reconnaissance. Malware uses this to find "
        "security tools, virtualization artifacts, or specific target processes. "
        "High-frequency enumeration suggests it's monitoring for security tools."
    ),
    args=[
        ApiArg("lpidProcess", 0, "pointer", "Array receiving process IDs"),
        ApiArg("cb", 1, "int", "Size of array"),
    ],
    mitre=["T1057"],
    rate_limit_per_sec=50,
))

_register(ApiHook(
    name="EnumProcessModules",
    module="psapi.dll",
    category=ApiCategory.PROCESS,
    baseline_risk=BaselineRisk.LOW,
    purpose="Retrieves a handle for each module in the specified process.",
    why_monitored=(
        "Module enumeration reveals which DLLs are loaded in a process. "
        "Malware uses this to detect security products, find injection targets, "
        "or locate specific API addresses for dynamic resolution."
    ),
    args=[
        ApiArg("hProcess", 0, "handle", "Target process"),
        ApiArg("lphModule", 1, "pointer", "Array receiving module handles"),
    ],
    mitre=["T1057", "T1014"],
    rate_limit_per_sec=50,
))

_register(ApiHook(
    name="GetModuleFileName",
    module="kernel32.dll",
    category=ApiCategory.PROCESS,
    baseline_risk=BaselineRisk.BENIGN,
    purpose="Retrieves the full path of the executable file.",
    why_monitored=(
        "Path discovery for the current process or other processes. Used to "
        "determine if running in a sandbox, locate dropped files, or construct "
        "persistence paths."
    ),
    args=[
        ApiArg("hModule", 0, "handle", "Module handle - null means current process"),
        ApiArg("lpFilename", 1, "wstring", "Buffer receiving path"),
    ],
    mitre=["T1014", "T1083"],
    rate_limit_per_sec=100,
))

_register(ApiHook(
    name="ShellExecute",
    module="shell32.dll",
    category=ApiCategory.EXECUTION,
    baseline_risk=BaselineRisk.MEDIUM,
    purpose="Launches a file, URL, or document via the shell.",
    why_monitored=(
        "A common living-off-the-land launcher: it starts powershell, cmd, "
        "mshta or rundll32 without the caller linking against them directly, "
        "and it opens URLs in the default browser for delivery chains."
    ),
    args=[
        ApiArg("lpOperation", 2, "wstring", "'open' vs 'runas' (elevation)"),
        ApiArg("lpFile", 3, "wstring", "Target binary, script or URL"),
        ApiArg("lpParameters", 4, "wstring", "Arguments"),
    ],
    mitre=["T1106", "T1204"],
))


# --- Memory / injection -----------------------------------------------------

_register(ApiHook(
    name="VirtualAlloc",
    module="kernel32.dll",
    category=ApiCategory.MEMORY,
    baseline_risk=BaselineRisk.BENIGN,
    purpose="Reserves or commits a region of virtual memory.",
    why_monitored=(
        "Ubiquitous and almost always benign — on its own this is noise. It is "
        "monitored because an RWX allocation is the first link in the injection "
        "chain, and because packers allocate RWX to unpack into. Alert on the "
        "protection and the sequence, never on the call."
    ),
    args=[
        ApiArg("lpAddress", 0, "pointer"),
        ApiArg("dwSize", 1, "int"),
        ApiArg("flAllocationType", 2, "flags", flag_map=MEM_ALLOCATION),
        ApiArg("flProtect", 3, "flags", "RWX is the signal",
               flag_map=PAGE_PROTECTION),
    ],
    mitre=["T1055"],
    rate_limit_per_sec=300,
))

_register(ApiHook(
    name="VirtualProtect",
    module="kernel32.dll",
    category=ApiCategory.MEMORY,
    baseline_risk=BaselineRisk.MEDIUM,
    purpose="Changes the protection on a committed memory region.",
    why_monitored=(
        "The unpacking tell. Malware allocates RW, writes decoded code into "
        "it, then flips the page to executable — which shows up here as a "
        "transition to PAGE_EXECUTE_*. Benign software rarely needs to make "
        "already-written memory executable."
    ),
    args=[
        ApiArg("lpAddress", 0, "pointer", "Correlates to prior VirtualAlloc"),
        ApiArg("dwSize", 1, "int"),
        ApiArg("flNewProtect", 2, "flags", "Transition to executable is the tell",
               flag_map=PAGE_PROTECTION),
    ],
    mitre=["T1055", "T1027.002"],
))

_register(ApiHook(
    name="NtWriteVirtualMemory",
    module="ntdll.dll",
    category=ApiCategory.INJECTION,
    baseline_risk=BaselineRisk.HIGH,
    purpose="Writes into the address space of a process.",
    why_monitored=(
        "Writing into *another* process is the middle link of injection and "
        "has almost no legitimate use outside debuggers and a handful of "
        "security products. The target process handle is what distinguishes "
        "self-modification from injection."
    ),
    args=[
        ApiArg("ProcessHandle", 0, "handle", "Foreign handle means injection"),
        ApiArg("BaseAddress", 1, "pointer"),
        ApiArg("Buffer", 2, "buffer", "Hashed — this is often the shellcode",
               hash_only=True),
        ApiArg("NumberOfBytesToWrite", 3, "int"),
    ],
    mitre=["T1055.002"],
))

_register(ApiHook(
    name="CreateRemoteThread",
    module="kernel32.dll",
    category=ApiCategory.INJECTION,
    baseline_risk=BaselineRisk.HIGH,
    purpose="Creates a thread inside another process.",
    why_monitored=(
        "The final link of classic injection — it is the moment injected code "
        "actually executes. There is essentially no benign reason for an "
        "application to start a thread in an unrelated process."
    ),
    args=[
        ApiArg("hProcess", 0, "handle", "Target process"),
        ApiArg("lpStartAddress", 3, "pointer", "Usually the injected region"),
        ApiArg("lpParameter", 4, "pointer"),
    ],
    mitre=["T1055.002", "T1055.003"],
))


# --- Dynamic resolution -----------------------------------------------------

_register(ApiHook(
    name="LoadLibrary",
    module="kernel32.dll",
    category=ApiCategory.DYNAMIC_RESOLUTION,
    baseline_risk=BaselineRisk.BENIGN,
    purpose="Loads a DLL into the calling process.",
    why_monitored=(
        "Normal on its own. It matters when the library name was decoded at "
        "runtime rather than sitting in the import table — that is deliberate "
        "concealment from static analysis. Loading from Temp or AppData rather "
        "than System32 is a second signal."
    ),
    args=[ApiArg("lpLibFileName", 0, "wstring", "Path or module name")],
    mitre=["T1129", "T1574.002"],
    rate_limit_per_sec=200,
))

_register(ApiHook(
    name="GetProcAddress",
    module="kernel32.dll",
    category=ApiCategory.DYNAMIC_RESOLUTION,
    baseline_risk=BaselineRisk.BENIGN,
    purpose="Resolves a function address by name from a loaded module.",
    why_monitored=(
        "Individually meaningless; in volume it is the signature of an import "
        "table rebuilt at runtime to keep the real capability invisible to "
        "static analysis. Resolving injection or crypto APIs this way is a "
        "much stronger signal than resolving them normally."
    ),
    args=[
        ApiArg("hModule", 0, "handle"),
        ApiArg("lpProcName", 1, "string", "Resolved function name"),
    ],
    mitre=["T1027", "T1106"],
    rate_limit_per_sec=1000,
))


# --- Crypto -----------------------------------------------------------------

_register(ApiHook(
    name="CryptEncrypt",
    module="advapi32.dll",
    category=ApiCategory.CRYPTO,
    baseline_risk=BaselineRisk.MEDIUM,
    purpose="Encrypts a buffer using a CryptoAPI key handle.",
    why_monitored=(
        "The ransomware primitive. Legitimate software encrypts too, so the "
        "call alone proves nothing — the discriminator is volume and pairing: "
        "thousands of calls interleaved with file reads and writes across user "
        "documents is encryption-for-extortion, not encryption-for-privacy."
    ),
    args=[
        ApiArg("hKey", 0, "handle"),
        ApiArg("pbData", 4, "buffer", "Hashed only", hash_only=True),
        ApiArg("pdwDataLen", 5, "int"),
    ],
    mitre=["T1486", "T1027"],
    rate_limit_per_sec=50,   # Ransomware issues these in floods; aggregate
))

_register(ApiHook(
    name="CryptDecrypt",
    module="advapi32.dll",
    category=ApiCategory.CRYPTO,
    baseline_risk=BaselineRisk.MEDIUM,
    purpose="Decrypts a buffer using a CryptoAPI key handle.",
    why_monitored=(
        "Decryption early in execution, before any network activity, usually "
        "means the sample is unpacking its own configuration or payload — "
        "which is where C2 addresses come from. It also appears when decoding "
        "C2 responses."
    ),
    args=[
        ApiArg("hKey", 0, "handle"),
        ApiArg("pbData", 4, "buffer", "Plaintext result hashed only",
               hash_only=True),
        ApiArg("pdwDataLen", 5, "int"),
    ],
    mitre=["T1027", "T1140"],
    rate_limit_per_sec=50,
))


# --- Device -----------------------------------------------------------------

_register(ApiHook(
    name="DeviceIoControl",
    module="kernel32.dll",
    category=ApiCategory.DEVICE,
    baseline_risk=BaselineRisk.MEDIUM,
    purpose="Sends a control code directly to a device driver.",
    why_monitored=(
        "The user-mode gateway to kernel-mode. Used to talk to loaded "
        "rootkit drivers, to access raw disk beneath the filesystem (bypassing "
        "file-level monitoring entirely), and in BYOVD attacks where a signed "
        "vulnerable driver is abused for privileged operations."
    ),
    args=[
        ApiArg("hDevice", 0, "handle"),
        ApiArg("dwIoControlCode", 1, "int", "IOCTL identifies the operation"),
        ApiArg("lpInBuffer", 2, "buffer", hash_only=True),
    ],
    mitre=["T1211", "T1068"],
))



# --- Services ---------------------------------------------------------------
# Service operations are a primary Windows persistence mechanism. Malware
# registers itself as a service to survive reboot and to run as SYSTEM.

_register(ApiHook(
    name="OpenSCManager",
    module="advapi32.dll",
    category=ApiCategory.EXECUTION,
    baseline_risk=BaselineRisk.MEDIUM,
    purpose="Opens a handle to the Service Control Manager.",
    why_monitored=(
        "The mandatory first step to install, start, or modify a service. "
        "A process that opens the SCM without prior user-visible reason is "
        "establishing the precondition for service-based persistence."
    ),
    args=[
        ApiArg("lpMachineName", 0, "wstring", "Remote machine — null means local"),
        ApiArg("dwDesiredAccess", 2, "int", "SC_MANAGER_CREATE_SERVICE=0x0002"),
    ],
    mitre=["T1543.003"],
))

_register(ApiHook(
    name="CreateService",
    module="advapi32.dll",
    category=ApiCategory.EXECUTION,
    baseline_risk=BaselineRisk.HIGH,
    purpose="Creates a new service entry in the SCM database.",
    why_monitored=(
        "Installing a service is one of the most durable persistence techniques "
        "on Windows: services start before user logon, run as SYSTEM by default, "
        "and survive reboots automatically. Non-installer software almost never "
        "calls this API."
    ),
    args=[
        ApiArg("lpServiceName", 1, "wstring", "Service key name"),
        ApiArg("lpDisplayName", 2, "wstring", "Human-readable name"),
        ApiArg("dwServiceType", 4, "int", "SERVICE_KERNEL_DRIVER=0x1, SERVICE_WIN32_OWN_PROCESS=0x10"),
        ApiArg("dwStartType", 5, "int", "SERVICE_AUTO_START=0x2, SERVICE_DEMAND_START=0x3"),
        ApiArg("lpBinaryPathName", 8, "wstring", "Path to service binary — primary IOC"),
    ],
    mitre=["T1543.003"],
))

_register(ApiHook(
    name="ChangeServiceConfig",
    module="advapi32.dll",
    category=ApiCategory.EXECUTION,
    baseline_risk=BaselineRisk.HIGH,
    purpose="Modifies the configuration of an existing service.",
    why_monitored=(
        "Malware hijacks existing services rather than creating new ones to "
        "avoid detection by 'new service' alerts. Changing a system service's "
        "binary path redirects execution to the attacker's code while keeping "
        "the legitimate service name visible."
    ),
    args=[
        ApiArg("hService", 0, "handle", "Handle to target service"),
        ApiArg("dwStartType", 2, "int", "Persistence setting change"),
        ApiArg("lpBinaryPathName", 5, "wstring", "New binary path — where execution goes"),
    ],
    mitre=["T1543.003", "T1574"],
))

_register(ApiHook(
    name="StartService",
    module="advapi32.dll",
    category=ApiCategory.EXECUTION,
    baseline_risk=BaselineRisk.MEDIUM,
    purpose="Starts a service.",
    why_monitored=(
        "Immediately starting a newly installed service is the activation step "
        "of service-based persistence. The sequence OpenSCManager → CreateService "
        "→ StartService is a complete service-installation attack chain."
    ),
    args=[
        ApiArg("hService", 0, "handle", "Handle to the service being started"),
    ],
    mitre=["T1543.003"],
))

_register(ApiHook(
    name="ControlService",
    module="advapi32.dll",
    category=ApiCategory.EXECUTION,
    baseline_risk=BaselineRisk.MEDIUM,
    purpose="Sends a control code to a service.",
    why_monitored=(
        "Used to stop security services, pause services, or send custom control "
        "codes. Stopping antivirus or security services is a common defense "
        "evasion technique."
    ),
    args=[
        ApiArg("hService", 0, "handle"),
        ApiArg("dwControl", 1, "int", "SERVICE_CONTROL_STOP=0x1 is the high-risk code"),
    ],
    mitre=["T1562.001", "T1543.003"],
))

_register(ApiHook(
    name="DeleteService",
    module="advapi32.dll",
    category=ApiCategory.EXECUTION,
    baseline_risk=BaselineRisk.HIGH,
    purpose="Marks a service for deletion from the SCM database.",
    why_monitored=(
        "Deleting security services or system services can break security "
        "mechanisms. Malware may also delete its own service after execution "
        "to remove evidence."
    ),
    args=[
        ApiArg("hService", 0, "handle", "Service being deleted"),
    ],
    mitre=["T1562.001", "T1070.006"],
))


# --- Drivers ----------------------------------------------------------------
# Driver-level attacks (rootkits, BYOVD) require loading a kernel module.
# NtLoadDriver is the only legitimate path to do this; calling it from user
# space with a non-standard driver path is essentially never benign.

_register(ApiHook(
    name="NtLoadDriver",
    module="ntdll.dll",
    category=ApiCategory.DEVICE,
    baseline_risk=BaselineRisk.HIGH,
    purpose="Loads a kernel driver from the path in the registry.",
    why_monitored=(
        "User-mode code that loads a driver is performing a privileged kernel "
        "operation. This is how rootkits install their kernel component, and "
        "how BYOVD (Bring Your Own Vulnerable Driver) attacks load a signed but "
        "exploitable driver to gain kernel execution."
    ),
    args=[
        ApiArg("DriverServiceName", 0, "wstring",
               "Registry path of the driver service — contains the .sys path"),
    ],
    mitre=["T1014", "T1068", "T1543.003"],
))

_register(ApiHook(
    name="NtSetSystemInformation",
    module="ntdll.dll",
    category=ApiCategory.DEVICE,
    baseline_risk=BaselineRisk.HIGH,
    purpose="Sets system-wide information, including loading kernel modules.",
    why_monitored=(
        "SystemLoadAndCallImage class can be used as an alternative driver-load "
        "path that bypasses some driver-load auditing. Rootkits use this to "
        "achieve kernel execution without touching NtLoadDriver."
    ),
    args=[
        ApiArg("SystemInformationClass", 0, "int",
               "38=SystemLoadAndCallImage (driver load alternate path)"),
    ],
    mitre=["T1014", "T1068"],
))


# --- Privilege Escalation ---------------------------------------------------
# Token manipulation is the kernel mechanism behind UAC bypass and lateral
# movement. These APIs individually look unremarkable; in sequences they
# reveal impersonation, elevation, and credential theft.

_register(ApiHook(
    name="OpenProcessToken",
    module="advapi32.dll",
    category=ApiCategory.PROCESS,
    baseline_risk=BaselineRisk.LOW,
    purpose="Opens the access token associated with a process.",
    why_monitored=(
        "The first step of every token manipulation attack: you must open the "
        "token before you can duplicate or adjust it. Opening the token of a "
        "SYSTEM process (lsass, winlogon) is almost never legitimate from "
        "application code."
    ),
    args=[
        ApiArg("ProcessHandle", 0, "handle", "Target process — SYSTEM processes are high-value"),
        ApiArg("DesiredAccess", 1, "int", "TOKEN_DUPLICATE=0x2, TOKEN_ADJUST_PRIVILEGES=0x20"),
    ],
    mitre=["T1134"],
))

_register(ApiHook(
    name="AdjustTokenPrivileges",
    module="advapi32.dll",
    category=ApiCategory.PROCESS,
    baseline_risk=BaselineRisk.MEDIUM,
    purpose="Enables or disables privileges in an access token.",
    why_monitored=(
        "Enabling SeDebugPrivilege grants the ability to open any process "
        "including lsass, which is the precondition for credential dumping. "
        "SeLoadDriverPrivilege enables driver loading without admin. "
        "SeTcbPrivilege grants Act-as-OS level access."
    ),
    args=[
        ApiArg("TokenHandle", 0, "handle"),
        ApiArg("NewState", 2, "pointer",
               "LUID_AND_ATTRIBUTES list — SeDebugPrivilege=0x14 is the target"),
    ],
    mitre=["T1134.001", "T1134"],
))

_register(ApiHook(
    name="DuplicateTokenEx",
    module="advapi32.dll",
    category=ApiCategory.PROCESS,
    baseline_risk=BaselineRisk.HIGH,
    purpose="Creates a new token duplicating an existing one with different impersonation level.",
    why_monitored=(
        "Token duplication is step two of token impersonation attacks: open a "
        "privileged process token, duplicate it to a primary token, then create "
        "a process using the stolen identity. This is how malware achieves "
        "SYSTEM execution without a kernel exploit."
    ),
    args=[
        ApiArg("hExistingToken", 0, "handle", "Source token — SYSTEM token = elevation"),
        ApiArg("dwDesiredAccess", 1, "int"),
        ApiArg("ImpersonationLevel", 4, "int",
               "SecurityImpersonation=2, SecurityDelegation=3"),
        ApiArg("TokenType", 5, "int", "TokenPrimary=1 creates a usable process token"),
    ],
    mitre=["T1134.001", "T1134.003"],
))

_register(ApiHook(
    name="ImpersonateLoggedOnUser",
    module="advapi32.dll",
    category=ApiCategory.PROCESS,
    baseline_risk=BaselineRisk.HIGH,
    purpose="Lets the calling thread impersonate a logged-on user's security context.",
    why_monitored=(
        "Impersonating a higher-privileged user (SYSTEM, Administrator) without "
        "the user's knowledge is the core of token impersonation attacks. "
        "Combined with a duplicated token it achieves privilege escalation "
        "entirely in user space."
    ),
    args=[
        ApiArg("hToken", 0, "handle", "Token to impersonate — its privilege level is the risk"),
    ],
    mitre=["T1134.003", "T1134"],
))

_register(ApiHook(
    name="SetThreadToken",
    module="advapi32.dll",
    category=ApiCategory.PROCESS,
    baseline_risk=BaselineRisk.HIGH,
    purpose="Enables or disables the impersonation token of a thread.",
    why_monitored=(
        "Direct manipulation of thread impersonation tokens. Used to toggle "
        "between privilege levels for different operations, often to bypass "
        "security checks or perform actions with elevated privileges."
    ),
    args=[
        ApiArg("hThread", 0, "handle", "Target thread - null means current thread"),
        ApiArg("hToken", 1, "handle", "Token to assign - null to disable impersonation"),
    ],
    mitre=["T1134.003"],
))

_register(ApiHook(
    name="GetTokenInformation",
    module="advapi32.dll",
    category=ApiCategory.PROCESS,
    baseline_risk=BaselineRisk.LOW,
    purpose="Retrieves information about a specified access token.",
    why_monitored=(
        "Used to enumerate privileges, groups, and session information from tokens. "
        "Malware uses this to determine if it's running with elevated privileges, "
        "to find privileged tokens to steal, or to detect security contexts."
    ),
    args=[
        ApiArg("TokenHandle", 0, "handle"),
        ApiArg("TokenInformationClass", 1, "int", "Type of information requested"),
    ],
    mitre=["T1134"],
    rate_limit_per_sec=100,
))

_register(ApiHook(
    name="CreateProcessWithToken",
    module="advapi32.dll",
    category=ApiCategory.PROCESS,
    baseline_risk=BaselineRisk.HIGH,
    purpose="Creates a new process running under the identity of a supplied token.",
    why_monitored=(
        "The payload step of token impersonation: after stealing a SYSTEM token "
        "via OpenProcessToken + DuplicateTokenEx, this call spawns a new process "
        "under that identity. The resulting process runs as SYSTEM with the "
        "parent's non-elevated appearance maintained."
    ),
    args=[
        ApiArg("hToken", 0, "handle", "Stolen token — SYSTEM = full compromise"),
        ApiArg("lpApplicationName", 2, "wstring"),
        ApiArg("lpCommandLine", 3, "wstring", "What runs under the elevated token"),
    ],
    mitre=["T1134.002"],
))


# ============================================================================
# Android — Java-layer surface (Phase 6)
# ============================================================================
#
# WHY THESE ARE CATALOG ENTRIES AND NOT JUST HOOKS
# ------------------------------------------------
# The Android agent already emitted these events, but the host engine drops
# anything resolve_api() does not recognise, so every SMS send, location fix
# and overlay window was being collected in the guest and discarded on
# arrival. Registering them here is what puts Android behaviour into the same
# normalize → correlate → score → MITRE path the Win32 calls already take.
#
# The base Android agent deliberately reports its filesystem, network,
# execution and crypto hooks under the *Windows* names (java.io.File.delete
# arrives as DeleteFile). That is not a shortcut — it means a chain rule like
# "read then send" is written once and matches on both platforms. The entries
# below are only for behaviour that has no Windows analogue at all.

# --- Permissions ------------------------------------------------------------

_register(ApiHook(
    name="RequestPermissions",
    module="android.app.Activity",
    category=ApiCategory.PERMISSIONS,
    baseline_risk=BaselineRisk.LOW,
    platform="android",
    purpose="Prompts the user to grant one or more runtime permissions.",
    why_monitored=(
        "A manifest lists what an app may ask for; this call is what it "
        "actually asks for, while running. The gap between the two is where "
        "loan-app and fake-eChallan samples hide — they declare little and "
        "escalate at runtime, often only after the user has entered personal "
        "details and is unlikely to abandon the flow."
    ),
    args=[
        ApiArg("permissions", 0, "string", "Permissions being requested"),
        ApiArg("requestCode", 1, "int"),
        ApiArg("dangerous", 2, "string", "Guest-side pre-filter of the sensitive subset"),
    ],
    mitre=["T1626"],
    rate_limit_per_sec=20,
))

_register(ApiHook(
    name="CheckPermission",
    module="androidx.core.content.ContextCompat",
    category=ApiCategory.PERMISSIONS,
    baseline_risk=BaselineRisk.BENIGN,
    platform="android",
    purpose="Tests whether a permission has already been granted.",
    why_monitored=(
        "Individually routine. In bulk it is capability probing: an app that "
        "checks fifteen permissions on launch is deciding which of its "
        "payloads the device will let it run."
    ),
    args=[
        ApiArg("permission", 1, "string"),
        ApiArg("result", 0, "int", "0 = PERMISSION_GRANTED"),
    ],
    mitre=["T1626"],
    rate_limit_per_sec=200,
))

_register(ApiHook(
    name="GrantRuntimePermission",
    module="android.content.pm.PackageManager",
    category=ApiCategory.PERMISSIONS,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Grants a runtime permission to a package (privileged operation).",
    why_monitored=(
        "This is a privileged operation normally reserved for system apps. "
        "Third-party apps calling this directly are using root access or "
        "exploiting vulnerabilities to bypass the permission grant flow."
    ),
    args=[
        ApiArg("permissionName", 0, "string", "Permission being granted"),
        ApiArg("packageName", 1, "string", "Target package"),
    ],
    mitre=["T1626", "T1068"],
    rate_limit_per_sec=10,
))

_register(ApiHook(
    name="SetPackagePermission",
    module="android.content.pm.PackageManager",
    category=ApiCategory.PERMISSIONS,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Sets permission state for a package (privileged operation).",
    why_monitored=(
        "Directly modifying permission states is a privileged operation. "
        "Malware with root or device admin privileges uses this to silently "
        "grant itself permissions without user consent."
    ),
    args=[
        ApiArg("permissionName", 0, "string"),
        ApiArg("permissionState", 1, "int", "GRANTED=1, DENIED=-1"),
    ],
    mitre=["T1626", "T1068"],
    rate_limit_per_sec=10,
))

# --- SMS --------------------------------------------------------------------

_register(ApiHook(
    name="SendSMS",
    module="android.telephony.SmsManager",
    category=ApiCategory.SMS,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Sends a text message without going through the messaging app.",
    why_monitored=(
        "Silent SMS is both the payload and the transport: premium-rate "
        "billing fraud, self-propagation to the victim's contacts, forwarding "
        "of intercepted banking OTPs to the operator, and a C2 channel that "
        "keeps working when the device has no data connection."
    ),
    args=[
        ApiArg("destinationAddress", 0, "string", "Recipient number"),
        ApiArg("scAddress", 1, "string", "Service centre, usually null"),
        ApiArg("messageBodyHash", 2, "buffer", "Body hashed in-guest, never sent",
               hash_only=True),
    ],
    mitre=["T1582", "T1643"],
    rate_limit_per_sec=50,
))

_register(ApiHook(
    name="SendMultipartSMS",
    module="android.telephony.SmsManager",
    category=ApiCategory.SMS,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Sends a text message split across multiple SMS parts.",
    why_monitored=(
        "The multipart variant carries more than 160 characters, which is what "
        "exfiltration over SMS looks like — a harvested contact list or an "
        "intercepted message body does not fit in a single part."
    ),
    args=[
        ApiArg("destinationAddress", 0, "string"),
        ApiArg("numParts", 2, "int", "Part count implies payload size"),
    ],
    mitre=["T1582", "T1639"],
    rate_limit_per_sec=50,
))

_register(ApiHook(
    name="ReadSMS",
    module="android.content.ContentResolver",
    category=ApiCategory.SMS,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Queries the SMS/MMS content provider.",
    why_monitored=(
        "The inbox holds one-time passwords, bank alerts and delivery codes. "
        "Reading it is the collection half of OTP theft; the send or upload "
        "that follows is the exfiltration half. Very little legitimate "
        "software outside a default SMS app has a reason to enumerate it."
    ),
    args=[
        ApiArg("uri", 0, "string", "content://sms, content://mms"),
        ApiArg("projection", 1, "string", "Columns requested"),
    ],
    mitre=["T1636.004"],
    rate_limit_per_sec=100,
))

_register(ApiHook(
    name="DeleteSMS",
    module="android.content.ContentResolver",
    category=ApiCategory.SMS,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Deletes SMS/MMS messages from the content provider.",
    why_monitored=(
        "Deleting messages removes evidence of OTP theft or fraudulent "
        "transactions. It also destroys legitimate evidence and is a common "
        "anti-forensics technique."
    ),
    args=[
        ApiArg("uri", 0, "string", "Message URI to delete"),
        ApiArg("selection", 1, "string", "Selection criteria"),
    ],
    mitre=["T1636.004", "T1070.004"],
    rate_limit_per_sec=50,
))

_register(ApiHook(
    name="SendMultipartTextMessage",
    module="android.telephony.SmsManager",
    category=ApiCategory.SMS,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Sends a multipart text message (alternative to SendMultipartSMS).",
    why_monitored=(
        "An alternative method for sending multipart SMS. Monitoring both "
        "ensures detection regardless of which API the malware uses for bulk "
        "messaging or data exfiltration."
    ),
    args=[
        ApiArg("destinationAddress", 0, "string"),
        ApiArg("scAddress", 1, "string"),
        ApiArg("parts", 2, "int", "Number of message parts"),
    ],
    mitre=["T1582", "T1639"],
    rate_limit_per_sec=50,
))

_register(ApiHook(
    name="DownloadMMS",
    module="android.telephony.SmsManager",
    category=ApiCategory.SMS,
    baseline_risk=BaselineRisk.MEDIUM,
    platform="android",
    purpose="Downloads MMS content from a server.",
    why_monitored=(
        "MMS download can be used to receive malicious payloads or configuration "
        "data. It's also used in some C2 implementations where commands are "
        "delivered via MMS messages."
    ),
    args=[
        ApiArg("contentUrl", 0, "string", "URL of MMS content"),
    ],
    mitre=["T1105", "T1582"],
    rate_limit_per_sec=20,
))

# --- Location ---------------------------------------------------------------

_register(ApiHook(
    name="RequestLocationUpdates",
    module="android.location.LocationManager",
    category=ApiCategory.LOCATION,
    baseline_risk=BaselineRisk.MEDIUM,
    platform="android",
    purpose="Subscribes to continuous position updates from a provider.",
    why_monitored=(
        "A navigation app subscribes while its map is on screen. Stalkerware "
        "subscribes from a background service at a short interval and never "
        "unsubscribes. The requested interval is what separates the two, so "
        "it is captured rather than just the fact of the call."
    ),
    args=[
        ApiArg("provider", 0, "string", "gps or network"),
        ApiArg("minTimeMs", 1, "int", "Requested update interval"),
        ApiArg("minDistanceM", 2, "int"),
        ApiArg("highFrequency", 3, "int", "Guest-side flag: interval under 10s"),
    ],
    mitre=["T1430"],
    rate_limit_per_sec=50,
))

_register(ApiHook(
    name="GetLastKnownLocation",
    module="android.location.LocationManager",
    category=ApiCategory.LOCATION,
    baseline_risk=BaselineRisk.MEDIUM,
    platform="android",
    purpose="Reads the most recent cached position without waiting for a fix.",
    why_monitored=(
        "The cheap, silent way to locate a device: no GPS hardware wakes up, "
        "so there is no location indicator for the user to notice. Repeated "
        "polling of the cache is tracking without the tracking signal."
    ),
    args=[
        ApiArg("provider", 0, "string"),
        ApiArg("hasResult", 1, "int", "Whether a cached fix was available"),
    ],
    mitre=["T1430"],
    rate_limit_per_sec=100,
))

_register(ApiHook(
    name="FusedLocationUpdates",
    module="com.google.android.gms.location.FusedLocationProviderClient",
    category=ApiCategory.LOCATION,
    baseline_risk=BaselineRisk.MEDIUM,
    platform="android",
    purpose="Subscribes to position updates via Play Services.",
    why_monitored=(
        "The modern path to the same capability. Monitoring only "
        "LocationManager misses every sample built against Play Services, "
        "which by now is most of them."
    ),
    args=[
        ApiArg("intervalMs", 0, "int", "Requested update interval"),
        ApiArg("highFrequency", 1, "int"),
    ],
    mitre=["T1430"],
    rate_limit_per_sec=50,
))

_register(ApiHook(
    name="GeofencingAdd",
    module="com.google.android.gms.location.GeofencingClient",
    category=ApiCategory.LOCATION,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Registers a geofence (virtual perimeter) for location alerts.",
    why_monitored=(
        "Geofencing is used by legitimate apps for location-based services, but "
        "also by stalkerware to trigger actions when the victim enters or leaves "
        "specific areas (work, home, competitor locations)."
    ),
    args=[
        ApiArg("latitude", 0, "float", "Geofence center latitude"),
        ApiArg("longitude", 1, "float", "Geofence center longitude"),
        ApiArg("radius", 2, "float", "Geofence radius in meters"),
        ApiArg("transitionType", 3, "int", "ENTER=1, EXIT=2"),
    ],
    mitre=["T1430"],
    rate_limit_per_sec=20,
))

_register(ApiHook(
    name="LocationRequestHighAccuracy",
    module="android.location.LocationRequest",
    category=ApiCategory.LOCATION,
    baseline_risk=BaselineRisk.MEDIUM,
    platform="android",
    purpose="Requests high-accuracy location updates.",
    why_monitored=(
        "High-accuracy location requests use GPS and significantly impact battery. "
        "Requesting this in the background without user interaction suggests "
        "surveillance rather than navigation."
    ),
    args=[
        ApiArg("quality", 0, "int", "HIGH_ACCURACY=100"),
        ApiArg("intervalMs", 1, "int"),
    ],
    mitre=["T1430"],
    rate_limit_per_sec=30,
))

# --- Contacts ---------------------------------------------------------------

_register(ApiHook(
    name="ReadContacts",
    module="android.content.ContentResolver",
    category=ApiCategory.CONTACTS,
    baseline_risk=BaselineRisk.MEDIUM,
    platform="android",
    purpose="Queries the contacts or phone content provider.",
    why_monitored=(
        "The contact list is the propagation surface for SMS worms and the "
        "target list for the harassment stage of loan-app extortion, where "
        "the victim's family and colleagues are messaged directly. It is also "
        "high-value personal data in its own right."
    ),
    args=[
        ApiArg("uri", 0, "string", "content://com.android.contacts"),
        ApiArg("projection", 1, "string"),
    ],
    mitre=["T1636.003"],
    rate_limit_per_sec=100,
))

_register(ApiHook(
    name="ContactsContractAccess",
    module="android.provider.ContactsContract",
    category=ApiCategory.CONTACTS,
    baseline_risk=BaselineRisk.LOW,
    platform="android",
    purpose="Direct use of the ContactsContract schema classes.",
    why_monitored=(
        "Catches contact access that reaches the provider through the "
        "contract helpers rather than a raw URI query."
    ),
    args=[ApiArg("type", 0, "string", "Which contract surface was touched")],
    mitre=["T1636.003"],
    rate_limit_per_sec=50,
))

_register(ApiHook(
    name="WriteContacts",
    module="android.content.ContentResolver",
    category=ApiCategory.CONTACTS,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Writes to the contacts content provider.",
    why_monitored=(
        "Writing contacts can be used to add attacker-controlled entries for "
        "smishing campaigns, or to replace legitimate contacts with fraudulent "
        "ones for ongoing scams."
    ),
    args=[
        ApiArg("uri", 0, "string", "content://com.android.contacts"),
        ApiArg("values", 1, "string", "Contact data being written"),
    ],
    mitre=["T1636.003", "T1582"],
    rate_limit_per_sec=50,
))

_register(ApiHook(
    name="DeleteContacts",
    module="android.content.ContentResolver",
    category=ApiCategory.CONTACTS,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Deletes contacts from the content provider.",
    why_monitored=(
        "Deleting contacts destroys evidence of contact-based attacks and can "
        "be used to disrupt the victim's personal communications."
    ),
    args=[
        ApiArg("uri", 0, "string", "Contact URI to delete"),
        ApiArg("selection", 1, "string", "Selection criteria"),
    ],
    mitre=["T1636.003", "T1070.004"],
    rate_limit_per_sec=50,
))

# --- Clipboard --------------------------------------------------------------

_register(ApiHook(
    name="ClipboardRead",
    module="android.content.ClipboardManager",
    category=ApiCategory.CLIPBOARD,
    baseline_risk=BaselineRisk.MEDIUM,
    platform="android",
    purpose="Reads the current clipboard contents.",
    why_monitored=(
        "Users paste exactly the things worth stealing: passwords out of a "
        "manager, OTPs out of a message, UPI IDs and wallet addresses. A "
        "background app reading the clipboard it did not write to is "
        "collection, and the content length alone often identifies what kind."
    ),
    args=[
        ApiArg("hasContent", 0, "int"),
        ApiArg("possibleCryptoAddress", 1, "int",
               "Guest-side length heuristic for a wallet address"),
    ],
    mitre=["T1414"],
    rate_limit_per_sec=200,
))

_register(ApiHook(
    name="ClipboardWrite",
    module="android.content.ClipboardManager",
    category=ApiCategory.CLIPBOARD,
    baseline_risk=BaselineRisk.MEDIUM,
    platform="android",
    purpose="Replaces the clipboard contents.",
    why_monitored=(
        "A read immediately followed by a write is a clipper: the victim "
        "copies a payee address, the malware substitutes its own, and the "
        "transfer completes to the wrong destination with the victim's full "
        "cooperation. Neither call is remarkable alone."
    ),
    args=[ApiArg("textLength", 0, "int")],
    mitre=["T1414"],
    rate_limit_per_sec=200,
))

_register(ApiHook(
    name="ClipboardCheck",
    module="android.content.ClipboardManager",
    category=ApiCategory.CLIPBOARD,
    baseline_risk=BaselineRisk.BENIGN,
    platform="android",
    purpose="Tests whether the clipboard currently holds anything.",
    why_monitored=(
        "The poll that precedes the read. On its own it is nothing; at a "
        "steady interval it is a clipboard monitor waiting for something "
        "worth taking."
    ),
    args=[ApiArg("hasClip", 0, "int")],
    mitre=["T1414"],
    rate_limit_per_sec=500,
))

# --- Camera -----------------------------------------------------------------

_register(ApiHook(
    name="CameraOpen",
    module="android.hardware.camera2.CameraManager",
    category=ApiCategory.CAMERA,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Acquires a camera device.",
    why_monitored=(
        "Opening a camera outside a user-visible camera flow is surveillance. "
        "Front-facing capture in particular appears in sextortion and in the "
        "'selfie verification' stage of fraudulent loan apps, where the image "
        "is later used as leverage."
    ),
    args=[
        ApiArg("cameraId", 0, "string"),
        ApiArg("facing", 1, "string", "0 back, 1 front"),
        ApiArg("api", 2, "string", "camera2 or legacy"),
    ],
    mitre=["T1512"],
    rate_limit_per_sec=20,
))

_register(ApiHook(
    name="CameraStartPreview",
    module="android.hardware.Camera",
    category=ApiCategory.CAMERA,
    baseline_risk=BaselineRisk.MEDIUM,
    platform="android",
    purpose="Starts the legacy camera preview stream.",
    why_monitored=(
        "Frames only flow once preview starts, so this — not open — is the "
        "moment capture actually begins on the legacy API."
    ),
    args=[],
    mitre=["T1512"],
    rate_limit_per_sec=20,
))

_register(ApiHook(
    name="MediaRecorderVideoSource",
    module="android.media.MediaRecorder",
    category=ApiCategory.CAMERA,
    baseline_risk=BaselineRisk.MEDIUM,
    platform="android",
    purpose="Selects the video input for a recording session.",
    why_monitored=(
        "Distinguishes a recording that will contain camera footage from one "
        "that is audio only, which decides whether the finding is 'watched' "
        "or 'listened to'."
    ),
    args=[ApiArg("source", 0, "int", "1 = CAMERA")],
    mitre=["T1512"],
    rate_limit_per_sec=20,
))

_register(ApiHook(
    name="CameraTakePicture",
    module="android.hardware.Camera",
    category=ApiCategory.CAMERA,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Captures a still image from the camera.",
    why_monitored=(
        "Taking pictures without user interaction or from background services "
        "is surveillance. This is how stalkerware captures photos of the victim "
        "or their surroundings without the camera UI appearing."
    ),
    args=[
        ApiArg("cameraId", 0, "string"),
        ApiArg("facing", 1, "string", "0 back, 1 front"),
    ],
    mitre=["T1512"],
    rate_limit_per_sec=20,
))

_register(ApiHook(
    name="CameraSetParameters",
    module="android.hardware.Camera",
    category=ApiCategory.CAMERA,
    baseline_risk=BaselineRisk.MEDIUM,
    platform="android",
    purpose="Sets camera parameters (picture size, focus mode, etc.).",
    why_monitored=(
        "Modifying camera parameters to disable shutter sounds, flash indicators, "
        "or focus sounds is done to make surveillance covert. Malware wants to "
        "capture without the user noticing."
    ),
    args=[
        ApiArg("parameters", 0, "string", "Camera parameter string"),
    ],
    mitre=["T1512"],
    rate_limit_per_sec=50,
))

# --- Microphone -------------------------------------------------------------

_register(ApiHook(
    name="AudioRecordStart",
    module="android.media.AudioRecord",
    category=ApiCategory.MICROPHONE,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Begins capturing from the microphone.",
    why_monitored=(
        "Ambient audio capture is the highest-intrusion capability on the "
        "device and has essentially no benign background use. Stalkerware and "
        "banking RATs both reach for it."
    ),
    args=[],
    mitre=["T1429"],
    rate_limit_per_sec=20,
))

_register(ApiHook(
    name="AudioRecordRead",
    module="android.media.AudioRecord",
    category=ApiCategory.MICROPHONE,
    baseline_risk=BaselineRisk.LOW,
    platform="android",
    purpose="Pulls a buffer of captured audio.",
    why_monitored=(
        "Proves the recording session was live rather than merely opened, and "
        "the accumulated byte count establishes how long the microphone was "
        "actually running — the difference between a permission check and "
        "evidence of surveillance."
    ),
    args=[ApiArg("sizeBytes", 2, "int")],
    mitre=["T1429"],
    rate_limit_per_sec=500,
))

_register(ApiHook(
    name="MediaRecorderAudioSource",
    module="android.media.MediaRecorder",
    category=ApiCategory.MICROPHONE,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Selects the audio input for a recording session.",
    why_monitored=(
        "MIC records the room. VOICE_CALL and the uplink/downlink sources "
        "record the conversation, which is a materially more serious finding "
        "and worth naming separately in the report."
    ),
    args=[
        ApiArg("source", 0, "int", "1 MIC, 4 VOICE_CALL"),
        ApiArg("isMic", 1, "int"),
    ],
    mitre=["T1429"],
    rate_limit_per_sec=20,
))

_register(ApiHook(
    name="MediaRecorderStart",
    module="android.media.MediaRecorder",
    category=ApiCategory.MEDIA_CAPTURE,
    baseline_risk=BaselineRisk.MEDIUM,
    platform="android",
    purpose="Starts a configured audio/video recording session.",
    why_monitored=(
        "The commit point. Whether it produces audio, video or both was "
        "decided by the source calls that preceded it, which is why those are "
        "correlated with this one rather than reported on their own."
    ),
    args=[ApiArg("type", 0, "string")],
    mitre=["T1429", "T1512"],
    rate_limit_per_sec=20,
))

# --- Accessibility ----------------------------------------------------------

_register(ApiHook(
    name="AccessibilityEvent",
    module="android.accessibilityservice.AccessibilityService",
    category=ApiCategory.ACCESSIBILITY,
    baseline_risk=BaselineRisk.MEDIUM,
    platform="android",
    purpose="Receives a UI event from any app on the device.",
    why_monitored=(
        "An accessibility service sees every screen and every keystroke in "
        "every other app, and can act on them. It is the single most powerful "
        "thing a user can be talked into granting, and the reason Android "
        "banking trojans ask for it first. TYPE_VIEW_TEXT_CHANGED events are "
        "keylogging; TYPE_WINDOW_STATE_CHANGED is the trojan watching for the "
        "banking app to come to the front so it knows when to overlay."
    ),
    args=[
        ApiArg("packageName", 0, "string", "App being observed"),
        ApiArg("eventType", 1, "flags", "Event bitmask",
               flag_map=ACCESSIBILITY_EVENT_TYPES),
        ApiArg("isTextChange", 2, "int"),
        ApiArg("isWindowChange", 3, "int"),
    ],
    mitre=["T1417.001", "T1513"],
    rate_limit_per_sec=300,
))

_register(ApiHook(
    name="AccessibilityFindByText",
    module="android.view.accessibility.AccessibilityNodeInfo",
    category=ApiCategory.ACCESSIBILITY,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Locates on-screen nodes matching a text string.",
    why_monitored=(
        "How a service finds a specific field to read or a specific button to "
        "press on the user's behalf. Searching for 'OTP', 'CVV' or 'UPI PIN' "
        "states the intent plainly: this is targeting a credential, not "
        "assisting a user."
    ),
    args=[
        ApiArg("searchText", 0, "string"),
        ApiArg("sensitiveSearch", 1, "int", "Guest-side credential-term match"),
    ],
    mitre=["T1417.001", "T1516"],
    rate_limit_per_sec=200,
))

_register(ApiHook(
    name="AccessibilityPerformAction",
    module="android.view.accessibility.AccessibilityNodeInfo",
    category=ApiCategory.ACCESSIBILITY,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Performs an action on an accessibility node (click, scroll, etc.).",
    why_monitored=(
        "This is how accessibility services interact with other apps on behalf "
        "of the user. Malware uses it to click buttons, fill forms, or dismiss "
        "security dialogs automatically."
    ),
    args=[
        ApiArg("action", 0, "int", "ACTION_CLICK=16, ACTION_SCROLL_FORWARD=8192"),
        ApiArg("packageName", 1, "string", "Target app package"),
    ],
    mitre=["T1417.001", "T1516"],
    rate_limit_per_sec=100,
))

_register(ApiHook(
    name="AccessibilityFindAccessibilityNodeInfo",
    module="android.view.accessibility.AccessibilityNodeInfo",
    category=ApiCategory.ACCESSIBILITY,
    baseline_risk=BaselineRisk.MEDIUM,
    platform="android",
    purpose="Finds accessibility nodes by various criteria.",
    why_monitored=(
        "General node finding capability. When combined with text search or "
        "coordinate-based searching, it enables the service to navigate and "
        "manipulate other app UIs systematically."
    ),
    args=[
        ApiArg("searchCriteria", 0, "string", "Search parameters"),
    ],
    mitre=["T1417.001"],
    rate_limit_per_sec=150,
))

# --- Overlay ----------------------------------------------------------------

_register(ApiHook(
    name="OverlayWindowAdded",
    module="android.view.WindowManagerImpl",
    category=ApiCategory.OVERLAY,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Attaches a window to the display.",
    why_monitored=(
        "With an overlay window type this draws over other apps. A pixel-"
        "perfect fake login placed over the real banking app collects the "
        "credentials while the genuine app sits untouched underneath — the "
        "victim's own records show nothing wrong. A non-focusable, "
        "non-touchable overlay is the other variant: an invisible sheet that "
        "records where the user taps."
    ),
    args=[
        ApiArg("windowType", 0, "int", "2038 TYPE_APPLICATION_OVERLAY"),
        ApiArg("flags", 1, "flags", "Layout flags", flag_map=WINDOW_FLAGS),
        ApiArg("isOverlay", 2, "int"),
        ApiArg("invisibleTapLogger", 3, "int"),
    ],
    mitre=["T1417.002", "T1516"],
    rate_limit_per_sec=50,
))

_register(ApiHook(
    name="LayoutInflate",
    module="android.view.LayoutInflater",
    category=ApiCategory.OVERLAY,
    baseline_risk=BaselineRisk.BENIGN,
    platform="android",
    purpose="Builds a view hierarchy from a layout resource.",
    why_monitored=(
        "Ubiquitous on its own — every screen in every app inflates layouts. "
        "It earns its place only as the link that shows an overlay window was "
        "populated with a crafted UI rather than left empty."
    ),
    args=[ApiArg("resourceId", 0, "int")],
    mitre=[],
    rate_limit_per_sec=300,
))

_register(ApiHook(
    name="WindowManagerAddView",
    module="android.view.WindowManager",
    category=ApiCategory.OVERLAY,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Adds a view to the window manager (alternative to OverlayWindowAdded).",
    why_monitored=(
        "An alternative method for adding overlay views. Monitoring both ensures "
        "detection regardless of which API the malware uses to create overlays "
        "for tapjacking or credential theft."
    ),
    args=[
        ApiArg("view", 0, "pointer", "View being added"),
        ApiArg("params", 1, "pointer", "WindowManager.LayoutParams"),
    ],
    mitre=["T1417.002", "T1516"],
    rate_limit_per_sec=50,
))

_register(ApiHook(
    name="SystemAlertWindowRequest",
    module="android.Manifest.permission",
    category=ApiCategory.OVERLAY,
    baseline_risk=BaselineRisk.HIGH,
    platform="android",
    purpose="Requests SYSTEM_ALERT_WINDOW permission for overlay capabilities.",
    why_monitored=(
        "This permission is specifically required for drawing over other apps. "
        "Requesting it at runtime is a strong indicator of overlay-based attacks "
        "like tapjacking or fake login screens."
    ),
    args=[
        ApiArg("requested", 0, "int", "Whether permission was requested"),
        ApiArg("granted", 1, "int", "Whether permission was granted"),
    ],
    mitre=["T1417.002", "T1626"],
    rate_limit_per_sec=10,
))


# ============================================================================
# Lookups
# ============================================================================

MONITORED_APIS: List[str] = list(API_CATALOG.keys())

WINDOWS_MONITORED_APIS: List[str] = [
    n for n, h in API_CATALOG.items() if h.platform == "windows"
]
ANDROID_MONITORED_APIS: List[str] = [
    n for n, h in API_CATALOG.items() if h.platform == "android"
]

# Windows exports many of these as -A/-W pairs. Hooks are installed on both,
# and both normalize back to the catalog name so downstream logic sees one
# identity per API rather than three. Java method names have no such variants,
# so Android entries map to themselves only — generating SendSMSW would be
# noise in a table that is also a readable inventory of what is hooked.
API_ALIASES: Dict[str, str] = {}
for _name, _hook in API_CATALOG.items():
    API_ALIASES[_name] = _name
    if _hook.platform != "windows":
        continue
    API_ALIASES[f"{_name}A"] = _name
    API_ALIASES[f"{_name}W"] = _name
API_ALIASES.update({
    "CreateFileA": "CreateFile", "CreateFileW": "CreateFile",
    "RegCreateKeyExA": "RegCreateKey", "RegCreateKeyExW": "RegCreateKey",
    "RegSetValueExA": "RegSetValue", "RegSetValueExW": "RegSetValue",
    "InternetConnectA": "InternetConnect", "InternetConnectW": "InternetConnect",
    "CreateProcessA": "CreateProcess", "CreateProcessW": "CreateProcess",
    "ShellExecuteA": "ShellExecute", "ShellExecuteW": "ShellExecute",
    "ShellExecuteExA": "ShellExecute", "ShellExecuteExW": "ShellExecute",
    "VirtualAllocEx": "VirtualAlloc",
    "VirtualProtectEx": "VirtualProtect",
    "WriteProcessMemory": "NtWriteVirtualMemory",
    "NtWriteVirtualMemory": "NtWriteVirtualMemory",
    "LoadLibraryA": "LoadLibrary", "LoadLibraryW": "LoadLibrary",
    "LoadLibraryExA": "LoadLibrary", "LoadLibraryExW": "LoadLibrary",
    "DeleteFileA": "DeleteFile", "DeleteFileW": "DeleteFile",
    # Service API aliases
    "OpenSCManagerA": "OpenSCManager", "OpenSCManagerW": "OpenSCManager",
    "CreateServiceA": "CreateService", "CreateServiceW": "CreateService",
    "ChangeServiceConfigA": "ChangeServiceConfig", "ChangeServiceConfigW": "ChangeServiceConfig",
    "StartServiceA": "StartService", "StartServiceW": "StartService",
    "ControlServiceA": "ControlService", "ControlServiceW": "ControlService",
    "DeleteServiceA": "DeleteService", "DeleteServiceW": "DeleteService",
    # Driver API aliases
    "ZwLoadDriver": "NtLoadDriver",
    "ZwSetSystemInformation": "NtSetSystemInformation",
    # Token API aliases
    "OpenProcessTokenA": "OpenProcessToken",
    "CreateProcessWithTokenW": "CreateProcessWithToken",
    "ImpersonateLoggedOnUserA": "ImpersonateLoggedOnUser",
    "DuplicateTokenExA": "DuplicateTokenEx",
    "AdjustTokenPrivilegesA": "AdjustTokenPrivileges",
    "SetThreadTokenA": "SetThreadToken", "SetThreadTokenW": "SetThreadToken",
    "GetTokenInformationA": "GetTokenInformation", "GetTokenInformationW": "GetTokenInformation",
    # Process API aliases
    "OpenProcessA": "OpenProcess", "OpenProcessW": "OpenProcess",
    "TerminateProcessA": "TerminateProcess", "TerminateProcessW": "TerminateProcess",
    "EnumProcessesA": "EnumProcesses", "EnumProcessesW": "EnumProcesses",
    "EnumProcessModulesA": "EnumProcessModules", "EnumProcessModulesW": "EnumProcessModules",
    "GetModuleFileNameA": "GetModuleFileName", "GetModuleFileNameW": "GetModuleFileName",
    "GetModuleFileNameExA": "GetModuleFileName", "GetModuleFileNameExW": "GetModuleFileName",
    # Registry API aliases
    "RegDeleteKeyA": "RegDeleteKey", "RegDeleteKeyW": "RegDeleteKey",
    "RegDeleteValueA": "RegDeleteValue", "RegDeleteValueW": "RegDeleteValue",
    "RegEnumKeyA": "RegEnumKey", "RegEnumKeyW": "RegEnumKey",
    "RegEnumKeyExA": "RegEnumKey", "RegEnumKeyExW": "RegEnumKey",
    "RegOpenKeyA": "RegOpenKey", "RegOpenKeyW": "RegOpenKey",
    "RegOpenKeyExA": "RegOpenKey", "RegOpenKeyExW": "RegOpenKey",
    # File system API aliases
    "MoveFileA": "MoveFile", "MoveFileW": "MoveFile",
    "MoveFileExA": "MoveFile", "MoveFileExW": "MoveFile",
    "CopyFileA": "CopyFile", "CopyFileW": "CopyFile",
    "CopyFileExA": "CopyFile", "CopyFileExW": "CopyFile",
    "FindFirstFileA": "FindFirstFile", "FindFirstFileW": "FindFirstFile",
    "FindNextFileA": "FindNextFile", "FindNextFileW": "FindNextFile",
    # Network API aliases
    "InternetOpenUrlA": "InternetOpenUrl", "InternetOpenUrlW": "InternetOpenUrl",
    "WinHttpSendRequestA": "WinHttpSendRequest", "WinHttpSendRequestW": "WinHttpSendRequest",
    "sendA": "send", "sendW": "send",
    "recvA": "recv", "recvW": "recv",
    "connectA": "connect", "connectW": "connect",
})


def resolve_api(name: str) -> Optional[ApiHook]:
    """Normalize a raw hooked name (CreateFileW, VirtualAllocEx) to a catalog entry."""
    canonical = API_ALIASES.get(name)
    if canonical:
        return API_CATALOG.get(canonical)
    return API_CATALOG.get(name)


def apis_by_category(category: ApiCategory) -> List[ApiHook]:
    return [h for h in API_CATALOG.values() if h.category is category]


def apis_by_platform(platform: str) -> List[ApiHook]:
    """Windows entries feed the CAPE/Win32 agent; Android entries the Java agent."""
    return [h for h in API_CATALOG.values() if h.platform == platform]


def decode_flags(value: int, flag_map: Dict[int, str]) -> List[str]:
    """Decode a numeric flags value into readable constant names."""
    if value is None:
        return []
    # Protection constants are exact values, not bitwise-combinable
    if flag_map is PAGE_PROTECTION:
        name = flag_map.get(value)
        return [name] if name else [hex(value)]
    out = [name for bit, name in flag_map.items() if value & bit]
    return out or [hex(value)]


def is_rwx(protection: Optional[int]) -> bool:
    """True if a protection constant grants write and execute simultaneously."""
    return protection in RWX_PROTECTIONS


def is_executable(protection: Optional[int]) -> bool:
    return protection in EXECUTABLE_PROTECTIONS


# ---- Android helpers --------------------------------------------------------

def is_dangerous_permission(permission: Optional[str]) -> bool:
    """
    True for permissions guarding data an investigator would call sensitive.

    Matches on the bare name too, since samples and logs are inconsistent
    about the `android.permission.` prefix.
    """
    if not permission:
        return False
    name = str(permission).strip()
    if name in ANDROID_DANGEROUS_PERMISSIONS:
        return True
    return f"android.permission.{name.rsplit('.', 1)[-1]}" in ANDROID_DANGEROUS_PERMISSIONS


def dangerous_permissions(permissions: Any) -> List[str]:
    """The sensitive subset of a requested permission list, in stable order."""
    if not permissions:
        return []
    if isinstance(permissions, str):
        permissions = [permissions]
    try:
        items = list(permissions)
    except TypeError:
        return []
    return sorted({str(p) for p in items if is_dangerous_permission(p)})


def classify_content_uri(uri: Optional[str]) -> Optional[str]:
    """Map a content:// URI to the provider family it reads ('sms', 'contacts')."""
    if not uri:
        return None
    lowered = str(uri).lower()
    for marker, family in CONTENT_URI_MARKERS.items():
        if marker in lowered:
            return family
    return None


def is_overlay_window(window_type: Optional[int]) -> bool:
    """True for window types that can be drawn on top of other applications."""
    if window_type is None:
        return False
    try:
        return int(window_type) in OVERLAY_WINDOW_TYPES
    except (TypeError, ValueError):
        return False


def is_covert_audio_source(source: Optional[int]) -> bool:
    """True for audio sources that capture the room or the call, not deliberate input."""
    if source is None:
        return False
    try:
        return int(source) in COVERT_AUDIO_SOURCES
    except (TypeError, ValueError):
        return False


def has_credential_search_term(text: Optional[str]) -> bool:
    """True when an accessibility node search is hunting for a credential field."""
    if not text:
        return False
    lowered = str(text).lower()
    return any(term in lowered for term in CREDENTIAL_SEARCH_TERMS)


# Sanity: the catalog must cover exactly the specified API surface.
REQUIRED_APIS = {
    # Original APIs
    "CreateFile", "ReadFile", "WriteFile", "DeleteFile",
    "RegCreateKey", "RegSetValue",
    "InternetConnect", "WinHttpSendRequest",
    "CreateProcess", "VirtualAlloc", "VirtualProtect",
    "NtWriteVirtualMemory", "CreateRemoteThread",
    "LoadLibrary", "GetProcAddress",
    "CryptEncrypt", "CryptDecrypt",
    "DeviceIoControl", "ShellExecute",
    # Phase 5 — Services
    "OpenSCManager", "CreateService", "ChangeServiceConfig", "StartService",
    # Phase 5 — Drivers
    "NtLoadDriver", "NtSetSystemInformation",
    # Phase 5 — Privilege Escalation
    "OpenProcessToken", "AdjustTokenPrivileges", "DuplicateTokenEx",
    "ImpersonateLoggedOnUser", "CreateProcessWithToken",
}

_missing = REQUIRED_APIS - set(API_CATALOG)
if _missing:  # pragma: no cover - guards against edits dropping an API
    raise RuntimeError(f"API catalog is missing required hooks: {sorted(_missing)}")


# Every event name the Android agent emits must resolve here. When it does
# not, HookEngine.ingest() silently drops the call — the failure mode this
# phase existed to fix — so the mismatch is made a startup error instead.
ANDROID_REQUIRED_APIS = {
    # Phase 6.1 — Permissions
    "RequestPermissions", "CheckPermission",
    # Phase 6.2 — SMS
    "SendSMS", "SendMultipartSMS", "ReadSMS",
    # Phase 6.3 — Location
    "RequestLocationUpdates", "GetLastKnownLocation", "FusedLocationUpdates",
    # Phase 6.4 — Contacts
    "ReadContacts", "ContactsContractAccess",
    # Phase 6.5 — Clipboard
    "ClipboardRead", "ClipboardWrite", "ClipboardCheck",
    # Phase 6.6 — Camera
    "CameraOpen", "CameraStartPreview", "MediaRecorderVideoSource",
    # Phase 6.7 — Microphone
    "AudioRecordStart", "AudioRecordRead", "MediaRecorderAudioSource",
    "MediaRecorderStart",
    # Phase 6.8 — Accessibility
    "AccessibilityEvent", "AccessibilityFindByText",
    # Phase 6.9 — Overlay
    "OverlayWindowAdded", "LayoutInflate",
}

_missing_android = ANDROID_REQUIRED_APIS - set(API_CATALOG)
if _missing_android:  # pragma: no cover - guards against edits dropping a hook
    raise RuntimeError(
        f"API catalog is missing required Android hooks: {sorted(_missing_android)}"
    )
