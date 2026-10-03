"""
stage_integration.py — Binds API hook monitoring to the eight-stage pipeline.

WHY THE BINDING MATTERS
-----------------------
Hook data and stage data are individually useful and jointly much stronger.
"Process injection detected" is a finding. "Process injection detected only
after reboot, having been completely absent through boot, idle, interaction and
network stages" is an evidence narrative — it establishes the payload was
deliberately gated, which speaks to intent rather than just capability.

This module tags every API call with the stage that was running when it fired,
then produces per-stage rollups and StageFinding objects the existing report
layer already knows how to render.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from .api_catalog import ApiCategory
from .hook_engine import BehaviorChain, ChainSeverity, HookEngine

_LOGGER = logging.getLogger(__name__)


# Chains at or above this severity become stage findings; lower ones stay in
# the aggregate rollup so the findings list stays readable.
FINDING_SEVERITY_FLOOR = ChainSeverity.HIGH

_SEVERITY_TO_FINDING = {
    ChainSeverity.LOW: "info",
    ChainSeverity.MEDIUM: "info",
    ChainSeverity.HIGH: "warning",
    ChainSeverity.CRITICAL: "critical",
}


class StageHookMonitor:
    """
    Wraps a HookEngine with stage awareness.

    The pipeline calls enter_stage()/exit_stage() around each stage; every call
    ingested in between is attributed to it.
    """

    def __init__(self, analysis_id: UUID):
        self.analysis_id = analysis_id
        self.engine = HookEngine(analysis_id)

        self._current_stage: Optional[str] = None
        self._stage_start_chain_count = 0
        self._stage_start_call_count = 0

        # stage_id -> rollup
        self.stage_rollups: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Stage lifecycle
    # ------------------------------------------------------------------

    def enter_stage(self, stage_id: str) -> None:
        self._current_stage = stage_id
        self._stage_start_chain_count = len(self.engine.chains)
        self._stage_start_call_count = self.engine.total_calls

    def exit_stage(self, stage_id: str) -> Dict[str, Any]:
        """Close out a stage and return its rollup."""
        new_chains = self.engine.chains[self._stage_start_chain_count:]
        call_delta = self.engine.total_calls - self._stage_start_call_count

        by_category: Dict[str, int] = {}
        for call_name, count in self.engine.calls_by_stage.get(stage_id, {}).items():
            from .api_catalog import API_CATALOG
            hook = API_CATALOG.get(call_name)
            if hook:
                key = hook.category.value
                by_category[key] = by_category.get(key, 0) + count

        rollup = {
            "stage_id": stage_id,
            "api_calls": call_delta,
            "calls_by_api": dict(self.engine.calls_by_stage.get(stage_id, {})),
            "calls_by_category": by_category,
            "chains": [
                {
                    "rule_id": c.rule_id,
                    "name": c.name,
                    "severity": c.severity.value,
                    "api_sequence": c.api_sequence,
                    "mitre": c.mitre,
                    "evidence": c.evidence,
                }
                for c in new_chains
            ],
            "critical_chains": len(
                [c for c in new_chains if c.severity == ChainSeverity.CRITICAL]
            ),
            # This is the field the pipeline's activity detection consumes.
            # Hook data is a first-class activity signal: a stage that saw a
            # behavior chain unambiguously saw the sample act, regardless of
            # whether the event database managed to record it.
            "activity_observed": call_delta > 0 or bool(new_chains),
        }

        self.stage_rollups[stage_id] = rollup
        self._current_stage = None
        return rollup

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------

    def ingest_batch(self, raw_calls: List[Dict[str, Any]]) -> List[BehaviorChain]:
        """Feed a batch from the guest agent. Returns newly completed chains."""
        chains: List[BehaviorChain] = []
        for raw in raw_calls:
            _, new_chains = self.engine.ingest(raw, stage_id=self._current_stage)
            chains.extend(new_chains)
        return chains

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def stage_findings(self, stage_id: str) -> List[Dict[str, Any]]:
        """
        Convert this stage's chains into report findings.

        Deliberately filtered: emitting a finding for every matched chain would
        bury the injection detection under a hundred dynamic-resolution notes.
        Lower-severity chains remain visible in the rollup.
        """
        rollup = self.stage_rollups.get(stage_id, {})
        findings: List[Dict[str, Any]] = []

        seen_rules = set()
        for chain in rollup.get("chains", []):
            severity = ChainSeverity(chain["severity"])
            if severity not in (ChainSeverity.HIGH, ChainSeverity.CRITICAL):
                continue
            # One finding per rule per stage — a loop that injects 40 times is
            # one behavior, not 40 findings.
            if chain["rule_id"] in seen_rules:
                continue
            seen_rules.add(chain["rule_id"])

            findings.append({
                "title": chain["name"],
                "detail": self._finding_detail(chain),
                "severity": _SEVERITY_TO_FINDING[severity],
                "mitre_techniques": chain["mitre"],
                "source": "api_hooks",
            })

        return findings

    @staticmethod
    def _finding_detail(chain: Dict[str, Any]) -> str:
        """Chain description plus whatever concrete evidence we captured."""
        from .hook_engine import CHAIN_RULES

        rule = next(
            (r for r in CHAIN_RULES if r.rule_id == chain["rule_id"]), None
        )
        parts = [rule.description if rule else chain["name"]]

        ev = chain.get("evidence") or {}
        if ev.get("paths"):
            parts.append("Files involved: " + ", ".join(ev["paths"][:3]) + ".")
        if ev.get("registry_keys"):
            parts.append("Registry entries: " + ", ".join(ev["registry_keys"][:3]) + ".")
        if ev.get("hosts"):
            parts.append("Contacted: " + ", ".join(ev["hosts"][:3]) + ".")
        if ev.get("target_pid") is not None:
            parts.append(f"Target process ID: {ev['target_pid']}.")

        parts.append(
            "Observed API sequence: " + " → ".join(chain["api_sequence"]) + "."
        )
        return " ".join(parts)

    def activation_analysis(self) -> Dict[str, Any]:
        """
        Cross-reference hook activity against stage order.

        This produces the joint finding neither system generates alone: the
        stage at which the sample first made *any* monitored call, and the
        stage at which it first exhibited a full malicious behavior chain.
        Those two are frequently different, and the gap is informative — a
        sample that calls APIs from boot but only injects after reboot was
        doing reconnaissance first.
        """
        first_call_stage = None
        first_chain_stage = None
        first_critical_stage = None

        for stage_id, rollup in self.stage_rollups.items():
            if first_call_stage is None and rollup["api_calls"] > 0:
                first_call_stage = stage_id
            if first_chain_stage is None and rollup["chains"]:
                first_chain_stage = stage_id
            if first_critical_stage is None and rollup["critical_chains"] > 0:
                first_critical_stage = stage_id

        silent_stages = [
            sid for sid, r in self.stage_rollups.items() if r["api_calls"] == 0
        ]

        return {
            "first_api_call_stage": first_call_stage,
            "first_behavior_chain_stage": first_chain_stage,
            "first_critical_behavior_stage": first_critical_stage,
            "silent_stages": silent_stages,
            "reconnaissance_gap": (
                first_call_stage is not None
                and first_critical_stage is not None
                and first_call_stage != first_critical_stage
            ),
        }

    def summary(self) -> Dict[str, Any]:
        return {
            **self.engine.summary(),
            "stage_rollups": self.stage_rollups,
            "activation_analysis": self.activation_analysis(),
        }


# ============================================================================
# Mock guest agent
# ============================================================================

class MockHookSource:
    """
    Generates synthetic API call streams for testing and demos.

    Scripted the same way MockBehaviorScript is: you declare which behaviors
    the fake sample performs, and the engine has to discover them. The point is
    to verify the correlation engine, not to rehearse it.
    """

    def __init__(self, pid: int = 4242):
        self.pid = pid
        self._handle = 1000
        self._t = 0.0

    def _next_handle(self) -> int:
        self._handle += 4
        return self._handle

    def _call(self, api: str, args: Dict[str, Any],
              ret: Any = None, target_pid: Optional[int] = None,
              dt: float = 0.01) -> Dict[str, Any]:
        self._t += dt
        base = datetime(2026, 1, 1, 12, 0, 0)
        from datetime import timedelta
        return {
            "api": api,
            "pid": self.pid,
            "tid": 1,
            "timestamp": (base + timedelta(seconds=self._t)).isoformat(),
            "args": args,
            "return": ret,
            "target_pid": target_pid,
        }

    # --- behaviors ----------------------------------------------------

    def benign_activity(self, n: int = 20) -> List[Dict[str, Any]]:
        """Ordinary noise: allocations, reads, library loads. Must not alert."""
        out = []
        for i in range(n):
            out.append(self._call("VirtualAlloc", {
                "dwSize": 4096, "flProtect": 0x04,   # PAGE_READWRITE
                "flAllocationType": 0x1000,
            }, ret=0x10000 + i * 0x1000))
            h = self._next_handle()
            out.append(self._call("CreateFileW", {
                "lpFileName": f"C:\\Windows\\System32\\config{i}.dat",
                "dwDesiredAccess": 0x80000000,
            }, ret=h))
            out.append(self._call("ReadFile", {
                "hFile": h, "nNumberOfBytesToRead": 512,
            }, ret=1))
        return out

    def process_injection(self, target_pid: int = 9001) -> List[Dict[str, Any]]:
        """VirtualAlloc(RWX) → NtWriteVirtualMemory(foreign) → CreateRemoteThread."""
        return [
            self._call("VirtualAllocEx", {
                "dwSize": 8192,
                "flProtect": 0x40,          # PAGE_EXECUTE_READWRITE
                "flAllocationType": 0x1000,
                "cross_process": True,
            }, ret=0x500000, target_pid=target_pid),
            self._call("NtWriteVirtualMemory", {
                "ProcessHandle": 0x123,
                "BaseAddress": "0x500000",
                "NumberOfBytesToWrite": 8192,
            }, ret=0, target_pid=target_pid),
            self._call("CreateRemoteThread", {
                "hProcess": 0x123,
                "lpStartAddress": "0x500000",
            }, ret=0x456, target_pid=target_pid),
        ]

    def process_hollowing(self, target_pid: int = 9002) -> List[Dict[str, Any]]:
        return [
            self._call("CreateProcessW", {
                "lpApplicationName": "C:\\Windows\\System32\\svchost.exe",
                "lpCommandLine": "svchost.exe",
                "dwCreationFlags": 0x00000004,   # CREATE_SUSPENDED
            }, ret=1),
            self._call("NtWriteVirtualMemory", {
                "ProcessHandle": 0x200,
                "BaseAddress": "0x400000",
                "NumberOfBytesToWrite": 65536,
            }, ret=0, target_pid=target_pid),
            self._call("CreateRemoteThread", {
                "hProcess": 0x200, "lpStartAddress": "0x400000",
            }, ret=0x789, target_pid=target_pid),
        ]

    def unpacking(self) -> List[Dict[str, Any]]:
        return [
            self._call("VirtualAlloc", {
                "dwSize": 32768, "flProtect": 0x04, "flAllocationType": 0x1000,
            }, ret=0x600000),
            self._call("VirtualProtect", {
                "lpAddress": "0x600000", "dwSize": 32768,
                "flNewProtect": 0x20,      # PAGE_EXECUTE_READ
            }, ret=1),
        ]

    def ransomware_cycle(self, count: int = 30) -> List[Dict[str, Any]]:
        """Read → encrypt → write across user documents."""
        out = []
        for i in range(count):
            h = self._next_handle()
            out.append(self._call("CreateFileW", {
                "lpFileName": f"C:\\Users\\Admin\\Documents\\report{i}.docx",
                "dwDesiredAccess": 0xC0000000,
            }, ret=h))
            out.append(self._call("ReadFile", {
                "hFile": h, "nNumberOfBytesToRead": 16384,
            }, ret=1))
            out.append(self._call("CryptEncrypt", {
                "hKey": 0x777, "pdwDataLen": 16384,
            }, ret=1))
            out.append(self._call("WriteFile", {
                "hFile": h, "nNumberOfBytesToWrite": 16400,
            }, ret=1))
        return out

    def persistence(self) -> List[Dict[str, Any]]:
        h = self._next_handle()
        key = self._next_handle()
        return [
            self._call("CreateFileW", {
                "lpFileName": "C:\\Users\\Admin\\AppData\\Roaming\\svcupd.exe",
                "dwDesiredAccess": 0x40000000,
            }, ret=h),
            self._call("WriteFile", {
                "hFile": h, "nNumberOfBytesToWrite": 245760,
            }, ret=1),
            self._call("RegCreateKeyExW", {
                "hKey": 0x80000001,   # HKEY_CURRENT_USER
                "lpSubKey": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            }, ret=key),
            self._call("RegSetValueExW", {
                "hKey": key,
                "lpValueName": "SystemUpdateSvc",
                "dwType": 1,
                "lpData": "C:\\Users\\Admin\\AppData\\Roaming\\svcupd.exe",
            }, ret=0),
        ]

    def exfiltration(self) -> List[Dict[str, Any]]:
        h = self._next_handle()
        return [
            self._call("CreateFileW", {
                "lpFileName": "C:\\Users\\Admin\\Documents\\passwords.txt",
                "dwDesiredAccess": 0x80000000,
            }, ret=h),
            self._call("ReadFile", {"hFile": h, "nNumberOfBytesToRead": 4096}, ret=1),
            self._call("InternetConnectW", {
                "lpszServerName": "exfil.badactor.test",
                "nServerPort": 443,
            }, ret=0x900),
            self._call("WinHttpSendRequest", {
                "hRequest": 0x900,
                "lpszHeaders": "User-Agent: Mozilla/4.0 (compatible)",
                "dwTotalLength": 4096,
            }, ret=1),
        ]

    def downloader(self) -> List[Dict[str, Any]]:
        h = self._next_handle()
        return [
            self._call("InternetConnectW", {
                "lpszServerName": "payload.delivery.test", "nServerPort": 80,
            }, ret=0xA00),
            self._call("WinHttpSendRequest", {
                "hRequest": 0xA00, "dwTotalLength": 0,
            }, ret=1),
            self._call("CreateFileW", {
                "lpFileName": "C:\\Users\\Admin\\AppData\\Local\\Temp\\stage2.exe",
                "dwDesiredAccess": 0x40000000,
            }, ret=h),
            self._call("WriteFile", {
                "hFile": h, "nNumberOfBytesToWrite": 512000,
            }, ret=1),
            self._call("ShellExecuteW", {
                "lpOperation": "open",
                "lpFile": "C:\\Users\\Admin\\AppData\\Local\\Temp\\stage2.exe",
            }, ret=42),
        ]

    def dynamic_resolution(self, count: int = 60) -> List[Dict[str, Any]]:
        out = [self._call("LoadLibraryW", {"lpLibFileName": "ntdll.dll"}, ret=0x7000)]
        names = ["NtWriteVirtualMemory", "NtCreateThreadEx", "NtProtectVirtualMemory",
                 "RtlDecompressBuffer", "NtQuerySystemInformation"]
        for i in range(count):
            out.append(self._call("GetProcAddress", {
                "hModule": 0x7000, "lpProcName": names[i % len(names)],
            }, ret=0x7100 + i))
        return out

    def driver_access(self) -> List[Dict[str, Any]]:
        h = self._next_handle()
        return [
            self._call("CreateFileW", {
                "lpFileName": "\\\\.\\MyVulnDriver", "dwDesiredAccess": 0xC0000000,
            }, ret=h),
            self._call("DeviceIoControl", {
                "hDevice": h, "dwIoControlCode": 0x9C402408,
            }, ret=1),
        ]

    # --- Android behaviors (Phase 6) ----------------------------------
    #
    # Event shapes match what the Frida Java agent actually emits, including
    # the guest-side pre-computed flags, so these exercise the same parsing
    # path a live Android detonation does.

    def android_benign_activity(self, n: int = 15) -> List[Dict[str, Any]]:
        """
        What an ordinary app does. Must stay silent.

        A messaging app reads SMS. A maps app polls location. A keyboard
        inflates layouts and adds views. Each of these appears here in its
        legitimate form — no follow-on network call, no overlay window type,
        no credential search — and none of it may produce a finding.
        """
        out: List[Dict[str, Any]] = []
        for i in range(n):
            out.append(self._call("ReadSMS", {
                "uri": "content://sms/inbox", "projection": "[body]",
            }))
            out.append(self._call("GetLastKnownLocation", {
                "provider": "network", "hasResult": True,
            }))
            out.append(self._call("LayoutInflate", {"resourceId": 0x7F0A0001 + i}))
            out.append(self._call("OverlayWindowAdded", {
                "windowType": 1,          # TYPE_APPLICATION — the app's own UI
                "flags": 0,
                "isOverlay": False,
                "invisibleTapLogger": False,
            }))
            out.append(self._call("CheckPermission", {
                "permission": "android.permission.INTERNET", "result": 0,
            }))
        return out

    def android_sms_interception(self) -> List[Dict[str, Any]]:
        """Read the inbox, forward the OTP. The loan-app/e-Challan pattern."""
        return [
            self._call("ReadSMS", {
                "uri": "content://sms/inbox",
                "projection": "[address, body, date]",
            }),
            self._call("SendSMS", {
                "destinationAddress": "+919876500011",
                "scAddress": None,
                "messageBodyHash": "142:8fa3c1",
            }, ret=None),
        ]

    def android_sms_exfiltration(self) -> List[Dict[str, Any]]:
        return [
            self._call("ReadSMS", {"uri": "content://sms", "projection": "[body]"}),
            self._call("InternetConnect", {
                "lpszServerName": "sms-collect.badactor.test", "nServerPort": 443,
            }, ret=0xB00),
        ]

    def android_contact_harvest(self, smish: bool = True) -> List[Dict[str, Any]]:
        out = [
            self._call("ReadContacts", {
                "uri": "content://com.android.contacts/data/phones",
                "projection": "[display_name, number]",
            }),
        ]
        if smish:
            out.append(self._call("SendSMS", {
                "destinationAddress": "+919876500022",
                "messageBodyHash": "88:1c9de2",
            }))
        else:
            out.append(self._call("InternetConnect", {
                "lpszServerName": "contacts.badactor.test", "nServerPort": 443,
            }, ret=0xB10))
        return out

    def android_location_tracking(self, polls: int = 25) -> List[Dict[str, Any]]:
        """High-frequency background polling, then upload."""
        out = [
            self._call("RequestLocationUpdates", {
                "provider": "gps",
                "minTimeMs": "5000",
                "minDistanceM": 0,
                "highFrequency": True,
            }),
        ]
        for _ in range(polls):
            out.append(self._call("GetLastKnownLocation", {
                "provider": "gps", "hasResult": True,
            }))
        out.append(self._call("InternetConnect", {
            "lpszServerName": "track.badactor.test", "nServerPort": 443,
        }, ret=0xB20))
        return out

    def android_crypto_clipper(self) -> List[Dict[str, Any]]:
        return [
            self._call("ClipboardRead", {
                "hasContent": True, "possibleCryptoAddress": True,
            }),
            self._call("ClipboardWrite", {"textLength": 42}, dt=0.5),
        ]

    def android_clipboard_monitoring(self, polls: int = 35) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for _ in range(polls):
            out.append(self._call("ClipboardCheck", {"hasClip": True}))
        return out

    def android_audio_surveillance(self, reads: int = 60) -> List[Dict[str, Any]]:
        out = [
            self._call("MediaRecorderAudioSource", {"source": 4, "isMic": False}),
            self._call("MediaRecorderStart", {"type": "unknown"}),
            self._call("AudioRecordStart", {}),
        ]
        for _ in range(reads):
            out.append(self._call("AudioRecordRead", {"sizeBytes": 4096}))
        out.append(self._call("InternetConnect", {
            "lpszServerName": "audio.badactor.test", "nServerPort": 443,
        }, ret=0xB30))
        return out

    def android_camera_surveillance(self) -> List[Dict[str, Any]]:
        return [
            self._call("CameraOpen", {"cameraId": "1", "facing": "1"}),
            self._call("MediaRecorderVideoSource", {"source": 1}),
            self._call("MediaRecorderStart", {"type": "unknown"}),
            self._call("InternetConnect", {
                "lpszServerName": "cam.badactor.test", "nServerPort": 443,
            }, ret=0xB40),
        ]

    def android_accessibility_credential_theft(
        self, text_events: int = 60
    ) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for _ in range(text_events):
            out.append(self._call("AccessibilityEvent", {
                "packageName": "com.bank.example",
                "eventType": 16,            # TYPE_VIEW_TEXT_CHANGED
                "isTextChange": True,
                "isWindowChange": False,
            }))
        out.append(self._call("AccessibilityFindByText", {
            "searchText": "Enter OTP", "sensitiveSearch": True,
        }))
        return out

    def android_banking_overlay(self) -> List[Dict[str, Any]]:
        """Watch for the bank app, then draw over it."""
        return [
            self._call("AccessibilityEvent", {
                "packageName": "com.bank.example",
                "eventType": 32,            # TYPE_WINDOW_STATE_CHANGED
                "isTextChange": False,
                "isWindowChange": True,
            }),
            self._call("OverlayWindowAdded", {
                "windowType": 2038,         # TYPE_APPLICATION_OVERLAY
                "flags": 0,
                "isOverlay": True,
                "invisibleTapLogger": False,
            }),
            self._call("LayoutInflate", {"resourceId": 0x7F0A00FF}),
            self._call("InternetConnect", {
                "lpszServerName": "creds.badactor.test", "nServerPort": 443,
            }, ret=0xB50),
        ]

    def android_tapjacking(self) -> List[Dict[str, Any]]:
        return [
            self._call("OverlayWindowAdded", {
                "windowType": 2038,
                "flags": 8 | 16,            # NOT_FOCUSABLE | NOT_TOUCHABLE
                "isOverlay": True,
                "invisibleTapLogger": True,
            }),
        ]

    def android_permission_escalation(self) -> List[Dict[str, Any]]:
        perms = [
            "android.permission.READ_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_CALL_LOG",
        ]
        return [
            self._call("RequestPermissions", {
                "permissions": perms,
                "requestCode": 1001,
                "dangerous": perms,
            }),
        ]

    def android_dynamic_dex(self) -> List[Dict[str, Any]]:
        return [
            self._call("LoadLibrary", {
                "lpLibFileName": "/data/data/com.fake.app/files/payload.dex",
                "dynamic_dex": True,
            }),
            self._call("InternetConnect", {
                "lpszServerName": "stage2.badactor.test", "nServerPort": 443,
            }, ret=0xB60),
        ]

    def android_sms_burst(self, count: int = 15) -> List[Dict[str, Any]]:
        return [
            self._call("SendSMS", {
                "destinationAddress": f"+91987650{i:04d}",
                "messageBodyHash": "70:aa11bb",
            })
            for i in range(count)
        ]
