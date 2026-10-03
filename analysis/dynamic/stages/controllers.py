"""
controllers.py — SandboxController implementations.

  CapeSandboxController     — Windows guests via CAPE/KVM REST API
  AndroidSandboxController  — Android-x86 via ADB + Frida
  MockSandboxController     — Scriptable fake for tests and demos

The mock is not an afterthought. It lets the entire eight-stage pipeline run
end to end on a laptop with no hypervisor, which is how the stage logic gets
tested in CI and how the dashboard gets demoed without detonating real malware.
It is scriptable: you describe *when* the fake sample should wake up, and the
pipeline should discover that activation stage on its own.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp

_LOGGER = logging.getLogger(__name__)


# ============================================================================
# CAPE (Windows)
# ============================================================================

class CapeSandboxController:
    """Drives a Windows guest through the CAPE sandbox REST API."""

    def __init__(self, base_url: str, task_id: int, timeout_sec: int = 30):
        self.base_url = base_url.rstrip("/")
        self.task_id = task_id
        self.timeout = aiohttp.ClientTimeout(total=timeout_sec)
        self._session: Optional[aiohttp.ClientSession] = None

    async def _client(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=self.timeout)
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        session = await self._client()
        url = f"{self.base_url}{path}"
        try:
            async with session.post(url, json={**payload, "task_id": self.task_id}) as resp:
                if resp.status != 200:
                    _LOGGER.warning("CAPE %s -> HTTP %d", path, resp.status)
                    return {}
                return await resp.json()
        except Exception as exc:
            _LOGGER.error("CAPE %s failed: %s", path, exc)
            return {}

    async def _get(self, path: str, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
        session = await self._client()
        url = f"{self.base_url}{path}"
        try:
            async with session.get(
                url, params={**(params or {}), "task_id": self.task_id}
            ) as resp:
                if resp.status != 200:
                    return {}
                return await resp.json()
        except Exception as exc:
            _LOGGER.error("CAPE %s failed: %s", path, exc)
            return {}

    # --- lifecycle ----------------------------------------------------

    async def restore_snapshot(self, snapshot: str = "golden") -> bool:
        r = await self._post("/api/machine/restore", {"snapshot": snapshot})
        return bool(r.get("success"))

    async def start_guest(self) -> bool:
        r = await self._post("/api/machine/start", {})
        return bool(r.get("success"))

    async def stop_guest(self) -> bool:
        r = await self._post("/api/machine/stop", {})
        return bool(r.get("success"))

    async def reboot_guest(self, graceful: bool = True, preserve_disk: bool = True) -> bool:
        r = await self._post(
            "/api/machine/reboot",
            {"graceful": graceful, "preserve_disk": preserve_disk},
        )
        return bool(r.get("success"))

    async def await_agent(self, timeout_sec: int) -> bool:
        deadline = asyncio.get_event_loop().time() + timeout_sec
        while asyncio.get_event_loop().time() < deadline:
            r = await self._get("/api/agent/status")
            if r.get("status") == "ready":
                return True
            await asyncio.sleep(2)
        return False

    # --- sample -------------------------------------------------------

    async def drop_sample(self, sample_path: str) -> str:
        r = await self._post("/api/sample/drop", {"host_path": sample_path})
        return r.get("guest_path", sample_path)

    async def execute_sample(self, guest_path: str) -> int:
        r = await self._post("/api/sample/execute", {"guest_path": guest_path})
        return int(r.get("pid", 0))

    # --- interaction --------------------------------------------------

    async def send_input(self, action: str, params: Dict[str, Any]) -> bool:
        r = await self._post("/api/input", {"action": action, "params": params})
        return bool(r.get("success"))

    async def screenshot(self) -> Optional[bytes]:
        session = await self._client()
        try:
            async with session.get(
                f"{self.base_url}/api/screenshot", params={"task_id": self.task_id}
            ) as resp:
                return await resp.read() if resp.status == 200 else None
        except Exception:
            return None

    async def dump_memory(self, pid: Optional[int] = None) -> Optional[str]:
        r = await self._post("/api/memory/dump", {"pid": pid})
        return r.get("path")

    # --- state --------------------------------------------------------

    async def list_processes(self) -> List[Dict[str, Any]]:
        r = await self._get("/api/processes")
        return r.get("processes", [])

    async def snapshot_state(self, targets: List[str]) -> Dict[str, Any]:
        r = await self._post("/api/state/snapshot", {"targets": targets})
        return r.get("state", {})

    async def diff_state(
        self, baseline: Dict[str, Any], targets: List[str]
    ) -> Dict[str, Any]:
        r = await self._post("/api/state/diff", {"baseline": baseline, "targets": targets})
        return r.get("diff", {})

    async def configure_network(self, profile: str, params: Dict[str, Any]) -> bool:
        r = await self._post("/api/network/configure", {"profile": profile, **params})
        return bool(r.get("success"))

    async def send_command(self, command: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return await self._post(f"/api/command/{command}", params)


# ============================================================================
# Android
# ============================================================================

class AndroidSandboxController:
    """
    Drives an Android-x86 QEMU guest via an ADB/Frida bridge service.

    Same interface as CAPE — stage actions are written once and run on both
    platforms; only the target names differ (see STAGE_CONFIGS android_targets).
    """

    def __init__(self, bridge_url: str, device_serial: str, timeout_sec: int = 30):
        self.bridge_url = bridge_url.rstrip("/")
        self.device_serial = device_serial
        self.timeout = aiohttp.ClientTimeout(total=timeout_sec)
        self._session: Optional[aiohttp.ClientSession] = None

    async def _client(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=self.timeout)
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        session = await self._client()
        try:
            async with session.post(
                f"{self.bridge_url}{path}",
                json={**payload, "serial": self.device_serial},
            ) as resp:
                return await resp.json() if resp.status == 200 else {}
        except Exception as exc:
            _LOGGER.error("Android bridge %s failed: %s", path, exc)
            return {}

    async def restore_snapshot(self, snapshot: str = "golden") -> bool:
        return bool((await self._post("/avd/restore", {"snapshot": snapshot})).get("success"))

    async def start_guest(self) -> bool:
        return bool((await self._post("/avd/start", {})).get("success"))

    async def stop_guest(self) -> bool:
        return bool((await self._post("/avd/stop", {})).get("success"))

    async def reboot_guest(self, graceful: bool = True, preserve_disk: bool = True) -> bool:
        return bool(
            (
                await self._post(
                    "/avd/reboot", {"graceful": graceful, "preserve_disk": preserve_disk}
                )
            ).get("success")
        )

    async def await_agent(self, timeout_sec: int) -> bool:
        deadline = asyncio.get_event_loop().time() + timeout_sec
        while asyncio.get_event_loop().time() < deadline:
            r = await self._post("/frida/status", {})
            if r.get("status") == "attached":
                return True
            await asyncio.sleep(2)
        return False

    async def drop_sample(self, sample_path: str) -> str:
        r = await self._post("/apk/install", {"host_path": sample_path})
        return r.get("package_name", sample_path)

    async def execute_sample(self, guest_path: str) -> int:
        r = await self._post("/apk/launch", {"package_name": guest_path})
        return int(r.get("pid", 0))

    async def send_input(self, action: str, params: Dict[str, Any]) -> bool:
        # Map desktop-flavored actions onto Android equivalents so stage
        # actions don't need platform branches.
        android_action = {
            "mouse_move_bezier": "swipe",
            "mouse_click": "tap",
            "mouse_scroll": "scroll",
            "keyboard_type": "input_text",
            "open_document": "open_app",
            "open_browser": "open_url",
            "lock_unlock": "screen_lock_cycle",
            "switch_windows": "recents_switch",
        }.get(action, action)
        r = await self._post("/input", {"action": android_action, "params": params})
        return bool(r.get("success"))

    async def screenshot(self) -> Optional[bytes]:
        session = await self._client()
        try:
            async with session.get(
                f"{self.bridge_url}/screenshot", params={"serial": self.device_serial}
            ) as resp:
                return await resp.read() if resp.status == 200 else None
        except Exception:
            return None

    async def dump_memory(self, pid: Optional[int] = None) -> Optional[str]:
        return (await self._post("/memory/dump", {"pid": pid})).get("path")

    async def list_processes(self) -> List[Dict[str, Any]]:
        return (await self._post("/processes", {})).get("processes", [])

    async def snapshot_state(self, targets: List[str]) -> Dict[str, Any]:
        return (await self._post("/state/snapshot", {"targets": targets})).get("state", {})

    async def diff_state(
        self, baseline: Dict[str, Any], targets: List[str]
    ) -> Dict[str, Any]:
        return (
            await self._post("/state/diff", {"baseline": baseline, "targets": targets})
        ).get("diff", {})

    async def configure_network(self, profile: str, params: Dict[str, Any]) -> bool:
        return bool(
            (await self._post("/network/configure", {"profile": profile, **params})).get(
                "success"
            )
        )

    async def send_command(self, command: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return await self._post(f"/command/{command}", params)


# ============================================================================
# Mock
# ============================================================================

@dataclass
class MockBehaviorScript:
    """
    Describes how the fake sample behaves, so tests can assert that the
    pipeline *discovers* a given evasion profile rather than being told it.

    Example — a reboot-gated, sleep-stalling sample:

        MockBehaviorScript(
            activates_after_reboot=True,
            activation_delay_sec=900,
            installs_persistence=True,
        )
    """
    # Gating conditions
    requires_user_interaction: bool = False
    requires_network: bool = False
    activates_after_reboot: bool = False
    activation_delay_sec: int = 0          # Wall-clock silence before waking

    # Observable behavior once active
    installs_persistence: bool = True
    beacons: bool = True
    beacon_interval_sec: float = 60.0
    c2_domains: List[str] = field(default_factory=lambda: ["c2.example-malware.test"])

    # Memory artifacts surfaced in Stage 8
    packed_in_memory: bool = True
    memory_yara_hits: List[str] = field(
        default_factory=lambda: ["india_scam_loanapp", "generic_packer"]
    )
    # Maps a payload DLL manually instead of using LoadLibrary — shows up as a
    # module with no file backing it.
    reflective_dll_loading: bool = True
    # Holds an injection-capable handle to another process at capture time.
    injects_into_processes: bool = True
    # Single-instance mutex; a family-stable host indicator in the handle table.
    mutex_name: str = "Global\\MOCK-LOANAPP-01"

    # Reliability simulation
    crashes_on_boot: bool = False
    resists_shutdown: bool = False


class MockSandboxController:
    """
    In-memory fake guest. No hypervisor, no network, no malware.

    Tracks enough internal state (activated / rebooted / interacted) that the
    pipeline's evasion inference has something real to discover.
    """

    def __init__(self, script: Optional[MockBehaviorScript] = None, speed: float = 1.0):
        self.script = script or MockBehaviorScript()
        self.speed = speed            # >1 compresses simulated waits

        self.running = False
        self.rebooted = False
        self.interacted = False
        self.network_up = False
        self.activated = False

        self.sample_pid = 4242
        self.start_time = datetime.utcnow()
        self._elapsed = 0.0
        self._processes: List[Dict[str, Any]] = []
        self._persistence: List[Dict[str, Any]] = []
        self._connections: List[Dict[str, Any]] = []
        self._dns: List[Dict[str, Any]] = []

        self.command_log: List[str] = []
        self.input_log: List[str] = []

    # --- activation model --------------------------------------------

    def _check_activation(self) -> None:
        """Evaluate whether every gate the script declares is now satisfied."""
        if self.activated:
            return
        s = self.script
        if s.requires_user_interaction and not self.interacted:
            return
        if s.requires_network and not self.network_up:
            return
        if s.activates_after_reboot and not self.rebooted:
            return
        if s.activation_delay_sec and self._elapsed < s.activation_delay_sec:
            return

        self.activated = True
        _LOGGER.info("[mock] Sample activated at T+%.0fs", self._elapsed)

        if s.installs_persistence:
            self._persistence = [
                {
                    "target": "registry_run_keys",
                    "name": "SystemUpdateSvc",
                    "path": r"C:\Users\Admin\AppData\Roaming\svcupd.exe",
                },
                {
                    "target": "scheduled_tasks",
                    "name": "\\Microsoft\\Windows\\UpdateOrchestrator\\SvcRefresh",
                    "path": r"C:\Users\Admin\AppData\Roaming\svcupd.exe",
                },
            ]

        self._processes.append(
            {"pid": 6001, "name": "svcupd.exe", "ppid": self.sample_pid, "suspicious": True}
        )

    # --- lifecycle ----------------------------------------------------

    async def restore_snapshot(self, snapshot: str = "golden") -> bool:
        self.command_log.append(f"restore_snapshot:{snapshot}")
        self.running = False
        self.activated = False
        self.rebooted = False
        self._processes = []
        self._persistence = []
        return True

    async def start_guest(self) -> bool:
        self.command_log.append("start_guest")
        self.running = True
        self._processes = [
            {"pid": 4, "name": "System", "ppid": 0},
            {"pid": 720, "name": "explorer.exe", "ppid": 640},
            {"pid": 1180, "name": "svchost.exe", "ppid": 640},
        ]
        return True

    async def stop_guest(self) -> bool:
        self.command_log.append("stop_guest")
        self.running = False
        return True

    async def reboot_guest(self, graceful: bool = True, preserve_disk: bool = True) -> bool:
        self.command_log.append(f"reboot:graceful={graceful}")
        if graceful and self.script.resists_shutdown:
            return False   # Force the orchestrator down its hard-reset path
        self.rebooted = True
        # Persistence-installed processes come back; transient ones don't
        self._processes = [
            {"pid": 4, "name": "System", "ppid": 0},
            {"pid": 726, "name": "explorer.exe", "ppid": 648},
        ]
        self._check_activation()
        return True

    async def await_agent(self, timeout_sec: int) -> bool:
        await asyncio.sleep(min(0.05, timeout_sec / self.speed))
        return not self.script.crashes_on_boot

    # --- sample -------------------------------------------------------

    async def drop_sample(self, sample_path: str) -> str:
        self.command_log.append(f"drop:{sample_path}")
        return r"C:\Users\Admin\AppData\Local\Temp\sample.exe"

    async def execute_sample(self, guest_path: str) -> int:
        self.command_log.append(f"execute:{guest_path}")
        if self.script.crashes_on_boot:
            return 0
        self._processes.append(
            {"pid": self.sample_pid, "name": "sample.exe", "ppid": 720, "suspicious": True}
        )
        self._check_activation()
        return self.sample_pid

    # --- interaction --------------------------------------------------

    async def send_input(self, action: str, params: Dict[str, Any]) -> bool:
        self.input_log.append(action)
        self.interacted = True
        self._check_activation()
        return True

    async def screenshot(self) -> Optional[bytes]:
        return b"\x89PNG\r\n\x1a\n" + b"\x00" * 128

    async def dump_memory(self, pid: Optional[int] = None) -> Optional[str]:
        self.command_log.append(f"dump_memory:{pid}")
        suffix = f"_pid{pid}" if pid else "_full"
        return f"/artifacts/mock/memdump{suffix}.raw"

    # --- state --------------------------------------------------------

    async def list_processes(self) -> List[Dict[str, Any]]:
        return list(self._processes)

    async def snapshot_state(self, targets: List[str]) -> Dict[str, Any]:
        return {t: [] for t in targets}

    async def diff_state(
        self, baseline: Dict[str, Any], targets: List[str]
    ) -> Dict[str, Any]:
        self._check_activation()
        diff: Dict[str, List[Dict[str, Any]]] = {t: [] for t in targets}
        for entry in self._persistence:
            target = entry.get("target")
            if target in diff:
                diff[target].append(entry)
        return diff

    async def configure_network(self, profile: str, params: Dict[str, Any]) -> bool:
        self.command_log.append(f"network:{profile}")
        self.network_up = True
        self._check_activation()

        if self.activated and self.script.beacons:
            now = self._elapsed
            for i in range(5):
                t = now + i * self.script.beacon_interval_sec
                self._connections.append(
                    {"timestamp": t, "dst_ip": "203.0.113.42", "dst_port": 443}
                )
            for domain in self.script.c2_domains:
                self._dns.append({"domain": domain, "timestamp": now})
        return True

    # --- memory inventory ---------------------------------------------

    def _loaded_dlls(self) -> List[Dict[str, Any]]:
        """Baseline module list, plus whatever the script's payload added."""
        modules: List[Dict[str, Any]] = [
            {
                "pid": 720, "process": "explorer.exe", "name": "ntdll.dll",
                "base": "0x7ffb10000000", "size": 2027520,
                "path": r"C:\Windows\System32\ntdll.dll",
                "disk_backed": True, "in_load_order": True,
                "path_mismatch": False, "signed": True,
            },
            {
                "pid": 720, "process": "explorer.exe", "name": "kernel32.dll",
                "base": "0x7ffb0f000000", "size": 786432,
                "path": r"C:\Windows\System32\kernel32.dll",
                "disk_backed": True, "in_load_order": True,
                "path_mismatch": False, "signed": True,
            },
            {
                "pid": 1180, "process": "svchost.exe", "name": "ws2_32.dll",
                "base": "0x7ffb0e800000", "size": 425984,
                "path": r"C:\Windows\System32\ws2_32.dll",
                "disk_backed": True, "in_load_order": True,
                "path_mismatch": False, "signed": True,
            },
        ]
        if not self.activated:
            return modules

        # Side-loaded module dropped next to the sample
        modules.append(
            {
                "pid": self.sample_pid, "process": "sample.exe",
                "name": "version.dll", "base": "0x180000000", "size": 98304,
                "path": r"C:\Users\Admin\AppData\Local\Temp\version.dll",
                "disk_backed": True, "in_load_order": True,
                "path_mismatch": False, "signed": False,
            }
        )
        if self.script.reflective_dll_loading:
            modules.append(
                {
                    "pid": self.sample_pid, "process": "sample.exe",
                    "name": "<unbacked>", "base": "0x2a0000", "size": 245760,
                    "path": "", "disk_backed": False, "in_load_order": False,
                    "path_mismatch": False, "signed": False,
                }
            )
        if self.script.injects_into_processes:
            modules.append(
                {
                    "pid": 720, "process": "explorer.exe", "name": "ntdll.dll",
                    "base": "0x3c0000", "size": 245760,
                    "path": r"C:\Windows\System32\ntdll.dll",
                    "disk_backed": True, "in_load_order": True,
                    "path_mismatch": True, "signed": False,
                }
            )
        return modules

    def _handles(self) -> List[Dict[str, Any]]:
        """Handle table entries worth reporting on."""
        handles: List[Dict[str, Any]] = [
            {
                "pid": 720, "process": "explorer.exe", "type": "Key",
                "name": r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows",
                "access": "KEY_READ",
            },
        ]
        if not self.activated:
            return handles

        handles.extend(
            [
                {
                    "pid": self.sample_pid, "process": "sample.exe",
                    "type": "Mutant", "name": self.script.mutex_name,
                    "access": "MUTANT_ALL_ACCESS",
                },
                {
                    "pid": self.sample_pid, "process": "sample.exe",
                    "type": "File",
                    "name": r"\Device\HarddiskVolume2\Users\Admin\AppData\Roaming\svcupd.exe",
                    "access": "FILE_GENERIC_WRITE",
                },
                {
                    "pid": self.sample_pid, "process": "sample.exe",
                    "type": "Key",
                    "name": r"\REGISTRY\USER\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run",
                    "access": "KEY_ALL_ACCESS",
                },
            ]
        )
        if self.script.injects_into_processes:
            handles.extend(
                [
                    {
                        "pid": self.sample_pid, "process": "sample.exe",
                        "type": "Process", "target_pid": 720,
                        "target_name": "explorer.exe",
                        "access": "PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_CREATE_THREAD",
                    },
                    {
                        "pid": self.sample_pid, "process": "sample.exe",
                        "type": "Section", "name": r"\BaseNamedObjects\MOCK-SHM-01",
                        "access": "SECTION_MAP_WRITE",
                    },
                    {
                        "pid": self.sample_pid, "process": "sample.exe",
                        "type": "Token", "name": "",
                        "access": "TOKEN_DUPLICATE|TOKEN_IMPERSONATE",
                    },
                ]
            )
        return handles

    async def send_command(self, command: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.command_log.append(f"cmd:{command}")

        # Advance simulated clock so delay-gated activation can fire
        window = params.get("window_sec", 0)
        if window:
            self._elapsed += window / self.speed
            self._check_activation()

        if command == "query_recent_connections":
            if not (self.activated and self.script.beacons):
                return {"connections": []}
            interval = self.script.beacon_interval_sec
            return {
                "connections": [
                    {"timestamp": self._elapsed + i * interval, "dst_ip": "203.0.113.42"}
                    for i in range(3)
                ]
            }

        if command == "query_network_summary":
            return {
                "dns_queries": list(self._dns),
                "connections": list(self._connections),
                "ja3": ["771,4865-4866-4867,0-23-65281", "771,49195-49199,0-23"]
                if self.activated
                else [],
            }

        if command == "query_activity_summary":
            return {"event_count": random.randint(8, 40) if self.activated else 0}

        if command == "extract_from_memory":
            extraction = params.get("extraction", "")
            # Modules and handles exist on any live system, so these return
            # inventory whether or not the sample ever woke up. Only the
            # anomalies inside them are evidence.
            if extraction == "loaded_dlls":
                return {"items": self._loaded_dlls()}
            if extraction == "handles":
                return {"items": self._handles()}
            if not self.activated:
                return {"items": []}
            if extraction == "unpacked_pe_images" and self.script.packed_in_memory:
                return {"items": [{"base": "0x400000", "size": 245760}]}
            if extraction == "config_blocks":
                return {"items": [{"c2_hosts": self.script.c2_domains, "campaign": "MOCK-01"}]}
            if extraction == "strings_urls_ips":
                return {"items": [f"https://{d}/gate.php" for d in self.script.c2_domains]}
            if extraction == "crypto_keys":
                return {"items": [{"algo": "AES-256", "offset": "0x7ffd1234"}]}
            if extraction == "staged_exfil_buffers":
                return {"items": [{"size": 8192, "type": "credential_dump"}]}
            return {"items": []}

        if command == "dump_module":
            base = params.get("base", "0x0")
            pid = params.get("pid")
            name = str(params.get("name") or "module").replace("\\", "_")
            return {
                "path": f"/artifacts/mock/dlls/pid{pid}_{base}_{name}",
                "size_bytes": 131072,
                "sha256": "0" * 64,
            }

        if command == "volatility":
            plugin = params.get("plugin")
            if plugin == "malfind" and self.activated:
                return {"regions": [{"pid": self.sample_pid, "protection": "PAGE_EXECUTE_READWRITE"}]}
            if plugin == "ldrmodules" and self.activated:
                return {"unlinked": [{"pid": self.sample_pid, "base": "0x400000"}]}
            if plugin == "dlllist":
                return {"modules": self._loaded_dlls()}
            if plugin == "handles":
                return {"handles": self._handles()}
            return {}

        if command == "yara_scan_memory":
            if not self.activated:
                return {"matches": []}
            return {"matches": [{"rule": r} for r in self.script.memory_yara_hits]}

        return {"success": True}
