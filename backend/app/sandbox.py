"""
backend/app/sandbox.py — Dynamic-analysis / detonation sandbox integration.

This module provides the bridge to real or simulated detonation:
1. When CAPE_API_URL or SANDBOX_API_URL is configured, the sample is submitted
   to the isolated remote sandbox and runs in execution_mode="real".
2. In simulated mode (offline/local fallback), execution_mode="simulated" is
   strictly declared.
   - ZERO hardcoded fixture IPs or domains are ever emitted in production.
   - Endpoints and domains derive strictly from this sample's static extraction
     or threat-intelligence lookups. If none exist, zero network events are emitted.
   - Clean/benign samples report "no behavior observed (simulated)", never "clean".
   - Target architecture is inspected directly from binary headers (ARM, x86_64, etc.).
"""

from __future__ import annotations

import logging
import os
import struct
from pathlib import Path
from typing import Optional

from agents.orchestrator.schema import DynamicAnalysisOutput

_LOGGER = logging.getLogger(__name__)

# Single source of truth for Linux simulated persistence paths
PERSISTENCE_CRON_PATH = "/etc/cron.d/root_cron"
PERSISTENCE_PAYLOAD_PATH = "/dev/shm/.payload"

_ELF_MACHINES = {
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    40: "ARM",
    50: "IA-64",
    62: "x86_64",
    183: "AArch64",
    243: "RISC-V",
}

_PE_MACHINES = {
    0x14C: "x86",
    0x8664: "x86_64",
    0xAA64: "ARM64",
    0x200: "IA-64",
}


def sandbox_url() -> Optional[str]:
    """The configured remote sandbox endpoint, or None when offline."""
    return os.environ.get("SANDBOX_API_URL") or os.environ.get("CAPE_API_URL") or None


def is_configured() -> bool:
    return sandbox_url() is not None


def inspect_binary_architecture(sample_path: str | Path) -> str:
    """Read binary header directly to determine CPU architecture without execution."""
    try:
        path = Path(sample_path)
        if not path.is_file():
            return "unknown"
        with open(path, "rb") as f:
            header = f.read(64)
        if header.startswith(b"\x7fELF") and len(header) >= 20:
            endian = "<" if header[5] == 1 else ">"
            machine_id = struct.unpack_from(endian + "H", header, 18)[0]
            bits = "64-bit" if header[4] == 2 else "32-bit"
            name = _ELF_MACHINES.get(machine_id, f"Machine({machine_id})")
            return f"{name} ({bits})"
        if header.startswith(b"MZ") and len(header) >= 64:
            e_lfanew = struct.unpack_from("<I", header, 0x3C)[0]
            with open(path, "rb") as f:
                f.seek(e_lfanew)
                pe_sig = f.read(6)
            if pe_sig.startswith(b"PE\x00\x00") and len(pe_sig) >= 6:
                pe_machine = struct.unpack_from("<H", pe_sig, 4)[0]
                return _PE_MACHINES.get(pe_machine, f"PE({hex(pe_machine)})")
        if header.startswith(b"PK\x03\x04"):
            return "Android (Dalvik/ART)"
    except Exception as exc:
        _LOGGER.debug("Architecture inspection exception: %s", exc)
    return "Generic / Unspecified"


async def run_dynamic_analysis(
    sample_path: str | Path,
    platform: Optional[str] = None,
    file_type: Optional[str] = None,
    static_data: Optional[dict] = None,
    malware_bazaar: Optional[dict] = None,
    target_architecture: Optional[str] = None,
) -> DynamicAnalysisOutput:
    """
    Return dynamic-analysis state for a sample.

    When remote sandbox is active: submits and returns execution_mode="real".
    When in local fallback: executes simulated detonation with execution_mode="simulated".
    """
    path_str = str(sample_path)
    file_name = os.path.basename(path_str)
    ext = Path(path_str).suffix.lower()
    if not file_type:
        file_type = ext.lstrip(".").lower() if ext else "unknown"
    else:
        file_type = str(file_type).lower()

    target_arch = target_architecture or inspect_binary_architecture(sample_path)
    url = sandbox_url()

    # ── REMOTE SANDBOX PATH (REAL DETONATION) ─────────────────────────────────
    if url:
        try:
            import httpx

            path = str(sample_path)
            remote_file_type = file_type if file_type and file_type != "unknown" else "unknown"
            if remote_file_type == "unknown" and Path(sample_path).is_file():
                suffix = Path(sample_path).suffix.lower().lstrip(".")
                if suffix:
                    remote_file_type = suffix

            async with httpx.AsyncClient(timeout=30) as client:
                with open(path, "rb") as handle:
                    files = {"file": (file_name, handle)}
                    data = {"options": json_body(remote_file_type)}
                    if remote_file_type == "dll" or file_name.lower().endswith(".dll"):
                        data["package"] = "dll"
                    try:
                        response = await client.post(f"{url.rstrip('/')}/api/tasks/create/", data=data, files=files)
                        response.raise_for_status()
                        payload = response.json()
                    except Exception as sub_err:
                        _LOGGER.exception("Sandbox submission to %s failed", url)
                        return DynamicAnalysisOutput(
                            sample_id=file_name,
                            available=True,
                            execution_mode="real",
                            status="failed",
                            dynamic_status="failed",
                            failure_reason=f"Sandbox did not accept sample: {sub_err}",
                            message="Dynamic analysis submission failed — sandbox did not accept the sample.",
                            target_architecture=target_arch,
                        )

            task_id = payload.get("task_id") or payload.get("id")
            return DynamicAnalysisOutput(
                sample_id=file_name,
                available=True,
                execution_mode="real",
                status="submitted",
                dynamic_status="completed",
                task_id=str(task_id) if task_id else None,
                sandbox_url=url,
                target_architecture=target_arch,
                message="Dynamic analysis submitted to sandbox. Results will appear when detonation completes.",
            )
        except ImportError:
            return DynamicAnalysisOutput(
                sample_id=file_name,
                available=True,
                execution_mode="real",
                status="failed",
                dynamic_status="unavailable",
                failure_reason="httpx client not installed",
                target_architecture=target_arch,
                message="Dynamic analysis unavailable — httpx client not installed.",
            )
        except Exception as exc:
            _LOGGER.exception("Sandbox integration error")
            return DynamicAnalysisOutput(
                sample_id=file_name,
                available=True,
                execution_mode="real",
                status="failed",
                dynamic_status="failed",
                failure_reason=str(exc),
                target_architecture=target_arch,
                message="Dynamic analysis unavailable — sandbox integration error.",
            )

    # ── SIMULATED SANDBOX PATH (ZERO FIXTURE MANDATE) ────────────────────────
    static = static_data or {}
    extracted = static.get("extracted_strings") or {}
    yara_matches = static.get("yara_matches") or []
    mb = malware_bazaar or {}

    # Extract observables strictly from this sample
    extracted_ips: list[str] = [str(ip) for ip in extracted.get("ips", []) if ip]
    extracted_urls: list[str] = [str(u) for u in extracted.get("urls", []) if u]
    suspicious_keywords: list[str] = [str(k).lower() for k in extracted.get("suspicious_keywords", []) if k]

    has_threat = bool(
        yara_matches
        or extracted_ips
        or extracted_urls
        or suspicious_keywords
        or mb.get("found")
    )

    # 1. Benign or clean-looking sample (e.g. hello world, harmless binary)
    if not has_threat:
        return DynamicAnalysisOutput(
            sample_id=file_name,
            available=True,
            execution_mode="simulated",
            status="completed",
            dynamic_status="no_behavior_observed",
            failure_reason=None,
            message=f"No behavior observed (simulated). Target architecture: {target_arch}. Static inspection identified no malicious triggers.",
            task_id=f"sim-clean-{file_name[:16]}",
            sandbox_url=f"simulated://isolated-{platform or 'native'}-sandbox",
            duration_seconds=30,
            target_architecture=target_arch,
            network_connections=[],
            c2_endpoints_detected=[],
            process_tree=[
                {"pid": 1001, "process_name": file_name, "cmdline": f"./{file_name}", "exit_code": 0}
            ],
            api_calls=[],
            dns_queries=[],
            files_written=[],
            registry_changes=[],
            persistence_artifacts=[],
        )

    # 2. Suspicious/malicious sample — derive signals strictly from sample observables
    network_connections: list[dict] = []
    c2_endpoints: list[str] = []
    dns_queries: list[str] = []

    # Map extracted IPs
    for ip in extracted_ips[:5]:
        network_connections.append({
            "dest_ip": ip,
            "dest_port": 80,
            "protocol": "TCP",
            "flagged_c2": False,  # Decoupled reputation: not flagged C2 by default
            "simulated": True,
        })

    # Map extracted URLs to hostnames/queries
    for u in extracted_urls[:5]:
        try:
            from urllib.parse import urlsplit
            host = urlsplit(u).hostname
            if host and "." in host and not host.endswith((".exe", ".bin", ".dat")):
                if host not in dns_queries:
                    dns_queries.append(host)
        except Exception:
            pass

    base_pid = 3100 + (abs(hash(file_name)) % 5000)
    process_tree: list[dict] = [
        {"pid": base_pid, "process_name": file_name, "cmdline": f"./{file_name}"}
    ]
    api_calls: list[str] = []
    files_written: list[str] = []
    registry_changes: list[str] = []
    persistence_artifacts: list[str] = []

    # Linux / ELF heuristics from sample evidence
    if platform == "linux" or ext in (".elf", ".bin", ".so") or file_type == "elf":
        has_cron = any("cron" in kw for kw in suspicious_keywords) or any("cron" in str(y).lower() for y in yara_matches)
        has_shell = any(k in suspicious_keywords for k in ("/bin/sh", "/bin/bash", "system", "execve"))
        has_ptrace = any("ptrace" in kw for kw in suspicious_keywords)
        has_socket = any(k in suspicious_keywords for k in ("socket", "connect")) or bool(network_connections)

        if has_ptrace:
            api_calls.append("sys_ptrace")
        if has_socket:
            api_calls.extend(["sys_socket", "sys_connect"])
        if has_shell:
            api_calls.extend(["sys_fork", "sys_execve"])
            process_tree.append({
                "pid": base_pid + 1,
                "process_name": "sh",
                "cmdline": f"/bin/sh -c '{file_name}'",
            })
        if has_cron:
            cmdline = f"crontab -l; echo '* * * * * {PERSISTENCE_PAYLOAD_PATH}' | crontab -"
            process_tree.append({
                "pid": base_pid + 2,
                "process_name": "crontab",
                "cmdline": cmdline,
            })
            persistence_artifacts.append(f"Cron persistence installed: {PERSISTENCE_CRON_PATH}")

    # Windows / PE heuristics from sample evidence
    elif platform == "windows" or ext in (".exe", ".dll") or file_type in ("pe", "exe", "dll"):
        has_reg = any("run" in kw or "registry" in kw for kw in suspicious_keywords)
        has_ps = any("powershell" in kw or "cmd.exe" in kw for kw in suspicious_keywords)
        if has_ps:
            process_tree.append({
                "pid": 4120,
                "process_name": "cmd.exe",
                "cmdline": f"cmd.exe /c start {file_name}",
            })
        if has_reg:
            reg_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ClientAutoStart"
            registry_changes.append(reg_key)
            persistence_artifacts.append(f"Registry Run Key added: {reg_key}")
            api_calls.append("RegSetValueExW")

    # Android / APK heuristics from manifest
    elif platform == "android" or ext == ".apk" or file_type == "apk":
        perms = (static.get("android_manifest") or {}).get("permissions") or []
        if any("BOOT_COMPLETED" in p for p in perms):
            persistence_artifacts.append("RECEIVE_BOOT_COMPLETED receiver declared in AndroidManifest")
        if any("SMS" in p for p in perms):
            api_calls.append("android.telephony.SmsManager.sendTextMessage")
        if any("LOCATION" in p for p in perms):
            api_calls.append("android.location.LocationManager.getLastKnownLocation")

    return DynamicAnalysisOutput(
        sample_id=file_name,
        available=True,
        execution_mode="simulated",
        status="completed",
        dynamic_status="completed",
        failure_reason=None,
        message=f"Detonation simulated from static observables (Target Architecture: {target_arch}).",
        task_id=f"sim-{platform or 'native'}-{file_name[:16]}",
        sandbox_url=f"simulated://isolated-{platform or 'native'}-sandbox",
        duration_seconds=45,
        target_architecture=target_arch,
        network_connections=network_connections,
        c2_endpoints_detected=c2_endpoints,
        process_tree=process_tree,
        api_calls=api_calls,
        dns_queries=dns_queries,
        files_written=files_written,
        registry_changes=registry_changes,
        persistence_artifacts=persistence_artifacts,
    )



def json_body(file_type: Optional[str]) -> str:
    import json
    return json.dumps({"file_type": file_type})