"""
backend/app/sandbox.py — Decoupled real dynamic-analysis sandbox client.

Connects to the standalone E-Rakshak Dynamic Sandbox Host (SANDBOX_API_URL).
When SANDBOX_API_URL is unconfigured, returns dynamic_status="unavailable".
Strictly real dynamic sandbox execution. ZERO fabricated events.
Cryptographically validates artifact manifest hashes before parsing via strace_parser.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import struct
import time
from pathlib import Path
from typing import Optional

import httpx

from agents.orchestrator.schema import DynamicAnalysisOutput
from providers.dynamic.base import DynamicState
from providers.dynamic.hybrid_analysis import HybridAnalysisAdapter
from providers.dynamic.pipeline import DynamicAnalysisPipeline
from .strace_parser import parse_strace_artifacts

_LOGGER = logging.getLogger(__name__)


def compute_file_sha256(file_path: str | Path) -> str:
    """Compute hex SHA-256 for a local file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def verify_manifest_hmac(manifest: dict, secret: Optional[str] = None) -> bool:
    """Cryptographically verify the HMAC signature on manifest.json."""
    if not isinstance(manifest, dict) or ("_hmac" not in manifest and "signature" not in manifest):
        return False
    sig = manifest.get("_hmac") or manifest.get("signature")
    core = {k: v for k, v in manifest.items() if k not in ("_hmac", "signature", "manifest.json")}
    token = secret or sandbox_token()
    canonical = json.dumps(core, sort_keys=True)
    expected = hmac.new(token.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)

_ELF_MACHINES = {
    2: "SPARC",
    3: "x86",
    4: "m68k",
    8: "MIPS",
    20: "PPC",
    21: "PPC64",
    40: "ARM",
    42: "SH",
    43: "SPARCV9",
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
    """The configured remote sandbox endpoint, or None when unconfigured."""
    return os.environ.get("SANDBOX_API_URL") or os.environ.get("CAPE_API_URL") or None


def sandbox_token() -> str:
    """Bearer authentication token for sandbox host."""
    return os.environ.get("SANDBOX_API_TOKEN", "erakshak-sandbox-secret-token")


def is_configured() -> bool:
    return sandbox_url() is not None or bool((os.environ.get("HYBRID_ANALYSIS_API_KEY") or "").strip())


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
            endian_label = "little-endian" if header[5] == 1 else "big-endian"
            name = _ELF_MACHINES.get(machine_id, f"e_machine=0x{machine_id:04x} (unmapped)")
            return f"{name} ({bits}, {endian_label})"
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


async def _run_hybrid_analysis_dynamic(
    sample_path: str | Path,
    file_name: str,
    platform: Optional[str] = None,
    file_type: Optional[str] = None,
    static_data: Optional[dict] = None,
    target_arch: Optional[str] = None,
    timeout_seconds: int = 90,
) -> DynamicAnalysisOutput:
    """Execute dynamic lookup/analysis via Hybrid Analysis adapter."""
    arch_str = str(target_arch or inspect_binary_architecture(sample_path))
    path_str = str(sample_path)

    try:
        submitted_sha256 = compute_file_sha256(path_str)
    except Exception as exc:
        return DynamicAnalysisOutput(
            sample_id=file_name,
            available=False,
            execution_mode="real",
            status="failed",
            dynamic_status="failed",
            failure_reason=f"Failed to read sample file: {exc}",
            message=f"Dynamic analysis failed: {exc}",
            target_architecture=arch_str,
        )

    # Architecture & platform gates run before checking provider credentials so
    # static-only formats complete without depending on dynamic services.
    plat_raw = str(platform or "").lower()
    ft_raw = str(file_type or "").lower()

    # Mach-O is static-only
    if "macho" in ft_raw or "mach_o" in ft_raw or plat_raw in ("macos", "darwin", "macho"):
        return DynamicAnalysisOutput(
            sample_id=file_name,
            available=False,
            execution_mode="real",
            status="not_supported",
            dynamic_status="unavailable",
            failure_reason="Mach-O is static-only",
            message="Dynamic analysis: not performed (static-only)",
            target_architecture=arch_str,
        )

    # Android APK
    if ft_raw in ("apk", "android") or plat_raw == "android":
        return DynamicAnalysisOutput(
            sample_id=file_name,
            available=False,
            execution_mode="real",
            status="not_supported",
            dynamic_status="unavailable",
            failure_reason="APK dynamic analysis not configured",
            message="Dynamic analysis not performed: APK dynamic analysis not configured",
            target_architecture=arch_str,
        )

    ha_key = (os.environ.get("HYBRID_ANALYSIS_API_KEY") or "").strip().strip('"').strip("'")
    if not ha_key:
        return DynamicAnalysisOutput(
            sample_id=file_name,
            available=False,
            execution_mode="real",
            status="unavailable",
            dynamic_status="unavailable",
            failure_reason="HYBRID_ANALYSIS_API_KEY is not configured",
            message="Dynamic analysis not performed: HYBRID_ANALYSIS_API_KEY is not configured",
            target_architecture=arch_str,
        )

    # Non-x86_64 ELF is static-only. Keep this provider-availability check
    # after the explicit Mach-O/APK gates, which never need a provider.
    if ft_raw == "elf" or plat_raw == "linux":
        arch_lower = arch_str.lower()
        if not ("x86_64" in arch_lower or "amd64" in arch_lower or "x64" in arch_lower):
            reason = f"{arch_str} is not supported (static-only)"
            return DynamicAnalysisOutput(
                sample_id=file_name,
                available=False,
                execution_mode="real",
                status="not_supported",
                dynamic_status="unavailable",
                failure_reason=reason,
                message=f"Dynamic analysis not performed: {reason}",
                target_architecture=arch_str,
            )

    try:
        adapter = HybridAnalysisAdapter(api_key=ha_key, timeout=min(timeout_seconds, 20))
        pipeline = DynamicAnalysisPipeline(providers={"hybrid_analysis": adapter})

        norm_plat = "ELF" if (ft_raw == "elf" or plat_raw == "linux") else "PE"
        norm_arch = "x86_64"

        static_endpoints = []
        if isinstance(static_data, dict):
            extracted = static_data.get("extracted_strings") or {}
            if isinstance(extracted, dict):
                static_endpoints.extend(extracted.get("ips") or [])
                static_endpoints.extend(extracted.get("urls") or [])

        result = await asyncio.to_thread(
            pipeline.run_execution,
            sample_path=path_str,
            sha256=submitted_sha256,
            platform=norm_plat,
            architecture=norm_arch,
            timeout_seconds=timeout_seconds,
            static_endpoints=tuple(static_endpoints),
        )

        if result.state == DynamicState.COMPLETED:
            has_behavior = result.observation.has_behavior()

            if not has_behavior:
                return DynamicAnalysisOutput(
                    sample_id=file_name,
                    available=False,
                    execution_mode="real",
                    status="unavailable",
                    dynamic_status="unavailable",
                    failure_reason="Hybrid Analysis execution task returned no behavioral evidence",
                    message="Dynamic analysis not performed: the completed task report contained no behavioral evidence",
                    target_architecture=arch_str,
                )

            proc_tree = []
            for proc in result.observation.process:
                proc_tree.append({
                    "pid": proc.get("pid") or 1,
                    "name": proc.get("name") or proc.get("command") or "process",
                    "command": proc.get("command") or proc.get("cmd") or proc.get("name") or "",
                })

            net_conns = []
            for conn in result.observation.network:
                net_conns.append({
                    "ip": conn.get("ip") or conn.get("dest_ip") or "",
                    "dest_ip": conn.get("dest_ip") or conn.get("ip") or "",
                    "port": conn.get("port") or conn.get("dest_port") or "",
                    "dest_port": conn.get("dest_port") or conn.get("port") or "",
                    "domain": conn.get("domain") or conn.get("name") or "",
                    "protocol": conn.get("protocol") or "TCP",
                    "flagged_c2": conn.get("flagged_c2", False),
                })

            dns_queries = []
            for d in result.observation.dns:
                dom = d.get("name") or d.get("domain")
                if dom and dom not in dns_queries:
                    dns_queries.append(dom)

            files_written = []
            for f in result.observation.file:
                fp = f.get("path") or f.get("name")
                if fp and fp not in files_written:
                    files_written.append(fp)

            registry_changes = []
            for r in result.observation.registry:
                rk = r.get("path") or r.get("name")
                if rk and rk not in registry_changes:
                    registry_changes.append(rk)

            api_calls = [row.get("name", "") for row in result.observation.api_call if row.get("name")]

            c2_detected = [
                c.get("ip") or c.get("domain") for c in net_conns if c.get("flagged_c2")
            ]

            msg = result.report_line or (
                "Hypervisor telemetry recorded." if has_behavior else "A provider verdict was reported, but no behavior was observed."
            )

            return DynamicAnalysisOutput(
                sample_id=file_name,
                available=True,
                execution_mode="real",
                status="completed",
                dynamic_status="completed",
                failure_reason=None,
                task_id=result.provenance.get("task_id"),
                sandbox_url="https://www.hybrid-analysis.com",
                message=msg,
                target_architecture=arch_str,
                process_tree=proc_tree,
                api_calls=api_calls,
                network_connections=net_conns,
                dns_queries=dns_queries,
                files_written=files_written,
                registry_changes=registry_changes,
                c2_endpoints_detected=c2_detected,
            )

        elif result.state == DynamicState.NO_RESULT:
            return DynamicAnalysisOutput(
                sample_id=file_name,
                available=False,
                execution_mode="real",
                status="unavailable",
                dynamic_status="unavailable",
                failure_reason=result.reason or "No Hybrid Analysis execution result",
                message=result.report_line or "Dynamic analysis not performed: no Hybrid Analysis execution result",
                target_architecture=arch_str,
            )

        elif result.state == DynamicState.TIMEOUT:
            return DynamicAnalysisOutput(
                sample_id=file_name,
                available=False,
                execution_mode="real",
                status="failed",
                dynamic_status="failed",
                failure_reason=result.reason or "Hybrid Analysis request timed out",
                task_id=result.provenance.get("task_id"),
                message=f"Dynamic analysis failed: {result.reason or 'timeout'}",
                target_architecture=arch_str,
            )

        elif result.state == DynamicState.NOT_SUPPORTED_PLATFORM:
            return DynamicAnalysisOutput(
                sample_id=file_name,
                available=False,
                execution_mode="real",
                status="not_supported",
                dynamic_status="unavailable",
                failure_reason=result.reason,
                message=result.report_line or f"Dynamic analysis not performed: {result.reason}",
                target_architecture=arch_str,
            )

        else:
            reason = result.reason or result.state.value.lower().replace("_", " ")
            return DynamicAnalysisOutput(
                sample_id=file_name,
                available=False,
                execution_mode="real",
                status="unavailable",
                dynamic_status="unavailable",
                failure_reason=reason,
                task_id=result.provenance.get("task_id"),
                message=f"Dynamic analysis not performed: {reason}",
                target_architecture=arch_str,
            )

    except Exception as exc:
        _LOGGER.warning("Hybrid Analysis dynamic analysis error: %s", exc)
        return DynamicAnalysisOutput(
            sample_id=file_name,
            available=False,
            execution_mode="real",
            status="failed",
            dynamic_status="failed",
            failure_reason=f"Hybrid Analysis execution error: {exc}",
            message=f"Dynamic analysis failed: {exc}",
            target_architecture=arch_str,
        )


async def run_dynamic_analysis(
    sample_path: str | Path,
    platform: Optional[str] = None,
    file_type: Optional[str] = None,
    static_data: Optional[dict] = None,
    malware_bazaar: Optional[dict] = None,
    target_architecture: Optional[str] = None,
    timeout_seconds: int = 90,
) -> DynamicAnalysisOutput:
    """
    Execute dynamic detonation in the isolated sandbox host.

    Zero simulation fallback:
    - If SANDBOX_API_URL is unconfigured -> delegate to Hybrid Analysis dynamic adapter
    - If sandbox fails or times out -> dynamic_status='failed'
    - Validates manifest.json SHA-256 for all artifacts before parsing.
    """
    path_str = str(sample_path)
    file_name = os.path.basename(path_str) or "sample.bin"
    target_arch = target_architecture or inspect_binary_architecture(sample_path)
    url = sandbox_url()

    # 1. Unconfigured remote sandbox host -> delegate to Hybrid Analysis
    if not url:
        return await _run_hybrid_analysis_dynamic(
            sample_path=sample_path,
            file_name=file_name,
            platform=platform,
            file_type=file_type,
            static_data=static_data,
            target_arch=target_arch,
            timeout_seconds=timeout_seconds,
        )

    # Compute submitted sample hash for evidence-to-sample binding
    try:
        submitted_sha256 = compute_file_sha256(path_str)
    except Exception as exc:
        return DynamicAnalysisOutput(
            sample_id=file_name,
            available=False,
            execution_mode="real",
            status="failed",
            dynamic_status="failed",
            failure_reason=f"Failed to read sample file: {exc}",
            message=f"Dynamic analysis failed: {exc}",
            target_architecture=target_arch,
        )

    # 2. Remote sandbox execution
    headers = {"Authorization": f"Bearer {sandbox_token()}"}
    client_timeout = max(timeout_seconds + 30, 120)

    try:
        async with httpx.AsyncClient(timeout=float(client_timeout)) as client:
            # Submit sample
            with open(path_str, "rb") as handle:
                files = {"file": (file_name, handle)}
                data = {
                    "target_architecture": target_arch,
                    "timeout_seconds": str(timeout_seconds),
                }
                submit_resp = await client.post(f"{url.rstrip('/')}/jobs", files=files, data=data, headers=headers)

            if submit_resp.status_code == 409:
                return DynamicAnalysisOutput(
                    sample_id=file_name,
                    available=True,
                    execution_mode="real",
                    status="failed",
                    dynamic_status="failed",
                    failure_reason="Sandbox runner is busy with another job",
                    message="Dynamic analysis failed: Sandbox runner busy",
                    target_architecture=target_arch,
                    sandbox_url=url,
                )

            if submit_resp.status_code == 503:
                return DynamicAnalysisOutput(
                    sample_id=file_name,
                    available=True,
                    execution_mode="real",
                    status="failed",
                    dynamic_status="failed",
                    failure_reason="Sandbox safety lock active: external egress check failed",
                    message="Dynamic analysis failed: Sandbox safety lock active",
                    target_architecture=target_arch,
                    sandbox_url=url,
                )

            if submit_resp.status_code != 201 and submit_resp.status_code != 200:
                return DynamicAnalysisOutput(
                    sample_id=file_name,
                    available=True,
                    execution_mode="real",
                    status="failed",
                    dynamic_status="failed",
                    failure_reason=f"Sandbox rejected job ({submit_resp.status_code}): {submit_resp.text}",
                    message="Dynamic analysis submission failed",
                    target_architecture=target_arch,
                    sandbox_url=url,
                )

            job_payload = submit_resp.json()
            job_id = job_payload.get("job_id")
            if not job_id:
                return DynamicAnalysisOutput(
                    sample_id=file_name,
                    available=True,
                    execution_mode="real",
                    status="failed",
                    dynamic_status="failed",
                    failure_reason="Sandbox response missing job_id",
                    message="Dynamic analysis failed: invalid sandbox response",
                    target_architecture=target_arch,
                    sandbox_url=url,
                )

            # Check if submission immediately yielded a terminal status
            final_job = None
            if job_payload.get("status") in ("completed", "timed_out", "failed", "incomplete"):
                final_job = job_payload

            # Poll job status until completion if not already terminated
            if not final_job:
                poll_start = time.time()
                max_poll = float(timeout_seconds + 10)

                while time.time() - poll_start < max_poll:
                    poll_resp = await client.get(f"{url.rstrip('/')}/jobs/{job_id}", headers=headers)
                    if poll_resp.status_code == 200:
                        data = poll_resp.json()
                        if data.get("status") in ("completed", "failed", "timed_out", "incomplete"):
                            final_job = data
                            break
                    await asyncio.sleep(1.0)

            if not final_job:
                return DynamicAnalysisOutput(
                    sample_id=file_name,
                    available=True,
                    execution_mode="real",
                    status="timed_out",
                    dynamic_status="timed_out",
                    failure_reason="Dynamic analysis timed out waiting for sandbox execution",
                    message="Dynamic analysis timed out",
                    target_architecture=target_arch,
                    task_id=job_id,
                    sandbox_url=url,
                )

            if final_job.get("status") == "timed_out":
                err = final_job.get("error", "Sandbox execution timed out")
                return DynamicAnalysisOutput(
                    sample_id=file_name,
                    available=True,
                    execution_mode="real",
                    status="timed_out",
                    dynamic_status="timed_out",
                    failure_reason=err,
                    message=f"Dynamic analysis timed out: {err}",
                    target_architecture=target_arch,
                    task_id=job_id,
                    sandbox_url=url,
                )

            if final_job.get("status") == "failed":
                err = final_job.get("error", "Sandbox execution failed")
                return DynamicAnalysisOutput(
                    sample_id=file_name,
                    available=True,
                    execution_mode="real",
                    status="failed",
                    dynamic_status="failed",
                    failure_reason=err,
                    message=f"Dynamic analysis failed: {err}",
                    target_architecture=target_arch,
                    task_id=job_id,
                    sandbox_url=url,
                )

            if final_job.get("status") == "incomplete":
                err = final_job.get("error", "Sandbox execution incomplete")
                return DynamicAnalysisOutput(
                    sample_id=file_name,
                    available=True,
                    execution_mode="real",
                    status="incomplete",
                    dynamic_status="incomplete",
                    failure_reason=err,
                    message=f"Dynamic analysis incomplete: {err}",
                    target_architecture=target_arch,
                    task_id=job_id,
                    sandbox_url=url,
                )

            # Fetch artifact manifest
            manifest_resp = await client.get(f"{url.rstrip('/')}/jobs/{job_id}/artifacts/manifest.json", headers=headers)
            if manifest_resp.status_code != 200:
                return DynamicAnalysisOutput(
                    sample_id=file_name,
                    available=True,
                    execution_mode="real",
                    status="failed",
                    dynamic_status="failed",
                    failure_reason=f"Failed to fetch artifact manifest ({manifest_resp.status_code})",
                    message="Dynamic analysis failed: manifest missing",
                    target_architecture=target_arch,
                    task_id=job_id,
                    sandbox_url=url,
                )

            manifest = manifest_resp.json()

            # Cryptographically verify manifest HMAC
            if not verify_manifest_hmac(manifest):
                return DynamicAnalysisOutput(
                    sample_id=file_name,
                    available=True,
                    execution_mode="real",
                    status="failed",
                    dynamic_status="failed",
                    failure_reason="Artifact manifest HMAC verification failed: manifest tampered or untrusted",
                    message="Dynamic analysis failed: manifest verification failed",
                    target_architecture=target_arch,
                    task_id=job_id,
                    sandbox_url=url,
                )

            # Evidence-to-sample binding verification: fetch and check meta.json
            meta_resp = await client.get(f"{url.rstrip('/')}/jobs/{job_id}/artifacts/meta.json", headers=headers)
            if meta_resp.status_code != 200:
                return DynamicAnalysisOutput(
                    sample_id=file_name,
                    available=True,
                    execution_mode="real",
                    status="failed",
                    dynamic_status="failed",
                    failure_reason=f"Failed to fetch execution metadata meta.json ({meta_resp.status_code})",
                    message="Dynamic analysis failed: metadata missing",
                    target_architecture=target_arch,
                    task_id=job_id,
                    sandbox_url=url,
                )

            # Verify meta.json hash against manifest
            expected_meta_hash = manifest.get("meta.json")
            if expected_meta_hash:
                actual_meta_hash = hashlib.sha256(meta_resp.content).hexdigest()
                if actual_meta_hash != expected_meta_hash:
                    return DynamicAnalysisOutput(
                        sample_id=file_name,
                        available=True,
                        execution_mode="real",
                        status="failed",
                        dynamic_status="failed",
                        failure_reason="Artifact manifest validation failed: meta.json",
                        message="Artifact manifest validation failed: meta.json",
                        target_architecture=target_arch,
                        task_id=job_id,
                        sandbox_url=url,
                    )

            try:
                meta_data = meta_resp.json()
            except Exception:
                meta_data = {}

            sandbox_sample_sha256 = meta_data.get("sample_sha256")
            if not sandbox_sample_sha256 or sandbox_sample_sha256 != submitted_sha256:
                return DynamicAnalysisOutput(
                    sample_id=file_name,
                    available=True,
                    execution_mode="real",
                    status="failed",
                    dynamic_status="failed",
                    failure_reason=f"Evidence-to-sample binding mismatch: submitted SHA-256 ({submitted_sha256}) does not match sandbox execution ({sandbox_sample_sha256})",
                    message="Dynamic analysis failed: sample binding mismatch",
                    target_architecture=target_arch,
                    task_id=job_id,
                    sandbox_url=url,
                )

            # Download raw artifacts and cryptographically verify each against manifest
            downloaded_artifacts: dict[str, bytes] = {}
            for art_name in ("strace.log", "capture.pcap", "fs_diff.json"):
                art_resp = await client.get(f"{url.rstrip('/')}/jobs/{job_id}/artifacts/{art_name}", headers=headers)
                if art_resp.status_code == 200:
                    content = art_resp.content
                    expected_hash = manifest.get(art_name)
                    if expected_hash:
                        actual_hash = hashlib.sha256(content).hexdigest()
                        if actual_hash != expected_hash:
                            return DynamicAnalysisOutput(
                                sample_id=file_name,
                                available=True,
                                execution_mode="real",
                                status="failed",
                                dynamic_status="failed",
                                failure_reason=f"Artifact manifest validation failed: {art_name}",
                                message=f"Artifact manifest validation failed: {art_name}",
                                target_architecture=target_arch,
                                task_id=job_id,
                                sandbox_url=url,
                            )
                    downloaded_artifacts[art_name] = content
                elif art_name == "strace.log":
                    # Critical artifact failed to download!
                    try:
                        await client.delete(f"{url.rstrip('/')}/jobs/{job_id}", headers=headers)
                    except Exception:
                        pass
                    return DynamicAnalysisOutput(
                        sample_id=file_name,
                        available=True,
                        execution_mode="real",
                        status="incomplete",
                        dynamic_status="incomplete",
                        failure_reason=f"Incomplete dynamic analysis: failed to download critical execution trace strace.log ({art_resp.status_code})",
                        message="Dynamic analysis incomplete: trace missing",
                        target_architecture=target_arch,
                        task_id=job_id,
                        sandbox_url=url,
                    )

            # Cleanup remote job on sandbox host after retrieving artifacts
            try:
                await client.delete(f"{url.rstrip('/')}/jobs/{job_id}", headers=headers)
            except Exception as clean_err:
                _LOGGER.debug(f"Failed to cleanup job {job_id} on sandbox host: {clean_err}")

            # Parse artifacts with backend/app/strace_parser.py
            strace_text = downloaded_artifacts.get("strace.log", b"").decode("utf-8", errors="replace")
            pcap_bytes = downloaded_artifacts.get("capture.pcap")
            fs_diff_data = None
            if "fs_diff.json" in downloaded_artifacts:
                try:
                    fs_diff_data = json.loads(downloaded_artifacts["fs_diff.json"].decode("utf-8", errors="replace"))
                except Exception:
                    pass

            output = parse_strace_artifacts(
                strace_log=strace_text,
                pcap_data=pcap_bytes,
                fs_diff=fs_diff_data,
                target_architecture=target_arch,
                sample_id=file_name,
                task_id=job_id,
                duration_seconds=int(final_job.get("duration_seconds") or 30),
            )
            output.sandbox_url = url
            output.artifact_hashes = manifest
            return output

    except Exception as exc:
        _LOGGER.exception("Sandbox client execution error")
        return DynamicAnalysisOutput(
            sample_id=file_name,
            available=True,
            execution_mode="real",
            status="failed",
            dynamic_status="failed",
            failure_reason=str(exc),
            message=f"Dynamic analysis failed: {exc}",
            target_architecture=target_arch,
            sandbox_url=url,
        )
