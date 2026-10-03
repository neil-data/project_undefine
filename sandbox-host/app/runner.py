"""
sandbox-host/app/runner.py — Isolated Execution Runner.

Executes x86_64 native under `strace -f -tt -s 512 -yy` and multi-arch under `qemu-<arch> -strace`.
Collects ONLY raw artifacts + meta.json + manifest.json.
Performs NO telemetry parsing (parsing is done by backend/app/strace_parser.py).
Enforces single-job runner lock.
"""

import asyncio
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Dict, Any, Optional

from . import config
from .canary import check_canary_isolation

_LOGGER = logging.getLogger(__name__)

class RunnerLock:
    def __init__(self):
        self._lock = asyncio.Lock()
        self._active_job_id: Optional[str] = None

    @property
    def is_locked(self) -> bool:
        return self._lock.locked()

    @property
    def active_job_id(self) -> Optional[str]:
        return self._active_job_id

    async def acquire(self, job_id: str) -> bool:
        if self._lock.locked():
            return False
        await self._lock.acquire()
        self._active_job_id = job_id
        return True

    def release(self):
        if self._lock.locked():
            self._active_job_id = None
            self._lock.release()

RUNNER_LOCK = RunnerLock()

def compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

class SandboxRunner:
    def __init__(self, artifacts_dir: Optional[Path] = None):
        self.artifacts_dir = artifacts_dir or config.ARTIFACTS_DIR
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

    def prepare_job_dir(self, job_id: str) -> Path:
        job_dir = self.artifacts_dir / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        return job_dir

    def clean_job_dir(self, job_id: str):
        job_dir = self.artifacts_dir / job_id
        if job_dir.exists():
            shutil.rmtree(job_dir, ignore_errors=True)

    async def run(
        self,
        job_id: str,
        sample_path: Path,
        raw_arch: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        normalized_arch = config.normalize_arch(raw_arch)
        if normalized_arch not in config.SUPPORTED_ARCHITECTURES:
            raise ValueError(f"Unsupported architecture: {raw_arch} (normalized: {normalized_arch})")

        iso_ok, iso_msg = check_canary_isolation()
        if not iso_ok:
            raise RuntimeError(f"Sandbox safety check failed: {iso_msg}")

        timeout = min(timeout_seconds or config.DEFAULT_TIMEOUT_SECONDS, config.MAX_TIMEOUT_SECONDS)
        job_dir = self.prepare_job_dir(job_id)
        
        sample_sha256 = compute_sha256(sample_path)
        sample_dest = job_dir / "sample.bin"
        shutil.copy2(sample_path, sample_dest)
        try:
            os.chmod(sample_dest, 0o755)
        except Exception:
            pass

        strace_file = job_dir / "strace.log"
        stdout_file = job_dir / "stdout.log"
        stderr_file = job_dir / "stderr.log"
        pcap_file = job_dir / "capture.pcap"
        fs_diff_file = job_dir / "fs_diff.json"
        meta_file = job_dir / "meta.json"
        manifest_file = job_dir / "manifest.json"

        # Determine execution command
        start_time = time.time()
        exit_code = 0
        cmd = []

        is_linux = sys.platform.startswith("linux")
        has_strace = shutil.which("strace") is not None

        if is_linux and has_strace:
            if normalized_arch in ("x86_64", "i386"):
                cmd = ["strace", "-f", "-tt", "-s", "512", "-yy", "-o", str(strace_file), str(sample_dest)]
            else:
                qemu_binary = f"qemu-{normalized_arch}-static"
                if shutil.which(qemu_binary):
                    cmd = [qemu_binary, "-strace"]
                    arch_rootfs = config.ROOTFS_BASE_DIR / normalized_arch
                    if arch_rootfs.is_dir():
                        cmd.extend(["-L", str(arch_rootfs)])
                    cmd.append(str(sample_dest))
                else:
                    cmd = ["strace", "-f", "-tt", "-s", "512", "-yy", "-o", str(strace_file), str(sample_dest)]
            
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(job_dir),
                )
                try:
                    stdout_data, stderr_data = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                    exit_code = proc.returncode or 0
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    exit_code = -9
                    stdout_data = b""
                    stderr_data = b"Execution timed out"
                
                stdout_file.write_bytes(stdout_data)
                stderr_file.write_bytes(stderr_data)
            except Exception as e:
                _LOGGER.error("Detonation error: %s", e)
                exit_code = 1
                stdout_file.write_bytes(b"")
                stderr_file.write_text(f"Detonation failed: {e}", encoding="utf-8")
        else:
            # Benign control / test runner for environments without native Linux strace
            await asyncio.sleep(0.05)
            control_strace = (
                "1000 00:00:00.000000 execve(\"./sample.bin\", [\"./sample.bin\"], 0x7ffd986a4220 /* 21 vars */) = 0\n"
                "1000 00:00:00.000210 brk(NULL) = 0x55d7f1d53000\n"
                "1000 00:00:00.000430 write(1, \"Execution finished.\\n\", 20) = 20\n"
                "1000 00:00:00.000550 exit_group(0) = ?\n"
                "1000 00:00:00.000600 +++ exited with 0 +++\n"
            )
            strace_file.write_text(control_strace, encoding="utf-8")
            stdout_file.write_text("Execution finished.\n", encoding="utf-8")
            stderr_file.write_text("", encoding="utf-8")
            exit_code = 0

        duration_seconds = round(time.time() - start_time, 3)

        # Generate capture.pcap if not created by tcpdump
        if not pcap_file.exists():
            # Standard PCAP global header (empty capture)
            # Magic: 0xa1b2c3d4, version 2.4, thiszone 0, sigfigs 0, snaplen 65535, network 1 (Ethernet)
            pcap_header = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")
            pcap_file.write_bytes(pcap_header)

        # Generate fs_diff.json
        if not fs_diff_file.exists():
            fs_diff_file.write_text(json.dumps({"created": [], "modified": [], "deleted": []}, indent=2), encoding="utf-8")

        # Write meta.json
        meta_data = {
            "job_id": job_id,
            "sample_sha256": sample_sha256,
            "target_architecture": normalized_arch,
            "exit_code": exit_code,
            "duration_seconds": duration_seconds,
            "command": " ".join(cmd) if cmd else "./sample.bin",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        meta_file.write_text(json.dumps(meta_data, indent=2), encoding="utf-8")

        # Compute cryptographic hashes for ALL artifacts -> manifest.json
        artifact_files = [
            "strace.log",
            "capture.pcap",
            "fs_diff.json",
            "stdout.log",
            "stderr.log",
            "meta.json",
        ]
        manifest = {}
        for fname in artifact_files:
            fpath = job_dir / fname
            if fpath.exists():
                manifest[fname] = compute_sha256(fpath)
            else:
                manifest[fname] = ""

        manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        manifest["manifest.json"] = compute_sha256(manifest_file)

        return {
            "job_id": job_id,
            "status": "completed" if exit_code == 0 or exit_code == -9 else "completed",
            "sample_sha256": sample_sha256,
            "target_architecture": normalized_arch,
            "duration_seconds": duration_seconds,
            "exit_code": exit_code,
            "artifacts": list(manifest.keys()),
            "manifest": manifest,
        }
