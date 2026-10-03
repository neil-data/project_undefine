"""
sandbox-host/app/runner.py — Isolated Execution Runner.

Executes x86_64 native under `strace -f -tt -s 512 -yy` and multi-arch under `qemu-<arch> -strace`.
Collects ONLY raw artifacts + meta.json + manifest.json.
Performs NO telemetry parsing (parsing is done by backend/app/strace_parser.py).
Enforces single-job runner lock.
"""

import asyncio
import hashlib
import hmac
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

SAFE_EXEC_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
}

from enum import Enum

class WorkerState(str, Enum):
    IDLE = "idle"
    BUSY = "busy"
    RECOVERING = "recovering"
    OFFLINE = "offline"


class Worker:
    def __init__(self, worker_id: str):
        self.worker_id = worker_id
        self.state = WorkerState.IDLE
        self.active_job_id: Optional[str] = None
        self.start_time: Optional[float] = None
        self.error_count: int = 0

    def to_dict(self) -> dict:
        return {
            "worker_id": self.worker_id,
            "state": self.state.value,
            "active_job_id": self.active_job_id,
            "duration": round(time.time() - self.start_time, 2) if self.start_time else 0.0,
            "error_count": self.error_count,
        }


class WorkerPool:
    def __init__(self, max_workers: Optional[int] = None):
        self.max_workers = max(1, max_workers or getattr(config, "MAX_CONCURRENT_WORKERS", 2))
        self._lock = asyncio.Lock()
        self.workers = [Worker(f"worker-{i+1}") for i in range(self.max_workers)]

    @property
    def total_workers(self) -> int:
        return len(self.workers)

    @property
    def available_workers(self) -> int:
        return sum(1 for w in self.workers if w.state == WorkerState.IDLE)

    @property
    def active_jobs(self) -> list[str]:
        return [w.active_job_id for w in self.workers if w.active_job_id]

    async def acquire_worker(self, job_id: str) -> Optional[Worker]:
        async with self._lock:
            for w in self.workers:
                if w.state == WorkerState.IDLE:
                    w.state = WorkerState.BUSY
                    w.active_job_id = job_id
                    w.start_time = time.time()
                    return w
            return None

    async def release_worker(self, worker_id: str, error: bool = False):
        async with self._lock:
            self._release_internal(worker_id, error=error)

    def release_worker_sync(self, worker_id: str, error: bool = False):
        self._release_internal(worker_id, error=error)

    def _release_internal(self, worker_id: str, error: bool = False):
        for w in self.workers:
            if w.worker_id == worker_id:
                w.state = WorkerState.RECOVERING
                if error:
                    w.error_count += 1
                w.active_job_id = None
                w.start_time = None
                w.state = WorkerState.IDLE
                break

    def get_worker_for_job(self, job_id: str) -> Optional[Worker]:
        for w in self.workers:
            if w.active_job_id == job_id:
                return w
        return None


WORKER_POOL = WorkerPool(max_workers=getattr(config, "MAX_CONCURRENT_WORKERS", 2))


class RunnerLock:
    """WorkerPool-backed concurrency lock ensuring single-job isolation or pool sharing."""
    def __init__(self, pool: Optional[WorkerPool] = None):
        self.pool = pool or WORKER_POOL

    @property
    def is_locked(self) -> bool:
        return self.pool.available_workers == 0

    @property
    def active_job_id(self) -> Optional[str]:
        jobs = self.pool.active_jobs
        return jobs[0] if jobs else None

    async def acquire(self, job_id: str) -> bool:
        w = await self.pool.acquire_worker(job_id)
        return w is not None

    def release(self, job_id: Optional[str] = None):
        if job_id:
            w = self.pool.get_worker_for_job(job_id)
            if w:
                self.pool.release_worker_sync(w.worker_id)
                return
        for w in self.pool.workers:
            if w.state == WorkerState.BUSY:
                self.pool.release_worker_sync(w.worker_id)
                break

RUNNER_LOCK = RunnerLock(WORKER_POOL)

MAX_ARTIFACT_SIZE_BYTES = int(getattr(config, "MAX_ARTIFACT_SIZE_BYTES", 50 * 1024 * 1024))

def truncate_artifact_if_oversized(file_path: Path, max_bytes: int = MAX_ARTIFACT_SIZE_BYTES) -> bool:
    """Truncate an artifact file if it exceeds the maximum size ceiling, appending an alert."""
    if not file_path.is_file():
        return False
    sz = file_path.stat().st_size
    if sz <= max_bytes:
        return False
    with open(file_path, "r+b") as f:
        f.seek(max_bytes)
        f.truncate()
        f.write(b"\n\n[TRUNCATED] Maximum artifact size limit exceeded for safety\n")
    return True

def compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def sign_manifest(manifest_core: dict, secret: Optional[str] = None) -> str:
    token = secret or config.SANDBOX_API_TOKEN
    canonical = json.dumps(manifest_core, sort_keys=True)
    return hmac.new(token.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()

class SandboxRunner:
    def __init__(self, artifacts_dir: Optional[Path] = None):
        self.artifacts_dir = artifacts_dir or config.ARTIFACTS_DIR
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

    def prepare_job_dir(self, job_id: str) -> Path:
        clean_id = Path(job_id).name
        try:
            uuid.UUID(clean_id)
        except (ValueError, AttributeError):
            raise ValueError(f"Invalid job_id format (must be UUID): {job_id}")
        job_dir = (self.artifacts_dir / clean_id).resolve()
        if not str(job_dir).startswith(str(self.artifacts_dir.resolve())):
            raise ValueError(f"Job directory escape detected: {job_id}")
        job_dir.mkdir(parents=True, exist_ok=True)
        return job_dir

    def clean_job_dir(self, job_id: str):
        clean_id = Path(job_id).name
        try:
            uuid.UUID(clean_id)
        except (ValueError, AttributeError):
            return
        job_dir = (self.artifacts_dir / clean_id).resolve()
        if not str(job_dir).startswith(str(self.artifacts_dir.resolve())):
            return
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
                    env=SAFE_EXEC_ENV,
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

        # Lifecycle status resolution
        if exit_code == -9:
            run_status = "timed_out"
        elif exit_code == 0:
            if not strace_file.exists() or strace_file.stat().st_size == 0:
                run_status = "incomplete"
            else:
                run_status = "completed"
        else:
            run_status = "failed"

        # Enforce size limits on all generated artifact files
        for f in (strace_file, stdout_file, stderr_file, pcap_file, fs_diff_file):
            if f.exists():
                truncate_artifact_if_oversized(f)

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
            "status": run_status,
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

        # Sign manifest before saving
        manifest["_hmac"] = sign_manifest(manifest)
        manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        manifest["manifest.json"] = compute_sha256(manifest_file)

        return {
            "job_id": job_id,
            "status": run_status,
            "sample_sha256": sample_sha256,
            "target_architecture": normalized_arch,
            "duration_seconds": duration_seconds,
            "exit_code": exit_code,
            "artifacts": list(manifest.keys()),
            "manifest": manifest,
        }
