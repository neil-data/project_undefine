"""
sandbox-host/app/main.py — FastAPI service for E-Rakshak Dynamic Sandbox Host.
"""

import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Security, UploadFile, File, Form, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse, JSONResponse

from . import config
from .canary import check_canary_isolation
from .runner import RUNNER_LOCK, WORKER_POOL, SandboxRunner

app = FastAPI(
    title="E-Rakshak Dynamic Sandbox Host",
    version="1.0.0",
    description="Isolated detonation microservice producing raw execution artifacts + manifest."
)

security = HTTPBearer(auto_error=False)

def verify_token(credentials: Optional[HTTPAuthorizationCredentials] = Security(security)):
    if not credentials or credentials.credentials != config.SANDBOX_API_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: invalid or missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials

# In-memory job store for fast status lookup
JOBS_STORE: dict[str, dict] = {}
runner = SandboxRunner()

@app.get("/health")
def health_check():
    iso_ok, iso_msg = check_canary_isolation()
    return {
        "status": "ok" if iso_ok else "warning",
        "isolation": iso_msg,
        "total_workers": WORKER_POOL.total_workers,
        "available_workers": WORKER_POOL.available_workers,
        "active_jobs": WORKER_POOL.active_jobs,
        "runner_locked": RUNNER_LOCK.is_locked,
        "active_job": RUNNER_LOCK.active_job_id,
        "workers": [w.to_dict() for w in WORKER_POOL.workers],
    }

@app.get("/canary")
def canary_check():
    iso_ok, iso_msg = check_canary_isolation()
    if not iso_ok:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=iso_msg)
    return {"status": "isolated", "detail": iso_msg}

@app.post("/jobs")
async def create_job(
    file: UploadFile = File(...),
    target_architecture: Optional[str] = Form(None),
    timeout_seconds: Optional[int] = Form(None),
    token: str = Depends(verify_token),
):
    norm_arch = config.normalize_arch(target_architecture)
    if norm_arch not in config.SUPPORTED_ARCHITECTURES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported architecture: {target_architecture} (normalized: {norm_arch}). Supported: {list(config.SUPPORTED_ARCHITECTURES)}",
        )

    job_id = str(uuid.uuid4())
    acquired = await RUNNER_LOCK.acquire(job_id)
    if not acquired:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Runner busy: all workers currently active ({RUNNER_LOCK.active_job_id})",
            headers={"Retry-After": "5"},
        )

    temp_sample = None
    try:
        iso_ok, iso_msg = check_canary_isolation()
        if not iso_ok:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Sandbox safety violation: {iso_msg}",
            )

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            temp_sample = Path(tmp.name)
            content = await file.read()
            tmp.write(content)

        job_result = await runner.run(
            job_id=job_id,
            sample_path=temp_sample,
            raw_arch=target_architecture,
            timeout_seconds=timeout_seconds,
        )
        JOBS_STORE[job_id] = job_result
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=job_result)
    except HTTPException:
        raise
    except Exception as e:
        JOBS_STORE[job_id] = {"job_id": job_id, "status": "failed", "error": str(e)}
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    finally:
        if temp_sample and temp_sample.exists():
            temp_sample.unlink(missing_ok=True)
        RUNNER_LOCK.release(job_id)

ALLOWED_ARTIFACTS = {
    "strace.log",
    "capture.pcap",
    "fs_diff.json",
    "stdout.log",
    "stderr.log",
    "meta.json",
    "manifest.json",
}

def validate_job_id(job_id: str) -> str:
    try:
        val = uuid.UUID(job_id)
        return str(val)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid job_id format (must be UUID): {job_id}",
        )

@app.get("/jobs/{job_id}")
async def get_job(job_id: str, token: str = Depends(verify_token)):
    clean_job_id = validate_job_id(job_id)
    if clean_job_id not in JOBS_STORE:
        meta_file = config.ARTIFACTS_DIR / clean_job_id / "meta.json"
        manifest_file = config.ARTIFACTS_DIR / clean_job_id / "manifest.json"
        if meta_file.exists() and manifest_file.exists():
            import json
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            return {
                "job_id": clean_job_id,
                "status": meta.get("status", "completed"),
                "sample_sha256": meta.get("sample_sha256"),
                "target_architecture": meta.get("target_architecture"),
                "duration_seconds": meta.get("duration_seconds"),
                "artifacts": list(manifest.keys()),
                "manifest": manifest,
            }
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {clean_job_id} not found")
    return JOBS_STORE[clean_job_id]

@app.get("/jobs/{job_id}/artifacts/{artifact_name}")
async def get_artifact(job_id: str, artifact_name: str, token: str = Depends(verify_token)):
    clean_job_id = validate_job_id(job_id)
    clean_name = Path(artifact_name).name
    if clean_name not in ALLOWED_ARTIFACTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Access denied: {artifact_name} is not an authorized artifact",
        )
    file_path = (config.ARTIFACTS_DIR / clean_job_id / clean_name).resolve()
    if not str(file_path).startswith(str(config.ARTIFACTS_DIR.resolve())):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Path traversal detected")
    if not file_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Artifact {clean_name} not found for job {clean_job_id}")
    return FileResponse(path=str(file_path), filename=clean_name)

@app.delete("/jobs/{job_id}")
async def delete_job(job_id: str, token: str = Depends(verify_token)):
    clean_job_id = validate_job_id(job_id)
    runner.clean_job_dir(clean_job_id)
    JOBS_STORE.pop(clean_job_id, None)
    return {"job_id": clean_job_id, "deleted": True}
