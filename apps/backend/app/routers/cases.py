import asyncio
import os
import stat
import hashlib
import shutil
import tempfile
import logging
import zipfile
from typing import Optional
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Query, Form, Request

from agents.orchestrator.orchestrator import build_graph
from ..analysis import (
    analyze_and_save,
    UnsupportedFormatError,
    compute_sha256,
    _extract_network_indicators,
    _build_threat_assessment,
    _build_ai_analysis,
    _build_ioc_intelligence,
    _build_evidence_correlations,
    _build_evidence_timeline,
    _build_risk_explanation,
)
from ..models.api_models import (
    SubmitSampleRequest,
    CaseSummary,
    CaseDetail,
    AnalysisStartResponse,
    AnalysisStatus,
    risk_score_to_status,
)
from ..store import save_case, get_case, list_cases, add_user_case_association
from .. import search
from .. import pipeline_status as ps
from .. import sandbox
from .. import geoip
from ..auth import get_current_user

router = APIRouter(prefix="/api/cases", tags=["cases"])

_LOGGER = logging.getLogger(__name__)

_graph = build_graph()  # compiled once at import time, reused by /submit (which doesn't touch the file system)

# Extensions accepted by /upload and the file_type value each maps to.
_ALLOWED_EXTENSIONS = {
    ".apk": "apk",
    ".exe": "pe",
    ".dll": "pe",
    ".elf": "elf",
    ".macho": "mach_o",
    ".dylib": "mach_o",
    ".zip": "zip",
    ".json": "json",
    ".bson": "bson",
}
_MAX_UPLOAD_BYTES = int(__import__("os").environ.get("MAX_UPLOAD_MB", "100")) * 1024 * 1024
_ANALYSIS_PIPELINE_TIMEOUT_SECONDS = max(60, int(os.environ.get("ANALYSIS_PIPELINE_TIMEOUT_SECONDS", "300")))


COMMON_ZIP_PASSWORDS = [
    b"infected",
    b"malware",
    b"password",
    b"virus",
    b"1234",
    b"123456",
    b"clean",
    b"bank",
    b"erakshak",
    b"danger",
    b"sample",
    b"mysample",
    b"123",
]


def _extract_zip_sample(archive_path: Path, temp_dir: str, password: Optional[str] = None) -> tuple[str, Path, str]:
    """Safely unpack exactly one supported sample from a ZIP archive, supporting encrypted/password-protected ZIPs."""
    try:
        import pyzipper
        zip_opener = pyzipper.AESZipFile
    except ImportError:
        zip_opener = zipfile.ZipFile

    try:
        with zip_opener(archive_path) as archive:
            entries = [
                info for info in archive.infolist()
                if not info.is_dir() and Path(info.filename).suffix.lower() in _ALLOWED_EXTENSIONS
                and Path(info.filename).suffix.lower() != ".zip"
            ]
            if len(entries) != 1:
                non_dir = [
                    info for info in archive.infolist()
                    if not info.is_dir() and Path(info.filename).suffix.lower() != ".zip"
                ]
                if len(non_dir) == 1:
                    entries = non_dir
                else:
                    raise HTTPException(
                        status_code=422,
                        detail=f"ZIP must contain exactly one supported sample (APK, EXE, DLL, ELF, or Mach-O). Found: {len(entries)}",
                    )

            entry = entries[0]
            member_name = Path(entry.filename).name
            target_path = Path(temp_dir) / member_name

            # Check if entry is password protected (flag bit 0)
            is_encrypted = bool(entry.flag_bits & 0x1)
            extracted_sha256 = None

            if is_encrypted:
                passwords_to_try: list[bytes] = []
                if password:
                    passwords_to_try.append(password.strip().encode("utf-8"))
                for cp in COMMON_ZIP_PASSWORDS:
                    if cp not in passwords_to_try:
                        passwords_to_try.append(cp)

                extracted = False
                for pwd in passwords_to_try:
                    try:
                        h = hashlib.sha256()
                        with archive.open(entry, pwd=pwd) as source, target_path.open("wb") as target:
                            while True:
                                chunk = source.read(1024 * 1024)
                                if not chunk:
                                    break
                                target.write(chunk)
                                h.update(chunk)
                        extracted_sha256 = h.hexdigest()
                        extracted = True
                        break
                    except Exception:
                        if target_path.exists():
                            target_path.unlink(missing_ok=True)
                        continue

                if not extracted:
                    raise HTTPException(
                        status_code=422,
                        detail="Password-protected ZIP could not be decrypted. Please provide the ZIP password.",
                    )
            else:
                if entry.file_size > _MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="ZIP sample exceeds the configured upload limit.")
                h = hashlib.sha256()
                with archive.open(entry) as source, target_path.open("wb") as target:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        target.write(chunk)
                        h.update(chunk)
                extracted_sha256 = h.hexdigest()

            try:
                os.chmod(target_path, stat.S_IREAD | stat.S_IWRITE)
            except Exception:
                pass

            if not target_path.exists() or target_path.stat().st_size <= 0:
                raise HTTPException(status_code=422, detail="Extracted file from ZIP is empty.")
            if target_path.stat().st_size > _MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail="ZIP sample exceeds the configured upload limit.")

    except (zipfile.BadZipFile, Exception) as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=422, detail=f"Failed to extract ZIP archive: {e}")

    archive_path.unlink(missing_ok=True)
    return member_name, target_path, extracted_sha256

def _guess_file_type(filename: str) -> Path:
    ext = Path(filename).suffix.lower()
    if ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported file type '{ext}'. Allowed: APK, EXE, DLL, ELF, Mach-O.",
        )
    return ext


async def _run_analysis_pipeline(
    file_path: str,
    temp_dir: str,
    analysis_id: str,
    *,
    user_email: str,
    original_filename: str,
    mime_type: str,
    file_size_bytes: int,
) -> None:
    """Background task owned by POST /api/cases/upload.

    Walks the real pipeline stage by stage, updating pipeline_status as it goes
    so the polling status endpoint reports actual progress. Cleans up the temp
    file in every path, including failure.
    """
    try:
        await ps.update_job(analysis_id, status=ps.VALIDATING, stage="Validating file format and integrity")
        _guess_file_type(original_filename)  # re-raise 422-shaped errors as a job failure below

        await ps.update_job(analysis_id, status=ps.STATIC_ANALYSIS, stage="Running static analysis and agent correlation")

        try:
            case_data = await asyncio.wait_for(
                analyze_and_save(
                    file_path,
                    event_type="static_analysis_complete",
                    extra_meta={
                        "original_filename": original_filename,
                        "mime_type": mime_type,
                        "analysis_status": ps.STATIC_ANALYSIS,
                        "user_email": user_email,
                    },
                ),
                timeout=_ANALYSIS_PIPELINE_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError as exc:
            raise TimeoutError(
                f"Static analysis/report pipeline exceeded {_ANALYSIS_PIPELINE_TIMEOUT_SECONDS} seconds"
            ) from exc
        case_data["analysis_status"] = ps.DYNAMIC_ANALYSIS
        case_data["user_email"] = user_email

        # For JSON/BSON files the embedded SHA-256 becomes the sample_id, which
        # differs from analysis_id (SHA-256 of the uploaded file itself).  Save
        # an alias so the frontend can still fetch by analysis_id.
        if case_data.get("sample_id") != analysis_id:
            alias = dict(case_data)
            alias["sample_id"] = analysis_id
            alias["user_email"] = user_email
            await save_case(analysis_id, alias, event_type="json_bson_alias")

        await ps.update_job(analysis_id, status=ps.DYNAMIC_ANALYSIS, stage="Checking isolated sandbox availability")

        # Only run sandbox for real binaries; JSON/BSON already carry dynamic data
        if case_data.get("dynamic_analysis") is None:
            case_data["dynamic_analysis"] = await sandbox.run_dynamic_analysis(
                file_path,
                platform=case_data.get("platform"),
                file_type=case_data.get("file_type"),
            )
        dynamic = case_data["dynamic_analysis"]

        # Re-extract network indicators & Geo-IP now that dynamic analysis results exist
        raw_static_net = {
            "extracted_strings": {
                "ips": (case_data.get("network_indicators") or {}).get("ips", []),
                "urls": (case_data.get("network_indicators") or {}).get("urls", []),
            },
            "explained_strings": case_data.get("explained_strings", []),
        }
        updated_network = _extract_network_indicators(raw_static_net, case_data.get("dynamic_analysis"))
        case_data["network_indicators"] = updated_network
        case_data["geo_iocs"] = geoip.lookup_many(updated_network["ips"])
        case_data["ioc_intelligence"] = _build_ioc_intelligence({}, dynamic, updated_network)
        case_data["evidence_correlation"] = _build_evidence_correlations(
            {"network_indicators": updated_network}, dynamic, updated_network,
            case_data.get("mitre_techniques", []),
        )
        case_data["evidence_timeline"] = _build_evidence_timeline(
            case_data.get("submitted_at"), dynamic, case_data["evidence_correlation"],
        )
        case_data["risk_explanation"] = _build_risk_explanation(
            {"yara_matches": case_data.get("yara_matches", [])},
            case_data.get("mitre_techniques", []), case_data.get("capability_tags", []),
            case_data.get("risk_score", 0),
        )

        # Update AI analysis interpretations with newly discovered dynamic network indicators
        if case_data.get("ai_analysis"):
            new_ai = _build_ai_analysis(
                final_state={
                    "narrative_summary": case_data.get("narrative_summary"),
                    "risk_score": case_data.get("risk_score", 0),
                    "mitre_techniques": case_data.get("mitre_techniques", []),
                },
                investigation_output={},
                network_indicators=case_data["network_indicators"],
                geo_iocs=case_data["geo_iocs"],
                threat_assessment=case_data.get("threat_assessment") or {},
            )
            case_data["ai_analysis"]["network_interpretation"] = new_ai.get("network_interpretation")
            case_data["ai_analysis"]["geoip_interpretation"] = new_ai.get("geoip_interpretation")

        case_data["analysis_status"] = ps.COMPLETED

        # Persist the dynamic state + completed status (upsert; the case row
        # created by analyze_and_save is updated, never duplicated).
        await save_case(case_data["sample_id"], case_data, event_type="dynamic_analysis_checked")
        # Keep alias in sync too
        if case_data.get("sample_id") != analysis_id:
            alias = dict(case_data)
            alias["sample_id"] = analysis_id
            await save_case(analysis_id, alias, event_type="dynamic_analysis_checked")

        await ps.update_job(
            analysis_id, status=ps.COMPLETED, stage="Analysis complete",
            dynamic_status=dynamic.get("status"), file_type=case_data.get("file_type"),
        )
    except UnsupportedFormatError as e:
        await ps.update_job(analysis_id, status=ps.FAILED, stage=None, error=str(e))
    except asyncio.CancelledError:
        await ps.update_job(analysis_id, status=ps.FAILED, stage=None, error="Analysis cancelled")
        raise
    except Exception as e:
        _LOGGER.exception("Background analysis failed for %s", analysis_id)
        await ps.update_job(analysis_id, status=ps.FAILED, stage=None, error=f"{type(e).__name__}: {e}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.post("/upload", response_model=AnalysisStartResponse, status_code=202)
async def upload_sample(
    request: Request,
    file: UploadFile = File(...),
    password: Optional[str] = Form(None),
    current_user: str = Depends(get_current_user),
):
    """
    Receives an uploaded binary file (APK, EXE, DLL, ELF, Mach-O), hashes it,
    and hands the analysis off to a background task. Returns immediately with
    the analysis id; the client polls GET /api/cases/{analysis_id}/status for
    the real pipeline state (VALIDATING -> STATIC_ANALYSIS -> DYNAMIC_ANALYSIS
    -> COMPLETED / FAILED).

    A sample whose SHA-256 already exists returns status COMPLETED with the
    existing case's id, so re-uploads are deduplicated instead of re-detonted.
    """
    original_filename = Path(file.filename or "").name or "sample.bin"
    uploaded_suffix = Path(original_filename).suffix.lower()
    if uploaded_suffix not in _ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported file type. Allowed: {', '.join(sorted(_ALLOWED_EXTENSIONS))}",
        )
    is_zip_upload = uploaded_suffix == ".zip"
    file_type_value = str(_ALLOWED_EXTENSIONS[uploaded_suffix])
    mime_type = file.content_type or "application/octet-stream"

    temp_dir = tempfile.mkdtemp(prefix="sentinel_upload_")
    file_path = Path(temp_dir) / original_filename
    file_size_bytes = 0
    hasher = hashlib.sha256()
    try:
        with open(file_path, "wb") as buffer:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                file_size_bytes += len(chunk)
                if file_size_bytes > _MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413, detail=f"File exceeds the {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit"
                    )
                buffer.write(chunk)
                hasher.update(chunk)
        if file_size_bytes == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")

        try:
            os.chmod(file_path, stat.S_IREAD | stat.S_IWRITE)
        except Exception:
            pass

        if is_zip_upload:
            effective_password = (
                password
                or request.query_params.get("password")
                or request.headers.get("x-zip-password")
            )
            original_filename, file_path, analysis_id = _extract_zip_sample(file_path, temp_dir, password=effective_password)
            file_type_value = str(_ALLOWED_EXTENSIONS[Path(original_filename).suffix.lower()])
            mime_type = "application/octet-stream"
            file_size_bytes = file_path.stat().st_size
        else:
            analysis_id = hasher.hexdigest()

        if not analysis_id:
            analysis_id = await asyncio.to_thread(compute_sha256, file_path)

        existing = await get_case(analysis_id, user_email=current_user)
        if existing is not None:
            await ps.update_job(
                analysis_id, status=ps.COMPLETED, stage="Already analyzed — returning existing case",
                original_filename=original_filename, mime_type=mime_type,
                file_size_bytes=file_size_bytes, file_type=existing.get("file_type"),
                user_email=current_user, dynamic_status=(existing.get("dynamic_analysis") or {}).get("status"),
            )
            return AnalysisStartResponse(
                analysis_id=analysis_id,
                sample_id=analysis_id,
                original_filename=existing.get("original_filename") or original_filename,
                file_type=existing.get("file_type") or file_type_value,
                mime_type=existing.get("mime_type") or mime_type,
                sha256=analysis_id,
                file_size_bytes=existing.get("file_size_bytes") or file_size_bytes,
                status=ps.COMPLETED,
                message="Duplicate sample — showing your existing analysis.",
            )

        existing_global = await get_case(analysis_id)
        if existing_global is not None:
            await add_user_case_association(current_user, analysis_id)
            await ps.create_job(
                analysis_id, user_email=current_user, original_filename=original_filename,
                file_size_bytes=file_size_bytes, mime_type=mime_type, file_type=existing_global.get("file_type") or file_type_value,
                status=ps.COMPLETED, stage="Already analyzed — attached to your account",
                dynamic_status=(existing_global.get("dynamic_analysis") or {}).get("status"),
            )
            return AnalysisStartResponse(
                analysis_id=analysis_id,
                sample_id=analysis_id,
                original_filename=original_filename,
                file_type=existing_global.get("file_type") or file_type_value,
                mime_type=existing_global.get("mime_type") or mime_type,
                sha256=analysis_id,
                file_size_bytes=file_size_bytes,
                status=ps.COMPLETED,
                message="Sample already analyzed across agency network — attached to your account registry.",
            )

        await ps.create_job(
            analysis_id, user_email=current_user, original_filename=original_filename,
            file_size_bytes=file_size_bytes, mime_type=mime_type, file_type=file_type_value,
            status=ps.UPLOADED, stage="File received; starting analysis",
        )
        asyncio.create_task(
            _run_analysis_pipeline(
                file_path, temp_dir, analysis_id,
                user_email=current_user, original_filename=original_filename,
                mime_type=mime_type, file_size_bytes=file_size_bytes,
            )
        )
        return AnalysisStartResponse(
            analysis_id=analysis_id,
            sample_id=analysis_id,
            original_filename=original_filename,
            file_type=file_type_value,
            mime_type=mime_type,
            sha256=analysis_id,
            file_size_bytes=file_size_bytes,
            status=ps.UPLOADED,
            message="Analysis started — poll /api/cases/{id}/status for progress.",
        )
    except HTTPException:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        _LOGGER.exception("Upload failed for %s", original_filename)
        raise HTTPException(status_code=500, detail=f"Upload failed: {type(e).__name__}: {e}")


@router.get("/{sample_id}/status", response_model=AnalysisStatus)
async def get_analysis_status(sample_id: str, current_user: str = Depends(get_current_user)):
    """Real analysis-pipeline progress for a sample being analyzed in the background."""
    job = await ps.get_job(sample_id)
    if job is not None and job.get("user_email") and job.get("user_email") != current_user:
        case_check = await get_case(sample_id, user_email=current_user)
        if case_check is None:
            raise HTTPException(status_code=404, detail=f"No analysis found for {sample_id}")

    if job is not None and job.get("status") != ps.COMPLETED:
        return AnalysisStatus(
            analysis_id=sample_id,
            status=job.get("status"),
            stage=job.get("stage"),
            dynamic_status=job.get("dynamic_status"),
            error=job.get("error"),
            file_type=job.get("file_type"),
            updated_at=job.get("updated_at"),
        )

    # COMPLETED: return final state from the job or fall back to the persisted case
    case = await get_case(sample_id, user_email=current_user)
    if case is None:
        if job is None or (job.get("user_email") and job.get("user_email") != current_user):
            raise HTTPException(status_code=404, detail=f"No analysis found for {sample_id}")
        return AnalysisStatus(analysis_id=sample_id, status=job.get("status"), stage=job.get("stage"))
    return AnalysisStatus(
        analysis_id=sample_id,
        status=ps.COMPLETED,
        stage="Analysis complete",
        dynamic_status=(case.get("dynamic_analysis") or {}).get("status"),
        file_type=case.get("file_type"),
        updated_at=job.get("updated_at") if job else None,
    )


@router.post("/submit", response_model=CaseDetail)
async def submit_sample(request: SubmitSampleRequest, current_user: str = Depends(get_current_user)):
    """
    Runs the full agent pipeline against submitted static/dynamic analysis data
    (used when static/dynamic results are already computed elsewhere, rather
    than uploading a raw file).
    """
    initial_state = {
        "static_output": request.static_analysis,
        "dynamic_output": request.dynamic_analysis,
    }

    try:
        final_state = await asyncio.to_thread(_graph.invoke, initial_state)

        # Convert static_analysis model to dict for extracting indicators
        raw_static = {
            "sha256": request.static_analysis.sha256,
            "file_type": request.static_analysis.file_type,
            "platform": request.static_analysis.platform,
            "file_size_bytes": request.static_analysis.file_size_bytes,
            "submitted_at": request.static_analysis.submitted_at,
            "yara_matches": [m.model_dump() for m in request.static_analysis.yara_matches],
            "extracted_strings": {
                "ips": request.static_analysis.extracted_strings.ips,
                "urls": request.static_analysis.extracted_strings.urls,
                "suspicious_keywords": request.static_analysis.extracted_strings.suspicious_keywords,
            },
            "md5": None,
            "sha1": None,
            "packing": None,
            "explained_strings": [],
        }

        dynamic_dict = request.dynamic_analysis.model_dump() if request.dynamic_analysis else None
        network_indicators = _extract_network_indicators(raw_static, dynamic_dict)

        # Geo-IP lookups
        geo_iocs = geoip.lookup_many(network_indicators["ips"])

        # Threat Assessment
        threat_assessment = _build_threat_assessment(
            risk_score=final_state["risk_score"],
            yara_matches=raw_static["yara_matches"],
            mitre_techniques=final_state.get("mitre_techniques", []),
            capability_tags=final_state.get("capability_tags", []),
            has_dynamic=request.dynamic_analysis is not None,
        )

        # Structured AI Analysis
        investigation_output = final_state.get("investigation_output") or {}
        ai_analysis = _build_ai_analysis(
            final_state=final_state,
            investigation_output=investigation_output,
            network_indicators=network_indicators,
            geo_iocs=geo_iocs,
            threat_assessment=threat_assessment,
        )

        case_data = {
            "sample_id": final_state["sample_id"],
            "platform": request.static_analysis.platform,
            "file_type": request.static_analysis.file_type,
            "file_size_bytes": request.static_analysis.file_size_bytes,
            "risk_score": final_state["risk_score"],
            "status": risk_score_to_status(final_state["risk_score"]),
            "mitre_techniques": [t.model_dump() for t in final_state["mitre_techniques"]],
            "capability_tags": [c.model_dump() for c in final_state["capability_tags"]],
            "narrative_summary": final_state["narrative_summary"],
            "submitted_at": request.static_analysis.submitted_at,
            "sha256": request.static_analysis.sha256,
            "yara_matches": [m.model_dump() for m in request.static_analysis.yara_matches],
            "geo_iocs": geo_iocs,
            "network_indicators": network_indicators,
            "threat_assessment": threat_assessment,
            "ai_analysis": ai_analysis,
        }
    except HTTPException:
        raise
    except Exception as e:
        _LOGGER.exception("Analysis pipeline failed for /api/cases/submit")
        raise HTTPException(status_code=500, detail=f"Analysis pipeline failed: {type(e).__name__}: {e}")

    await save_case(case_data["sample_id"], case_data, event_type="static_analysis_complete")
    return CaseDetail(**case_data)


@router.get("/search", response_model=list[CaseSummary])
async def search_cases_endpoint(q: str = Query(..., min_length=1), current_user: str = Depends(get_current_user)):
    """
    Elasticsearch-backed case search. Falls back to substring-matching the
    user's case list when Elasticsearch is unavailable, so search never just
    breaks — it only loses fuzzy/full-text matching until ES comes back.
    """
    matched_ids = await search.search_cases(q)
    all_cases = await list_cases(user_email=current_user)

    if matched_ids is not None:
        matched_set = set(matched_ids)
        results = [c for c in all_cases if c["sample_id"] in matched_set]
    else:
        needle = q.lower()
        results = [
            c for c in all_cases
            if needle in c["sample_id"].lower()
            or needle in (c.get("narrative_summary") or "").lower()
            or needle in (c.get("original_filename") or "").lower()
        ]

    return [CaseSummary.model_validate(_with_summary_fields(c)) for c in results]


@router.get("", response_model=list[CaseSummary])
async def get_all_cases(current_user: str = Depends(get_current_user)):
    """Case table data for the dashboard's main list view."""
    cases = await list_cases(user_email=current_user)
    return [CaseSummary.model_validate(_with_summary_fields(c)) for c in cases]


def _with_summary_fields(c: dict) -> dict:
    """Carry the extra persisted fields onto the summary model."""
    return {
        "sample_id": c["sample_id"],
        "platform": c["platform"],
        "file_type": c["file_type"],
        "risk_score": c["risk_score"],
        "status": c["status"],
        "submitted_at": c["submitted_at"],
        "original_filename": c.get("original_filename"),
    }


@router.get("/{sample_id}", response_model=CaseDetail)
async def get_case_detail(sample_id: str, current_user: str = Depends(get_current_user)):
    """Full case detail for the dashboard's case detail panel."""
    case_data = await get_case(sample_id, user_email=current_user)
    if case_data is None:
        raise HTTPException(status_code=404, detail=f"Case {sample_id} not found")
    try:
        return CaseDetail(**case_data)
    except Exception as e:
        _LOGGER.exception("Failed to construct CaseDetail for %s", sample_id)
        # Ensure sample_id is present and try model_validate
        case_data.setdefault("sample_id", sample_id)
        return CaseDetail.model_validate(case_data)
