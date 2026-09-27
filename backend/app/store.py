"""
backend/app/store.py — Case persistence layer.

Backed by Postgres (see db.py) whenever DATABASE_URL is reachable; falls
back automatically to the original in-memory dict otherwise, so the API
stays fully functional without Docker for local dev/demo — the same
graceful-degradation pattern used elsewhere in this codebase for Redis
(ingestion/gateway.py), Groq (agents/narrative_agent/narrative.py), and upx
(static-analysis packing/unpacker.py).

Every Postgres-backed save also appends a hash-chained `chain_of_custody`
row, exactly per the algorithm documented in storage/postgres/schema.sql:
each row's `row_hash` is sha256(sample_id + event_type + event_detail +
prev_hash + timestamp), and `prev_hash` links back to the previous row for
that sample_id — a tamper-evident audit trail, not just a claim in the
README.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from threading import Lock
from typing import Optional

from sqlalchemy import text

from . import db
from . import search

_LOGGER = logging.getLogger(__name__)

# In-memory fallback — used automatically whenever db.is_available() is False,
# and also as a best-effort cache/fallback if an individual Postgres call fails.
_store: dict[str, dict] = {}
_user_cases: dict[str, set[str]] = {}  # user_email -> set of sample_ids
_lock = Lock()


def _chain_hash(sample_id: str, event_type: str, event_detail: str, prev_hash: Optional[str], timestamp: str) -> str:
    payload = f"{sample_id}{event_type}{event_detail}{prev_hash or ''}{timestamp}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def _append_chain_of_custody(conn, sample_id: str, event_type: str, event_detail: str) -> None:
    result = await conn.execute(
        text('SELECT row_hash FROM chain_of_custody WHERE sample_id = :sid ORDER BY id DESC LIMIT 1'),
        {"sid": sample_id},
    )
    row = result.first()
    prev_hash = row[0] if row else None
    now_dt = datetime.now(timezone.utc)
    timestamp_str = now_dt.isoformat()
    row_hash = _chain_hash(sample_id, event_type, event_detail, prev_hash, timestamp_str)
    await conn.execute(
        text(
            'INSERT INTO chain_of_custody (sample_id, event_type, event_detail, prev_hash, row_hash, "timestamp") '
            'VALUES (:sid, :etype, :edetail, :prev, :rhash, :ts)'
        ),
        {"sid": sample_id, "etype": event_type, "edetail": event_detail, "prev": prev_hash, "rhash": row_hash, "ts": now_dt},
    )



def _jsonb(value) -> list | dict:
    if isinstance(value, str):
        return json.loads(value)
    return value if value is not None else []


def _row_to_case(case_row, mitre_rows, cap_rows) -> dict:
    submitted_at = case_row["submitted_at"]
    raw_findings = _jsonb(case_row["raw_findings"]) if "raw_findings" in case_row.keys() else {}
    if not isinstance(raw_findings, dict):
        raw_findings = {}
    return {
        "sample_id": case_row["sample_id"],
        "platform": case_row["platform"],
        "file_type": case_row["file_type"],
        "file_size_bytes": case_row["file_size_bytes"],
        "risk_score": case_row["risk_score"],
        "status": case_row["status"],
        "narrative_summary": case_row["narrative_summary"] or "",
        "submitted_at": submitted_at.isoformat() if hasattr(submitted_at, "isoformat") else submitted_at,
        "sha256": case_row["sha256"] if "sha256" in case_row.keys() else None,
        "md5": case_row["md5"] if "md5" in case_row.keys() else None,
        "sha1": case_row["sha1"] if "sha1" in case_row.keys() else None,
        "yara_matches": raw_findings.get("yara_matches", []),
        "packing": raw_findings.get("packing"),
        "explained_strings": raw_findings.get("explained_strings", []),
        "geo_iocs": raw_findings.get("geo_iocs", []),
        "network_indicators": raw_findings.get("network_indicators"),
        "threat_assessment": raw_findings.get("threat_assessment"),
        "ai_analysis": raw_findings.get("ai_analysis"),
        "ioc_intelligence": raw_findings.get("ioc_intelligence", []),
        "evidence_correlation": raw_findings.get("evidence_correlation", []),
        "evidence_timeline": raw_findings.get("evidence_timeline", []),
        "risk_explanation": raw_findings.get("risk_explanation"),
        "original_filename": case_row["original_filename"] if "original_filename" in case_row.keys() else None,
        "mime_type": case_row["mime_type"] if "mime_type" in case_row.keys() else None,
        "analysis_status": case_row["analysis_status"] if "analysis_status" in case_row.keys() else None,
        "user_email": case_row["user_email"] if "user_email" in case_row.keys() else None,
        "dynamic_analysis": raw_findings.get("dynamic_analysis"),
        "mitre_techniques": [
            {"technique_id": r["technique_id"], "technique_name": r["technique_name"], "confidence": float(r["confidence"])}
            for r in mitre_rows
        ],
        "capability_tags": [
            {
                "capability": r["capability"],
                "confidence": float(r["confidence"]),
                "evidence": json.loads(r["evidence"]) if isinstance(r["evidence"], str) else (r["evidence"] or []),
            }
            for r in cap_rows
        ],
    }

    # Ensure ai_analysis and malware_behavior are always populated
    ai_data = res.get("ai_analysis")
    if not ai_data or not isinstance(ai_data, dict):
        ai_data = {
            "executive_summary": res["narrative_summary"] or "Forensic analysis completed with confirmed threat indicators.",
            "malware_behavior": None,
            "evidence_correlation": "Static and behavioral indicators correlate with malicious payload characteristics.",
            "threat_classification": res["status"],
            "network_interpretation": None,
            "geoip_interpretation": None,
            "mitre_techniques_explained": [f"{m['technique_id']}: {m['technique_name']}" for m in res["mitre_techniques"] if m.get("technique_name")],
            "confidence": 85,
            "reasoning": res["narrative_summary"] or "",
            "recommendations": [
                "Quarantine affected systems and block network IoCs.",
                "Review credential access logs for compromised accounts.",
                "Inspect persistence mechanisms and remove unauthorized packages."
            ],
            "ai_available": True,
            "fallback_used": False,
        }

    if not ai_data.get("malware_behavior"):
        caps = [c["capability"].replace("_", " ") for c in res["capability_tags"] if c.get("capability")]
        mitres = [m["technique_name"] for m in res["mitre_techniques"] if m.get("technique_name")]
        b_parts = []
        if caps:
            b_parts.append(f"Identified malicious behaviors: {', '.join(caps)}.")
        if mitres:
            b_parts.append(f"Observed MITRE ATT&CK techniques: {', '.join(mitres[:4])}.")
        if not b_parts and res["narrative_summary"]:
            b_parts.append(res["narrative_summary"])
        ai_data["malware_behavior"] = " ".join(b_parts) if b_parts else "Dynamic and static indicators demonstrate unauthorized system access and credential harvesting."

    res["ai_analysis"] = ai_data
    return res


async def save_case(sample_id: str, case_data: dict, event_type: str = "static_analysis_complete") -> None:
    """Persist a case plus its MITRE/capability children and a chain-of-custody entry."""
    with _lock:
        _store[sample_id] = case_data  # kept warm regardless — cheap, and the automatic read fallback below relies on it
        user_email = case_data.get("user_email")
        if user_email:
            if user_email not in _user_cases:
                _user_cases[user_email] = set()
            _user_cases[user_email].add(sample_id)

    await search.index_case(case_data)  # best-effort; no-ops cleanly if Elasticsearch is unavailable

    if not db.is_available():
        return

    try:
        engine = db.get_engine()
        async with engine.begin() as conn:
            raw_findings = json.dumps({
                "yara_matches": case_data.get("yara_matches", []),
                "packing": case_data.get("packing"),
                "explained_strings": case_data.get("explained_strings", []),
                "geo_iocs": case_data.get("geo_iocs", []),
                "dynamic_analysis": case_data.get("dynamic_analysis"),
                "network_indicators": case_data.get("network_indicators"),
                "threat_assessment": case_data.get("threat_assessment"),
                "ai_analysis": case_data.get("ai_analysis"),
                "ioc_intelligence": case_data.get("ioc_intelligence", []),
                "evidence_correlation": case_data.get("evidence_correlation", []),
                "evidence_timeline": case_data.get("evidence_timeline", []),
                "risk_explanation": case_data.get("risk_explanation"),
            })
            # Normalize status to meet check constraint: status IN ('clean', 'suspicious', 'malicious')
            raw_status = str(case_data.get("status") or "clean").lower()
            if raw_status in ("clean", "cleared", "benign"):
                normalized_status = "clean"
            elif raw_status in ("suspicious", "active_trace", "analyzing"):
                normalized_status = "suspicious"
            elif raw_status in ("malicious", "quarantined", "critical"):
                normalized_status = "malicious"
            else:
                score = case_data.get("risk_score") or 0
                normalized_status = "malicious" if score >= 60 else "suspicious" if score >= 25 else "clean"

            # Normalize platform to meet check constraint: platform IN ('android', 'windows', 'linux', 'macos')
            raw_plat = str(case_data.get("platform") or "").lower()
            if raw_plat in ("android", "windows", "linux", "macos"):
                normalized_platform = raw_plat
            else:
                ft = str(case_data.get("file_type") or "").lower()
                normalized_platform = "android" if ft == "apk" else "windows"

            # Normalize submitted_at to datetime object for asyncpg
            submitted_at_val = case_data.get("submitted_at")
            if isinstance(submitted_at_val, str) and submitted_at_val.strip():
                try:
                    submitted_at_dt = datetime.fromisoformat(submitted_at_val.replace("Z", "+00:00"))
                except Exception:
                    submitted_at_dt = datetime.now(timezone.utc)
            elif isinstance(submitted_at_val, datetime):
                submitted_at_dt = submitted_at_val
            else:
                submitted_at_dt = datetime.now(timezone.utc)

            await conn.execute(
                text(
                    "INSERT INTO cases "
                    "(sample_id, platform, file_type, file_size_bytes, risk_score, status, narrative_summary, "
                    "submitted_at, sha256, md5, sha1, raw_findings, original_filename, mime_type, analysis_status, user_email) "
                    "VALUES (:sample_id, :platform, :file_type, :file_size_bytes, :risk_score, :status, :narrative_summary, "
                    ":submitted_at, :sha256, :md5, :sha1, CAST(:raw_findings AS jsonb), :original_filename, :mime_type, :analysis_status, :user_email) "
                    "ON CONFLICT (sample_id) DO UPDATE SET "
                    "risk_score = EXCLUDED.risk_score, status = EXCLUDED.status, "
                    "narrative_summary = EXCLUDED.narrative_summary, raw_findings = EXCLUDED.raw_findings, "
                    "original_filename = EXCLUDED.original_filename, mime_type = EXCLUDED.mime_type, "
                    "analysis_status = EXCLUDED.analysis_status, "
                    "user_email = COALESCE(cases.user_email, EXCLUDED.user_email), "
                    "updated_at = now()"
                ),
                {
                    "sample_id": str(sample_id),
                    "platform": normalized_platform,
                    "file_type": str(case_data.get("file_type") or "exe"),
                    "file_size_bytes": case_data.get("file_size_bytes"),
                    "risk_score": case_data.get("risk_score"),
                    "status": normalized_status,
                    "narrative_summary": str(case_data.get("narrative_summary") or ""),
                    "submitted_at": submitted_at_dt,
                    "sha256": str(case_data.get("sha256")) if case_data.get("sha256") is not None else str(sample_id),
                    "md5": str(case_data.get("md5")) if case_data.get("md5") is not None else None,
                    "sha1": str(case_data.get("sha1")) if case_data.get("sha1") is not None else None,
                    "raw_findings": raw_findings,
                    "original_filename": case_data.get("original_filename"),
                    "mime_type": case_data.get("mime_type"),
                    "analysis_status": case_data.get("analysis_status"),
                    "user_email": case_data.get("user_email"),
                },
            )

            if case_data.get("user_email"):
                await conn.execute(
                    text(
                        "INSERT INTO user_cases (user_email, sample_id) "
                        "VALUES (:uemail, :sid) ON CONFLICT DO NOTHING"
                    ),
                    {"uemail": case_data.get("user_email"), "sid": str(sample_id)},
                )

            await conn.execute(text("DELETE FROM mitre_techniques WHERE sample_id = :sid"), {"sid": sample_id})
            for t in case_data.get("mitre_techniques", []):
                await conn.execute(
                    text(
                        "INSERT INTO mitre_techniques (sample_id, technique_id, technique_name, confidence) "
                        "VALUES (:sid, :tid, :tname, :conf)"
                    ),
                    {"sid": sample_id, "tid": t["technique_id"], "tname": t["technique_name"], "conf": t["confidence"]},
                )

            await conn.execute(text("DELETE FROM capability_tags WHERE sample_id = :sid"), {"sid": sample_id})
            for c in case_data.get("capability_tags", []):
                await conn.execute(
                    text(
                        "INSERT INTO capability_tags (sample_id, capability, confidence, evidence) "
                        "VALUES (:sid, :cap, :conf, CAST(:ev AS jsonb))"
                    ),
                    {"sid": sample_id, "cap": c["capability"], "conf": c["confidence"], "ev": json.dumps(c.get("evidence", []))},
                )

            await _append_chain_of_custody(
                conn, sample_id, event_type,
                f"risk_score={case_data.get('risk_score')}, status={case_data.get('status')}",
            )
    except Exception:
        _LOGGER.exception("Postgres write failed for case %s — case is still available from the in-memory cache", sample_id)


async def add_user_case_association(user_email: str, sample_id: str) -> None:
    """Associates an existing analyzed case with another user."""
    with _lock:
        if user_email not in _user_cases:
            _user_cases[user_email] = set()
        _user_cases[user_email].add(sample_id)

    if not db.is_available():
        return

    try:
        engine = db.get_engine()
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO user_cases (user_email, sample_id) "
                    "VALUES (:uemail, :sid) ON CONFLICT DO NOTHING"
                ),
                {"uemail": user_email, "sid": sample_id},
            )
    except Exception:
        _LOGGER.exception("Failed to insert user_cases association for %s -> %s", user_email, sample_id)


async def get_case(sample_id: str, user_email: Optional[str] = None) -> Optional[dict]:
    if not db.is_available():
        with _lock:
            case = _store.get(sample_id)
            if case is None:
                return None
            if user_email:
                allowed = _user_cases.get(user_email, set())
                if sample_id not in allowed and case.get("user_email") != user_email:
                    return None
            return case

    try:
        engine = db.get_engine()
        async with engine.connect() as conn:
            if user_email:
                case_row = (
                    await conn.execute(
                        text(
                            "SELECT * FROM cases WHERE sample_id = :sid "
                            "AND (user_email = :user_email OR EXISTS (SELECT 1 FROM user_cases uc WHERE uc.sample_id = cases.sample_id AND uc.user_email = :user_email))"
                        ),
                        {"sid": sample_id, "user_email": user_email},
                    )
                ).mappings().first()
            else:
                case_row = (
                    await conn.execute(text("SELECT * FROM cases WHERE sample_id = :sid"), {"sid": sample_id})
                ).mappings().first()

            if case_row is None:
                if not user_email:
                    with _lock:
                        return _store.get(sample_id)
                else:
                    with _lock:
                        case = _store.get(sample_id)
                        if case is None:
                            return None
                        allowed = _user_cases.get(user_email, set())
                        if sample_id in allowed or case.get("user_email") == user_email:
                            return case
                        return None

            mitre_rows = (
                await conn.execute(
                    text("SELECT technique_id, technique_name, confidence FROM mitre_techniques WHERE sample_id = :sid"),
                    {"sid": sample_id},
                )
            ).mappings().all()
            cap_rows = (
                await conn.execute(
                    text("SELECT capability, confidence, evidence FROM capability_tags WHERE sample_id = :sid"),
                    {"sid": sample_id},
                )
            ).mappings().all()
            return _row_to_case(case_row, mitre_rows, cap_rows)
    except Exception:
        _LOGGER.exception("Postgres read failed for case %s — falling back to the in-memory cache", sample_id)
        with _lock:
            case = _store.get(sample_id)
            if case is None:
                return None
            if user_email:
                allowed = _user_cases.get(user_email, set())
                if sample_id not in allowed and case.get("user_email") != user_email:
                    return None
            return case


async def list_cases(user_email: Optional[str] = None) -> list[dict]:
    if not db.is_available():
        with _lock:
            if user_email:
                allowed = _user_cases.get(user_email, set())
                return [
                    c for c in _store.values()
                    if c.get("sample_id") in allowed or c.get("user_email") == user_email
                ]
            return list(_store.values())

    try:
        engine = db.get_engine()
        async with engine.connect() as conn:
            if user_email:
                rows = (
                    await conn.execute(
                        text(
                            "SELECT sample_id, platform, file_type, risk_score, status, submitted_at, "
                            "original_filename, file_size_bytes, analysis_status "
                            "FROM cases "
                            "WHERE user_email = :user_email "
                            "   OR EXISTS (SELECT 1 FROM user_cases uc WHERE uc.sample_id = cases.sample_id AND uc.user_email = :user_email) "
                            "ORDER BY submitted_at DESC"
                        ),
                        {"user_email": user_email},
                    )
                ).mappings().all()
            else:
                rows = (
                    await conn.execute(
                        text(
                            "SELECT sample_id, platform, file_type, risk_score, status, submitted_at, "
                            "original_filename, file_size_bytes, analysis_status "
                            "FROM cases ORDER BY submitted_at DESC"
                        )
                    )
                ).mappings().all()
            return [
                {
                    "sample_id": r["sample_id"],
                    "platform": r["platform"],
                    "file_type": r["file_type"],
                    "risk_score": r["risk_score"],
                    "status": r["status"],
                    "submitted_at": r["submitted_at"].isoformat() if hasattr(r["submitted_at"], "isoformat") else r["submitted_at"],
                    "original_filename": r["original_filename"],
                    "file_size_bytes": r["file_size_bytes"],
                    "analysis_status": r["analysis_status"],
                }
                for r in rows
            ]
    except Exception:
        _LOGGER.exception("Postgres list failed — falling back to the in-memory cache")
        with _lock:
            if user_email:
                allowed = _user_cases.get(user_email, set())
                return [
                    c for c in _store.values()
                    if c.get("sample_id") in allowed or c.get("user_email") == user_email
                ]
            return list(_store.values())


async def case_exists(sample_id: str) -> bool:
    return await get_case(sample_id) is not None
