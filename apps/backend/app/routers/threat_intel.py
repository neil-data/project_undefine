"""
backend/app/routers/threat_intel.py — Threat Intelligence & MalwareBazaar API router.
Provides endpoints for on-demand hash lookups, recent malware feeds, tag queries,
and signature matching backed by abuse.ch MalwareBazaar.
"""

from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query, Depends
from .. import malware_bazaar
from ..auth import get_current_user

router = APIRouter(prefix="/api/threat-intel", tags=["threat-intel"])


@router.get("/status")
async def get_threat_intel_status():
    """Check configuration and connectivity status of threat intel providers."""
    api_key = malware_bazaar.get_api_key()
    has_key = bool(api_key and len(api_key) > 10)
    return {
        "malware_bazaar": {
            "configured": has_key,
            "provider": "abuse.ch MalwareBazaar",
            "api_endpoint": "https://mb-api.abuse.ch/api/v1/",
            "features": ["hash_lookup", "recent_samples", "tag_search", "signature_search"],
        }
    }


@router.get("/bazaar/lookup/{hash_value}")
async def lookup_bazaar_hash(hash_value: str):
    """
    Query MalwareBazaar for a cryptographic hash (SHA-256, MD5, SHA-1).
    Returns verified malware family signature, tags, YARA rules, and vendor intel.
    """
    clean_hash = hash_value.strip().lower()
    if len(clean_hash) not in (32, 40, 64):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid hash format '{hash_value}'. Expected MD5 (32), SHA1 (40), or SHA256 (64 hex characters)."
        )

    result = await malware_bazaar.lookup_hash(clean_hash)
    if not result:
        return {
            "found": False,
            "hash": clean_hash,
            "message": "Hash not found in MalwareBazaar repository."
        }
    return result


@router.get("/bazaar/recent")
async def get_recent_bazaar_samples(selector: str = Query("time", description="Selector: 'time' or '100'")):
    """Get the latest recent malware samples uploaded to MalwareBazaar."""
    samples = await malware_bazaar.get_recent_samples(selector=selector)
    return {
        "count": len(samples),
        "samples": samples
    }


@router.get("/bazaar/tag/{tag}")
async def query_bazaar_tag(tag: str, limit: int = Query(25, ge=1, le=50)):
    """Search MalwareBazaar for samples categorized under a specific tag."""
    samples = await malware_bazaar.query_tag(tag=tag, limit=limit)
    return {
        "tag": tag,
        "count": len(samples),
        "samples": samples
    }


@router.get("/bazaar/signature/{signature}")
async def query_bazaar_signature(signature: str, limit: int = Query(25, ge=1, le=50)):
    """Search MalwareBazaar for samples belonging to a specific malware family."""
    samples = await malware_bazaar.query_signature(signature=signature, limit=limit)
    return {
        "signature": signature,
        "count": len(samples),
        "samples": samples
    }
