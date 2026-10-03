"""
backend/app/search.py — Elasticsearch-backed case search.

Applies the existing storage/elasticsearch/case_index_mapping.json on
startup if the `cases` index doesn't exist yet, indexes each case as it's
saved, and backs GET /api/cases/search. Gracefully degrades to `None`/no-op
when Elasticsearch is unreachable — the dashboard's search box already
falls back to filtering the cases it already has client-side, so ES being
down never blocks the UI, only makes search less capable.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

_LOGGER = logging.getLogger(__name__)

_MAPPING_PATH = Path(__file__).resolve().parents[3] / "data" / "schemas" / "elasticsearch" / "case_index_mapping.json"
if not _MAPPING_PATH.exists():
    _MAPPING_PATH = Path(__file__).resolve().parents[2] / "storage" / "elasticsearch" / "case_index_mapping.json"
_INDEX_NAME = "cases"

_client = None
_es_available = False

try:
    from elasticsearch import AsyncElasticsearch
except ImportError:  # pragma: no cover - package listed in requirements.txt, guarded for dev-without-install
    AsyncElasticsearch = None  # type: ignore[assignment]


async def init_search() -> bool:
    """Connect to Elasticsearch and ensure the `cases` index/mapping exists."""
    global _client, _es_available

    if AsyncElasticsearch is None:
        _LOGGER.warning("elasticsearch package not installed — case search disabled")
        return False

    es_url = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")
    try:
        client = AsyncElasticsearch(es_url, request_timeout=5)
        if not await client.ping():
            raise ConnectionError(f"Elasticsearch did not respond at {es_url}")

        if not await client.indices.exists(index=_INDEX_NAME):
            mapping = json.loads(_MAPPING_PATH.read_text(encoding="utf-8"))
            await client.indices.create(index=_INDEX_NAME, **mapping)
            _LOGGER.info("Created Elasticsearch index '%s' from %s", _INDEX_NAME, _MAPPING_PATH.name)

        _client = client
        _es_available = True
        _LOGGER.info("Elasticsearch connected at %s", es_url)
    except Exception as error:
        _es_available = False
        _LOGGER.warning(
            "Elasticsearch unavailable (%s: %s) — case search falls back to the dashboard's "
            "client-side filtering. Run `docker-compose up -d elasticsearch` to enable it.",
            type(error).__name__, error,
        )

    return _es_available


def is_available() -> bool:
    return _es_available


async def close_search() -> None:
    global _client, _es_available
    if _client is not None:
        await _client.close()
    _client = None
    _es_available = False


async def index_case(case_data: dict) -> None:
    """Best-effort indexing — a failure here never blocks the case save."""
    if not _es_available or _client is None:
        return
    try:
        document = {
            "sample_id": case_data.get("sample_id"),
            "platform": case_data.get("platform"),
            "file_type": case_data.get("file_type"),
            "risk_score": case_data.get("risk_score"),
            "status": case_data.get("status"),
            "narrative_summary": case_data.get("narrative_summary"),
            "mitre_technique_ids": [t.get("technique_id") for t in case_data.get("mitre_techniques", [])],
            "capability_tags": [c.get("capability") for c in case_data.get("capability_tags", [])],
            "submitted_at": case_data.get("submitted_at"),
        }
        await _client.index(index=_INDEX_NAME, id=case_data.get("sample_id"), document=document)
    except Exception:
        _LOGGER.exception("Elasticsearch indexing failed for case %s", case_data.get("sample_id"))


async def search_cases(query: str) -> Optional[list[str]]:
    """Return matching sample_ids, or None if search is unavailable (caller should fall back)."""
    if not _es_available or _client is None:
        return None
    try:
        response = await _client.search(
            index=_INDEX_NAME,
            query={
                "multi_match": {
                    "query": query,
                    "fields": ["sample_id", "narrative_summary", "capability_tags", "mitre_technique_ids"],
                    "fuzziness": "AUTO",
                }
            },
            size=100,
        )
        return [hit["_id"] for hit in response["hits"]["hits"]]
    except Exception:
        _LOGGER.exception("Elasticsearch search failed for query %r", query)
        return None
