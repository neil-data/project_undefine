"""
backend/app/main.py — FastAPI application entrypoint.

Run from the backend directory with:
    uvicorn app.main:app --reload --port 8000

Or from the project root with:
    uvicorn backend.app.main:app --reload --port 8000

Then visit:
    http://localhost:8000/docs

for the interactive FastAPI documentation.
"""

from dotenv import load_dotenv
load_dotenv()

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import db, search
# Imported by name, not as `from . import auth`: the router import below binds
# `auth` to backend.app.routers.auth and would shadow the module.
from .auth import get_secret_key
from .ingestion_worker import start_ingestion_worker, stop_ingestion_worker
from .routers import auth, cases, health, network_intelligence, live_monitoring, threat_intel

_LOGGER = logging.getLogger(__name__)

# Global Redis client
_redis_client = None


async def get_redis():
    """Get or create the global Redis client."""
    global _redis_client
    if _redis_client is None:
        import redis.asyncio as redis
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        _redis_client = await redis.from_url(redis_url, decode_responses=True)
    return _redis_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Best-effort: Postgres/Elasticsearch/the ingestion-queue consumer are all
    # optional at startup — each degrades gracefully (see db.py, search.py,
    # ingestion_worker.py) rather than preventing the API from serving requests
    # when the surrounding infrastructure (docker-compose) isn't up yet.
    # Note: live_monitoring requires Postgres with sync driver to avoid 503 errors
    #
    # Resolved first and deliberately not caught: a missing or placeholder
    # JWT_SECRET_KEY means every token this process issues is forgeable by
    # anyone who has read the repo, so it must stop the server rather than
    # surface later as a working-looking login.
    get_secret_key()

    await db.init_db()
    await search.init_search()
    await start_ingestion_worker()
    try:
        yield
    finally:
        await stop_ingestion_worker()
        await search.close_search()
        await db.close_db()


app = FastAPI(
    title="SentinelScan API",
    description="Unified cross-platform malware detection & behavioral analysis suite — PS-4, E-Rakshak 2026",
    version="0.1.0-alpha",
    lifespan=lifespan,
)

# Allow the frontend to communicate with the backend during development.
# CORS_ORIGINS can be set to a comma-separated list in production; falls back
# to the known local dev ports when unset.
_default_origins = "http://localhost:5173,http://localhost:3000,http://localhost:8000"
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.environ.get("CORS_ORIGINS", _default_origins).split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(cases.router)
app.include_router(network_intelligence.router)
app.include_router(live_monitoring.router)
app.include_router(threat_intel.router)



@app.get("/")
def root():
    return {
        "message": "SentinelScan API — see /docs for interactive documentation"
    }