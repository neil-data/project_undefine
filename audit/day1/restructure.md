# Day 1 — Restructure Verification Report

## 1. Summary of Restructure Verification

All monorepo subsystems were systematically inspected and verified following the structural reorganization:

### Python Imports & Discovery
- `pytest.ini` pythonpath configured for `.`, `apps`, `packages`, `analysis`, `analysis/static`, `sandbox/host`.
- Pytest test discovery collects all 1,066 tests cleanly across `analysis`, `apps/backend/tests`, `apps/ingestion`, `sandbox/host/tests` with 0 collection errors.

### Backend Startup
- Backend entrypoint `apps/backend/app/main.py` verified.
- FastAPI initializes with title `"SentinelScan API"`.
- Health check router at `/api/health` verified functional without auth requirements.

### Frontend Build
- Executed `npm run build` in `apps/frontend/`.
- Vite 6 compiled 2,702 modules into production assets in `dist/` in 24.8s without errors.

### Docker & Compose Configuration
- `docker-compose.yml` build contexts verified:
  - `backend`: context `.`, dockerfile `apps/backend/Dockerfile`
  - `sandbox-host`: context `sandbox/host`, dockerfile `Dockerfile`
  - `ingestion`: context `.`, dockerfile `apps/ingestion/Dockerfile`
  - `frontend`: context `.`, dockerfile `apps/frontend/Dockerfile`
- Shared volume `ingestion_samples` configured across ingestion gateway and backend worker.

### Environment & Secrets Hygiene
- `.env.example` audited: specifies Postgres host port 5434 matching compose mapping `5434:5432`, `INGESTION_SAMPLES_DIR=ingestion_samples`, and JWT secret requirements.
- Checked `git ls-files`:
  - Removed empty temporary file `analysis/dynamic/hooks/test_hooks.py.tmp`.
  - Untracked `apps/backend/tests/fixtures/synthetic_logs/sample_capture.pcap` (267 bytes) from git; added `_ensure_pcap_fixture` to `test_strace_parser_stage1.py` so fresh clones create the synthetic fixture on demand.
  - Added `*.pcap`, `*.pcapng`, `*.mmdb`, `*.tmp` to `.gitignore`.
  - Confirmed 0 secrets, binaries, pcaps, or mmdb databases are tracked by git.

---

## 2. Render & Vercel Root / Build Settings

### Render Dashboard Settings
- **Configuration File**: `infrastructure/render/render.yaml` declares service `e-rakshak-backend` using Docker runtime with `dockerfilePath: ./apps/backend/Dockerfile` and `dockerContext: .`.
- **Required Render Dashboard Settings**:
  - **Root Directory**: Must be repository root (`.`). Do **not** set Root Directory to `apps/backend`, because the backend Dockerfile requires access to sibling folders `analysis/`, `packages/`, `apps/`, and `data/` during image build.
  - **Docker Build Context Directory**: `.`
  - **DockerfilePath**: `./apps/backend/Dockerfile`
  - **Health Check Path**: `/api/health`
  - **Environment Variables**: Provide `DATABASE_URL` (from Postgres service), auto-generated `JWT_SECRET_KEY`, `ALLOW_DB_FALLBACK=0`, `ALLOW_DEV_JWT_SECRET=0`, `CORS_ORIGINS`, `INGESTION_SAMPLES_DIR=/tmp/ingestion_samples`.

### Vercel Dashboard Settings
- **Configuration File**: `apps/frontend/vercel.json` contains SPA route rewrites:
  ```json
  {
    "rewrites": [{ "source": "/(.*)", "destination": "/" }]
  }
  ```
- **Required Vercel Dashboard Settings**:
  - **Root Directory**: Set to `apps/frontend` in Project Settings > General > Root Directory.
  - **Framework Preset**: Vite
  - **Build Command**: `npm run build` (or `vite build`)
  - **Output Directory**: `dist`
  - **Install Command**: `npm install`
  - **Environment Variables**: `VITE_API_BASE=https://<your-render-backend-url>/api`
  - *Alternative (if Root Directory remains monorepo root)*:
    - Root Directory: `.`
    - Build Command: `cd apps/frontend && npm install && npm run build`
    - Output Directory: `apps/frontend/dist`
