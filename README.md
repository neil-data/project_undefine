# E-Rakshak v4.1 — Multi-Modal Malware Analysis & Threat Intelligence Platform

[![Build Status](https://img.shields.io/badge/tests-1050%2B%20passing-brightgreen.svg)]()
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)]()
[![React Version](https://img.shields.io/badge/react-19.2-61dafb.svg)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**E-Rakshak** is an evidence-grade, automated malware analysis, behavioral detonation, and threat intelligence platform designed for digital forensics investigators and cybersecurity response teams.

The platform provides unified inspection for **Windows Portable Executables (PE)**, **Linux Executables (ELF)**, and **Android Applications (APK)**, coupling deep static extraction, hypervisor-managed dynamic sandboxing, memory forensics, automated MITRE ATT&CK correlation, and plain-language narrative report generation.

---

## 1. Monorepo Structure

The repository is organized as a clean, modular production monorepo:

```
.
├── apps/                        # Deployable applications and services
│   ├── backend/                 # FastAPI REST API service & report generation
│   ├── frontend/                # React / TypeScript / Vite analyst dashboard
│   └── ingestion/               # Gateway service, validation & scam triage
├── analysis/                    # Core analysis engines & detection logic
│   ├── static/                  # PE, ELF, and APK static parsers & extractors
│   ├── dynamic/                 # Detonation stages, behavioral logging, hooks
│   ├── memory/                  # Volatility memory dump inspection & injection detection
│   ├── correlation/             # Capability classification & investigation engine
│   ├── scoring/                 # Risk scoring model & narrative threat agent
│   ├── rules/                   # YARA rules (India scam signatures) & MITRE mappings
│   └── threat_intel/            # Multi-provider threat feeds, mock fallbacks & GeoIP
├── sandbox/                     # Hypervisor orchestration & external adapters
│   ├── host/                    # QEMU/KVM runner service & canary health checks
│   └── adapters/                # MobSF adapter for dynamic Android analysis
├── packages/                    # Shared internal libraries and shims
│   ├── agents/                  # Backward-compatible agent facades
│   └── schemas/                 # Canonical data contracts & investigation schemas
├── infrastructure/              # Deployment and infrastructure automation
│   ├── deployment/              # Bare-metal KVM and cloud provisioning scripts
│   ├── docker/                  # Docker container recipes
│   └── render/                  # Render cloud blueprint configurations
├── data/                        # Database schemas and search mappings
│   ├── schemas/postgres/        # PostgreSQL relational schema
│   └── schemas/elasticsearch/   # Elasticsearch index mapping
├── reports/                     # Report fixtures and sample outputs
│   └── examples/                # Authoritative reference reports
├── scripts/                     # Operational, testing, and maintenance utilities
│   ├── deployment/              # Service deployment scripts
│   ├── development/             # Development pipelines & performance benchmarks
│   ├── maintenance/             # DB verification & health-check scripts
│   └── testing/                 # System integration test suites
└── docs/                        # Architecture and development documentation
    ├── architecture/            # System architecture & ASCII data flow diagrams
    ├── development/             # Monorepo developer guide & project structure
    └── phases/                  # Historical phase summaries & audit reports
```

For an exhaustive breakdown of directory conventions and design rules, see [`docs/development/PROJECT_STRUCTURE.md`](docs/development/PROJECT_STRUCTURE.md).

---

## 2. Architecture & Data Flow

```
Samples (PE / ELF / APK)
       │
       ▼
[ Ingestion Gateway ] ─────────► [ Cryptographic Evidence Manifest ]
       │
       ├─────────────────────────────────┬─────────────────────────────────┐
       ▼                                 ▼                                 ▼
[ Static Analysis ]             [ Dynamic Sandbox ]               [ Memory Forensics ]
(PE/ELF/APK, YARA)              (KVM/MobSF Runtime)               (Process Injection)
       │                                 │                                 │
       └─────────────────────────────────┼─────────────────────────────────┘
                                         ▼
                           [ Correlation & MITRE Mapping ]
                                         │
                                         ▼
                           [ Threat Intelligence & GeoIP ]
                                         │
                                         ▼
                           [ Scoring & Narrative Agent ]
                                         │
                                         ▼
                       [ Authoritative JSON & PDF Reports ]
                                         │
                                         ▼
                       [ Analyst React Dashboard & REST API ]
```

Read the full architecture specification at [`docs/architecture/system-architecture.md`](docs/architecture/system-architecture.md).

---

## 3. Quickstart

### Prerequisites
- Python 3.11+
- Node.js 20+ & npm
- Docker & Docker Compose (optional for services)

### Environment Configuration
```bash
cp .env.example .env
# Configure database credentials and optional threat intel API keys in .env
```

### Running with Docker Compose
To launch the full backend stack (PostgreSQL, Elasticsearch, Redis, Backend API, Sandbox Host, Ingestion Gateway, and Frontend):
```bash
docker-compose up -d
```

### Running Locally for Development

#### 1. Backend Service
```bash
# Setup virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r apps/backend/requirements.txt
pip install -r sandbox/host/requirements.txt

# Run FastAPI backend
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### 2. Frontend Analyst Dashboard
```bash
cd apps/frontend
npm install
npm run dev
```
Access the dashboard at `http://localhost:5173`.

---

## 4. Running Tests

The test suite contains over 1,050 tests across static analysis, dynamic stages, ingestion, scoring models, and hypervisor runners.

### Unified Test Suite (Monorepo Root)
```bash
# Run all unit and integration tests from repo root
pytest
```

### Subsystem-Specific Test Runs
```bash
# Analysis engine tests (Static, Dynamic, Correlation, Scoring)
pytest analysis

# Ingestion gateway tests
pytest apps/ingestion

# Core backend API and regression suites
pytest apps/backend/tests

# Sandbox host runner and canary tests
pytest sandbox/host/tests
```

### Frontend Typechecking & Linting
```bash
cd apps/frontend
npx tsc --noEmit
```

---

## 5. Security & Isolation

- **Malware Containment**: Never execute live samples on host environments. Detonation occurs solely inside isolated QEMU/KVM virtual machines with auto-reverting gold snapshots and network sinkholing (INetSim).
- **Evidence Integrity**: All analysis runs generate cryptographic HMAC-SHA256 manifests that bind extracted artifacts, logs, and network pcaps to the submitted sample hash.
- **Sample Protection**: Live binaries (`*.exe`, `*.apk`, `*.elf`) are strictly excluded from version control via `.gitignore`.

---

## 6. Historical Records & Audit

Detailed phase records and verified audit logs for Phases 0 through 6 remediation are documented in [`docs/phases/README.md`](docs/phases/README.md).

---

## 7. License

This project is licensed under the terms of the [MIT License](LICENSE).
