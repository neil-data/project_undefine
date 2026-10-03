# E-Rakshak Production Monorepo Structure

This document outlines the architectural organization, component ownership boundaries, and development guidelines for the E-Rakshak malware analysis and triage platform.

---

## 1. Context & Motivation

As E-Rakshak grew across multiple phases (Phases 1 through 12 and forensic audit remediation phases 0 through 6), experimental scripts, ad-hoc sandbox code, partial static analysis tools, and phase summaries accumulated in the repository root.

The reorganized architecture establishes clear boundaries between:
- **Application Services** (`apps/`): Independently deployable services (API backend, React frontend, upload ingestion gateway).
- **Core Analysis Engines** (`analysis/`): Reusable static, dynamic, intelligence, correlation, and scoring modules.
- **Sandbox Infrastructure** (`sandbox/`): Decoupled execution host microservices, environment runners, and third-party adapters.
- **Shared Data & Packages** (`packages/`, `data/`): Common schemas, storage definitions, and shared utilities.
- **Operational Automation** (`infrastructure/`, `scripts/`): Containerization, cloud deployment, and administrative scripts.
- **Documentation & History** (`docs/`, `archive/`): Architecture specifications, developer documentation, and chronological audit archives.

---

## 2. Monorepo Directory Architecture

```text
E-Rakshak/
├── README.md                           # Main repository overview & quickstart
├── LICENSE                             # Apache-2.0 License
├── CHANGELOG.md                        # Version history and milestone changelog
├── .gitignore                          # Cleaned global gitignore
├── .dockerignore                       # Cleaned global dockerignore
├── .env.example                        # Template environment variables (no secrets)
├── docker-compose.yml                  # Root multi-container orchestration
├── pyproject.toml                      # Monorepo Python packaging & pytest config
├── pytest.ini                          # Root test discovery configuration
│
├── apps/                               # Deployable applications & microservices
│   ├── backend/                        # FastAPI REST API server
│   │   ├── Dockerfile                  # Production container definition
│   │   ├── requirements.txt            # Python dependencies
│   │   ├── app/                        # Application source (routers, models, DB)
│   │   └── tests/                      # Application tests & regression suites
│   │
│   ├── frontend/                       # React / Vite / Tailwind UI dashboard
│   │   ├── Dockerfile                  # Frontend container definition
│   │   ├── package.json                # Node dependencies
│   │   ├── src/                        # UI components, pages, state management
│   │   └── public/                     # Static web assets
│   │
│   └── ingestion/                      # Layer 1 Ingestion gateway
│       ├── Dockerfile                  # Ingestion container definition
│       ├── requirements.txt            # Ingestion dependencies
│       ├── gateway.py                  # Ingestion HTTP API (port 8001)
│       ├── india_scam_triage.py        # Regional scam detection
│       ├── validation.py               # Binary format validation
│       └── tests/                      # Ingestion test suite
│
├── analysis/                           # Reusable analysis engines
│   ├── static/                         # Multi-format static analysis engine
│   │   ├── static_analysis/            # Parsers for ELF, PE, APK, Mach-O
│   │   └── tests/                      # Static analysis test suite
│   ├── dynamic/                        # Dynamic sandbox execution engines
│   │   ├── stages/                     # Multi-stage behavioral execution
│   │   ├── hooks/                      # API monitoring & syscall interception
│   │   ├── artifacts/                  # Memory forensics & artifact parsing
│   │   ├── timeline/                   # Behavioral timeline reconstruction
│   │   └── manager/                    # Dynamic session manager & queues
│   ├── intel/                          # Network intelligence, threat feeds & GeoIP
│   ├── correlation/                    # Capability classification & chain of custody
│   │   ├── capability_classifier/      # Behavioral capability tagging
│   │   └── investigation_engine/       # Evidence graph & HMAC chain verification
│   ├── scoring/                        # Risk scoring & grounded narrative generation
│   │   ├── orchestrator/               # Threat scoring rules & pipeline engine
│   │   └── narrative_agent/            # Grounded AI forensic narrative generator
│   └── rules/                          # Detection signatures & threat mappings
│       ├── yara/                       # Shipped YARA signature rules
│       └── mitre/                      # MITRE ATT&CK technique mappings
│
├── sandbox/                            # Dynamic detonation infrastructure
│   ├── host/                           # Standalone sandbox execution microservice
│   │   ├── Dockerfile                  # Hardened Debian container (strace + qemu)
│   │   ├── requirements.txt            # Host dependencies
│   │   ├── app/                        # Runner lock, worker pool, canary monitor
│   │   └── tests/                      # Sandbox host test suite
│   ├── adapters/                       # Sandboxing engine adapters
│   │   └── mobsf/                      # MobSF dynamic Android integration
│   ├── configs/                        # QEMU multi-arch rootfs & environment configs
│   └── README.md                       # Dynamic sandbox architecture documentation
│
├── packages/                           # Shared internal packages & libraries
│   ├── schemas/                        # Canonical Pydantic data schemas
│   ├── shared/                         # Shared utilities, logging, and helpers
│   ├── config/                         # Unified configuration models
│   └── agents/                         # Backward-compatible import shims
│
├── data/                               # Data definitions & schemas
│   ├── fixtures/                       # Test data fixtures and synthetic traces
│   ├── schemas/                        # Database & search index schemas
│   │   ├── postgres/schema.sql         # Postgres relational schema
│   │   └── elasticsearch/              # Case index mapping JSON
│   └── README.md                       # Data dictionary & storage layout docs
│
├── reports/                            # Example reports & verified case studies
│   ├── examples/                       # Verified sample reports (benign & Mirai)
│   ├── fixtures/                       # Golden report fixtures for regression tests
│   └── README.md                       # Report schemas and sample documentation
│
├── scripts/                            # Platform tooling & operational scripts
│   ├── development/                    # demo_pipeline.py, performance_optimization.py
│   ├── testing/                        # system_testing.py
│   ├── deployment/                     # setup_live_monitoring.sh
│   └── maintenance/                    # verify_neon.py
│
├── infrastructure/                     # Deployment manifests & cloud configurations
│   ├── docker/                         # Dockerfiles & container utilities
│   ├── deployment/                     # GCP VM setup and KVM CAPE scripts
│   ├── render/                         # render.yaml deployment manifest
│   └── monitoring/                     # Prometheus/Grafana service monitors
│
├── docs/                               # Project documentation & historical archive
│   ├── architecture/                   # system-architecture.md, system diagrams, ps4.png
│   ├── development/                    # PROJECT_STRUCTURE.md, developer guidelines
│   ├── phases/                         # Historical phase implementation summaries
│   │   ├── audit/                      # Phase 0 through Phase 6 audit reports
│   │   └── README.md                   # Index and explanation of phase documents
│   └── README.md                       # Documentation index
│
└── archive/                            # Deprecated & historical references
    ├── historical/                     # Legacy experimental code
    └── phase-documents/                # Obsolete notes
```

---

## 3. Migration Map (Old Path → New Path)

| Old Path | New Path | Reason |
| :--- | :--- | :--- |
| `backend/` | `apps/backend/` | Move active backend application under `apps/` |
| `frontend/` | `apps/frontend/` | Move active frontend dashboard under `apps/` |
| `ingestion/` | `apps/ingestion/` | Move active ingestion microservice under `apps/` |
| `sandbox-host/` | `sandbox/host/` | Decoupled sandbox host microservice belongs in `sandbox/` |
| `dynamic-sandbox/mobsf/` | `sandbox/adapters/mobsf/` | Mobile Security Framework adapter belongs in `sandbox/adapters/` |
| `dynamic-sandbox/{stages,hooks,artifacts,timeline,manager}` | `analysis/dynamic/` | Dynamic execution stages, hook engine, and forensics belong in `analysis/dynamic/` |
| `static-analysis/src/static_analysis/` | `analysis/static/static_analysis/` | Static analysis engine belongs in `analysis/static/` |
| `static-analysis/yara_rules/` | `analysis/rules/yara/` | YARA rules separated into reusable `analysis/rules/` |
| `static-analysis/tests/` | `analysis/static/tests/` | Static tests grouped with static engine |
| `agents/capability_classifier/` | `analysis/correlation/capability_classifier/` | Correlation engine component |
| `agents/investigation_engine/` | `analysis/correlation/investigation_engine/` | Forensic chain verification & investigation |
| `agents/mitre_mapper/` | `analysis/rules/mitre/` | MITRE ATT&CK rules |
| `agents/narrative_agent/` | `analysis/scoring/narrative_agent/` | Grounded AI narrative generation |
| `agents/orchestrator/` | `analysis/scoring/orchestrator/` | Risk scoring & orchestration rules |
| `storage/postgres/schema.sql` | `data/schemas/postgres/schema.sql` | Storage schemas consolidated under `data/schemas/` |
| `storage/elasticsearch/...` | `data/schemas/elasticsearch/...` | Elasticsearch mappings consolidated under `data/schemas/` |
| `reports/*.json` | `reports/examples/` | Example reports moved to `reports/examples/` |
| `demo_pipeline.py` | `scripts/development/demo_pipeline.py` | Standalone script categorized by purpose |
| `performance_optimization.py` | `scripts/development/performance_optimization.py` | Profiling utility categorized by purpose |
| `system_testing.py` | `scripts/testing/system_testing.py` | Testing utility categorized by purpose |
| `setup_live_monitoring.sh` | `scripts/deployment/setup_live_monitoring.sh` | Deployment script categorized by purpose |
| `scripts/verify_neon.py` | `scripts/maintenance/verify_neon.py` | Maintenance script categorized by purpose |
| `infra/*.sh` | `infrastructure/deployment/` | Cloud VM setup scripts moved to `infrastructure/` |
| `render.yaml` | `infrastructure/render/render.yaml` | Cloud deployment manifest moved to `infrastructure/` |
| `audit/` | `docs/phases/audit/` | Audit trail organized with phase documentation |
| `PHASE_*.md` (root) | `docs/phases/` | All historical phase summaries consolidated |

---

## 4. Developer Guidelines & Boundaries

1. **Adding Backend Endpoints**: Place routers in `apps/backend/app/routers/` and register them in `apps/backend/app/main.py`.
2. **Adding Frontend Components**: Place components in `apps/frontend/src/components/` and routes in `apps/frontend/src/pages/`.
3. **Extending Static Analysis**: Add new parsers/analyzers to `analysis/static/static_analysis/`. Add corresponding tests to `analysis/static/tests/`.
4. **Adding Detection Signatures**: Place new YARA rules under `analysis/rules/yara/generic/` or `analysis/rules/yara/india_scam_rules/`.
5. **Adding Dynamic Execution Hooks**: Add syscalls or API hooks under `analysis/dynamic/hooks/`.
6. **Adding Tests**: Place backend tests in `apps/backend/tests/`, ingestion tests in `apps/ingestion/test_*.py`, sandbox host tests in `sandbox/host/tests/`, and analysis tests in `analysis/static/tests/` or `analysis/dynamic/`.
7. **Environment Variables**: Never commit `.env` or real API keys. Add variable documentation to `.env.example`.
