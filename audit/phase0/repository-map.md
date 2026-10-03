# E-Rakshak Repository Architecture Map (Phase 0 Baseline)

## 1. Overview
The codebase is a multi-platform malware analysis platform (primarily focusing on Linux ELF, Windows PE, and Android APK). It integrates static analysis, dynamic sandbox execution, LangGraph agent orchestration, MITRE ATT&CK mapping, capability tagging, threat intelligence enrichment, and automated PDF forensic reporting.

---

## 2. Directory & Module Responsibilities

### `backend/`
- **Application Entry Point**: `backend/app/main.py` (FastAPI web server).
- **Core Pipeline Orchestrator**: `backend/app/analysis.py` (`run_analysis_pipeline()`). Coordinates static analysis, dynamic sandbox triggering, orchestrator graph execution, network indicator extraction, GeoIP enrichment, threat assessment, IoC intelligence, and forensic timeline generation.
- **Dynamic Sandbox Client**: `backend/app/sandbox.py`. Communicates over HTTP with `SANDBOX_API_URL`, downloads artifacts, validates SHA-256 digests against `manifest.json`.
- **Deterministic Strace & PCAP Parser**: `backend/app/strace_parser.py`. Parses native and QEMU strace logs, reconstructs multi-threaded syscalls, extracts network events from PCAP via `dpkt`.
- **IoC Normalization**: `backend/app/ioc_extractor.py`. Regex and helper routines for extracting IPv4/URLs/domains.
- **GeoIP Integration**: `backend/app/geoip.py`. Local offline MaxMind GeoLite2-City and GeoLite2-ASN database lookups.
- **Threat Intelligence Client**: `backend/app/malware_bazaar.py`. Queries Abuse.ch MalwareBazaar hash lookup API with memory and optional Redis caching.
- **API Routers**:
  - `backend/app/routers/cases.py`: Case upload, case details retrieval, re-analysis, PDF download.
  - `backend/app/routers/health.py`: Healthcheck endpoint.
  - `backend/app/routers/live.py`: WebSocket live analysis events.

### `agents/`
- **Orchestrator**: `agents/orchestrator/orchestrator.py`. Implements the LangGraph state machine (`StaticAnalysis` -> `DynamicAnalysis` -> `MitreMapper` -> `CapabilityClassifier` -> `NarrativeAgent` -> `InvestigationEngine`).
- **Data Contracts**: `agents/orchestrator/schema.py`. Pydantic models: `StaticAnalysisOutput`, `DynamicAnalysisOutput`, `MitreTechnique`, `CapabilityTag`, `OrchestratorState`.
- **Risk Scoring**: `agents/orchestrator/risk_scoring.py`. Calculates risk score (0-100), threat level, confidence, and rule contributions.
- **MITRE ATT&CK Engine**: `agents/mitre_mapper/mitre_rules.py`. Deterministic rule engine checking static and dynamic indicators to emit `MitreTechnique` instances.
- **Capability Classifier**: `agents/capability_classifier/capability_rules.py`. Deterministic rule engine emitting `CapabilityTag` instances with human-readable evidence.
- **Narrative Agent**: `agents/narrative_agent/narrative.py`. Calls Groq LLM to generate plain-language officer reports; includes whole-word grounding checks and template fallback.
- **Investigation Engine**: `agents/investigation_engine/investigation_engine.py`. Multi-step investigator workflow (`_explain_malware()`, `_explain_victim_impact()`, `_explain_exfiltration()`, `_generate_recommendations()`, `_generate_summary()`).
- **Chain of Custody**: `agents/investigation_engine/chain_verification.py`. Cryptographic HMAC binding of sample SHA-256, task_id, sandbox_id, artifact hashes, and evidence states.

### `sandbox-host/`
- **Standalone Microservice**: Fast execution service meant to run in an isolated Linux VM/host.
- **API Entry Point**: `sandbox-host/app/main.py`. Exposes `/health`, `/canary`, and `/jobs`.
- **Configuration**: `sandbox-host/app/config.py`. Environment variables, paths, supported architectures (`x86_64`, `i386`, `arm`, `aarch64`, `mips`, `mipsel`, `riscv64`, `ppc`).
- **Execution Runner**: `sandbox-host/app/runner.py`. Executes sample natively or via `qemu-<arch>-static` with `strace` and `tcpdump`.
- **Pre-detonation Egress Canary**: `sandbox-host/app/canary.py`. Verifies egress isolation before launching jobs.
- **Provisioning**: `sandbox-host/provision.sh`. Installs host packages and creates bridge interface.

### `static-analysis/`
- **ELF Parser**: `static-analysis/src/static_analysis/elf/parser.py`. Pure-Python ELF32/64 parser (headers, sections, symbols, dynamic entries).
- **String Extractor & Explainer**: `static-analysis/src/static_analysis/strings/service.py` & `explain.py`. Chunked string scanner extracting ASCII/UTF-8/UTF-16 runs and mapping strings to explanations.
- **YARA Engine**: `static-analysis/src/static_analysis/yara/`. Scans files against curated rule sets.
- **Packing & Entropy**: `static-analysis/src/static_analysis/packing/`. Detects packers (UPX) and calculates section entropy.

### `frontend/`
- **UI Framework**: React 19, TypeScript, Vite, Tailwind CSS.
- **Key Views**:
  - `OverviewTab.tsx`: Summary metrics and recent cases.
  - `DynamicSandboxTab.tsx`: Dynamic detonation timeline, network connections, process tree, API calls.
  - `AiReportsTab.tsx`: Dual-language (EN/GU) case analysis view with explanations and recommendations.
  - `reportPdf.tsx`: PDF report layout generator generating multi-page HTML rendered to PDF via html2canvas/jspdf.

### `ingestion/`
- **File Ingestion Gateway**: `ingestion/gateway.py`. Validates magic bytes, checks hash deduplication, stores file uploads.
- **India Scam Triage**: `ingestion/india_scam_triage.py`. Specific rules for regional APK scams.

### `infra/`
- `setup_gcp_vm.sh`: Shell script using `gcloud` CLI to provision a nested virtualization VM for legacy CAPE sandbox.
- `install_kvm_cape.sh`: Script installing KVM/QEMU inside an Ubuntu VM.
