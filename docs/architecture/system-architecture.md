# E-Rakshak v4.1 — System Architecture & Data Flow

## 1. System Overview

**E-Rakshak** is a multi-modal malware analysis and threat intelligence platform designed to automate the triage, deep inspection, behavioral execution, and reporting of suspicious executables and applications across Windows (PE), Linux (ELF), and Android (APK).

The platform couples high-throughput static extraction, hypervisor-managed dynamic sandboxing, automated memory forensics, ATT&CK matrix correlation, threat intelligence enrichment, and automated narrative reporting into an integrated, tamper-evident pipeline.

---

## 2. High-Level Architecture Diagram

```
+----------------------------------------------------------------------------------------------------+
|                                         MALWARE SAMPLES                                            |
|                                    [ PE (.exe) / ELF / APK ]                                       |
+-------------------------------------------------+--------------------------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
|                                    1. INGESTION & TRIAGE GATEWAY                                   |
|   - File validation & magic byte verification                                                      |
|   - Cryptographic hashing (MD5, SHA-1, SHA-256, SSDEEP)                                            |
|   - India scam triage & targeted threat categorization                                             |
|   - Evidence-sample binding & manifest generation (HMAC-SHA256)                                    |
+-------------------------------------------------+--------------------------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
|                                        2. MULTI-MODAL ANALYSIS                                     |
|                                                                                                    |
|  +---------------------------+  +-------------------------------+  +----------------------------+  |
|  |      STATIC ANALYSIS      |  |        DYNAMIC SANDBOX        |  |      MEMORY FORENSICS      |  |
|  | - PE/ELF/APK parsing      |  | - QEMU/KVM hypervisor runner  |  | - Memory dump acquisition  |  |
|  | - Section entropy & crypto|  | - MobSF adapter (Android)     |  | - Volatility analysis      |  |
|  | - String & IoC extraction |  | - Syscall & API hook tracing  |  | - Process injection checks |  |
|  | - YARA multi-rule scanner |  | - Network PCAP & DNS captures |  | - Hidden module detection  |  |
|  +---------------------------+  +-------------------------------+  +----------------------------+  |
+-------------------------------------------------+--------------------------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
|                                   3. CORRELATION & RISK SCORING                                    |
|   - MITRE ATT&CK mapping & tactic classification                                                   |
|   - Malware capability classification (Ransomware, Spyware, Dropper, Botnet, C2)                   |
|   - Investigation engine & evidence-chain verification                                             |
|   - Weighted composite risk scoring algorithm                                                      |
+-------------------------------------------------+--------------------------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
|                                       4. NARRATIVE GENERATION                                      |
|   - Threat narrative synthesis (Executive, Technical, Detection, Containment)                      |
|   - IoC classification, normalization & deduplication                                             |
|   - Confidence scoring & defense recommendation mapping                                            |
+-------------------------------------------------+--------------------------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
|                                     5. THREAT INTELLIGENCE                                         |
|   - Multi-provider feed lookup (AlienVault OTX, VirusTotal, AbuseIPDB, CIRCL)                      |
|   - Autonomous fallback & mock provider resilience under offline/timeout scenarios                 |
|   - GeoIP enrichment (City, Country, ASN, ISP) & endpoint classification                          |
+-------------------------------------------------+--------------------------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
|                                    6. REPORT GENERATION ENGINE                                     |
|   - Authoritative JSON report compilation                                                          |
|   - High-fidelity PDF report generation (ReportLab, tables, vector risk gauges)                     |
|   - Cryptographic report signature & evidence tamper verification                                  |
+-------------------------------------------------+--------------------------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
|                                    7. APIS & PRESENTATION LAYER                                    |
|   - FastAPI Backend (`apps/backend/app/main.py`)                                                   |
|   - Interactive React/Vite Dashboard (`apps/frontend/`)                                            |
|   - Real-time SSE / WebSocket sample monitoring & network relationship graph                       |
+----------------------------------------------------------------------------------------------------+
```

---

## 3. End-to-End Data Flow

1. **Submission & Ingestion**:
   A sample (`.exe`, ELF binary, or `.apk`) is submitted through the API gateway (`apps/ingestion/`). The file format is validated against magic bytes, normalized cryptographic hashes are computed, and a tamper-resistant evidence manifest is created.

2. **Parallel Analysis Execution**:
   - **Static Analysis** (`analysis/static/`): Headers, imported functions, exported symbols, sections, and embedded strings are extracted. File entropy is calculated per section. YARA rules (`analysis/rules/yara/`) are executed against the payload.
   - **Dynamic Execution** (`analysis/dynamic/` & `sandbox/host/`): The binary is dispatched to a locked-down virtual machine (QEMU/KVM for PE/ELF, MobSF for APK). Guest canaries verify hypervisor health, execution is monitored, network traffic is captured, and behavioral logs are collected.
   - **Memory Forensics** (`analysis/memory/`): In-memory artifacts are inspected for unbacked code, hollowed processes, and injected shellcode.

3. **Correlation & Threat Intelligence**:
   - Extracted indicators and behavioral artifacts are fed into the correlation engine (`analysis/correlation/`).
   - MITRE ATT&CK techniques are matched against known threat behaviors (`analysis/rules/mitre/`).
   - Discovered IPs and domains are queried across threat intelligence feeds (`analysis/threat_intel/`) and geolocated with fallback providers.

4. **Scoring & Narrative Synthesis**:
   - The risk engine (`analysis/scoring/`) calculates a composite threat score (0–100) based on static indicators, dynamic behavior, and MITRE mapping.
   - The narrative agent generates human-readable incident summaries and remediation steps.
   - The chain verification engine confirms that every finding has a verifiable evidentiary root.

5. **Reporting & UI Delivery**:
   - Machine-readable JSON reports and professional multi-page PDF documents are compiled and stored in `reports/`.
   - The FastAPI backend serves reports, metrics, and incident streams to the React dashboard (`apps/frontend/`).

---

## 4. Repository Layout Mapping

The architecture directly mirrors the monorepo directory layout:

| Architectural Component | Monorepo Directory |
|---|---|
| Ingestion & Gateway | `apps/ingestion/` |
| Core Backend & API | `apps/backend/` |
| Analyst Web Dashboard | `apps/frontend/` |
| Static Analysis Engine | `analysis/static/` |
| Dynamic Analysis Hooks | `analysis/dynamic/` |
| Memory Forensics Engine | `analysis/memory/` |
| Correlation & Investigation | `analysis/correlation/` |
| Scoring & Narrative Agent | `analysis/scoring/` |
| Detection Rules (YARA/MITRE) | `analysis/rules/` |
| Threat Intel & GeoIP | `analysis/threat_intel/` |
| Hypervisor Sandbox Runner | `sandbox/host/` |
| External Sandbox Adapters | `sandbox/adapters/` |
| Database & Case Schemas | `data/schemas/` |
| Reports & Generated Artifacts | `reports/` |
