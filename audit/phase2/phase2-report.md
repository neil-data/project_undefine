# Phase 2 Audit Report — IoC, Network Classification & Persistence Truth (Fixes A6–A10)

**Date**: 2026-10-03  
**Status**: **PASS**  
**Target Scope**: Fixes A6 through A10 only (IoC, Network Classification & Persistence Truth).  
**Out of Scope**: A11 through A16, sandbox infrastructure, PDF layout changes, etc. (All untouched).

---

## 1. Executive Summary

Phase 2 addressed network indicator extraction veracity, domain validation, public DNS resolver handling, GeoIP severity reconciliation, proxy-port neutrality, and static persistence path surfacing (A6–A10). Development adhered strictly to the mandatory Test-Driven Development (TDD) cycle:

1. **28 targeted regression tests** were authored in `backend/tests/test_phase2_regression.py` before making production fixes.
2. Baseline test execution against the untouched Phase 1 code confirmed **21 failures and 7 passes** (trace recorded in `audit/phase2/baseline-failures.txt`).
3. Targeted, minimal production changes were applied to:
   - `static-analysis/src/static_analysis/strings/service.py`
   - `backend/app/analysis.py`
   - `backend/app/geoip.py`
   - `agents/mitre_mapper/mitre_rules.py`
   - `agents/capability_classifier/capability_rules.py`
4. Post-fix execution of `test_phase2_regression.py` resulted in **28 passed, 0 failed (100% PASS)**.
5. The combined Phase 1 + Phase 2 regression suite produced **68 passed, 0 failed**.
6. The entire repository test suite (`python -m pytest`) passed with **900 passed, 0 failed, 1 warning** across 115.19s.
7. The isolated `sandbox-host/tests` suite passed with **11 passed, 0 failed**.
8. Frontend typecheck (`tsc --noEmit`) completed with **0 errors**.

---

## 2. Issues Summary Table

| Issue ID | Description | Root Cause | Baseline Failure Count | Status |
| :--- | :--- | :--- | :--- | :--- |
| **A6** | Invalid domain / filename classification (`index.html`, `rc.local`, etc.) | Domain regex matched ordinary file extensions and paths without TLD/extension validation; `analysis.py` rejected 2-letter second-level domains like `.co.uk` and hardcoded `example.com` rejection. | 4 failing tests | **PASS** |
| **A7** | Public DNS resolver (`8.8.8.8`) classified as C2 / high severity | No public DNS resolver allowlist in IoC classification; static presence triggered C2 recommendations and default elevated suspicion. | 2 failing tests | **PASS** |
| **A8** | GeoIP ↔ IoC severity contradiction | `geoip.py` set `threat_level="HIGH"` solely for hosting/proxy ASNs; IoC classification remained `UNKNOWN`, causing direct contradiction. | 3 failing tests | **PASS** |
| **A9** | Proxy-port endpoints (`:3128`, `:8080`, `:8888`) treated as suspicious/C2 | Static URLs with proxy ports were labeled `SUSPICIOUS` by default without corroborating dynamic connections or threat intelligence. | 1 failing test | **PASS** |
| **A10** | Static persistence paths not surfaced | Persistence rules in MITRE and Capability classifier only inspected dynamic artifacts; static strings with cron/init/rc/hidden paths were ignored. | 11 failing tests | **PASS** |

---

## 3. Deep Dive: Bug, Root Cause, Implementation & Verification

### A6 — Invalid Strings Must Not Become Domains
- **Bug**: Strings like `index.html`, `rc.local`, `config.json`, `script.sh`, and filesystem paths (`/path/to/file`, `./index.html`) were extracted as network domains and surfaced in the IoC table and DNS sinkholing recommendations.
- **Root Cause**:
  1. `static-analysis/src/static_analysis/strings/service.py`: `_DOMAIN_PATTERN` matched any word with dots and 2-63 letter endings without checking if the string was preceded/followed by path separators or if the TLD was a common file extension.
  2. `backend/app/analysis.py`: `_is_valid_domain()` lacked `.html`, `.htm`, `.json`, `.js`, `.css` in `_INVALID_DOMAIN_EXTENSIONS`, rejected valid 2-letter second-level domains like `co` in `example.co.uk` due to `len(second_level) < 3`, and had hardcoded rejection of `example.com`.
- **Implementation**:
  - In `service.py`: Defined `_NON_DOMAIN_FILE_EXTENSIONS` and `_is_valid_domain_candidate(candidate, context, start, end)`. Path context (e.g., preceded/followed by `/`, `\`, `@`, `.`) and non-domain file extensions are filtered before creating a `StringType.DOMAIN` record.
  - In `analysis.py`: Added `.html`, `.htm`, `.json`, `.js`, `.css` to `_INVALID_DOMAIN_EXTENSIONS`, relaxed second-level domain length check to `len(second_level) < 2`, rejected paths starting with `./` or `../` or `/`, and removed `example.com` from the rejection set.
- **Verification Tests**:
  - `TestA6DomainValidation::test_a6_index_html_not_a_domain`
  - `TestA6DomainValidation::test_a6_rc_local_not_a_domain`
  - `TestA6DomainValidation::test_a6_filesystem_paths_not_domains`
  - `TestA6DomainValidation::test_a6_common_file_extensions_not_domains`
  - `TestA6DomainValidation::test_a6_legitimate_domains_still_detected` (`example.com`, `sub.example.com`, `example.co.uk`)
  - `TestA6DomainValidation::test_a6_string_extraction_service_does_not_label_index_html_as_domain`

---

### A7 — Public DNS Resolver Must Not Be Classified as C2
- **Bug**: `8.8.8.8` was classified as a suspicious/potential C2 endpoint and included in perimeter firewall blocking recommendations purely because it appeared in static strings.
- **Root Cause**: `backend/app/analysis.py` had no concept of public DNS resolvers in `_build_ioc_intelligence()` or `_generate_recommendations()`, treating hardcoded IP occurrences as candidate C2 connections.
- **Implementation**:
  - Added `_PUBLIC_DNS_RESOLVERS` set containing standard resolver IPs (`8.8.8.8`, `8.8.4.4`, `1.1.1.1`, `1.0.0.1`, `9.9.9.9`, `149.112.112.112`, `208.67.222.222`, `208.67.220.220`, etc.).
  - In `_build_ioc_intelligence()`: When `ip in _PUBLIC_DNS_RESOLVERS` and no dynamic `flagged_c2` exists, classified as `BENIGN` with `related="Public DNS resolver"` and `confidence="LOW"`.
  - In `_generate_recommendations()`: Excluded `_PUBLIC_DNS_RESOLVERS` from `c2_ips` candidate lists so public resolvers are never recommended for firewall perimeter blocking unless corroborated by dynamic runtime C2 activity.
  - Stronger dynamic/intel evidence invariance: If dynamic execution flags `flagged_c2=True` on `8.8.8.8`, the runtime finding takes precedence and correctly marks the connection as `MALICIOUS` with `evidence_state="OBSERVED"`.
- **Verification Tests**:
  - `TestA7PublicDNSResolver::test_a7_8888_recognized_as_public_dns_resolver_in_ioc`
  - `TestA7PublicDNSResolver::test_a7_8888_static_only_not_c2_in_recommendations`
  - `TestA7PublicDNSResolver::test_a7_8888_static_not_high_confidence`
  - `TestA7PublicDNSResolver::test_a7_ordinary_ips_continue_normal_classification`
  - `TestA7PublicDNSResolver::test_a7_dynamic_flagged_evidence_still_represented_for_resolver`

---

### A8 — GeoIP and IoC Severity Must Agree
- **Bug**: GeoIP lookup produced `threat_level="HIGH"` for an IP simply because the ASN belongs to a hosting/proxy provider (e.g. Google Cloud, AWS), while the IoC intelligence table reported the same IP as `UNKNOWN` or `LOW`, creating an internal contradiction.
- **Root Cause**:
  - `backend/app/geoip.py:237`: `_lookup_http_fallback()` set `"threat_level": "HIGH" if data.get("proxy") or data.get("hosting") else "MEDIUM"`.
  - No reconciliation step existed between GeoIP lookup results and the IoC threat intelligence layer.
- **Implementation**:
  - In `geoip.py`: Separated contextual hosting/proxy metadata (`is_hosting`, `is_proxy`) from malicious threat severity. Changed default fallback threat level to `"LOW"`.
  - In `backend/app/analysis.py`: Added `_reconcile_geoip_severity(geo_iocs, ioc_records)`. Matches each GeoIP record to its IoC intelligence record:
    - If IoC is `MALICIOUS` -> GeoIP `threat_level="CRITICAL"` or `"HIGH"`.
    - If IoC is `SUSPICIOUS` -> GeoIP `threat_level="MEDIUM"`.
    - If IoC is `UNKNOWN` or `BENIGN` -> GeoIP `threat_level="LOW"`.
  - Called `_reconcile_geoip_severity()` during case data compilation, ensuring GeoIP and IoC severity never contradict.
- **Verification Tests**:
  - `TestA8GeoIPConsistency::test_a8_geoip_hosting_context_alone_not_high`
  - `TestA8GeoIPConsistency::test_a8_geoip_and_ioc_severity_consistent`
  - `TestA8GeoIPConsistency::test_a8_genuine_malicious_intelligence_produces_high_severity`

---

### A9 — Proxy Ports Must Be Neutral Hardcoded Endpoints
- **Bug**: Ports commonly associated with proxy services (`3128`, `8080`, `8888`) caused endpoints like `http://1.2.3.4:8080` to be marked `SUSPICIOUS` by default.
- **Root Cause**: In `_build_ioc_intelligence()`, any static URL not matching `_is_benign_domain()` was assigned `classification="SUSPICIOUS"`.
- **Implementation**:
  - Defined `_NEUTRAL_PROXY_PORTS = {3128, 8080, 8888}`.
  - In `_build_ioc_intelligence()`: When a URL contains a proxy port without dynamic C2 or threat intel corroboration, it is classified as `UNKNOWN` (neutral) with `related="Hardcoded endpoint"`, `confidence="LOW"`, and `evidence_state="STATIC"`.
  - Maintained capability and MITRE rules such that proxy ports alone do not generate `c2_communication` capability.
  - Stronger evidence invariance: If dynamic execution observes beaconing or flagged C2 to port 8080, `c2_communication` capability is triggered with `evidence_state="OBSERVED"`.
- **Verification Tests**:
  - `TestA9ProxyPortsNeutral::test_a9_proxy_ports_static_only_neutral_endpoint`
  - `TestA9ProxyPortsNeutral::test_a9_proxy_ports_alone_do_not_produce_c2_capability`
  - `TestA9ProxyPortsNeutral::test_a9_dynamic_flagged_can_still_elevate_proxy_port`

---

### A10 — Static Persistence Paths Must Be Surfaced
- **Bug**: Persistence indicators found in static strings (such as `/etc/cron.d/qv3b`, `/etc/init.d/qv3b`, `/etc/rc%d.d/S90qv3b`, `/tmp/.qv3b`, `/var/run/.qv3b`, `/usr/lib/.qv3b`) were ignored when dynamic analysis was unavailable.
- **Root Cause**:
  - `mitre_rules.py` (`_rule_init_persistence`, `_rule_hidden_files`) checked only `dynamic.files_written` or `dynamic.persistence_artifacts`, returning `None` if `dynamic` was unavailable.
  - `capability_rules.py` (`_cap_persistence_init`, `_cap_cron_persistence`) returned `None` if dynamic execution was absent.
  - `analysis.py` had no static persistence path extractor.
- **Implementation**:
  - In `backend/app/analysis.py`:
    - Defined pattern regexes `_PERSISTENCE_PATH_PATTERNS` matching:
      - Cron directories and files (`/etc/cron*`, `/var/spool/cron/*`, `/etc/crontab`)
      - Init scripts (`/etc/init.d/*`)
      - Runlevel scripts (`/etc/rc[0-6S%d*]*\.d/*`, `/etc/rc.local`)
      - Systemd services (`/etc/systemd/system/*`)
      - Hidden temporary files and payloads (`/tmp/\..*`, `/var/tmp/\..*`)
      - Runtime payload paths (`/var/run/\..*`, `/run/\..*`)
      - Hidden library paths (`/usr/lib/\..*`, `/usr/local/lib/\..*`)
    - Implemented `_is_persistence_path(path: str) -> bool`.
    - Implemented `_extract_persistence_artifacts(raw_static, dynamic_output) -> list[dict]`:
      - Dynamic artifacts receive `evidence_state="OBSERVED"`.
      - Static artifacts receive `evidence_state="STATIC"`.
    - Surfaced unified artifacts in `case_data["persistence_artifacts"]` and `case_data["persistence_artifacts_details"]`.
  - In `agents/mitre_mapper/mitre_rules.py`:
    - Extended `_rule_cron_persistence` to emit `T1053.003` with `evidence_state="STATIC"` for static cron paths.
    - Extended `_rule_init_persistence` to emit `T1037` / `T1543.002` with `evidence_state="STATIC"` for static init/rc.d/systemd paths.
    - Extended `_rule_hidden_files` to emit `T1564.001` with `evidence_state="STATIC"` for static hidden dotfile paths in system directories.
  - In `agents/capability_classifier/capability_rules.py`:
    - Extended `_cap_cron_persistence` to emit `persistence_cron` with `evidence_state="STATIC"` for static cron paths.
    - Extended `_cap_persistence_init` to emit `persistence_init` with `evidence_state="STATIC"` for static startup paths.
    - Extended `_cap_persistence` to emit `persistence` with `evidence_state="STATIC"` for static hidden payloads in `/tmp/.*`, `/var/run/.*`, etc.
- **Verification Tests**:
  - `TestA10StaticPersistencePaths::test_a10_known_persistence_paths_detected` (for all 6 known paths: `/etc/cron.d/qv3b`, `/etc/init.d/qv3b`, `/etc/rc%d.d/S90qv3b`, `/tmp/.qv3b`, `/var/run/.qv3b`, `/usr/lib/.qv3b`)
  - `TestA10StaticPersistencePaths::test_a10_ordinary_paths_not_detected_as_persistence`
  - `TestA10StaticPersistencePaths::test_a10_static_persistence_surfaced_in_case_data`
  - `TestA10StaticPersistencePaths::test_a10_static_persistence_does_not_become_observed`
  - `TestA10StaticPersistencePaths::test_a10_dynamic_persistence_remains_observed`
  - `TestA10StaticPersistencePaths::test_a10_mitre_and_capabilities_surface_static_persistence`

---

## 4. Test Summary

```text
Phase 2 regression tests BEFORE fixes:
PASS: 7
FAIL: 21
ERROR: 0

Phase 2 regression tests AFTER fixes:
PASS: 28
FAIL: 0
ERROR: 0

Full Python suite (pytest):
PASS: 900
FAIL: 0
ERROR: 0
SKIPPED: 0
(1 deprecation warning from starlette.testclient in venv)

Sandbox-host suite:
PASS: 11
FAIL: 0
ERROR: 0

Frontend lint (tsc --noEmit):
PASS (0 errors)
```

**New regression tests added in Phase 2**: **28 tests** (located in `backend/tests/test_phase2_regression.py`).

---

## 5. Scope Invariance Verification

1. **No malware binaries added**: `git status` confirms no binaries added to Git.
2. **Phase 0 & Phase 1 preserved**: `audit/phase0/` and `audit/phase1/phase1-report.md` are completely untouched.
3. **No A11–A16 modifications**: No changes were made to dynamic failure duration handling (A11), recommendation deduplication (A12), timeline presentation (A13), PDF layout/footer (A14), malware family naming (A15), or GeoIP unconfigured notice (A16).
4. **No sandbox host infrastructure modified**: `sandbox-host/app/` and provisioning scripts were not modified.
5. **Git diff stat**:
```
 agents/capability_classifier/capability_rules.py   | 122 +++++++---
 .../investigation_engine/investigation_engine.py   |  55 ++++-
 agents/mitre_mapper/mitre_rules.py                 |  47 ++--
 agents/narrative_agent/narrative.py                |  48 +++-
 agents/orchestrator/risk_scoring.py                |  51 ++++-
 agents/orchestrator/schema.py                      |   1 +
 backend/app/analysis.py                            | 251 ++++++++++++++++++---
 backend/app/geoip.py                               |   2 +-
 backend/tests/test_evidence_correlation.py         |   4 +-
 .../src/static_analysis/strings/service.py         |  42 ++++
 10 files changed, 513 insertions(+), 110 deletions(-)
```

---

## 6. Stop Condition Compliance

Phase 2 (A6–A10) is fully implemented, demonstrated by baseline failure evidence, verified with 100% passing tests across all test suites, and audited.

**Execution is halted. Ready for Phase 3 upon user instruction.**
