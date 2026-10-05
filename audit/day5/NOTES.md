# Day 5 Provider Notes — Phase 1: Human-Run Scripts & Preflight

## Overview
Implemented human-run scripts and configuration management for Phase 1 of Day 5:
- Centralized configuration loader in `packages/config/loader.py` loading both `.env` and `sandbox/adapters/mobsf/.env`. Never logs secret values.
- Built-in sensitive data redaction for API keys, authorization headers, bearer tokens, and nested structures.
- `scripts/provider_selfcheck.py`: tests HA key presence, documented GET `/search/hash` public hash lookup, MobSF compose tag pinning (WARN on floating tag), MobSF reachability, API key acceptance, version/about, and dynamic readiness. Exits non-zero if nothing is configured or if a configured provider fails.
- `scripts/record_provider_responses.py`: human-run recording script for SHA-256 lookups (with header `User-Agent: Falcon Sandbox`), environments, key info, overview summary, and MobSF upload/scan/report/delete workflow. Redacts all secrets before generating `MANIFEST.sha256` and `RECORDING_SUMMARY.md`.
- `audit/day5/HUMAN_STEPS.md`: step-by-step PowerShell guide for the human operator to pin MobSF tag, run selfcheck, record responses, verify redaction, and commit.
- `tests/test_provider_scripts.py`: mocked HTTP tests for selfcheck, recorder, and redaction logic.

## Single Self-Check Attempt
Executed `scripts/provider_selfcheck.py` once via the config loader:
- Hybrid Analysis API key: Present and loaded via config loader.
- Hybrid Analysis public hash lookup: PASS (HTTP 200).
- MobSF Docker compose pin: WARN (uses floating `latest` tag).
- MobSF reachability: FAIL (connection refused on port 8001; MobSF container restarting due to Django path error on latest image).

## Phase 1 Gate Status
`tests/fixtures/providers/RECORDING_SUMMARY.md` does not yet exist.
Under the Phase 1 Gate rules, Phase 2 starts ONLY after the human runs `audit/day5/HUMAN_STEPS.md`, produces the recorded fixtures, and commits them.
Execution halts at the Phase 1 Gate awaiting human recording.
