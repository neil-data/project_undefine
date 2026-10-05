# Day 5 preflight

Captured 2026-10-05. `scripts/provider_selfcheck.py` ran without making network
requests and returned exit 0.

| Check | Status | Reason |
| --- | --- | --- |
| Hybrid Analysis runtime key | SKIP | `HYBRID_ANALYSIS_API_KEY` is not configured in the process environment. No key from chat was copied into the environment or sent. |
| Hybrid Analysis auth acceptance | UNVERIFIED | Not attempted without a runtime key; auth contract is not sufficiently verified in Day 4 notes. |
| Hybrid Analysis key restriction/submission permission | UNVERIFIED | No key probe; submit contract not verified. |
| Hybrid Analysis rate-limit response | UNVERIFIED | No provider call made. |
| MobSF URL reachability | SKIP | `MOBSF_URL` is not configured. |
| MobSF API-key acceptance | UNVERIFIED | No URL/key and installed-version routes are unknown. |
| MobSF analyzer readiness | UNVERIFIED | No running MobSF instance to query. |
| Docker/MobSF version | FAIL / BLOCKED | Docker daemon pipe denied access; compose uses floating `latest`; no installed version can be read or pinned safely. |

No provider API calls, APK scans, uploads, or sample submissions were made.
The provided Hybrid Analysis credential is not represented in files or output.
The MobSF image tag is unchanged because a version pin cannot be verified from
a running instance.
