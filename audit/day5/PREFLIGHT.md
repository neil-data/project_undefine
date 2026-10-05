# Day 5 Preflight & Self-Check Status

Captured 2026-10-05. `scripts/provider_selfcheck.py` executed once through the app's config loader.
No secret values or key materials were logged, printed, or written to disk.

| Provider / Check | Status | Reason |
| --- | --- | --- |
| Hybrid Analysis runtime key | PASS | `HYBRID_ANALYSIS_API_KEY` is present and loaded via config loader (value redacted). |
| Hybrid Analysis hash lookup | PASS | Documented GET `https://www.hybrid-analysis.com/api/v2/search/hash` returned HTTP 200 for public hash `4faccd95...`. |
| Hybrid Analysis key-info / quota | UNVERIFIED | Not officially verified against public documentation for this key tier; undocumented endpoints are not guessed. |
| Hybrid Analysis submit permission | UNVERIFIED | No live sample submitted; external submission requires verified key permissions. |
| MobSF Docker image pin | WARN | `docker-compose.yml` specifies floating/unpinned tag `opensecurity/mobile-security-framework-mobsf:latest`. |
| MobSF URL reachability | FAIL | Connection actively refused at configured URL (`http://localhost:8001`). MobSF container in crash-loop (`DWD_DIR` posixpath issue on `latest` image). |
| MobSF API key acceptance | FAIL | Unreachable host; could not probe `/api/v1/upload`. |
| MobSF version / about | UNVERIFIED | Unreachable host. |
| MobSF dynamic analyzer readiness | UNVERIFIED | Unreachable host. |

## Actions required
See `audit/day5/HUMAN_STEPS.md` for exact PowerShell steps:
1. Pin the MobSF Docker tag in `docker-compose.yml` (replacing `latest`) and restart the container.
2. Run `python scripts/provider_selfcheck.py` to confirm MobSF passes.
3. Run `python scripts/record_provider_responses.py` (with `--apk` if testing MobSF).
4. Run secrets check and commit the recordings to proceed past the Phase 2 GATE.
