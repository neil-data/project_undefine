# Provider Response Recording Summary

## Operations Status

| Provider | Operation | Status | File | Reason |
| --- | --- | --- | --- | --- |
| Hybrid Analysis | Lookup (Known hash 1) | SUCCEEDED | `hybrid_analysis/lookup_4faccd95.json` | HTTP 200 |
| Hybrid Analysis | Lookup (Known hash 2) | SUCCEEDED | `hybrid_analysis/lookup_12c9f247.json` | HTTP 200 |
| Hybrid Analysis | Lookup (Random 64-hex hash (expected NO_RESULT)) | SUCCEEDED | `hybrid_analysis/lookup_random_no_result.json` | HTTP 404 |
| Hybrid Analysis | Environment List | SUCCEEDED | `hybrid_analysis/environments.json` | HTTP 200 |
| Hybrid Analysis | Key Info / Quota | SUCCEEDED | `hybrid_analysis/key_current.json` | HTTP 200 |
| Hybrid Analysis | Overview Summary | SUCCEEDED | `hybrid_analysis/overview_summary_4faccd95.json` | HTTP 200 |
| MobSF | Version / About | SKIPPED | `-` | HTTP 401 |
| MobSF | Dynamic Readiness | SKIPPED | `-` | HTTP 401 |
| MobSF | Scan Workflow | FAILED | `-` | APK path does not exist: C:\Users\Neil\Downloads\your-harmless.apk |

## Recorded Files & Top-Level Fields

Top-level field names only; no values or credentials are recorded.

### `hybrid_analysis/environments.json`
- **Top-level fields**: `analysis_mode`, `architecture`, `busy_virtual_machines`, `description`, `environment_id`, `group_icon`, `id`, `invalid_virtual_machines`, `total_virtual_machines`, `virtual_machines`

### `hybrid_analysis/key_current.json`
- **Top-level fields**: `api_key`, `auth_level`, `auth_level_name`, `user`

### `hybrid_analysis/lookup_12c9f247.json`
- **Top-level fields**: `reports`, `sha256s`

### `hybrid_analysis/lookup_4faccd95.json`
- **Top-level fields**: `reports`, `sha256s`

### `hybrid_analysis/lookup_random_no_result.json`
- **Top-level fields**: `message`

### `hybrid_analysis/overview_summary_4faccd95.json`
- **Top-level fields**: `analysis_start_time`, `last_multi_scan`, `multiscan_result`, `sha256`, `submitted_at`, `threat_score`, `verdict`

