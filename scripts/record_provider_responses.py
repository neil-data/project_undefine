"""Human-run script to record real provider responses for offline adapter development.

Lookups send SHA-256 only. Never runs, downloads, or uploads malware.
All auth headers and key materials are redacted before fixtures are written to disk.
Produces:
  tests/fixtures/providers/hybrid_analysis/*.json
  tests/fixtures/providers/mobsf/*.json
  tests/fixtures/providers/MANIFEST.sha256
  tests/fixtures/providers/RECORDING_SUMMARY.md
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from packages.config import get_active_secrets, load_config, redact_sensitive, redact_structure
except ImportError:
    load_config = lambda: dict(os.environ)  # noqa: E731
    get_active_secrets = lambda s=None: []  # noqa: E731
    redact_sensitive = lambda t, s=None: t  # noqa: E731
    redact_structure = lambda d, s=None: d  # noqa: E731


def _save_redacted_json(target_path: Path, data: Any, extra_secrets: list[str] | None = None) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    redacted = redact_structure(data, extra_secrets=extra_secrets)
    text = json.dumps(redacted, indent=2, sort_keys=True)
    clean_text = redact_sensitive(text, extra_secrets=extra_secrets)
    target_path.write_text(clean_text, encoding="utf-8")


def _get_top_level_fields(data: Any) -> list[str]:
    if isinstance(data, dict):
        return sorted(str(k) for k in data.keys())
    elif isinstance(data, list):
        if data and isinstance(data[0], dict):
            return sorted(str(k) for k in data[0].keys())
        return ["<list>"]
    return ["<primitive>"]


def record_responses(output_base: Path, apk_path: str | None = None) -> tuple[list[dict], dict[str, list[str]]]:
    config = load_config()
    ha_key = (config.get("HYBRID_ANALYSIS_API_KEY") or "").strip()
    mobsf_url = (config.get("MOBSF_URL") or "").strip()
    mobsf_key = (config.get("MOBSF_API_KEY") or "").strip()

    extra_secrets = []
    if ha_key:
        extra_secrets.append(ha_key)
    if mobsf_key:
        extra_secrets.append(mobsf_key)

    ha_dir = output_base / "hybrid_analysis"
    mobsf_dir = output_base / "mobsf"

    operations: list[dict] = []
    recorded_files: dict[str, list[str]] = {}

    import requests

    # 1. Hybrid Analysis operations
    if not ha_key:
        operations.append({
            "provider": "Hybrid Analysis",
            "operation": "API Key Check",
            "status": "SKIPPED",
            "reason": "HYBRID_ANALYSIS_API_KEY is not configured",
            "file": "-",
        })
    else:
        ha_headers = {
            "api-key": ha_key,
            "User-Agent": "Falcon Sandbox",
            "accept": "application/json",
        }

        # SHA-256 Lookups
        lookups = [
            ("4faccd95d23724469122505b90cdfd280ff552528be38e73e2b969be90eb7380", "lookup_4faccd95.json", "Known hash 1"),
            ("12c9f247e46d3ee8f3b26c2abe3c545d8dca48886925a646981ed8328c5e8eef", "lookup_12c9f247.json", "Known hash 2"),
            (secrets.token_hex(32), "lookup_random_no_result.json", "Random 64-hex hash (expected NO_RESULT)"),
        ]

        for sha, filename, desc in lookups:
            dest = ha_dir / filename
            rel_name = f"hybrid_analysis/{filename}"
            try:
                url = "https://www.hybrid-analysis.com/api/v2/search/hash"
                resp = requests.get(url, params={"hash": sha}, headers=ha_headers, timeout=15)
                if resp.status_code in (200, 404):
                    try:
                        data = resp.json()
                    except Exception:
                        data = {"raw_text": resp.text}
                    _save_redacted_json(dest, data, extra_secrets=extra_secrets)
                    recorded_files[rel_name] = _get_top_level_fields(data)
                    operations.append({
                        "provider": "Hybrid Analysis",
                        "operation": f"Lookup ({desc})",
                        "status": "SUCCEEDED",
                        "reason": f"HTTP {resp.status_code}",
                        "file": rel_name,
                    })
                elif resp.status_code in (401, 403, 429):
                    try:
                        data = resp.json()
                    except Exception:
                        data = {"error": resp.text, "status_code": resp.status_code}
                    _save_redacted_json(dest, data, extra_secrets=extra_secrets)
                    recorded_files[rel_name] = _get_top_level_fields(data)
                    operations.append({
                        "provider": "Hybrid Analysis",
                        "operation": f"Lookup ({desc})",
                        "status": "FAILED",
                        "reason": f"Naturally occurring HTTP {resp.status_code}",
                        "file": rel_name,
                    })
                else:
                    operations.append({
                        "provider": "Hybrid Analysis",
                        "operation": f"Lookup ({desc})",
                        "status": "FAILED",
                        "reason": f"Unexpected HTTP {resp.status_code}",
                        "file": "-",
                    })
            except Exception as e:
                clean_err = redact_sensitive(str(e), extra_secrets=extra_secrets)
                operations.append({
                    "provider": "Hybrid Analysis",
                    "operation": f"Lookup ({desc})",
                    "status": "FAILED",
                    "reason": f"Network exception: {clean_err}",
                    "file": "-",
                })

        # Documented Environment list
        try:
            env_url = "https://www.hybrid-analysis.com/api/v2/system/environments"
            resp = requests.get(env_url, headers=ha_headers, timeout=15)
            rel_name = "hybrid_analysis/environments.json"
            if resp.status_code == 200:
                data = resp.json()
                _save_redacted_json(ha_dir / "environments.json", data, extra_secrets=extra_secrets)
                recorded_files[rel_name] = _get_top_level_fields(data)
                operations.append({
                    "provider": "Hybrid Analysis",
                    "operation": "Environment List",
                    "status": "SUCCEEDED",
                    "reason": "HTTP 200",
                    "file": rel_name,
                })
            else:
                operations.append({
                    "provider": "Hybrid Analysis",
                    "operation": "Environment List",
                    "status": "SKIPPED",
                    "reason": f"HTTP {resp.status_code} (not permitted or documented for key tier)",
                    "file": "-",
                })
        except Exception as e:
            operations.append({
                "provider": "Hybrid Analysis",
                "operation": "Environment List",
                "status": "FAILED",
                "reason": f"Exception: {redact_sensitive(str(e), extra_secrets=extra_secrets)}",
                "file": "-",
            })

        # Key info / quota check
        try:
            key_url = "https://www.hybrid-analysis.com/api/v2/key/current"
            resp = requests.get(key_url, headers=ha_headers, timeout=15)
            rel_name = "hybrid_analysis/key_current.json"
            if resp.status_code == 200:
                data = resp.json()
                _save_redacted_json(ha_dir / "key_current.json", data, extra_secrets=extra_secrets)
                recorded_files[rel_name] = _get_top_level_fields(data)
                operations.append({
                    "provider": "Hybrid Analysis",
                    "operation": "Key Info / Quota",
                    "status": "SUCCEEDED",
                    "reason": "HTTP 200",
                    "file": rel_name,
                })
            else:
                operations.append({
                    "provider": "Hybrid Analysis",
                    "operation": "Key Info / Quota",
                    "status": "SKIPPED",
                    "reason": f"HTTP {resp.status_code} (endpoint not available for key)",
                    "file": "-",
                })
        except Exception as e:
            operations.append({
                "provider": "Hybrid Analysis",
                "operation": "Key Info / Quota",
                "status": "FAILED",
                "reason": f"Exception: {redact_sensitive(str(e), extra_secrets=extra_secrets)}",
                "file": "-",
            })

        # Overview summary for a hash that has a report
        known_hash_with_report = "4faccd95d23724469122505b90cdfd280ff552528be38e73e2b969be90eb7380"
        try:
            ov_url = f"https://www.hybrid-analysis.com/api/v2/overview/{known_hash_with_report}/summary"
            resp = requests.get(ov_url, headers=ha_headers, timeout=15)
            rel_name = "hybrid_analysis/overview_summary_4faccd95.json"
            if resp.status_code == 200:
                data = resp.json()
                _save_redacted_json(ha_dir / "overview_summary_4faccd95.json", data, extra_secrets=extra_secrets)
                recorded_files[rel_name] = _get_top_level_fields(data)
                operations.append({
                    "provider": "Hybrid Analysis",
                    "operation": "Overview Summary",
                    "status": "SUCCEEDED",
                    "reason": "HTTP 200",
                    "file": rel_name,
                })
            else:
                operations.append({
                    "provider": "Hybrid Analysis",
                    "operation": "Overview Summary",
                    "status": "SKIPPED",
                    "reason": f"HTTP {resp.status_code}",
                    "file": "-",
                })
        except Exception as e:
            operations.append({
                "provider": "Hybrid Analysis",
                "operation": "Overview Summary",
                "status": "FAILED",
                "reason": f"Exception: {redact_sensitive(str(e), extra_secrets=extra_secrets)}",
                "file": "-",
            })

    # 2. MobSF operations
    if not mobsf_url:
        operations.append({
            "provider": "MobSF",
            "operation": "Server Config Check",
            "status": "SKIPPED",
            "reason": "MOBSF_URL is not configured",
            "file": "-",
        })
    else:
        mobsf_headers = {}
        if mobsf_key:
            mobsf_headers["Authorization"] = mobsf_key
            mobsf_headers["X-Mobsf-Api-Key"] = mobsf_key

        # version/about
        try:
            about_url = f"{mobsf_url.rstrip('/')}/api/v1/about"
            resp = requests.get(about_url, headers=mobsf_headers, timeout=10)
            rel_name = "mobsf/about.json"
            if resp.status_code == 200:
                data = resp.json()
                _save_redacted_json(mobsf_dir / "about.json", data, extra_secrets=extra_secrets)
                recorded_files[rel_name] = _get_top_level_fields(data)
                operations.append({
                    "provider": "MobSF",
                    "operation": "Version / About",
                    "status": "SUCCEEDED",
                    "reason": "HTTP 200",
                    "file": rel_name,
                })
            else:
                operations.append({
                    "provider": "MobSF",
                    "operation": "Version / About",
                    "status": "SKIPPED",
                    "reason": f"HTTP {resp.status_code}",
                    "file": "-",
                })
        except Exception as e:
            operations.append({
                "provider": "MobSF",
                "operation": "Version / About",
                "status": "FAILED",
                "reason": f"Exception: {redact_sensitive(str(e), extra_secrets=extra_secrets)}",
                "file": "-",
            })

        # readiness
        try:
            ready_url = f"{mobsf_url.rstrip('/')}/api/v1/dynamic/is_ready"
            resp = requests.get(ready_url, headers=mobsf_headers, timeout=10)
            rel_name = "mobsf/readiness.json"
            if resp.status_code == 200:
                data = resp.json()
                _save_redacted_json(mobsf_dir / "readiness.json", data, extra_secrets=extra_secrets)
                recorded_files[rel_name] = _get_top_level_fields(data)
                operations.append({
                    "provider": "MobSF",
                    "operation": "Dynamic Readiness",
                    "status": "SUCCEEDED",
                    "reason": "HTTP 200",
                    "file": rel_name,
                })
            else:
                operations.append({
                    "provider": "MobSF",
                    "operation": "Dynamic Readiness",
                    "status": "SKIPPED",
                    "reason": f"HTTP {resp.status_code}",
                    "file": "-",
                })
        except Exception as e:
            operations.append({
                "provider": "MobSF",
                "operation": "Dynamic Readiness",
                "status": "FAILED",
                "reason": f"Exception: {redact_sensitive(str(e), extra_secrets=extra_secrets)}",
                "file": "-",
            })

        # APK scan workflow (only with --apk)
        if not apk_path:
            operations.append({
                "provider": "MobSF",
                "operation": "Scan Workflow (upload -> scan -> report -> delete)",
                "status": "SKIPPED",
                "reason": "--apk <path to harmless APK> was not supplied",
                "file": "-",
            })
        else:
            apk_file = Path(apk_path)
            if not apk_file.exists():
                operations.append({
                    "provider": "MobSF",
                    "operation": "Scan Workflow",
                    "status": "FAILED",
                    "reason": f"APK path does not exist: {apk_path}",
                    "file": "-",
                })
            else:
                # Upload
                upload_hash = None
                try:
                    with open(apk_file, "rb") as f:
                        files = {"file": (apk_file.name, f, "application/octet-stream")}
                        upload_url = f"{mobsf_url.rstrip('/')}/api/v1/upload"
                        resp = requests.post(upload_url, files=files, headers=mobsf_headers, timeout=60)
                    rel_name = "mobsf/upload.json"
                    if resp.status_code == 200:
                        data = resp.json()
                        upload_hash = data.get("hash")
                        _save_redacted_json(mobsf_dir / "upload.json", data, extra_secrets=extra_secrets)
                        recorded_files[rel_name] = _get_top_level_fields(data)
                        operations.append({
                            "provider": "MobSF",
                            "operation": "APK Upload",
                            "status": "SUCCEEDED",
                            "reason": "HTTP 200",
                            "file": rel_name,
                        })
                    else:
                        operations.append({
                            "provider": "MobSF",
                            "operation": "APK Upload",
                            "status": "FAILED",
                            "reason": f"HTTP {resp.status_code}: {resp.text[:100]}",
                            "file": "-",
                        })
                except Exception as e:
                    operations.append({
                        "provider": "MobSF",
                        "operation": "APK Upload",
                        "status": "FAILED",
                        "reason": f"Exception: {redact_sensitive(str(e), extra_secrets=extra_secrets)}",
                        "file": "-",
                    })

                # Scan
                if upload_hash:
                    try:
                        scan_url = f"{mobsf_url.rstrip('/')}/api/v1/scan"
                        resp = requests.post(scan_url, data={"hash": upload_hash}, headers=mobsf_headers, timeout=120)
                        rel_name = "mobsf/scan.json"
                        if resp.status_code == 200:
                            data = resp.json()
                            _save_redacted_json(mobsf_dir / "scan.json", data, extra_secrets=extra_secrets)
                            recorded_files[rel_name] = _get_top_level_fields(data)
                            operations.append({
                                "provider": "MobSF",
                                "operation": "APK Scan",
                                "status": "SUCCEEDED",
                                "reason": "HTTP 200",
                                "file": rel_name,
                            })
                        else:
                            operations.append({
                                "provider": "MobSF",
                                "operation": "APK Scan",
                                "status": "FAILED",
                                "reason": f"HTTP {resp.status_code}",
                                "file": "-",
                            })
                    except Exception as e:
                        operations.append({
                            "provider": "MobSF",
                            "operation": "APK Scan",
                            "status": "FAILED",
                            "reason": f"Exception: {redact_sensitive(str(e), extra_secrets=extra_secrets)}",
                            "file": "-",
                        })

                    # Report
                    try:
                        rep_url = f"{mobsf_url.rstrip('/')}/api/v1/report_json"
                        resp = requests.post(rep_url, data={"hash": upload_hash}, headers=mobsf_headers, timeout=60)
                        rel_name = "mobsf/report_json.json"
                        if resp.status_code == 200:
                            data = resp.json()
                            _save_redacted_json(mobsf_dir / "report_json.json", data, extra_secrets=extra_secrets)
                            recorded_files[rel_name] = _get_top_level_fields(data)
                            operations.append({
                                "provider": "MobSF",
                                "operation": "APK Report",
                                "status": "SUCCEEDED",
                                "reason": "HTTP 200",
                                "file": rel_name,
                            })
                        else:
                            operations.append({
                                "provider": "MobSF",
                                "operation": "APK Report",
                                "status": "FAILED",
                                "reason": f"HTTP {resp.status_code}",
                                "file": "-",
                            })
                    except Exception as e:
                        operations.append({
                            "provider": "MobSF",
                            "operation": "APK Report",
                            "status": "FAILED",
                            "reason": f"Exception: {redact_sensitive(str(e), extra_secrets=extra_secrets)}",
                            "file": "-",
                        })

                    # Delete scan
                    try:
                        del_url = f"{mobsf_url.rstrip('/')}/api/v1/delete_scan"
                        resp = requests.post(del_url, data={"hash": upload_hash}, headers=mobsf_headers, timeout=30)
                        rel_name = "mobsf/delete_scan.json"
                        if resp.status_code == 200:
                            data = resp.json()
                            _save_redacted_json(mobsf_dir / "delete_scan.json", data, extra_secrets=extra_secrets)
                            recorded_files[rel_name] = _get_top_level_fields(data)
                            operations.append({
                                "provider": "MobSF",
                                "operation": "APK Scan Deletion",
                                "status": "SUCCEEDED",
                                "reason": "HTTP 200",
                                "file": rel_name,
                            })
                        else:
                            operations.append({
                                "provider": "MobSF",
                                "operation": "APK Scan Deletion",
                                "status": "FAILED",
                                "reason": f"HTTP {resp.status_code}",
                                "file": "-",
                            })
                    except Exception as e:
                        operations.append({
                            "provider": "MobSF",
                            "operation": "APK Scan Deletion",
                            "status": "FAILED",
                            "reason": f"Exception: {redact_sensitive(str(e), extra_secrets=extra_secrets)}",
                            "file": "-",
                        })

    return operations, recorded_files


def generate_manifest_and_summary(output_base: Path, operations: list[dict], recorded_files: dict[str, list[str]]) -> None:
    output_base.mkdir(parents=True, exist_ok=True)

    # 1. MANIFEST.sha256
    manifest_lines = []
    for root, _, files in sorted(os.walk(output_base)):
        for f in sorted(files):
            if f.endswith(".json"):
                f_path = Path(root) / f
                rel_path = f_path.relative_to(output_base).as_posix()
                content = f_path.read_bytes()
                digest = hashlib.sha256(content).hexdigest()
                manifest_lines.append(f"{digest}  {rel_path}")

    manifest_path = output_base / "MANIFEST.sha256"
    manifest_path.write_text("\n".join(manifest_lines) + ("\n" if manifest_lines else ""), encoding="utf-8")

    # 2. RECORDING_SUMMARY.md
    summary_lines = [
        "# Provider Response Recording Summary",
        "",
        "## Operations Status",
        "",
        "| Provider | Operation | Status | File | Reason |",
        "| --- | --- | --- | --- | --- |",
    ]
    for op in operations:
        summary_lines.append(
            f"| {op['provider']} | {op['operation']} | {op['status']} | `{op['file']}` | {op['reason']} |"
        )

    summary_lines.extend([
        "",
        "## Recorded Files & Top-Level Fields",
        "",
        "Top-level field names only; no values or credentials are recorded.",
        "",
    ])

    if not recorded_files:
        summary_lines.append("_No response fixtures were recorded._\n")
    else:
        for file_rel, fields in sorted(recorded_files.items()):
            field_list_str = ", ".join(f"`{f}`" for f in fields)
            summary_lines.append(f"### `{file_rel}`")
            summary_lines.append(f"- **Top-level fields**: {field_list_str}")
            summary_lines.append("")

    summary_path = output_base / "RECORDING_SUMMARY.md"
    summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Record real provider responses for offline testing")
    parser.add_argument("--apk", help="Path to a harmless APK file for MobSF recording (never malware)")
    parser.add_argument(
        "--output-dir",
        default=str(ROOT_DIR / "tests" / "fixtures" / "providers"),
        help="Base directory for provider fixtures",
    )
    args = parser.parse_args()

    output_base = Path(args.output_dir)
    print(f"Recording responses into {output_base}...")
    operations, recorded_files = record_responses(output_base, apk_path=args.apk)
    generate_manifest_and_summary(output_base, operations, recorded_files)

    print("\nOperations summary:")
    for op in operations:
        print(f"[{op['status']}] {op['provider']} - {op['operation']}: {op['reason']}")

    print(f"\nManifest and summary written to {output_base}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
