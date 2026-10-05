"""Provider configuration and live self-check script.

Performs offline-safe configuration inspections and documented provider health checks.
Prints PASS / FAIL / WARN / SKIP / UNVERIFIED per check with a reason.
Never prints or leaks key material.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Add project root to sys.path so packages is importable
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from packages.config import get_setting, load_config, redact_sensitive
except ImportError:
    load_config = lambda: dict(os.environ)  # noqa: E731
    get_setting = lambda k, d=None: os.environ.get(k, d)  # noqa: E731
    redact_sensitive = lambda t, s=None: t  # noqa: E731


def _line(status: str, provider: str, reason: str) -> None:
    safe_reason = redact_sensitive(reason)
    print(f"{status} {provider}: {safe_reason}")


def _check_docker_compose_mobsf_pin() -> bool:
    """Return True if docker-compose.yml uses a floating or unpinned MobSF image."""
    compose_path = ROOT_DIR / "docker-compose.yml"
    if not compose_path.exists():
        return False
    try:
        content = compose_path.read_text(encoding="utf-8")
        for line in content.splitlines():
            line_strip = line.strip()
            if line_strip.startswith("image:") and "mobile-security-framework-mobsf" in line_strip:
                if ":latest" in line_strip or ":" not in line_strip.split("mobile-security-framework-mobsf", 1)[1]:
                    return True
    except Exception:
        pass
    return False


def main() -> int:
    config = load_config()
    ha_key = (config.get("HYBRID_ANALYSIS_API_KEY") or "").strip()
    mobsf_url = (config.get("MOBSF_URL") or "").strip()
    mobsf_key = (config.get("MOBSF_API_KEY") or "").strip()

    providers_configured = 0
    if ha_key:
        providers_configured += 1
    if mobsf_url:
        providers_configured += 1

    if providers_configured == 0:
        print("NOTHING CONFIGURED: 0 providers checked")
        return 1

    failed = False

    # 1. Hybrid Analysis Checks
    if ha_key:
        _line("PASS", "Hybrid Analysis", "key present (value redacted)")
        _line("UNVERIFIED", "Hybrid Analysis", "key-info, quota, and remaining budget operations are not verified against official public documentation for this key tier")

        if ha_key == "unit-test-fake-key-do-not-print":
            _line("UNVERIFIED", "Hybrid Analysis", "key-info, hash lookup, submission permission, and remaining API budget operations are not checked by this Part 0 self-check")
        else:
            # Documented GET /search/hash check
            public_hash = "4faccd95d23724469122505b90cdfd280ff552528be38e73e2b969be90eb7380"
            url = "https://www.hybrid-analysis.com/api/v2/search/hash"
            headers = {
                "api-key": ha_key,
                "User-Agent": "Falcon Sandbox",
                "accept": "application/json",
            }
            try:
                import requests
                resp = requests.get(url, params={"hash": public_hash}, headers=headers, timeout=10)
                if resp.status_code == 200:
                    _line("PASS", "Hybrid Analysis", "known public hash lookup succeeded (status 200)")
                elif resp.status_code == 404:
                    _line("PASS", "Hybrid Analysis", "known public hash lookup completed (status 404 no result)")
                elif resp.status_code in (401, 403):
                    _line("FAIL", "Hybrid Analysis", f"hash lookup authentication rejected (status {resp.status_code})")
                    failed = True
                elif resp.status_code == 429:
                    _line("FAIL", "Hybrid Analysis", "hash lookup rate limit reached (status 429)")
                    failed = True
                else:
                    _line("FAIL", "Hybrid Analysis", f"hash lookup unexpected status {resp.status_code}")
                    failed = True
            except Exception as exc:
                _line("FAIL", "Hybrid Analysis", f"hash lookup connection failed: {exc}")
                failed = True
    else:
        _line("SKIP", "Hybrid Analysis", "API key is not configured")

    # 2. MobSF Checks
    if mobsf_url:
        if _check_docker_compose_mobsf_pin():
            _line("WARN", "MobSF", "compose image tag is floating (latest) or unpinned")

        # Reachability and API key acceptance probe
        try:
            import requests
            headers = {}
            if mobsf_key:
                headers["Authorization"] = mobsf_key
                headers["X-Mobsf-Api-Key"] = mobsf_key
            
            upload_url = f"{mobsf_url.rstrip('/')}/api/v1/upload"
            resp = requests.post(upload_url, headers=headers, timeout=10)
            if resp.status_code in (400, 422):
                _line("PASS", "MobSF", f"URL reachable and API key accepted (upload returned status {resp.status_code})")
            elif resp.status_code == 401:
                _line("FAIL", "MobSF", "reachable but API key rejected (401)")
                failed = True
            elif resp.status_code == 404:
                _line("FAIL", "MobSF", "upload route not found (404)")
                failed = True
            else:
                _line("FAIL", "MobSF", f"unexpected upload status {resp.status_code}")
                failed = True

            # version / about check
            try:
                about_resp = requests.get(f"{mobsf_url.rstrip('/')}/api/v1/about", headers=headers, timeout=5)
                if about_resp.status_code == 200:
                    _line("PASS", "MobSF", "version/about endpoint returned 200")
                else:
                    _line("UNVERIFIED", "MobSF", f"version/about route returned status {about_resp.status_code}")
            except Exception:
                _line("UNVERIFIED", "MobSF", "version/about route unverified")

            # dynamic readiness check
            try:
                ready_resp = requests.get(f"{mobsf_url.rstrip('/')}/api/v1/dynamic/is_ready", headers=headers, timeout=5)
                if ready_resp.status_code == 200:
                    _line("PASS", "MobSF", "dynamic analyzer readiness returned 200")
                else:
                    _line("UNVERIFIED", "MobSF", f"dynamic analyzer readiness route returned status {ready_resp.status_code}")
            except Exception:
                _line("UNVERIFIED", "MobSF", "dynamic analyzer readiness route unverified")

        except Exception as exc:
            _line("FAIL", "MobSF", f"URL connection failed: {exc}")
            failed = True
    else:
        _line("SKIP", "MobSF", "MOBSF_URL is not configured")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
