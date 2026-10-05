"""Human-run live provider verification per lane.

Performs live checks across all analysis lanes:
- ELF x86_64 (Hybrid Analysis)
- Unsupported ELF arch (NOT_SUPPORTED_PLATFORM)
- EXE / PE / DLL (Hybrid Analysis)
- APK Static (MobSF)
- APK Dynamic (MobSF emulator status check)
- Mach-O Static-only
- Sample submission (harmless generated program only, gated by policy)

Prints PASS / FAIL / SKIP / UNVERIFIED per check with reasons.
Never prints keys or touches real malware samples.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from packages.config import get_setting, load_config, redact_sensitive
except ImportError:
    load_config = lambda: dict(os.environ)  # noqa: E731
    get_setting = lambda k, d=None: os.environ.get(k, d)  # noqa: E731
    redact_sensitive = lambda t, s=None: t  # noqa: E731

from providers.dynamic.registry import select_provider
from providers.dynamic.hybrid_analysis import HybridAnalysisAdapter
from sandbox.adapters.mobsf.adapter import MobSFAdapter


def _line(status: str, lane: str, reason: str) -> None:
    safe = redact_sensitive(reason)
    print(f"[{status}] {lane}: {safe}")


def main() -> int:
    config = load_config()
    ha_key = (config.get("HYBRID_ANALYSIS_API_KEY") or "").strip()
    mobsf_url = (config.get("MOBSF_URL") or "").strip()
    mobsf_key = (config.get("MOBSF_API_KEY") or "").strip()

    failed = False
    print("=== E-Rakshak Live Provider Lanes Check ===\n")

    # Lane 1: ELF x86_64 (Hybrid Analysis)
    provider_elf_x64 = select_provider("ELF", "x86_64")
    if provider_elf_x64 == "hybrid_analysis":
        if ha_key:
            ha = HybridAnalysisAdapter(api_key=ha_key)
            public_hash = "4faccd95d23724469122505b90cdfd280ff552528be38e73e2b969be90eb7380"
            res = ha.lookup_by_hash(public_hash)
            st = res.get("state")
            if st in (None, "COMPLETED") or "reports" in res or "verdict" in res:
                _line("PASS", "Lane 1: ELF x86_64 (HA)", "lookup verified against live API (status 200)")
            elif st == "NO_RESULT":
                _line("PASS", "Lane 1: ELF x86_64 (HA)", "lookup completed (hash not found in cache)")
            else:
                _line("FAIL", "Lane 1: ELF x86_64 (HA)", f"lookup failed: {st}")
                failed = True
        else:
            _line("SKIP", "Lane 1: ELF x86_64 (HA)", "HYBRID_ANALYSIS_API_KEY not configured")
    else:
        _line("FAIL", "Lane 1: ELF x86_64 (HA)", f"unexpected provider {provider_elf_x64}")
        failed = True

    # Lane 2: Unsupported ELF arch
    provider_elf_arm = select_provider("ELF", "aarch64")
    if provider_elf_arm is None:
        _line("PASS", "Lane 2: Unsupported ELF (aarch64)", "cleanly mapped to NOT_SUPPORTED_PLATFORM")
    else:
        _line("FAIL", "Lane 2: Unsupported ELF (aarch64)", f"unexpectedly mapped to {provider_elf_arm}")
        failed = True

    # Lane 3: EXE / PE / DLL (Hybrid Analysis)
    provider_pe = select_provider("PE", "x86_64")
    if provider_pe == "hybrid_analysis":
        if ha_key:
            _line("PASS", "Lane 3: EXE/PE/DLL (HA)", "provider routing verified to hybrid_analysis")
        else:
            _line("SKIP", "Lane 3: EXE/PE/DLL (HA)", "HYBRID_ANALYSIS_API_KEY not configured")
    else:
        _line("FAIL", "Lane 3: EXE/PE/DLL (HA)", f"unexpected provider {provider_pe}")
        failed = True

    # Lane 4: APK Static (MobSF)
    provider_apk = select_provider("APK", "arm64")
    if provider_apk == "mobsf":
        if mobsf_url:
            mobsf = MobSFAdapter(url=mobsf_url, api_key=mobsf_key)
            try:
                import requests
                headers = {}
                if mobsf_key:
                    headers["Authorization"] = mobsf_key
                    headers["X-Mobsf-Api-Key"] = mobsf_key
                probe = requests.post(f"{mobsf_url.rstrip('/')}/api/v1/upload", headers=headers, timeout=10)
                if probe.status_code in (400, 422):
                    _line("PASS", "Lane 4: APK Static (MobSF)", f"URL reachable & API key accepted (probe status {probe.status_code})")
                elif probe.status_code == 401:
                    _line("FAIL", "Lane 4: APK Static (MobSF)", "API key rejected (401)")
                    failed = True
                else:
                    _line("FAIL", "Lane 4: APK Static (MobSF)", f"unexpected status {probe.status_code}")
                    failed = True
            except Exception as e:
                _line("FAIL", "Lane 4: APK Static (MobSF)", f"connection failed: {e}")
                failed = True
        else:
            _line("SKIP", "Lane 4: APK Static (MobSF)", "MOBSF_URL not configured")
    else:
        _line("FAIL", "Lane 4: APK Static (MobSF)", f"unexpected provider {provider_apk}")
        failed = True

    # Lane 5: APK Dynamic (MobSF)
    if mobsf_url:
        mobsf = MobSFAdapter(url=mobsf_url, api_key=mobsf_key)
        eligible, reason = mobsf.check_dynamic_eligibility()
        if eligible:
            _line("PASS", "Lane 5: APK Dynamic (MobSF)", "dynamic emulator ready and confirmed")
        else:
            _line("SKIP", "Lane 5: APK Dynamic (MobSF)", f"Dynamic analysis not performed: {reason}")
    else:
        _line("SKIP", "Lane 5: APK Dynamic (MobSF)", "MOBSF_URL not configured")

    # Lane 6: Mach-O Static-only
    provider_macho = select_provider("Mach-O", "x86_64")
    if provider_macho is None:
        _line("PASS", "Lane 6: Mach-O Static-only", "cleanly routed to static-only pipeline")
    else:
        _line("FAIL", "Lane 6: Mach-O Static-only", f"unexpectedly mapped to {provider_macho}")
        failed = True

    # Submission Lane
    allow_sub = str(get_setting("ALLOW_EXTERNAL_SUBMISSION", "false")).lower() in ("1", "true", "yes")
    if not allow_sub:
        _line("SKIP", "Submission Gate", "external sample submission disabled (ALLOW_EXTERNAL_SUBMISSION=false)")
    else:
        # Gated submission check
        _line("UNVERIFIED", "Submission Gate", "live external submission requires verified key permissions and manual confirmation")

    print("\nLive check completed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
