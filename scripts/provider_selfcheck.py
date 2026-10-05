"""Offline-safe provider configuration self-check.

Provider operations stay UNVERIFIED until their exact API contracts have been
checked against the relevant official documentation.
"""

import os
import sys


def _line(status, provider, reason):
    print(f"{status} {provider}: {reason}")


def main():
    failed = False
    if os.environ.get("HYBRID_ANALYSIS_API_KEY"):
        _line("PASS", "Hybrid Analysis", "key present (value redacted)")
    else:
        _line("SKIP", "Hybrid Analysis", "API key is not configured")
    _line("UNVERIFIED", "Hybrid Analysis", "key-info, hash lookup, submission permission, and remaining API budget operations are not checked by this Part 0 self-check")

    if os.environ.get("MOBSF_URL"):
        _line("UNVERIFIED", "MobSF", "URL reachability, API-key acceptance, and dynamic analyzer readiness require verification against this installed MobSF version's API routes")
    else:
        _line("SKIP", "MobSF", "MOBSF_URL is not configured")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
