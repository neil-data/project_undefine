"""
sandbox-host/app/canary.py — Canary external egress check.
Flags failure and locks runner if real public internet is accessible.
"""

import os
import urllib.request
import urllib.error
from . import config

def check_canary_isolation() -> tuple[bool, str]:
    """
    Attempt to reach the canary URL outside the sandbox.
    In a properly isolated malware detonation network, ALL public egress is blocked.
    If connection succeeds, isolation is compromised (canary failure).
    If connection fails/times out, isolation is working as intended.
    """
    if os.environ.get("SIMULATE_CANARY_FAIL") == "1":
        return False, "Canary check failed: egress probe succeeded, sandbox internet isolation compromised!"

    try:
        req = urllib.request.Request(config.CANARY_URL, headers={"User-Agent": "CanaryEgressProbe/1.0"})
        with urllib.request.urlopen(req, timeout=1.5):
            return False, "Canary check failed: egress probe succeeded, sandbox internet isolation compromised!"
    except (urllib.error.URLError, TimeoutError, OSError):
        return True, "Egress isolation verified: public internet unreachable."
