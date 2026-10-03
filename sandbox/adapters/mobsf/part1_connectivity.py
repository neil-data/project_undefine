"""
part1_connectivity.py
----------------------
PART 1: MobSF Server Setup & Connectivity

Holds shared config (URL, API key, headers) used by all other parts,
plus the connectivity/auth check.
"""

import os
import requests

MOBSF_URL = os.environ.get("MOBSF_URL", "http://localhost:8000")
MOBSF_API_KEY = os.environ.get("MOBSF_API_KEY", "")
HEADERS = {
    "Authorization": MOBSF_API_KEY,
    "X-Mobsf-Api-Key": MOBSF_API_KEY,
}


def check_connectivity():
    """
    Returns (passed: bool, detail: str)
    /api/v1/scans is not a stable route across MobSF versions, so instead
    we POST to /api/v1/upload with no file attached. MobSF checks auth
    before checking the file, so the response tells us what we need:
      - 401            -> reachable, but API key rejected
      - 400/422        -> reachable AND API key accepted (just missing file, expected)
      - anything else  -> unexpected, investigate
    """
    try:
        resp = requests.post(f"{MOBSF_URL}/api/v1/upload", headers=HEADERS, timeout=10)
        if resp.status_code in (400, 422):
            return True, f"reachable, API key accepted (status {resp.status_code}, missing file as expected)"
        elif resp.status_code == 401:
            return False, "server reachable but API key rejected (401)"
        elif resp.status_code == 404:
            return False, "404 — /api/v1/upload not found, check MOBSF_URL and that the server is actually up"
        else:
            return False, f"unexpected status {resp.status_code}: {resp.text[:200]}"
    except requests.exceptions.RequestException as e:
        return False, f"connection error: {e}"


if __name__ == "__main__":
    ok, detail = check_connectivity()
    print(f"Part 1 - Connectivity: {'PASS' if ok else 'FAIL'} — {detail}")