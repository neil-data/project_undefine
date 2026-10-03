"""
part3_dynamic_run.py
----------------------
PART 3: Dynamic Analysis Execution

Starts the MobSF dynamic analyzer (emulator/device), lets the app run,
then stops it.
"""

import time
import requests
from part1_connectivity import MOBSF_URL, HEADERS


def start_dynamic(file_hash):
    resp = requests.post(
        f"{MOBSF_URL}/api/v1/dynamic/start_analysis",
        headers=HEADERS,
        data={"hash": file_hash},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def stop_dynamic(file_hash):
    resp = requests.post(
        f"{MOBSF_URL}/api/v1/dynamic/stop_analysis",
        headers=HEADERS,
        data={"hash": file_hash},
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()


def run_dynamic_check(file_hash, run_seconds=30):
    """
    Returns (passed: bool, detail: str)
    """
    if not file_hash:
        return False, "skipped — no file hash from Part 2"
    try:
        start_dynamic(file_hash)
        time.sleep(run_seconds)  # let the app run inside the emulator
        stop_result = stop_dynamic(file_hash)
        return True, f"ran {run_seconds}s, stop_result keys={list(stop_result.keys())}"
    except Exception as e:
        return False, f"error: {e}"


if __name__ == "__main__":
    import sys
    test_hash = sys.argv[1] if len(sys.argv) > 1 else None
    ok, detail = run_dynamic_check(test_hash)
    print(f"Part 3 - Dynamic run: {'PASS' if ok else 'FAIL'} — {detail}")