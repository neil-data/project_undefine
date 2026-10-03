"""
part2_upload.py
----------------
PART 2: Upload & Static Trigger

Uploads the APK to MobSF and gets back the scan hash used by every
later step.
"""

import os
import requests
from part1_connectivity import MOBSF_URL, HEADERS


def upload_apk(apk_path):
    """Uploads apk_path to MobSF. Returns MobSF's JSON response (contains 'hash')."""
    with open(apk_path, "rb") as f:
        files = {"file": (os.path.basename(apk_path), f, "application/octet-stream")}
        resp = requests.post(f"{MOBSF_URL}/api/v1/upload", headers=HEADERS, files=files, timeout=60)
    resp.raise_for_status()
    return resp.json()


def run_upload_check(apk_path):
    """
    Returns (passed: bool, detail: str, file_hash: str|None)
    """
    if not os.path.exists(apk_path):
        return False, f"test APK not found at {apk_path}", None
    try:
        data = upload_apk(apk_path)
        file_hash = data.get("hash")
        if file_hash:
            return True, f"hash={file_hash}", file_hash
        return False, f"no hash in response: {data}", None
    except Exception as e:
        return False, f"error: {e}", None


if __name__ == "__main__":
    apk = os.environ.get("TEST_APK_PATH", "./sample.apk")
    ok, detail, file_hash = run_upload_check(apk)
    print(f"Part 2 - Upload: {'PASS' if ok else 'FAIL'} — {detail}")