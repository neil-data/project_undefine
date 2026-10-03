"""
part5_pipeline.py
-------------------
PART 5: Cleanup, Error Handling & Orchestrator Hook

The single function the Static Analysis Orchestrator should call.
Wraps Parts 2-4 with error handling and always attempts cleanup.
"""

import os
import time
import requests
from part1_connectivity import MOBSF_URL, HEADERS
from part2_upload import upload_apk
from part3_dynamic_run import start_dynamic, stop_dynamic
from part4_report_adapter import get_dynamic_report, convert_to_common_schema


def delete_scan(file_hash):
    resp = requests.post(f"{MOBSF_URL}/api/v1/delete_scan", headers=HEADERS, data={"hash": file_hash}, timeout=30)
    return resp.status_code == 200


def run_mobsf_dynamic_pipeline(apk_path):
    """
    Orchestrator entrypoint. Always returns a dict — either the converted
    schema result, or {"error": "..."} — and always attempts cleanup.
    """
    file_hash = None
    try:
        data = upload_apk(apk_path)
        file_hash = data.get("hash")
        if not file_hash:
            raise RuntimeError("upload succeeded but no hash returned")
        start_dynamic(file_hash)
        time.sleep(30)
        stop_dynamic(file_hash)
        report = get_dynamic_report(file_hash)
        return convert_to_common_schema(report)
    except Exception as e:
        return {"tool": "MobSF", "scan_type": "dynamic", "error": str(e)}
    finally:
        if file_hash:
            try:
                delete_scan(file_hash)
            except Exception:
                pass  # cleanup best-effort, don't mask the original result


def run_pipeline_check(apk_path):
    """
    Returns (passed: bool, detail: str)
    """
    if not os.path.exists(apk_path):
        return False, f"test APK not found at {apk_path}"
    try:
        result = run_mobsf_dynamic_pipeline(apk_path)
        if "error" in result:
            return False, f"pipeline returned error: {result['error']}"
        return True, "pipeline returned converted result, cleanup attempted"
    except Exception as e:
        return False, f"unhandled exception (should have been caught!): {e}"


if __name__ == "__main__":
    apk = os.environ.get("TEST_APK_PATH", "./sample.apk")
    ok, detail = run_pipeline_check(apk)
    print(f"Part 5 - Orchestrator pipeline: {'PASS' if ok else 'FAIL'} — {detail}")