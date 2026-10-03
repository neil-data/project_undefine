"""
test_mobsf_dynamic.py
----------------------
Checklist runner for the 5-part MobSF Dynamic Analysis integration.
Imports the real functions from part1..part5 (no placeholder logic
duplicated here) and reports PASS/FAIL per part.

USAGE:
    export MOBSF_URL="http://localhost:8000"
    export MOBSF_API_KEY="your_mobsf_api_key"
    export TEST_APK_PATH="/path/to/sample.apk"
    python test_mobsf_dynamic.py

    # Run a single part only:
    python test_mobsf_dynamic.py --part 3
"""

import os
import argparse

from part1_connectivity import check_connectivity
from part2_upload import run_upload_check
from part3_dynamic_run import run_dynamic_check
from part4_report_adapter import run_report_check
from part5_pipeline import run_pipeline_check

TEST_APK_PATH = os.environ.get("TEST_APK_PATH", "./sample.apk")

RESULTS = []  # (part_number, name, passed, detail)


def record(part, name, passed, detail=""):
    RESULTS.append((part, name, passed, detail))
    print(f"[Part {part}] {name}: {'PASS' if passed else 'FAIL'}" + (f" — {detail}" if detail else ""))


def print_checklist():
    print("\n" + "=" * 60)
    print("MOBSF DYNAMIC LAYER — CHECKLIST")
    print("=" * 60)
    for part, name, ok, _ in RESULTS:
        print(f"{'[x]' if ok else '[ ]'} Part {part}: {name}")
    passed = sum(1 for r in RESULTS if r[2])
    print("-" * 60)
    print(f"{passed}/{len(RESULTS)} parts passing")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--part", type=int, choices=[1, 2, 3, 4, 5], help="run only one part")
    args = parser.parse_args()

    file_hash = None

    if args.part in (None, 1):
        ok, detail = check_connectivity()
        record(1, "Server connectivity / API key valid", ok, detail)

    if args.part in (None, 2):
        ok, detail, file_hash = run_upload_check(TEST_APK_PATH)
        record(2, "Upload APK & get scan hash", ok, detail)

    if args.part in (None, 3):
        ok, detail = run_dynamic_check(file_hash)
        record(3, "Start/stop dynamic analysis", ok, detail)

    if args.part in (None, 4):
        ok, detail, _ = run_report_check(file_hash)
        record(4, "Fetch report & convert to common schema", ok, detail)

    if args.part in (None, 5):
        ok, detail = run_pipeline_check(TEST_APK_PATH)
        record(5, "Orchestrator-callable pipeline function + cleanup", ok, detail)

    print_checklist()


if __name__ == "__main__":
    main()