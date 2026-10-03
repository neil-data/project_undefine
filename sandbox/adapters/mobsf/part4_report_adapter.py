"""
part4_report_adapter.py
--------------------------
PART 4: Report Retrieval & Adapter Conversion

Pulls the dynamic analysis report JSON from MobSF and converts it into
the common schema used by the Adapter Layer (same shape as CAPE/LiSa/
macOS adapters should produce).
"""

import requests
from part1_connectivity import MOBSF_URL, HEADERS


def get_dynamic_report(file_hash):
    resp = requests.post(
        f"{MOBSF_URL}/api/v1/dynamic/report_json",
        headers=HEADERS,
        data={"hash": file_hash},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def convert_to_common_schema(mobsf_report):
    """
    Convert MobSF report to common schema aligned with DynamicAnalysisOutput.
    
    This aligns with the orchestrator schema in agents/orchestrator/schema.py:
    - sample_id: str
    - process_tree: list[dict]
    - api_calls: list[str]
    - network_connections: list[dict]
    - files_written: list[str]
    - registry_changes: list[str]
    - persistence_artifacts: list[str]
    - c2_endpoints_detected: list[str]
    """
    # Extract process information from MobSF report
    process_tree = []
    if "processes" in mobsf_report:
        for proc in mobsf_report.get("processes", []):
            process_tree.append({
                "pid": proc.get("pid"),
                "name": proc.get("name"),
                "parent_pid": proc.get("parent_pid"),
                "cmdline": proc.get("cmdline"),
            })
    
    # Extract API calls
    api_calls = []
    if "api_calls" in mobsf_report:
        api_calls = [call.get("api_name", "") for call in mobsf_report.get("api_calls", [])]
    
    # Extract network connections
    network_connections = []
    if "network_traffic" in mobsf_report:
        for conn in mobsf_report.get("network_traffic", []):
            network_connections.append({
                "dst_ip": conn.get("dst_ip"),
                "dst_port": conn.get("dst_port"),
                "protocol": conn.get("protocol"),
                "bytes_sent": conn.get("bytes_sent", 0),
                "bytes_received": conn.get("bytes_received", 0),
                "flagged_c2": conn.get("flagged_c2", False),
            })
    
    # Extract file operations
    files_written = []
    if "files" in mobsf_report:
        for file_op in mobsf_report.get("files", []):
            if file_op.get("operation") == "write":
                files_written.append(file_op.get("path"))
    
    # Extract registry changes (Windows-specific)
    registry_changes = []
    if "registry" in mobsf_report:
        for reg_op in mobsf_report.get("registry", []):
            registry_changes.append(reg_op.get("key_path"))
    
    # Extract persistence artifacts
    persistence_artifacts = []
    if "services" in mobsf_report:
        for svc in mobsf_report.get("services", []):
            persistence_artifacts.append(f"service: {svc.get('name')}")
    if "startup" in mobsf_report:
        for startup in mobsf_report.get("startup", []):
            persistence_artifacts.append(f"startup: {startup.get('path')}")
    
    # Extract C2 endpoints
    c2_endpoints_detected = []
    if "c2" in mobsf_report:
        c2_endpoints_detected = mobsf_report.get("c2", [])
    
    return {
        "sample_id": mobsf_report.get("hash") or mobsf_report.get("md5", ""),
        "process_tree": process_tree,
        "api_calls": api_calls,
        "network_connections": network_connections,
        "files_written": files_written,
        "registry_changes": registry_changes,
        "persistence_artifacts": persistence_artifacts,
        "c2_endpoints_detected": c2_endpoints_detected,
        "raw": mobsf_report,
    }


def run_report_check(file_hash):
    """
    Returns (passed: bool, detail: str, converted: dict|None)
    """
    if not file_hash:
        return False, "skipped — no file hash", None
    try:
        report = get_dynamic_report(file_hash)
        converted = convert_to_common_schema(report)
        required_keys = {"sample_id", "process_tree", "api_calls", "network_connections"}
        if required_keys.issubset(converted.keys()):
            return True, "schema fields present", converted
        return False, f"missing keys: {required_keys - converted.keys()}", None
    except Exception as e:
        return False, f"error: {e}", None


if __name__ == "__main__":
    import sys
    test_hash = sys.argv[1] if len(sys.argv) > 1 else None
    ok, detail, converted = run_report_check(test_hash)
    print(f"Part 4 - Report/Adapter: {'PASS' if ok else 'FAIL'} — {detail}")