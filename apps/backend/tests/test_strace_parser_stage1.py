import json
from pathlib import Path
import pytest

from backend.app.strace_parser import parse_strace_output, parse_pcap_dns


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "synthetic_logs"


def test_parse_pcap_dns():
    """Verify dpkt/scapy parses DNS queries and maps answers to domains."""
    pcap_path = FIXTURES_DIR / "sample_capture.pcap"
    assert pcap_path.is_file(), "sample_capture.pcap must exist"

    queries, ip_map = parse_pcap_dns(pcap_path)
    assert "update.malicious-feed.org" in queries
    assert ip_map.get("192.168.100.1") == "update.malicious-feed.org"


def test_native_strace_parser_full():
    """Verify parsing native strace with interleaved lines, failed exec, ptrace, and bridge mapping."""
    log_path = FIXTURES_DIR / "native_strace.log"
    pcap_path = FIXTURES_DIR / "sample_capture.pcap"
    fs_diff_path = FIXTURES_DIR / "fs_diff.json"

    fs_diff = json.loads(fs_diff_path.read_text())

    output = parse_strace_output(
        strace_log=log_path.read_text(),
        sample_id="test_native_sample",
        target_architecture="x86_64",
        pcap_data=pcap_path,
        fs_diff=fs_diff,
        duration_seconds=45,
        task_id="test-task-123",
        bridge_ip="192.168.100.1",
    )

    # 1. Status & Limitations
    assert output.dynamic_status == "completed"
    assert output.execution_mode == "real"
    assert output.target_architecture == "x86_64"
    assert output.duration_seconds == 45
    assert "Network is emulated by a fake-service host; remote servers did not respond" in output.limitations
    assert "User-mode emulation: kernel, init system and service behavior not observed" in output.limitations
    assert "Run limited to 45s; time-delayed behavior may not appear" in output.limitations

    # 2. Bridge IP never appears in network connections or C2 endpoints
    for conn in output.network_connections:
        assert conn["dest_ip"] != "192.168.100.1", "Bridge IP must not appear in network_connections"
    for c2 in output.c2_endpoints_detected:
        assert "192.168.100.1" not in c2, "Bridge IP must not appear in c2_endpoints_detected"

    # 3. Connection to bridge mapped back to resolved domain
    mapped_conns = [c for c in output.network_connections if c["dest_ip"] == "update.malicious-feed.org"]
    assert len(mapped_conns) == 1
    assert mapped_conns[0]["dest_port"] == 80
    assert mapped_conns[0]["result"] == "connected"
    assert mapped_conns[0]["resolved_domain"] == "update.malicious-feed.org"

    # 4. External IP connection (failed ECONNREFUSED)
    ext_conns = [c for c in output.network_connections if c["dest_ip"] == "198.51.100.5"]
    assert len(ext_conns) == 1
    assert ext_conns[0]["dest_port"] == 4444
    assert "failed" in ext_conns[0]["result"].lower() or "refused" in ext_conns[0]["result"].lower()

    # 5. Process tree with successful and failed execve (ENOENT)
    proc_names = [p["name"] for p in output.process_tree]
    assert "busybox" in proc_names
    assert "missing_tool" in proc_names
    failed_proc = next(p for p in output.process_tree if p["name"] == "missing_tool")
    assert failed_proc["status"] == "failed_exec"
    assert failed_proc.get("error") == "ENOENT"

    # 6. Fork / Clone tracked
    child_procs = [p for p in output.process_tree if p.get("pid") == 1002]
    assert len(child_procs) >= 1

    # 7. Persistence derived from path (/etc/cron.d/root_job)
    assert any("cron" in p.lower() and "/etc/cron.d/root_job" in p for p in output.persistence_artifacts)

    # 8. Anti-debugging (ptrace)
    assert "sys_ptrace" in output.api_calls
    assert any("anti-debugging" in p.lower() or "ptrace" in p.lower() for p in output.persistence_artifacts)

    # 9. Dropped files from fs_diff
    assert len(output.dropped_files) >= 1
    dropped_paths = [d["path"] for d in output.dropped_files]
    assert "/tmp/dropped.bin" in dropped_paths


def test_qemu_strace_parser():
    """Verify parsing qemu-<arch> -strace logs with curly brace argv, fork, and rc.local persistence."""
    log_path = FIXTURES_DIR / "qemu_strace.log"

    output = parse_strace_output(
        strace_log=log_path.read_text(),
        sample_id="test_arm_sample",
        target_architecture="ARM (32-bit)",
        duration_seconds=30,
        task_id="test-task-456",
    )

    assert output.dynamic_status == "completed"
    assert output.target_architecture == "ARM (32-bit)"

    # Process tree from qemu curly brace argv
    proc_names = [p["name"] for p in output.process_tree]
    assert "sh" in proc_names
    sh_proc = next(p for p in output.process_tree if p["name"] == "sh")
    assert "/etc/rc.local" in sh_proc["cmdline"]

    # Child process from fork
    assert any(p.get("pid") == 2002 for p in output.process_tree)

    # Network connection to 198.51.100.20:8080
    assert any(c["dest_ip"] == "198.51.100.20" and c["dest_port"] == 8080 for c in output.network_connections)

    # Persistence from /etc/rc.local
    assert any("rc.local" in p.lower() for p in output.persistence_artifacts)

    # Ptrace
    assert "sys_ptrace" in output.api_calls
    assert any("ptrace" in p.lower() for p in output.persistence_artifacts)


def test_quiet_run_no_behavior_observed():
    """Benign or un-executed run reports no_behavior_observed with honest disclaimer."""
    output = parse_strace_output(
        strace_log="",
        sample_id="hello_clean",
        target_architecture="x86_64",
        duration_seconds=20,
    )
    assert output.dynamic_status == "no_behavior_observed"
    assert "no behavior observed in 20s under user-mode emulation" in output.message.lower()
    assert "this is not evidence the file is benign" in output.message.lower()
    assert output.network_connections == []
    assert output.process_tree == []


def test_timeout_and_caps_limitations():
    """Timeout and truncated artifacts add explicit lines to limitations list."""
    output = parse_strace_output(
        strace_log="1001 execve(\"/bin/sleep\", [\"sleep\", \"100\"], 0x0) = 0\n",
        sample_id="timeout_sample",
        duration_seconds=90,
        timed_out=True,
        caps_hit=["strace_log_bytes", "pcap_size"],
    )
    assert any("Run terminated by hard timeout (90s)" in lim for lim in output.limitations)
    assert any("strace_log_bytes cap exceeded" in lim for lim in output.limitations)
    assert any("pcap_size cap exceeded" in lim for lim in output.limitations)


def test_scanning_traffic_detection():
    """Many connection attempts are detected and recorded as scanning behavior."""
    synthetic_scan_lines = []
    for i in range(1, 20):
        synthetic_scan_lines.append(
            f"1001 12:00:{i:02d}.000000 connect(3, {{sa_family=AF_INET, sin_port=htons(23), sin_addr=inet_addr(\"198.51.100.{i}\")}}, 16) = -1\n"
        )
    scan_log = "".join(synthetic_scan_lines)

    output = parse_strace_output(
        strace_log=scan_log,
        sample_id="scanner_sample",
    )
    assert output.scanning_behavior is not None
    assert output.scanning_behavior["attempts_count"] == 19
    assert "scanning behavior detected" in output.scanning_behavior["summary"].lower()
