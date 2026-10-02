"""
backend/app/strace_parser.py — Strace and pcap log parser for isolated ELF sandbox runners.

Parses raw `strace -f -tt` logs and DNS queries into a validated DynamicAnalysisOutput.
Filters out internal hypervisor and bridge IPs (10.0.2.x, 127.0.0.1, 192.168.100.x)
to ensure forensic integrity of the public IOC tables.
"""

from __future__ import annotations

import re
from typing import Optional
from agents.orchestrator.schema import DynamicAnalysisOutput

# Internal bridge networks to filter from IOC tables
_FILTERED_IP_PREFIXES = ("10.0.2.", "192.168.100.", "192.168.122.", "127.", "0.")

_CONNECT_RE = re.compile(
    r'sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)'
)
_EXECVE_RE = re.compile(
    r'(?:\[pid\s+(\d+)\]\s+)?(?:[\d:.]+\s+)?execve\("([^"]+)",\s*\[([^\]]*)\]'
)
_OPEN_WRITE_RE = re.compile(
    r'(?:\[pid\s+(\d+)\]\s+)?(?:[\d:.]+\s+)?(?:openat\([^,]+,\s*"([^"]+)"|open\("([^"]+)")'
)
_SYSCALL_NAME_RE = re.compile(
    r'(?:\[pid\s+\d+\]\s+)?(?:[\d:.]+\s+)?([a-zA-Z0-9_]+)\('
)


def parse_strace_output(
    strace_log: str,
    sample_id: str,
    target_architecture: Optional[str] = None,
    dns_queries: Optional[list[str]] = None,
    duration_seconds: Optional[int] = 30,
    task_id: Optional[str] = None,
) -> DynamicAnalysisOutput:
    """
    Parse an strace log from a real sandbox execution into DynamicAnalysisOutput.
    """
    if not strace_log or not strace_log.strip():
        return DynamicAnalysisOutput(
            sample_id=sample_id,
            execution_mode="real",
            status="completed",
            dynamic_status="no_behavior_observed",
            failure_reason=None,
            task_id=task_id,
            target_architecture=target_architecture or "unknown",
            duration_seconds=duration_seconds,
            process_tree=[],
            api_calls=[],
            network_connections=[],
            dns_queries=dns_queries or [],
            files_written=[],
            registry_changes=[],
            persistence_artifacts=[],
            c2_endpoints_detected=[],
            message="No system calls observed during dynamic sandbox execution.",
        )

    network_connections: list[dict] = []
    seen_conns: set[tuple[str, int]] = set()
    process_tree: list[dict] = []
    seen_processes: set[tuple[int, str]] = set()
    files_written: list[str] = []
    seen_files: set[str] = set()
    persistence_artifacts: list[str] = []
    seen_persistence: set[str] = set()
    api_calls: list[str] = []
    seen_syscalls: set[str] = set()
    c2_endpoints: list[str] = []

    lines = strace_log.splitlines()

    for line in lines:
        line_str = line.strip()
        if not line_str:
            continue

        # 1. Syscall extraction
        m_sys = _SYSCALL_NAME_RE.search(line_str)
        if m_sys:
            call_name = f"sys_{m_sys.group(1)}"
            if call_name not in seen_syscalls:
                seen_syscalls.add(call_name)
                api_calls.append(call_name)

        # 2. Network connect extraction
        m_conn = _CONNECT_RE.search(line_str)
        if m_conn:
            port = int(m_conn.group(1))
            ip = m_conn.group(2).strip()
            # Filter internal sandbox bridges
            if not any(ip.startswith(prefix) for prefix in _FILTERED_IP_PREFIXES) and ip != "255.255.255.255":
                if (ip, port) not in seen_conns:
                    seen_conns.add((ip, port))
                    network_connections.append({
                        "dest_ip": ip,
                        "dest_port": port,
                        "protocol": "TCP",
                        "flagged_c2": False,
                        "simulated": False,
                    })
                    c2_endpoints.append(f"{ip}:{port}")

        # 3. Process execution extraction
        m_exec = _EXECVE_RE.search(line_str)
        if m_exec:
            pid = int(m_exec.group(1)) if m_exec.group(1) else 1000 + len(process_tree)
            binary = m_exec.group(2)
            raw_args = m_exec.group(3)
            # Reconstruct cmdline
            args = [a.strip().strip('"').strip("'") for a in raw_args.split(",") if a.strip()]
            cmdline = " ".join(args) if args else binary
            if (pid, binary) not in seen_processes:
                seen_processes.add((pid, binary))
                process_tree.append({
                    "pid": pid,
                    "name": binary.split("/")[-1],
                    "process_name": binary.split("/")[-1],
                    "cmdline": cmdline,
                })

        # 4. File access / modification extraction
        if any(flag in line_str for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC")):
            m_open = _OPEN_WRITE_RE.search(line_str)
            if m_open:
                fpath = (m_open.group(2) or m_open.group(3) or "").strip()
                if fpath and fpath not in seen_files:
                    seen_files.add(fpath)
                    files_written.append(fpath)

                    # Persistence check
                    lower_f = fpath.lower()
                    if any(p in lower_f for p in ("/etc/cron", "crontab", "/etc/systemd", "/etc/init.d", ".bashrc", ".profile")):
                        if fpath not in seen_persistence:
                            seen_persistence.add(fpath)
                            persistence_artifacts.append(f"Persistence artifact: {fpath}")

    return DynamicAnalysisOutput(
        sample_id=sample_id,
        execution_mode="real",
        status="completed",
        dynamic_status="completed" if (process_tree or network_connections or api_calls) else "no_behavior_observed",
        failure_reason=None,
        task_id=task_id,
        target_architecture=target_architecture or "unknown",
        duration_seconds=duration_seconds,
        process_tree=process_tree,
        api_calls=api_calls,
        network_connections=network_connections,
        dns_queries=dns_queries or [],
        files_written=files_written,
        registry_changes=[],
        persistence_artifacts=persistence_artifacts,
        c2_endpoints_detected=c2_endpoints,
        message=f"Real execution captured {len(process_tree)} processes, {len(network_connections)} network connections, and {len(api_calls)} syscalls.",
    )
