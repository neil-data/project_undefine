"""
backend/app/strace_parser.py — Syscall (strace & qemu-user) and PCAP log parser.

Parses raw execution artifacts from the real sandbox host:
1. Native `strace -f -tt -s 512 -yy` and `qemu-<arch> -strace` logs.
2. PCAP DNS traffic via dpkt (with scapy fallback) to map bridge connections
   back to their requested domains.
3. Process trees (clone/fork/vfork/execve), file mutations (open/unlink),
   persistence rules, ptrace anti-debugging, and honest limitations.
"""

from __future__ import annotations

import io
import re
import socket
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Set, Tuple, Any

from agents.orchestrator.schema import DynamicAnalysisOutput

# Filter internal hypervisor & bridge subnets from public IoC output
DEFAULT_FILTERED_IP_PREFIXES = (
    "10.0.2.",
    "192.168.100.",
    "192.168.122.",
    "127.",
    "0.",
    "169.254.",
)

# Regex patterns for native strace and qemu -strace
_TT_TIMESTAMP_RE = re.compile(r"^(\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)")
_PID_PREFIX_RE = re.compile(r"^(?:\[pid\s+(\d+)\]|\s*(\d+))\s+")

_UNFINISHED_RE = re.compile(r"<unfinished\s*\.{3}>$")
_RESUMED_RE = re.compile(r"<\.{3}\s*([a-zA-Z0-9_]+)\s+resumed>\s*(.*)$")

_EXECVE_RE = re.compile(
    r'execve\("([^"]+)",\s*(?:\[([^\]]*)\]|\{([^\}]*)\})'
)
_CLONE_FORK_RE = re.compile(r'\b(?:clone|fork|vfork)\([^\)]*\)\s*=\s*(\d+)')
_UNLINK_RE = re.compile(r'\b(?:unlinkat\([^,]+,\s*"([^"]+)"|unlink\("([^"]+)")[^\)]*\)\s*=\s*(-?\d+)')
_OPEN_WRITE_RE = re.compile(
    r'(?:openat\([^,]+,\s*"([^"]+)"|open\("([^"]+)"),\s*([^,\)]+)'
)
_PTRACE_RE = re.compile(r'\bptrace\(')

_CONNECT_SOCKADDR_RE = re.compile(
    r'sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)'
)
_CONNECT_RESULT_RE = re.compile(r'\)\s*=\s*(-?\d+)(?:\s+([A-Z0-9_]+))?')

_SYSCALL_NAME_RE = re.compile(r'(?:^|[\s\]])([a-zA-Z0-9_]+)\(')


def parse_pcap_dns(pcap_data: bytes | str | Path) -> Tuple[List[str], Dict[str, str]]:
    """
    Extract DNS query names and map resolved IP answers back to domains from a PCAP.

    Returns:
        (dns_queries, ip_to_domain_map)
    """
    dns_queries: List[str] = []
    ip_to_domain: Dict[str, str] = {}
    seen_queries: Set[str] = set()

    raw_bytes: Optional[bytes] = None
    if isinstance(pcap_data, (str, Path)):
        p = Path(pcap_data)
        if p.is_file():
            try:
                raw_bytes = p.read_bytes()
            except Exception:
                return [], {}
        else:
            return [], {}
    elif isinstance(pcap_data, bytes):
        raw_bytes = pcap_data

    if not raw_bytes or len(raw_bytes) < 24:
        return [], {}

    # Attempt 1: dpkt
    try:
        import dpkt

        f = io.BytesIO(raw_bytes)
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception:
            f.seek(0)
            pcap = dpkt.pcapng.Reader(f)

        for _, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not hasattr(ip, "data"):
                    continue
                udp = ip.data
                if not hasattr(udp, "data") or not hasattr(udp, "dport"):
                    continue
                if udp.dport == 53 or udp.sport == 53:
                    dns = dpkt.dns.DNS(udp.data)
                    for q in dns.qd:
                        name = q.name.strip().rstrip(".")
                        if name and name not in seen_queries:
                            seen_queries.add(name)
                            dns_queries.append(name)
                    # Parse answers
                    for ans in dns.an:
                        qname = getattr(ans, "name", "").strip().rstrip(".")
                        if ans.type == dpkt.dns.DNS_A and len(ans.rdata) == 4:
                            resolved_ip = socket.inet_ntoa(ans.rdata)
                            if qname and resolved_ip:
                                ip_to_domain[resolved_ip] = qname
            except Exception:
                continue

        if dns_queries or ip_to_domain:
            return dns_queries, ip_to_domain
    except ImportError:
        pass
    except Exception:
        pass

    # Attempt 2: scapy fallback
    try:
        from scapy.all import rdpcap, DNS, DNSQR, DNSRR

        packets = rdpcap(io.BytesIO(raw_bytes))
        for pkt in packets:
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.haslayer(DNSQR):
                    qname = dns[DNSQR].qname.decode("utf-8", "ignore").strip().rstrip(".")
                    if qname and qname not in seen_queries:
                        seen_queries.add(qname)
                        dns_queries.append(qname)
                if dns.an:
                    for i in range(dns.ancount):
                        rr = dns.an[i]
                        if rr.type == 1:  # Type A
                            ans_ip = rr.rdata
                            ans_name = rr.rrname.decode("utf-8", "ignore").strip().rstrip(".")
                            if ans_ip and ans_name:
                                ip_to_domain[ans_ip] = ans_name
    except Exception:
        pass

    return dns_queries, ip_to_domain


def _parse_time(time_str: str) -> Optional[datetime]:
    try:
        if "." in time_str:
            return datetime.strptime(time_str, "%H:%M:%S.%f")
        return datetime.strptime(time_str, "%H:%M:%S")
    except ValueError:
        return None


def parse_strace_output(
    strace_log: str,
    sample_id: str,
    target_architecture: Optional[str] = None,
    dns_queries: Optional[list[str]] = None,
    pcap_data: Optional[bytes | str | Path] = None,
    fs_diff: Optional[dict] = None,
    duration_seconds: Optional[int] = 30,
    task_id: Optional[str] = None,
    bridge_ip: Optional[str] = None,
    timed_out: bool = False,
    caps_hit: Optional[list[str]] = None,
) -> DynamicAnalysisOutput:
    """
    Parse native strace or qemu-<arch> -strace logs into DynamicAnalysisOutput.

    Zero synthetic events are ever invented. All findings trace to raw logs.
    """
    dur = duration_seconds or 30
    limitations: List[str] = [
        "User-mode emulation: kernel, init system and service behavior not observed",
        "Network is emulated by a fake-service host; remote servers did not respond",
        f"Run limited to {dur}s; time-delayed behavior may not appear",
    ]
    if timed_out:
        limitations.append(f"Run terminated by hard timeout ({dur}s)")
    if caps_hit:
        for cap in caps_hit:
            limitations.append(f"Artifact truncated: {cap} cap exceeded")

    # Extract DNS & IP->Domain mapping from PCAP if provided
    ip_to_domain: Dict[str, str] = {}
    pcap_dns_queries: List[str] = []
    if pcap_data:
        pcap_dns_queries, ip_to_domain = parse_pcap_dns(pcap_data)

    all_dns_queries = list(dict.fromkeys((dns_queries or []) + pcap_dns_queries))

    if not strace_log or not strace_log.strip():
        return DynamicAnalysisOutput(
            sample_id=sample_id,
            execution_mode="real",
            status="completed",
            dynamic_status="no_behavior_observed",
            failure_reason=None,
            task_id=task_id,
            target_architecture=target_architecture or "unknown",
            duration_seconds=dur,
            process_tree=[],
            api_calls=[],
            network_connections=[],
            dns_queries=all_dns_queries,
            files_written=[],
            registry_changes=[],
            persistence_artifacts=[],
            c2_endpoints_detected=[],
            limitations=limitations,
            dropped_files=[],
            message=f"No behavior observed in {dur}s under user-mode emulation; this is not evidence the file is benign.",
        )

    # Bridge prefixes to suppress from direct IoC attribution
    filtered_prefixes = list(DEFAULT_FILTERED_IP_PREFIXES)
    if bridge_ip:
        filtered_prefixes.append(bridge_ip)

    # State accumulation
    network_connections: List[dict] = []
    seen_conns: Set[Tuple[str, int, str]] = set()
    scanning_targets: List[Tuple[str, int]] = []
    process_tree: List[dict] = []
    seen_processes: Set[Tuple[int, str]] = set()
    files_written: List[str] = []
    seen_files: Set[str] = set()
    files_deleted: List[str] = []
    persistence_artifacts: List[str] = []
    seen_persistence: Set[str] = set()
    api_calls: List[str] = []
    seen_syscalls: Set[str] = set()
    c2_endpoints: List[str] = []
    dropped_files: List[dict] = []

    # Unfinished line reassembly: buffer by PID
    unfinished_buffers: Dict[str, str] = {}
    first_timestamp: Optional[datetime] = None

    lines = strace_log.splitlines()
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        # Extract PID prefix if present
        pid_str = "1000"
        m_pid = _PID_PREFIX_RE.match(line)
        if m_pid:
            pid_str = m_pid.group(1) or m_pid.group(2)
            line = line[m_pid.end():].strip()

        # Extract timestamp if present
        rel_ts_str = "+0.000s"
        m_time = _TT_TIMESTAMP_RE.match(line)
        if m_time:
            t_str = m_time.group(1)
            line = line[m_time.end():].strip()
            parsed_t = _parse_time(t_str)
            if parsed_t:
                if first_timestamp is None:
                    first_timestamp = parsed_t
                delta_sec = (parsed_t - first_timestamp).total_seconds()
                rel_ts_str = f"+{max(0.0, delta_sec):.3f}s"

        # Check for unfinished / resumed syscall lines
        if _UNFINISHED_RE.search(line):
            cleaned = _UNFINISHED_RE.sub("", line).strip()
            unfinished_buffers[pid_str] = cleaned
            continue

        m_res = _RESUMED_RE.search(line)
        if m_res and pid_str in unfinished_buffers:
            prev = unfinished_buffers.pop(pid_str)
            tail = m_res.group(2)
            line = f"{prev} {tail}".strip()

        # 1. Syscall name recording
        m_sys = _SYSCALL_NAME_RE.search(line)
        if m_sys:
            call_name = f"sys_{m_sys.group(1)}"
            if call_name not in seen_syscalls:
                seen_syscalls.add(call_name)
                api_calls.append(call_name)

        # 2. Anti-debugging (ptrace)
        if _PTRACE_RE.search(line):
            if "sys_ptrace" not in seen_syscalls:
                seen_syscalls.add("sys_ptrace")
                api_calls.append("sys_ptrace")
            ptrace_note = "Anti-debugging check observed (ptrace)"
            if ptrace_note not in seen_persistence:
                seen_persistence.add(ptrace_note)
                persistence_artifacts.append(ptrace_note)

        # 3. Process execution (execve)
        m_exec = _EXECVE_RE.search(line)
        if m_exec:
            binary = m_exec.group(1)
            raw_args = m_exec.group(2) or m_exec.group(3) or ""
            args = [a.strip().strip('"').strip("'") for a in raw_args.split(",") if a.strip()]
            cmdline = " ".join(args) if args else binary

            # Detect return status (0 or -1 with ENOENT, etc.)
            status = "completed"
            error = None
            if " = -1" in line:
                status = "failed_exec"
                if "ENOENT" in line:
                    error = "ENOENT"
                elif "EACCES" in line:
                    error = "EACCES"

            proc_pid = int(pid_str) if pid_str.isdigit() else 1000 + len(process_tree)
            proc_key = (proc_pid, binary)
            if proc_key not in seen_processes:
                seen_processes.add(proc_key)
                proc_entry: dict = {
                    "pid": proc_pid,
                    "name": binary.split("/")[-1],
                    "process_name": binary.split("/")[-1],
                    "cmdline": cmdline,
                    "timestamp": rel_ts_str,
                    "status": status,
                }
                if error:
                    proc_entry["error"] = error
                process_tree.append(proc_entry)

        # 4. Clone / Fork
        m_fork = _CLONE_FORK_RE.search(line)
        if m_fork:
            child_pid = int(m_fork.group(1))
            parent_pid = int(pid_str) if pid_str.isdigit() else 1000
            child_key = (child_pid, f"forked_{child_pid}")
            if child_key not in seen_processes:
                seen_processes.add(child_key)
                process_tree.append({
                    "pid": child_pid,
                    "parent_pid": parent_pid,
                    "name": f"process_{child_pid}",
                    "process_name": f"process_{child_pid}",
                    "cmdline": f"forked from pid {parent_pid}",
                    "timestamp": rel_ts_str,
                    "status": "spawned",
                })

        # 5. Network connect extraction
        if "connect(" in line:
            m_conn = _CONNECT_SOCKADDR_RE.search(line)
            if m_conn:
                port = int(m_conn.group(1))
                ip = m_conn.group(2).strip()

                # Determine result
                m_res = _CONNECT_RESULT_RE.search(line)
                res_code = int(m_res.group(1)) if m_res else 0
                res_status = "connected" if res_code == 0 else f"failed ({m_res.group(2) if m_res and m_res.group(2) else 'refused'})"

                # Check if this IP is the bridge IP mapped to a domain
                is_bridge = any(ip.startswith(prefix) for prefix in filtered_prefixes)
                resolved_domain = ip_to_domain.get(ip)

                if is_bridge:
                    # Bridge connection with known domain mapping
                    if resolved_domain:
                        conn_key = (resolved_domain, port, "TCP")
                        if conn_key not in seen_conns:
                            seen_conns.add(conn_key)
                            network_connections.append({
                                "dest_ip": resolved_domain,
                                "dest_port": port,
                                "protocol": "TCP",
                                "result": res_status,
                                "timestamp": rel_ts_str,
                                "resolved_domain": resolved_domain,
                                "flagged_c2": False,
                            })
                            c2_endpoints.append(f"{resolved_domain}:{port}")
                    # If bridge connection has no domain, do NOT expose bridge IP in public table
                else:
                    # External IP
                    conn_key = (ip, port, "TCP")
                    if conn_key not in seen_conns:
                        seen_conns.add(conn_key)
                        scanning_targets.append((ip, port))
                        network_connections.append({
                            "dest_ip": ip,
                            "dest_port": port,
                            "protocol": "TCP",
                            "result": res_status,
                            "timestamp": rel_ts_str,
                            "resolved_domain": resolved_domain,
                            "flagged_c2": False,
                        })
                        c2_endpoints.append(f"{ip}:{port}")

        # 6. File modifications (open, openat)
        m_open = _OPEN_WRITE_RE.search(line)
        if m_open:
            flags = m_open.group(3)
            if any(f in flags for f in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC")):
                fpath = (m_open.group(1) or m_open.group(2) or "").strip()
                if fpath and fpath not in seen_files:
                    seen_files.add(fpath)
                    files_written.append(fpath)

                    # Persistence artifact check derived by strict rules
                    lower_f = fpath.lower()
                    if any(p in lower_f for p in ("/etc/cron", "crontab", "/var/spool/cron")):
                        p_art = f"Cron persistence artifact: {fpath}"
                        if p_art not in seen_persistence:
                            seen_persistence.add(p_art)
                            persistence_artifacts.append(p_art)
                    elif "/etc/rc.local" in lower_f:
                        p_art = f"System startup rc.local persistence: {fpath}"
                        if p_art not in seen_persistence:
                            seen_persistence.add(p_art)
                            persistence_artifacts.append(p_art)
                    elif "/etc/init.d" in lower_f:
                        p_art = f"Init script persistence: {fpath}"
                        if p_art not in seen_persistence:
                            seen_persistence.add(p_art)
                            persistence_artifacts.append(p_art)
                    elif "/etc/systemd" in lower_f:
                        p_art = f"Systemd unit persistence: {fpath}"
                        if p_art not in seen_persistence:
                            seen_persistence.add(p_art)
                            persistence_artifacts.append(p_art)
                    elif any(p in lower_f for p in (".bashrc", ".profile", "/etc/profile")):
                        p_art = f"Shell profile persistence: {fpath}"
                        if p_art not in seen_persistence:
                            seen_persistence.add(p_art)
                            persistence_artifacts.append(p_art)
                    elif "autostart" in lower_f:
                        p_art = f"Autostart entry persistence: {fpath}"
                        if p_art not in seen_persistence:
                            seen_persistence.add(p_art)
                            persistence_artifacts.append(p_art)

        # 7. Unlink / Unlinkat (deleted files)
        m_del = _UNLINK_RE.search(line)
        if m_del:
            dpath = (m_del.group(1) or m_del.group(2) or "").strip()
            if dpath and dpath not in files_deleted:
                files_deleted.append(dpath)

    # 8. Merge filesystem diff (fs_diff) if provided from overlayfs upper dir
    if fs_diff and isinstance(fs_diff, dict):
        for cr in fs_diff.get("created", []):
            path = cr.get("path") if isinstance(cr, dict) else str(cr)
            sha = cr.get("sha256") if isinstance(cr, dict) else None
            size = cr.get("size") if isinstance(cr, dict) else None
            if path and path not in seen_files:
                seen_files.add(path)
                files_written.append(path)
            if path and sha:
                dropped_files.append({"path": path, "sha256": sha, "size": size})

        for mod in fs_diff.get("modified", []):
            path = mod.get("path") if isinstance(mod, dict) else str(mod)
            sha = mod.get("sha256") if isinstance(mod, dict) else None
            size = mod.get("size") if isinstance(mod, dict) else None
            if path and path not in seen_files:
                seen_files.add(path)
                files_written.append(path)
            if path and sha:
                dropped_files.append({"path": path, "sha256": sha, "size": size})

        for dl in fs_diff.get("deleted", []):
            path = dl.get("path") if isinstance(dl, dict) else str(dl)
            if path and path not in files_deleted:
                files_deleted.append(path)

    # 9. Scanning traffic detection: if process connected to many distinct addresses/ports
    scanning_behavior = None
    if len(scanning_targets) >= 10:
        unique_ips = len(set(t[0] for t in scanning_targets))
        scanning_behavior = {
            "attempts_count": len(scanning_targets),
            "unique_destinations": unique_ips,
            "summary": f"Scanning behavior detected: {len(scanning_targets)} connection attempts across {unique_ips} distinct destination(s).",
        }
        # Cap public network_connections list to prevent reporting explosion
        if len(network_connections) > 25:
            network_connections = network_connections[:25]
            limitations.append("Network telemetry truncated: high-volume scanning traffic capped to first 25 attempts")

    # 10. Status resolution
    has_activity = bool(process_tree or network_connections or api_calls or files_written)
    if has_activity:
        dyn_status = "completed"
        msg = (
            f"Observed real execution: {len(process_tree)} processes, "
            f"{len(network_connections)} network connections, "
            f"{len(files_written)} files modified, and {len(api_calls)} syscalls."
        )
    else:
        dyn_status = "no_behavior_observed"
        msg = f"No behavior observed in {dur}s under user-mode emulation; this is not evidence the file is benign."

    return DynamicAnalysisOutput(
        sample_id=sample_id,
        execution_mode="real",
        status="completed",
        dynamic_status=dyn_status,
        failure_reason=None,
        task_id=task_id,
        target_architecture=target_architecture or "unknown",
        duration_seconds=dur,
        process_tree=process_tree,
        api_calls=api_calls,
        network_connections=network_connections,
        dns_queries=all_dns_queries,
        files_written=files_written,
        registry_changes=[],
        persistence_artifacts=persistence_artifacts,
        c2_endpoints_detected=c2_endpoints,
        limitations=limitations,
        dropped_files=dropped_files,
        scanning_behavior=scanning_behavior,
        message=msg,
    )


# Alias for artifact parsing
parse_strace_artifacts = parse_strace_output
