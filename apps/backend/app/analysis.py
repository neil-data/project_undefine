"""
backend/app/analysis.py — Shared static-analysis + agent-pipeline + persistence flow.

Extracted out of routers/cases.py so the same "analyze a file, run the agent
graph, save the result" flow can be triggered from two different entry
points: the interactive POST /api/cases/upload endpoint, and the background
ingestion_worker.py consumer that drains the ingestion gateway's Redis
queue. Keeping this in one place means both paths get identical behavior
(same normalization, same DB/ES writes) instead of two copies that could
drift apart.
"""

from __future__ import annotations

import asyncio
import logging
import re
import json
import struct
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from static_analysis.bootstrap import create_engine
from agents.orchestrator.schema import AndroidManifestInfo, PEAnalysisInfo, StaticAnalysisOutput, DynamicAnalysisOutput, YaraMatch, ExtractedStrings
from agents.orchestrator.orchestrator import build_graph

from .models.api_models import (
    risk_score_to_status,
    threat_level_from_score,
    verdict_from_score,
    confidence_from_signals,
)
from . import geoip, store, malware_bazaar, sandbox
from packages.shared.ioc_classifier import (
    IoCClassifier,
    IOCType,
    validate_domain as _validate_domain_ioc,
    strip_glued_hex as _strip_glued_hex_ioc,
    truncate_display_value,
    is_base64_blob,
    is_system_library,
    is_symbol,
    is_package_entry,
)
from packages.shared.allowlist import (
    PUBLIC_DNS_RESOLVERS,
    LEGITIMATE_BENIGN_DOMAINS,
)
from packages.shared.vendor_verdict_labels import is_clean_vendor_label, is_unrated_vendor_label

_LOGGER = logging.getLogger(__name__)


def _format_file_size(size_bytes: int) -> str:
    size = max(0, int(size_bytes or 0))
    if size < 1024:
        return f"{size} B"
    value = float(size)
    for unit in ("KB", "MB", "GB", "TB"):
        value /= 1024
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
    return f"{value:.1f} TB"


def _finalize_report_quality(case_data: dict, stage_timestamps: dict) -> dict:
    prior = case_data.get("stage_timestamps") or {}
    for name in ("ingestion", "static", "intel"):
        stage_timestamps[name] = stage_timestamps.get(name) or prior.get(name)
    stage_timestamps["report"] = datetime.now(timezone.utc).isoformat()
    case_data["stage_timestamps"] = dict(stage_timestamps)
    timeline = case_data.setdefault("evidence_timeline", [])
    for event in timeline:
        event.setdefault("timestamp_display", event.get("timestamp") or "not recorded")
    existing_stages = {event.get("indicator") for event in timeline if event.get("source") == "Pipeline"}
    for stage in ("ingestion", "static", "intel", "report"):
        if stage not in existing_stages:
            timestamp = stage_timestamps.get(stage)
            timeline.append({"seq": max((int(event.get("seq", 0)) for event in timeline), default=0) + 1, "timestamp": timestamp, "timestamp_display": timestamp or "not recorded", "event": f"{stage.title()} stage completed", "source": "Pipeline", "indicator": stage, "severity": "INFO"})
    case_data["file_size_formatted"] = _format_file_size(case_data.get("file_size_bytes", 0))
    explained = case_data.get("explained_strings") or []
    if len(explained) > 20:
        remaining = len(explained) - 20
        case_data["explained_strings"] = explained[:20]
        case_data["explained_strings_note"] = f"{remaining} additional strings omitted; see full analysis artifacts."
    return case_data

_graph = build_graph()  # compiled once at import time, reused across all callers
_static_engine = create_engine()

_SUPPORTED_FILE_TYPES = ("apk", "pe", "exe", "dll", "elf", "mach_o", "json", "bson")


def decode_bson(data: bytes) -> dict:
    """Pure-python minimal BSON decoder supporting common types."""
    def read_cstring(b: bytes, offset: int) -> tuple[str, int]:
        end = b.index(b"\x00", offset)
        return b[offset:end].decode("utf-8"), end + 1

    def decode_document(b: bytes, offset: int) -> tuple[dict, int]:
        doc_size = struct.unpack_from("<i", b, offset)[0]
        end_offset = offset + doc_size
        res = {}
        curr = offset + 4
        while curr < end_offset - 1:
            element_type = b[curr]
            curr += 1
            name, curr = read_cstring(b, curr)
            if element_type == 1:  # double
                val = struct.unpack_from("<d", b, curr)[0]
                curr += 8
            elif element_type == 2:  # string
                length = struct.unpack_from("<i", b, curr)[0]
                curr += 4
                val = b[curr : curr + length - 1].decode("utf-8", errors="ignore")
                curr += length
            elif element_type == 3:  # document
                val, curr = decode_document(b, curr)
            elif element_type == 4:  # array
                arr_doc, curr = decode_document(b, curr)
                val = [arr_doc[k] for k in sorted(arr_doc.keys(), key=int)]
            elif element_type == 5:  # binary
                length = struct.unpack_from("<i", b, curr)[0]
                curr += 5  # skip length and subtype byte
                val = b[curr : curr + length]
                curr += length
            elif element_type == 8:  # boolean
                val = b[curr] == 1
                curr += 1
            elif element_type == 9:  # datetime (UTC ms)
                val = struct.unpack_from("<q", b, curr)[0]
                curr += 8
            elif element_type == 10:  # null
                val = None
            elif element_type == 16:  # 32-bit integer
                val = struct.unpack_from("<i", b, curr)[0]
                curr += 4
            elif element_type == 18:  # 64-bit integer
                val = struct.unpack_from("<q", b, curr)[0]
                curr += 8
            else:
                raise ValueError(f"Unsupported BSON type {element_type}")
            res[name] = val
        return res, end_offset

    res, _ = decode_document(data, 0)
    return res


class UnsupportedFormatError(ValueError):
    """Raised when the analyzed file isn't a format the engine supports."""


_INVALID_DOMAIN_EXTENSIONS = (
    ".out", ".bin", ".dex", ".dexpk", ".p", ".sh", ".bash", ".zsh", ".exe", ".dat", ".tmp",
    ".so", ".dll", ".o", ".a", ".py", ".pyc", ".c", ".h", ".cpp", ".txt",
    ".log", ".conf", ".cfg", ".ini", ".xml", ".json", ".js", ".css", ".yaml", ".yml", ".md",
    ".class", ".jar", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".html", ".htm",
)

_PUBLIC_DNS_RESOLVERS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "8.26.56.26", "8.20.247.20",
    "94.140.14.14", "94.140.15.15",
}

_NEUTRAL_PROXY_PORTS = {3128, 8080, 8888}

_PERSISTENCE_PATH_PATTERNS = [
    re.compile(r"^/etc/cron(\.d|\.daily|\.hourly|\.weekly|\.monthly)?/"),
    re.compile(r"^/var/spool/cron/"),
    re.compile(r"^/etc/crontab"),
    re.compile(r"^/etc/init\.d/"),
    re.compile(r"^/etc/rc[0-6S%d*]*\.d/"),
    re.compile(r"^/etc/rc\.local"),
    re.compile(r"^/etc/systemd/system/"),
    re.compile(r"^/tmp/\.[^/]+$"),
    re.compile(r"^/var/tmp/\.[^/]+$"),
    re.compile(r"^/var/run/\.[^/]+$"),
    re.compile(r"^/run/\.[^/]+$"),
    re.compile(r"^/usr/lib/\.[^/]+$"),
    re.compile(r"^/usr/local/lib/\.[^/]+$"),
]


def _is_persistence_path(path: str) -> bool:
    if not path or not isinstance(path, str):
        return False
    clean = path.strip()
    if is_base64_blob(clean) or is_system_library(clean) or is_symbol(clean) or is_package_entry(clean):
        return False
    return any(p.search(clean) is not None for p in _PERSISTENCE_PATH_PATTERNS)


def _extract_persistence_artifacts(raw_static: dict, dynamic_output: Optional[dict | DynamicAnalysisOutput]) -> list[dict]:
    """
    Extract and unify persistence artifacts from both dynamic execution and static discovery.
    Static-only findings strictly have evidence_state='STATIC'.
    """
    artifacts: list[dict] = []
    seen = set()

    # Dynamic persistence artifacts
    dyn_dict: Optional[dict] = None
    if dynamic_output is not None:
        if hasattr(dynamic_output, "model_dump"):
            dyn_dict = dynamic_output.model_dump()
        elif isinstance(dynamic_output, dict):
            dyn_dict = dynamic_output

    if dyn_dict:
        for p in dyn_dict.get("persistence_artifacts", []):
            if p and str(p) not in seen:
                seen.add(str(p))
                artifacts.append({
                    "path": str(p),
                    "evidence_state": "OBSERVED",
                    "source": "Dynamic Sandbox",
                })

    # Static persistence paths
    extracted = raw_static.get("extracted_strings") or {}
    candidates = list(extracted.get("suspicious_keywords") or [])
    for es in raw_static.get("explained_strings") or []:
        val = es.get("value")
        if val and val not in candidates:
            candidates.append(val)

    for cand in candidates:
        if _is_persistence_path(cand) and cand not in seen:
            seen.add(cand)
            artifacts.append({
                "path": cand,
                "evidence_state": "STATIC",
                "source": "Static Strings",
            })

    return artifacts


def _reconcile_geoip_severity(geo_iocs: list[dict], ioc_records: list[dict]) -> list[dict]:
    """
    Ensure GeoIP threat_level and IoC threat classification never contradict.
    Hosting/proxy ASN characteristics alone are contextual metadata, not an automatic HIGH verdict.
    """
    ioc_map = {}
    for r in ioc_records:
        ind = r.get("indicator")
        if ind:
            ioc_map[ind] = r

    reconciled = []
    for geo in geo_iocs:
        g = dict(geo)
        ip = g.get("ip")
        ioc = ioc_map.get(ip)
        if ioc:
            cls = (ioc.get("classification") or "UNKNOWN").upper()
            if cls == "MALICIOUS":
                g["threat_level"] = "CRITICAL" if ioc.get("confidence") == "HIGH" else "HIGH"
            elif cls == "SUSPICIOUS":
                g["threat_level"] = "MEDIUM"
            else:  # BENIGN, UNKNOWN
                g["threat_level"] = "LOW"
        else:
            if g.get("threat_level") in (None, "HIGH"):
                g["threat_level"] = "LOW"
        reconciled.append(g)
    return reconciled


def _is_valid_ipv4(val: str, allow_private: bool = False) -> bool:
    try:
        import ipaddress
        ip = ipaddress.ip_address(val)
        if ip.version != 4:
            return False
        # Reject loopback, link_local, reserved, multicast, unspecified
        if (ip.is_unspecified or ip.is_multicast or
            ip.is_loopback or ip.is_link_local or ip.is_reserved):
            return False
        if not allow_private and ip.is_private:
            return False
        # Reject internal sandbox bridge networks (QEMU/libvirt/INetSim)
        if val.startswith("10.0.2.") or val.startswith("192.168.100.") or val.startswith("192.168.122.") or val.startswith("127."):
            return False
        if val.startswith("0.") or val == "255.255.255.255":
            return False
        oids = ("1.3.6.1", "1.2.840", "2.16.840", "2.5.4", "0.9.2342", "1.3.14.3")
        if any(val == prefix or val.startswith(prefix + ".") for prefix in oids):
            return False
        return True
    except Exception:
        return False


_REJECTED_TLDS = {
    "local", "target", "service", "socket", "mount", "timer", "path", "scope", "slice",
}


def _is_valid_domain(val: str, *, contextual: bool = False) -> bool:
    domain = str(val).strip()
    if (is_symbol(domain)
            or re.fullmatch(r"\d+(?:\.\d+){1,}", domain)
            or domain.lower().endswith(".nsis")):
        return False
    valid, _ = _validate_domain_ioc(domain, allow_short_sld=contextual)
    return valid


def _is_valid_url(url: str) -> bool:
    if not url or len(url) < 10:
        return False
    clean_url = _strip_glued_hex_ioc(url)
    lowered = clean_url.lower()
    if any(lowered.startswith(bad) for bad in ("http/1.", "http/2", "httponly", "httpu", "http-equiv")):
        return False
    try:
        from urllib.parse import urlsplit
        parts = urlsplit(clean_url)
        if parts.scheme.lower() not in ("http", "https", "ftp", "ftps"):
            return False
        host = parts.hostname or ""
        if not host or not _is_valid_domain(host, contextual=True) and not _is_valid_ipv4(host):
            return False
        return True
    except Exception:
        return False


def _validated_extracted_strings(raw: dict) -> ExtractedStrings:
    """Normalize network IoCs before the orchestrator can use them for tags."""
    raw = raw if isinstance(raw, dict) else {}
    return ExtractedStrings(
        urls=[str(value) for value in (raw.get("urls") or []) if _is_valid_url(str(value))],
        ips=[str(value) for value in (raw.get("ips") or []) if _is_valid_ipv4(str(value), allow_private=True)],
        suspicious_keywords=raw.get("suspicious_keywords") or [],
    )


def _extract_network_indicators(raw_static: dict, dynamic_output: Optional[dict | DynamicAnalysisOutput] = None) -> dict:
    """
    Combine and deduplicate network observables from static + dynamic sources.
    Returns a dict with keys: ips, domains, urls, dns_queries, connections.
    Never fabricates indicators — only uses real analysis engine output.
    """
    dyn_dict: Optional[dict] = None
    if dynamic_output is not None:
        if hasattr(dynamic_output, "model_dump"):
            dyn_dict = dynamic_output.model_dump()
        elif isinstance(dynamic_output, dict):
            dyn_dict = dynamic_output

    extracted = raw_static.get("extracted_strings", {})
    static_ips: list[str] = [ip for ip in extracted.get("ips", []) if _is_valid_ipv4(ip)]
    static_urls: list[str] = [u for u in extracted.get("urls", []) if _is_valid_url(u)]
    static_domains: list[str] = []

    # Also look for bare domain/URL/IP strings in explained_strings
    for es in raw_static.get("explained_strings", []):
        val = es.get("value", "")
        etype = es.get("type", "")
        cat = es.get("category", "")
        if val:
            if (etype == "ip" or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val)) and _is_valid_ipv4(val) and val not in static_ips:
                static_ips.append(val)
            elif (etype == "domain" or cat == "network_indicator") and _is_valid_domain(val) and val not in static_domains:
                static_domains.append(val)
            elif (etype == "url" or val.startswith("http://") or val.startswith("https://")) and _is_valid_url(val) and val not in static_urls:
                static_urls.append(val)

    # Extract domains/IPs from URLs found in static strings
    for url in static_urls:
        m = re.match(r"https?://([^/:?#]+)", url)
        if m:
            host = m.group(1)
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host) and _is_valid_ipv4(host):
                if host not in static_ips:
                    static_ips.append(host)
            elif _is_valid_domain(host):
                if host not in static_domains:
                    static_domains.append(host)

    # Dynamic analysis network connections
    dynamic_ips: list[str] = []
    dynamic_domains: list[str] = []
    dynamic_connections: list[dict] = []
    dns_queries: list[str] = []

    if dyn_dict:
        for ip in dyn_dict.get("ips", []):
            if ip and _is_valid_ipv4(str(ip)) and str(ip) not in dynamic_ips:
                dynamic_ips.append(str(ip))
        for dom in dyn_dict.get("domains", []):
            if dom and _is_valid_domain(str(dom)) and str(dom) not in dynamic_domains:
                dynamic_domains.append(str(dom))
        for url in dyn_dict.get("urls", []):
            if url and _is_valid_url(str(url)) and str(url) not in static_urls:
                static_urls.append(str(url))

        for conn in dyn_dict.get("network_connections", []):
            ip = conn.get("dest_ip") or conn.get("ip")
            if ip and _is_valid_ipv4(str(ip), allow_private=True):
                ip_str = str(ip)
                if ip_str not in dynamic_ips:
                    dynamic_ips.append(ip_str)
                dynamic_connections.append({
                    "ip": ip_str,
                    "port": conn.get("dest_port") or conn.get("port"),
                    "protocol": conn.get("protocol", "unknown"),
                    "flagged_c2": bool(conn.get("flagged_c2")),
                })
            domain = conn.get("domain") or conn.get("hostname")
            if domain and _is_valid_domain(str(domain), contextual=True) and str(domain) not in dynamic_domains:
                dynamic_domains.append(str(domain))

        for ep in dyn_dict.get("c2_endpoints_detected", []):
            host = str(ep).split(":")[0]
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
                if _is_valid_ipv4(host) and host not in dynamic_ips:
                    dynamic_ips.append(host)
            elif _is_valid_domain(host, contextual=True):
                if host not in dynamic_domains:
                    dynamic_domains.append(host)

        for q in dyn_dict.get("dns_queries", []):
            q_str = str(q)
            if _is_valid_domain(q_str, contextual=True):
                if q_str not in dns_queries:
                    dns_queries.append(q_str)
                if q_str not in dynamic_domains:
                    dynamic_domains.append(q_str)

    # Merge and deduplicate (preserve order)
    all_ips = list(dict.fromkeys(static_ips + dynamic_ips))
    all_domains = list(dict.fromkeys(static_domains + dynamic_domains))
    all_urls = list(dict.fromkeys(static_urls))

    return {
        "ips": all_ips,
        "domains": all_domains,
        "urls": all_urls,
        "dns_queries": dns_queries,
        "connections": dynamic_connections,
    }


def _is_benign_domain(value: str) -> bool:
    domain = value.lower().strip(".")
    return domain.endswith(("android.com", "google.com", "gstatic.com", "androidx.com")) or domain in {"localhost", "schemas.android.com"}


def _build_ioc_intelligence(raw_static: dict, dynamic_output: Optional[dict | DynamicAnalysisOutput], indicators: dict, malware_bazaar: Optional[dict] = None) -> list[dict]:
    """Classify indicators from provenance using canonical IoCClassifier; never mark a static string malicious by itself."""
    dyn_dict: Optional[dict] = None
    if dynamic_output is not None:
        if hasattr(dynamic_output, "model_dump"):
            dyn_dict = dynamic_output.model_dump()
        elif isinstance(dynamic_output, dict):
            dyn_dict = dynamic_output

    static_ips = set((raw_static.get("extracted_strings") or {}).get("ips") or [])
    dynamic_connections = {str(c.get("dest_ip") or c.get("ip")): c for c in (dyn_dict or {}).get("network_connections", []) if c.get("dest_ip") or c.get("ip")}
    dynamic_domains = {str(q) for q in (dyn_dict or {}).get("dns_queries", [])}
    records: list[dict] = []

    # 1. File Hash IoCs (anchored forensic indicators)
    for htype in ("sha256", "md5", "sha1"):
        hval = raw_static.get(htype) or (malware_bazaar.get(htype) if malware_bazaar and htype == "sha256" else None)
        if hval:
            classified = IoCClassifier.classify(
                hval,
                hint_type="HASH",
                source="Static Analysis",
                source_type="STATIC",
                evidence_state="STATIC",
                first_seen=raw_static.get("submitted_at"),
                malware_bazaar=malware_bazaar if htype == "sha256" else None,
            )
            rec = classified.model_dump()
            rec["type"] = f"HASH_{htype.upper()}"
            records.append(rec)

    # 2. IP IoCs
    for ip in indicators.get("ips", []):
        if not _is_valid_ipv4(str(ip), allow_private=True):
            continue
        connection = dynamic_connections.get(ip)
        flagged = bool(connection and connection.get("flagged_c2"))
        is_tor, tor_label = geoip.check_tor_status(ip)
        classified = IoCClassifier.classify(
            ip,
            hint_type="IP",
            source="Static + Dynamic" if ip in static_ips and connection else "Dynamic Network" if connection else "Static Analysis",
            source_type="DYNAMIC" if connection else "STATIC",
            evidence_state="OBSERVED" if connection else "STATIC",
            first_seen=(connection.get("timestamp") if connection else None) or raw_static.get("submitted_at"),
            is_dynamic_observed=bool(connection),
            threat_intel={"malicious": True} if flagged else None,
        )
        rec = classified.model_dump()
        if is_tor and rec["classification"] != "MALICIOUS" and rec["type"] != "SYSTEM_INFRASTRUCTURE":
            rec["classification"] = "SUSPICIOUS"
            rec["related_behavior"] = (rec.get("related_behavior") or "") + f" ({tor_label})"
        records.append(rec)

    # 3. Domain IoCs
    for domain in indicators.get("domains", []):
        dynamic = domain in dynamic_domains
        domain_text = str(domain).strip()
        # Known extraction noise that can resemble a DNS name: language/.NET
        # symbols, version tuples, and installer metadata fragments.
        if (is_symbol(domain_text)
                or re.fullmatch(r"\d+(?:\.\d+){1,}", domain_text)
                or domain_text.lower().endswith(".nsis")
                or not _is_valid_domain(domain_text, contextual=dynamic)):
            continue
        classified = IoCClassifier.classify(
            domain_text,
            hint_type="DOMAIN",
            source="Static + Dynamic" if dynamic else "Static Analysis",
            source_type="DYNAMIC" if dynamic else "STATIC",
            evidence_state="OBSERVED" if dynamic else "STATIC",
            first_seen=raw_static.get("submitted_at"),
            is_dynamic_observed=bool(dynamic),
        )
        rec = classified.model_dump()
        records.append(rec)

    # 4. URL IoCs
    for url in indicators.get("urls", []):
        clean_url = _strip_glued_hex_ioc(url)
        if not _is_valid_url(clean_url):
            continue
        classified = IoCClassifier.classify(
            clean_url,
            hint_type="URL",
            source="Static Analysis",
            source_type="STATIC",
            evidence_state="STATIC",
            first_seen=raw_static.get("submitted_at"),
            is_dynamic_observed=False,
        )
        rec = classified.model_dump()
        records.append(rec)

    # 5. Dropped Files IoCs
    if dyn_dict:
        for fw in dyn_dict.get("files_written", []):
            if fw:
                classified = IoCClassifier.classify(
                    str(fw),
                    hint_type="FILE_PATH",
                    source="Dynamic Sandbox",
                    source_type="DYNAMIC",
                    evidence_state="OBSERVED",
                    first_seen=raw_static.get("submitted_at"),
                    is_dynamic_observed=True,
                )
                rec = classified.model_dump()
                rec["type"] = "DROPPED_FILE"
                rec["related_behavior"] = "File written / dropped by sample"
                records.append(rec)

    # 6. Persistence Paths IoCs
    persistence_details = _extract_persistence_artifacts(raw_static, dynamic_output)
    for p_art in persistence_details:
        p_path = p_art.get("path")
        p_state = p_art.get("evidence_state", "STATIC")
        p_source = p_art.get("source", "Persistence Detection")
        if p_path:
            classified = IoCClassifier.classify(
                str(p_path),
                hint_type="FILE_PATH",
                source=p_source,
                source_type=p_state,
                evidence_state=p_state,
                first_seen=raw_static.get("submitted_at"),
                is_dynamic_observed=(p_state == "OBSERVED"),
            )
            rec = classified.model_dump()
            if rec["type"] == "FILE_PATH":
                rec["type"] = "PERSISTENCE_PATH"
                rec["related_behavior"] = "Persistence artifact identified"
            records.append(rec)

    # 7. Dynamic Process Executions
    if dyn_dict:
        for proc in dyn_dict.get("process_tree", []):
            if isinstance(proc, dict):
                cmd = proc.get("cmdline") or proc.get("process_name")
                pid = proc.get("pid")
                is_susp = bool(proc.get("is_suspicious"))
            else:
                cmd = getattr(proc, "cmdline", None) or getattr(proc, "process_name", None)
                pid = getattr(proc, "pid", None)
                is_susp = bool(getattr(proc, "is_suspicious", False))
            if cmd:
                records.append({
                    "indicator": str(cmd),
                    "display_value": truncate_display_value(str(cmd)),
                    "type": "PROCESS",
                    "source": "Dynamic Sandbox",
                    "source_type": "DYNAMIC",
                    "evidence_state": "OBSERVED",
                    "classification": "SUSPICIOUS" if is_susp else "UNKNOWN",
                    "confidence": "HIGH",
                    "first_seen": raw_static.get("submitted_at"),
                    "occurrence_count": 1,
                    "intel_corroborated": False,
                    "related_behavior": f"Process execution observed (PID {pid})" if pid else "Process execution observed",
                })

    # IoCClassifier also returns descriptive categories (SYMBOL, LIBRARY,
    # PACKAGE_ENTRY, SYSTEM_INFRASTRUCTURE, UNKNOWN). Those are useful while
    # parsing strings, but are not pivots and must not flow into report IoCs,
    # correlations, recommendations, or exports. Process rows are retained
    # only when sourced from observed dynamic process evidence.
    pivot_types = {"HASH", "HASH_SHA256", "HASH_SHA1", "HASH_MD5", "IP", "DOMAIN", "URL",
                   "SYSTEM_INFRASTRUCTURE",
                   "PERSISTENCE_PATH", "DROPPED_FILE"}
    return [
        record for record in records
        if (str(record.get("type", "")).upper() in pivot_types
            or (str(record.get("type", "")).upper() == "PROCESS"
                and str(record.get("evidence_state", "")).upper() == "OBSERVED"
                and str(record.get("source_type", "")).upper() == "DYNAMIC"))
    ]


def _build_evidence_correlations(raw_static: dict, dynamic_output: Optional[dict | DynamicAnalysisOutput], indicators: dict, mitre_techniques: list) -> list[dict]:
    """Join static observables with runtime behavior into traceable findings."""
    dyn_dict: Optional[dict] = None
    if dynamic_output is not None:
        if hasattr(dynamic_output, "model_dump"):
            dyn_dict = dynamic_output.model_dump()
        elif isinstance(dynamic_output, dict):
            dyn_dict = dynamic_output

    static_ips = set((raw_static.get("extracted_strings") or {}).get("ips") or [])
    cards: list[dict] = []

    for connection in (dyn_dict or {}).get("network_connections", []):
        ip = str(connection.get("dest_ip") or connection.get("ip") or "")
        if not ip:
            continue
        corroborated = ip in static_ips
        flagged = bool(connection.get("flagged_c2"))

        cards.append({
            "finding": f"Network endpoint {ip}:{connection.get('dest_port') or connection.get('port') or 'unknown'}",
            "static_evidence": f"Embedded endpoint {ip}" if corroborated else "No matching static endpoint observed",
            "dynamic_evidence": f"{connection.get('protocol') or 'Network'} connection observed",
            "correlation": "STATIC + DYNAMIC MATCH" if corroborated else "DYNAMIC-ONLY OBSERVATION",
            "confidence": "HIGH" if flagged or corroborated else "MEDIUM",
            "evidence_state": "OBSERVED",
            "severity": "HIGH" if flagged else "MEDIUM",
        })

    dyn_status = (dyn_dict.get("dynamic_status") if dyn_dict else None) or (dyn_dict.get("status") if dyn_dict else None)
    has_dyn_completed = bool(dyn_dict and dyn_status in ("completed", "no_behavior_observed"))

    for match in raw_static.get("yara_matches", []):
        cards.append({
            "finding": f"YARA: {match.get('rule_name', 'unknown')}",
            "static_evidence": match.get("description") or "Rule match",
            "dynamic_evidence": "Not available (dynamic analysis not performed)" if not has_dyn_completed else "Not available (static rule)",
            "correlation": "STATIC RULE EVIDENCE",
            "confidence": "HIGH" if match.get("severity") in ("high", "critical") else "MEDIUM",
            "evidence_state": "INTEL" if str(match.get("rule_name", "")).startswith("[MalwareBazaar]") else "STATIC",
            "source_type": "INTEL" if str(match.get("rule_name", "")).startswith("[MalwareBazaar]") else "STATIC",
            "source": "MalwareBazaar API" if str(match.get("rule_name", "")).startswith("[MalwareBazaar]") else "Local YARA scan",
            "severity": str(match.get("severity") or "medium").upper(),
        })

    for technique in mitre_techniques:
        tid = technique.get("technique_id") if isinstance(technique, dict) else getattr(technique, "technique_id", "")
        name = technique.get("technique_name") if isinstance(technique, dict) else getattr(technique, "technique_name", "")
        raw_state = (technique.get("evidence_state") if isinstance(technique, dict) else getattr(technique, "evidence_state", "STATIC")) or "STATIC"
        raw_state = str(raw_state).upper()

        if has_dyn_completed and raw_state == "OBSERVED":
            ev_state = "OBSERVED"
            dyn_ev = "See correlated runtime findings"
        else:
            ev_state = "STATIC"
            if not has_dyn_completed:
                dyn_ev = "Not available (dynamic analysis not performed)"
            else:
                dyn_ev = "Not available (no matching dynamic event observed)"

        cards.append({
            "finding": f"MITRE {tid}: {name}",
            "static_evidence": "Mapped from analysis evidence",
            "dynamic_evidence": dyn_ev,
            "correlation": "EVIDENCE-BASED MITRE MAPPING",
            "confidence": "MEDIUM",
            "evidence_state": ev_state,
            "severity": "MEDIUM",
        })

    return cards


def _build_evidence_timeline(submitted_at: str, dynamic_output: Optional[dict | DynamicAnalysisOutput], correlations: list[dict], stage_timestamps: Optional[dict] = None) -> list[dict]:
    dyn_dict: Optional[dict] = None
    if dynamic_output is not None:
        if hasattr(dynamic_output, "model_dump"):
            dyn_dict = dynamic_output.model_dump()
        elif isinstance(dynamic_output, dict):
            dyn_dict = dynamic_output

    stage_timestamps = stage_timestamps or {}
    static_ts = stage_timestamps.get("static")

    source_label = "Dynamic Sandbox"
    timeline = [
        {"seq": 1, "timestamp": submitted_at, "event": "Sample received", "source": "Ingestion", "indicator": "SHA-256 anchored artifact", "severity": "INFO"},
        {"seq": 2, "timestamp": static_ts, "event": "Static analysis completed", "source": "Static Analysis", "indicator": "YARA / metadata / IOC extraction", "severity": "INFO"},
    ]
    for stage in ("ingestion", "static", "intel"):
        timeline.append({"seq": len(timeline) + 1, "timestamp": stage_timestamps.get(stage), "timestamp_display": stage_timestamps.get(stage) or "not recorded", "event": f"{stage.title()} stage completed", "source": "Pipeline", "indicator": stage, "severity": "INFO"})
    for event in timeline:
        event.setdefault("timestamp_display", event.get("timestamp") or "not recorded")

    event_idx = len(timeline) + 1
    for conn in (dyn_dict or {}).get("network_connections", []):
        raw_ts = conn.get("timestamp")
        ts = raw_ts or None

        timeline.append({
            "seq": event_idx,
            "timestamp": ts,
            "event": "Network connection",
            "source": source_label,
            "indicator": f"{conn.get('dest_ip') or conn.get('ip') or 'unknown'}:{conn.get('dest_port') or conn.get('port') or '?'}",
            "severity": "HIGH" if conn.get("flagged_c2") else "MEDIUM",
            "timestamp_display": ts or "not recorded",
        })
        event_idx += 1

    for query in (dyn_dict or {}).get("dns_queries", []):
        timeline.append({
            "seq": event_idx,
            "timestamp": None,
            "event": "DNS query",
            "source": source_label,
            "indicator": str(query),
            "severity": "MEDIUM",
            "timestamp_display": "not recorded",
        })
        event_idx += 1

    if correlations:
        timeline.append({
            "seq": event_idx,
            "timestamp": None,
            "event": "Evidence correlation completed",
            "source": "Correlation Engine",
            "indicator": f"{len(correlations)} evidence link(s)",
            "severity": "INFO",
            "timestamp_display": "not recorded",
        })
    return timeline


GENERIC_YARA_RULES = {
    "md5_constants", "sha1_constants", "ripemd160_constants",
    "enterpriseapps2", "detectencryptedvariants"
}


def _build_risk_explanation(
    static_output: StaticAnalysisOutput | dict,
    mitre_techniques: list,
    capability_tags: list,
    risk_score: int,
    malware_bazaar: Optional[dict] = None,
    score_cap_reason: Optional[str] = None,
) -> dict:
    yara_matches = static_output.get("yara_matches", []) if isinstance(static_output, dict) else getattr(static_output, "yara_matches", [])
    
    # Calculate YARA points distinguishing generic vs family
    yara_points = 0
    seen_fams: set[str] = set()
    for ym in yara_matches:
        rname = ym.get("rule_name", "") if isinstance(ym, dict) else getattr(ym, "rule_name", "")
        rcat = ym.get("category", "") if isinstance(ym, dict) else getattr(ym, "category", "")
        name_low = rname.lower()
        if name_low in GENERIC_YARA_RULES or name_low.endswith("_constants") or "_constants" in name_low or rcat.lower() in ("crypto", "mass_hunt", "generic") or any(term in name_low or term in rcat.lower() for term in ("generic", "compiler", "hash_constant")):
            continue  # Generic rules contribute 0
        fam_key = rname.split("_")[0].lower() if "_" in rname else rname.lower()
        if fam_key not in seen_fams:
            seen_fams.add(fam_key)
            yara_points += 15
        else:
            yara_points += 5
    yara_points = min(yara_points, 40)

    def field(item, key, default=None):
        return item.get(key, default) if isinstance(item, dict) else getattr(item, key, default)

    static_mitre = sum(8 for t in mitre_techniques if str(field(t, "evidence_state", "STATIC")).upper() != "OBSERVED")
    observed_mitre = len(mitre_techniques) * 8 - static_mitre
    static_caps = sum(int(float(field(c, "confidence", 0)) * 15) for c in capability_tags if str(field(c, "evidence_state", "STATIC")).upper() != "OBSERVED")
    observed_caps = sum(int(float(field(c, "confidence", 0)) * 15) for c in capability_tags if str(field(c, "evidence_state", "STATIC")).upper() == "OBSERVED")
    static_total = static_mitre + static_caps
    if static_total > 20:
        static_caps = min(static_caps, 20)
        static_mitre = min(static_mitre, 20 - static_caps)

    parts = [
        {"rule": "yara", "label": "YARA detections", "points": yara_points, "kind": "rule"},
        {"rule": "mitre", "label": "Static MITRE techniques", "points": static_mitre, "kind": "rule"},
        {"rule": "capabilities", "label": "Static capability evidence", "points": static_caps, "kind": "rule"},
        {"rule": "observed_mitre", "label": "Observed MITRE techniques", "points": observed_mitre, "kind": "rule"},
        {"rule": "observed_capabilities", "label": "Observed capability evidence", "points": observed_caps, "kind": "rule"},
    ]
    rule_explained = sum(item["points"] for item in parts)

    intel_floor_applied = False
    intel_sig = (malware_bazaar or {}).get("signature") if malware_bazaar else None

    if risk_score > rule_explained:
        diff = risk_score - rule_explained
        if intel_sig:
            parts.append({
                "rule": "intel_floor",
                "label": f"Threat intelligence floor (MalwareBazaar intelligence floor - {intel_sig or 'confirmed malware'}): high-confidence known malware signature (raised to {risk_score})",
                "points": diff,
                "kind": "intel_floor",
            })
            intel_floor_applied = True
        else:
            parts.append({
                "rule": "deterministic_heuristics",
                "label": "Other deterministic behavior rules",
                "points": diff,
                "kind": "rule",
            })
    elif risk_score < rule_explained:
        # Explicit score cap adjustment line so sum(points) == risk_score EXACTLY
        diff = risk_score - rule_explained  # Negative value
        parts.append({
            "rule": "cap_adjustment",
            "label": "Score capping adjustment (score capped at maximum limit)",
            "points": diff,
            "kind": "cap",
        })

    result = {
        "score": risk_score,
        "contributions": [item for item in parts if item["points"] != 0],
        "method": "Deterministic weighted risk scoring",
    }
    if score_cap_reason:
        result["contributions"].append({"rule": "critical_gate", "label": score_cap_reason, "points": 0, "kind": "cap"})
    if intel_floor_applied:
        result["intel_floor_note"] = f"Score floor raised to {risk_score} by MalwareBazaar match (known family: {intel_sig})"
    return result


def normalize_malware_family(rule_name: str) -> str:
    """Extract a normalized malware family name from raw rule names."""
    if not rule_name:
        return ""
    name = str(rule_name).strip()
    if name.startswith("[MalwareBazaar]"):
        name = name[len("[MalwareBazaar]"):].strip()

    name_low = name.lower()
    if "community" in name_low or "generic" in name_low:
        return name

    for fam in ("Mirai", "Gafgyt", "Mozi", "Tsunami", "Qbot", "Hajime", "Bashlite", "Dofloo", "XorDdos", "ChamelGang"):
        if fam.lower() in name_low:
            return fam

    import re
    tokens = [t for t in re.split(r"[_.\-]", name) if t]
    _DISCARD = {"linux", "win32", "win64", "windows", "android", "elf", "pe", "osx", "macos", "trojan", "backdoor", "worm", "botnet", "ransomware", "virus", "rootkit", "miner", "dropper", "downloader"}
    meaningful = []
    for t in tokens:
        if t.lower() in _DISCARD:
            continue
        if len(t) >= 6 and re.fullmatch(r"[0-9a-fA-F]+", t):
            continue
        if re.fullmatch(r"variant\d*", t, re.IGNORECASE):
            continue
        meaningful.append(t)

    if len(meaningful) == 1:
        return meaningful[0]
    elif meaningful:
        return meaningful[0]
    return name


def _format_pdf_static_strings(explained_strings: list, max_items: int = 20) -> tuple[list, int]:
    """Format and cap explained strings for PDF static analysis layout."""
    if not explained_strings:
        return [], 0
    if len(explained_strings) <= max_items:
        return explained_strings, 0
    return explained_strings[:max_items], len(explained_strings) - max_items


def _build_threat_assessment(
    risk_score: int,
    yara_matches: list,
    mitre_techniques: list,
    capability_tags: list,
    has_dynamic: bool,
    malware_bazaar: Optional[dict] = None,
) -> dict:
    """Build an evidence-based threat assessment dict enriched with threat intel."""
    key_findings: list[str] = []
    has_intel_floor = bool(malware_bazaar and malware_bazaar.get("found") and malware_bazaar.get("signature"))
    family_labels = ("mirai", "gafgyt", "mozi", "tsunami", "qbot", "hajime", "bashlite", "dofloo", "xorddos", "chamelgang", "amos")
    family_hits = set()
    for match in yara_matches:
        rule_name = str(match.get("rule_name", "") if isinstance(match, dict) else getattr(match, "rule_name", "")).lower()
        category = str(match.get("category", "") if isinstance(match, dict) else getattr(match, "category", "")).lower()
        severity = str(match.get("severity", "") if isinstance(match, dict) else getattr(match, "severity", "")).lower()
        for family in family_labels:
            if family in rule_name and ("family_specific" in category or "high_confidence" in category or severity in {"high", "critical"}):
                family_hits.add(family)
    has_family_hit = bool(family_hits)
    corroborated = has_intel_floor or has_dynamic or has_family_hit
    if risk_score >= 85 and not corroborated:
        risk_score = 84
        key_findings.append("Score capped at 84: no threat-intelligence floor, observed behavior, or family-specific high-confidence hit.")

    if malware_bazaar and malware_bazaar.get("found"):
        sig = malware_bazaar.get("signature")
        if sig:
            key_findings.append(f"MalwareBazaar Intelligence: Confirmed malware signature '{sig}'")
            risk_score = max(risk_score, 85)
        tags = malware_bazaar.get("tags") or []
        if tags:
            key_findings.append(f"MalwareBazaar Threat Tags: {', '.join(tags)}")
        vendor_verdicts = malware_bazaar.get("vendor_verdicts") or []
        if vendor_verdicts:
            formatted_vv = [
                f"{v.get('vendor')}: {v.get('verdict')}" if isinstance(v, dict) else str(v)
                for v in vendor_verdicts[:3]
            ]
            key_findings.append(f"Threat Intel Vendor Detections: {', '.join(formatted_vv)}")

        # Check for family classification disagreement (e.g. Mirai vs Mozi)
        if sig:
            norm_sig = normalize_malware_family(sig)
            for ym in yara_matches:
                rname = ym.get("rule_name") if isinstance(ym, dict) else getattr(ym, "rule_name", "")
                norm_rname = normalize_malware_family(rname)
                if any(fam in rname.lower() or fam in norm_rname.lower() for fam in ("mirai", "mozi", "gafgyt", "tsunami", "qbot", "dropper")):
                    if norm_sig.lower() != norm_rname.lower() and sig.lower() not in rname.lower():
                        key_findings.append(
                            f"Sources disagree on family classification: MalwareBazaar reports {norm_sig}, "
                            f"while YARA matched {norm_rname}. These families share code and tooling; "
                            f"manual binary review is recommended."
                        )
                        break
    elif malware_bazaar:
        q_status = malware_bazaar.get("query_status", "unknown")
        if q_status in ("offline", "timeout") or "error" in str(q_status).lower():
            key_findings.append("Threat intelligence feed offline or unreachable; results based on local analysis.")
        elif q_status == "hash_not_found":
            key_findings.append("Sample hash not present in threat intelligence feeds (unreported/novel sample).")
        else:
            key_findings.append(f"Threat intelligence query returned no matching records ({q_status}).")

    if yara_matches:
        severities = [m.get("severity", "medium") if isinstance(m, dict) else getattr(m, "severity", "medium") for m in yara_matches]
        high_sev = [s for s in severities if s in ("high", "critical")]
        key_findings.append(
            f"{len(yara_matches)} YARA rule(s) matched"
            + (f" ({len(high_sev)} high/critical severity)" if high_sev else "")
        )

    if mitre_techniques:
        ids = [
            t.get("technique_id", str(t)) if isinstance(t, dict)
            else getattr(t, "technique_id", str(t))
            for t in mitre_techniques
        ]
        key_findings.append(
            f"MITRE ATT&CK techniques identified: {', '.join(ids[:5])}"
            + (f" +{len(ids) - 5} more" if len(ids) > 5 else "")
        )

    if capability_tags:
        caps_with_state = []
        confirmed_count = 0
        static_count = 0
        for c in capability_tags:
            c_name = c.get("capability", str(c)) if isinstance(c, dict) else getattr(c, "capability", str(c))
            c_state = (c.get("evidence_state") if isinstance(c, dict) else getattr(c, "evidence_state", None)) or "STATIC"
            c_state = str(c_state).upper()
            caps_with_state.append(f"{c_name} ({c_state})")
            if c_state in ("OBSERVED", "INTEL"):
                confirmed_count += 1
            else:
                static_count += 1
        key_findings.append(f"Capabilities identified: {confirmed_count} observed/intel, {static_count} static indicators ({', '.join(caps_with_state)})")

    if not key_findings:
        key_findings.append(
            "No high-confidence malicious indicators found from static analysis alone."
        )

    # Vendor confidence agreement calculation
    vendor_intel = (malware_bazaar.get("vendor_intel") or {}) if malware_bazaar else {}
    counted: list[str] = []
    agreeing = 0
    for vname, vdata in vendor_intel.items():
        verdict = (vdata.get("verdict") or vdata.get("detection") or vdata.get("threat_name")) if isinstance(vdata, dict) else vdata
        if is_unrated_vendor_label(verdict):
            continue
        counted.append(str(vname))
        if not is_clean_vendor_label(verdict):
            agreeing += 1

    mb_sig = (malware_bazaar or {}).get("signature") if malware_bazaar else None
    if mb_sig:
        counted.append("MalwareBazaar")
        agreeing += 1
    if counted:
        computed_conf = max(50, round(95 * agreeing / len(counted)))
        if len(counted) < 3:
            computed_conf = min(computed_conf, 70)
        if agreeing < len(counted):
            key_findings.append(f"Vendor disagreement observed ({agreeing}/{len(counted)} agree).")
        key_findings.append(f"Vendor consensus: ({agreeing}/{len(counted)}) vendors agree.")
    elif not has_intel_floor:
        computed_conf = 50
        key_findings.append("Verdict rests on static rules only; no vendor verdicts were rated.")
    else:
        computed_conf = 70

    family_rule_names = set()
    for match in yara_matches:
        rule_name = str(match.get("rule_name", "") if isinstance(match, dict) else getattr(match, "rule_name", "")).lower()
        family_rule_names.update(f for f in family_labels if f in rule_name)
    vendor_support = agreeing > 0
    if len(family_rule_names) >= 3 and not vendor_support and not has_intel_floor:
        key_findings.append("Conflicting family signatures detected; confidence reduced.")
        computed_conf = max(50, computed_conf - 15)

    if has_family_hit and not has_intel_floor and not has_dynamic:
        key_findings.append("Verdict rests on static rules only.")
    final_verdict = verdict_from_score(risk_score)
    if final_verdict == "MALICIOUS" and not corroborated:
        final_verdict = "SUSPICIOUS"
    final_threat_level = threat_level_from_score(risk_score)

    return {
        "risk_score": risk_score,
        "threat_level": final_threat_level,
        "verdict": final_verdict,
        "confidence": computed_conf,
        "key_findings": key_findings,
        "victim_impact": "critical" if final_threat_level == "CRITICAL" and (has_intel_floor or has_dynamic) else "high" if final_threat_level == "HIGH" else "medium" if final_threat_level == "MEDIUM" else "low",
    }


def _build_threat_intelligence_summary(sha256: Optional[str], malware_bazaar: Optional[dict]) -> dict:
    """Build a structured threat intelligence summary with clear provenance."""
    if malware_bazaar and malware_bazaar.get("found"):
        return {
            "provider": "MalwareBazaar (abuse.ch)",
            "query_hash": sha256 or malware_bazaar.get("sha256"),
            "status": "ok",
            "found": True,
            "signature": malware_bazaar.get("signature"),
            "tags": malware_bazaar.get("tags") or [],
            "vendor_intel": malware_bazaar.get("vendor_intel") or {},
            "vendor_verdicts": malware_bazaar.get("vendor_verdicts") or [],
            "first_seen": malware_bazaar.get("first_seen"),
            "last_seen": malware_bazaar.get("last_seen"),
            "bazaar_url": malware_bazaar.get("bazaar_url"),
            "evidence_state": "INTEL",
            "provenance": "External Threat Intelligence Feed",
        }
    elif malware_bazaar:
        return {
            "provider": "MalwareBazaar (abuse.ch)",
            "query_hash": sha256 or malware_bazaar.get("hash"),
            "status": malware_bazaar.get("query_status", "offline"),
            "found": False,
            "signature": None,
            "tags": [],
            "vendor_intel": {},
            "vendor_verdicts": [],
            "intel_note": malware_bazaar.get("intel_note", "No matching records or feed unreachable"),
            "evidence_state": "INTEL",
            "provenance": "External Threat Intelligence Feed",
        }
    else:
        return {
            "provider": "MalwareBazaar (abuse.ch)",
            "query_hash": sha256,
            "status": "unqueried",
            "found": False,
            "signature": None,
            "tags": [],
            "vendor_intel": {},
            "vendor_verdicts": [],
            "intel_note": "Threat intelligence lookup was not performed",
            "evidence_state": "INTEL",
            "provenance": "External Threat Intelligence Feed",
        }


def _generate_recommendations(
    verdict: str,
    risk_score: int,
    capabilities: list,
    mitre: list,
    network_indicators: dict,
    dynamic_output: Optional[dict] = None,
    existing_recommendations: Optional[list] = None,
    platform: Optional[str] = None,
    static_persistence_paths: Optional[list[str]] = None,
    intel_family: Optional[str] = None,
) -> list[str]:
    """
    Synthesizes actionable, evidence-based recommendations for incident responders.
    Derived from actual verdict, risk score, capabilities detected, and network C2 observables.
    """
    recs: list[str] = []
    seen: set[str] = set()

    def add_rec(text: str):
        cleaned = text.strip()
        key = cleaned.casefold()
        if cleaned and key not in seen:
            seen.add(key)
            recs.append(cleaned)

    # 1. Include pre-existing recommendations from investigation output
    if existing_recommendations:
        for r in existing_recommendations:
            if isinstance(r, dict):
                msg = r.get("description") or r.get("action") or str(r)
            else:
                msg = str(r)
            if msg and len(msg) > 5 and not msg.startswith("Recommendation("):
                add_rec(msg)

    # Extract capability names & MITRE techniques
    cap_names = {
        (c.capability if hasattr(c, "capability") else c.get("capability", "")).lower()
        for c in (capabilities or [])
        if (getattr(c, "capability", None) or (isinstance(c, dict) and c.get("capability")))
    }
    credential_caps = {"credential_access", "credential_dumping", "password_theft", "keylogging"}
    has_credential_evidence = any(
        (c.capability if hasattr(c, "capability") else c.get("capability", "")).lower() in credential_caps
        and str(c.evidence_state if hasattr(c, "evidence_state") else c.get("evidence_state", "STATIC")).upper() == "OBSERVED"
        for c in (capabilities or [])
    )
    infostealer_family = str(intel_family or "").strip()
    has_intel_credential = bool(infostealer_family and any(tag in infostealer_family.casefold() for tag in ("infostealer", "amos", "redline", "raccoon", "lumma", "vidar")))
    may_advise_credentials = has_credential_evidence or has_intel_credential
    mitre_ids = {
        (t.technique_id if hasattr(t, "technique_id") else t.get("technique_id", "")).upper()
        for t in (mitre or [])
        if (getattr(t, "technique_id", None) or (isinstance(t, dict) and t.get("technique_id")))
    }
    c2_ips = [
        c.get("ip") or c.get("dest_ip")
        for c in (network_indicators.get("connections") or [])
        if c.get("flagged_c2")
        and str(c.get("evidence_state") or "").upper() in {"OBSERVED", "INTEL"}
        and (c.get("ip") or c.get("dest_ip")) not in _PUBLIC_DNS_RESOLVERS
    ]
    for endpoint in (dynamic_output or {}).get("c2_endpoints_detected") or []:
        endpoint_ip = str(endpoint).rsplit(":", 1)[0]
        if endpoint_ip not in _PUBLIC_DNS_RESOLVERS and _is_valid_ipv4(endpoint_ip):
            c2_ips.append(endpoint_ip)
    c2_domains = network_indicators.get("domains") or []

    # 2. Urgent Containment & Host Isolation based on Verdict & Risk Score
    has_existing_isolation = any("isolate" in r.lower() for r in recs)
    if risk_score >= 70 or verdict == "MALICIOUS":
        if not has_existing_isolation:
            add_rec("Isolate infected endpoint(s) from the internal network immediately to halt command-and-control communication and lateral propagation.")
        plat_lower = str(platform or "").lower()
        if plat_lower == "android" and may_advise_credentials:
            add_rec("Revoke all active session tokens, OAuth grants, and mobile device credentials.")
        elif plat_lower in ("windows", "pe", "exe") and may_advise_credentials:
            add_rec("Revoke all active session tokens, Kerberos tickets, and stored credentials accessed from this endpoint.")
        else:
            if may_advise_credentials:
                add_rec("Revoke active SSH keys, local session credentials, and user tokens accessed from this endpoint.")
    elif risk_score >= 30 or verdict == "SUSPICIOUS":
        if not has_existing_isolation:
            add_rec("Quarantine the suspicious binary artifact and initiate continuous monitoring on host and perimeter network interfaces.")

    # 3. Network & C2 Blocking (Perimeter Firewall structured rules)
    if c2_ips:
        unique_ips = list(dict.fromkeys(str(ip) for ip in c2_ips))
        shown = unique_ips[:15]
        suffix = f"; and {len(unique_ips) - 15} more (see IoC table)" if len(unique_ips) > 15 else ""
        for ip in shown:
            add_rec(f"Firewall rule: iptables -A OUTPUT -d {ip} -j DROP")
        if suffix:
            add_rec(f"Firewall rule list truncated after 15 IPs{suffix}.")
    if c2_domains:
        suspicious_doms = [
            d for d in c2_domains
            if _is_valid_domain(d) and not any(d.endswith(x) for x in ("google.com", "android.com", "w3.org", "schema.org"))
        ]
        if suspicious_doms:
            add_rec(f"Sinkhole or blacklist malicious domain queries at internal DNS resolvers: {', '.join(suspicious_doms[:3])}.")

    # 4. Capability-Specific Remediation Actions
    if any("sms" in c for c in cap_names) or "T1517" in mitre_ids:
        add_rec("Audit linked financial accounts and notify mobile operators regarding potential SMS OTP interception and unauthorized transaction attempts.")
    if may_advise_credentials:
        family_note = f" (based on intel family match: {infostealer_family})" if has_intel_credential and not has_credential_evidence else ""
        add_rec(f"Enforce evidence-based credential resets{family_note}.")
    if any("overlay" in c or "phishing" in c for c in cap_names) or "T1417" in mitre_ids:
        add_rec("Inspect accessibility service permissions and overlay privileges (SYSTEM_ALERT_WINDOW) to remove rogue UI hijackers.")
    if any("reverse_shell" in c or "shell" in c for c in cap_names) or "T1059" in mitre_ids:
        add_rec("Audit active process trees for unauthorized command interpreters (/bin/sh, powershell.exe, cmd.exe) and terminate active reverse-shell sessions.")
    if any("location" in c or "gps" in c for c in cap_names) or "T1430" in mitre_ids:
        add_rec("Revoke background location permissions and check device admin configurations for unauthorized tracking services.")

    # 5. Persistence Removals
    persistence_artifacts = (dynamic_output or {}).get("persistence_artifacts") or []
    if persistence_artifacts:
        if str((dynamic_output or {}).get("execution_mode", "real")).lower() == "real" and (dynamic_output or {}).get("dynamic_status", "completed") == "completed":
            add_rec(f"Remove persistence artifacts identified during analysis: {'; '.join(str(p) for p in persistence_artifacts[:3])}.")
    elif static_persistence_paths:
        add_rec(f"Check hosts for these paths (static persistence indicators): {'; '.join(str(p) for p in static_persistence_paths[:3])}.")
    else:
        registry_changes = (dynamic_output or {}).get("registry_changes") or []
        if registry_changes:
            add_rec(f"Clean malicious autostart registry entries under HKCU/HKLM Run keys: {'; '.join(str(r) for r in registry_changes[:2])}.")

    # 6. Fallback if clean or no findings
    if not recs:
        if risk_score == 0 or verdict in ("CLEAN", "BENIGN", "LOW_RISK") or risk_score < 20:
            add_rec("No critical malicious indicators detected. Retain file hash in baseline repository for automated change tracking.")
            add_rec("Continue routine endpoint monitoring and ensure standard defense-in-depth policies remain active.")
        else:
            add_rec("No network or file indicators were produced. Block the SHA-256 and review the host manually.")

    if not may_advise_credentials:
        credential_terms = ("password", "oauth", "kerberos", "credential", "token rotation", "reset credentials", "session token", "ssh key")
        recs = [r for r in recs if not any(term in r.lower() for term in credential_terms)]
    has_observed = any(str(c.get("evidence_state", "STATIC") if isinstance(c, dict) else getattr(c, "evidence_state", "STATIC")).upper() == "OBSERVED" for c in (capabilities or [])) or bool((dynamic_output or {}).get("network_connections") or (dynamic_output or {}).get("files_written") or (dynamic_output or {}).get("persistence_artifacts"))
    if not has_observed:
        recs = [r for r in recs if not any(term in r.casefold() for term in ("kill ", "terminate ", "remove persistence", "delete "))]
    return recs


def _build_ai_analysis(
    final_state: dict,
    investigation_output: dict,
    network_indicators: dict,
    geo_iocs: list,
    threat_assessment: dict,
    malware_bazaar: Optional[dict] = None,
    static_persistence_paths: Optional[list[str]] = None,
) -> dict:
    """
    Assemble a structured AI analysis payload from real agent output and threat intel.
    Merges narrative summary, investigation engine output, network intelligence,
    MalwareBazaar attribution, and geo-ip context into a single structured object.
    """
    narrative = final_state.get("narrative_summary") or ""
    is_fallback = "[FALLBACK" in narrative or "Groq call failed" in narrative

    # Narrative output has already passed the evidence-scoped validator.
    # Investigation summaries are not normalized evidence and must not render.
    exec_summary = narrative or "Analysis completed; consult the normalized evidence sections for findings."

    # Enrich executive summary with confirmed MalwareBazaar intelligence
    if malware_bazaar and malware_bazaar.get("found"):
        mb_sig = malware_bazaar.get("signature")
        mb_tags = malware_bazaar.get("tags") or []
        mb_desc = f"Identified as known malware family '{mb_sig}' on MalwareBazaar" if mb_sig else f"Cataloged on MalwareBazaar (Tags: {', '.join(mb_tags)})"
        if is_fallback or not exec_summary or "Insufficient evidence" in exec_summary:
            exec_summary = f"[Threat Intelligence Confirmed] {mb_desc}. " + exec_summary
        else:
            exec_summary = f"{mb_desc}. " + exec_summary

    # Extract recommendations with evidence-based synthesis
    dyn_out = final_state.get("dynamic_output")
    dyn_dict = dyn_out.model_dump() if hasattr(dyn_out, "model_dump") else (dyn_out if isinstance(dyn_out, dict) else None)

    # Recommendations are actions for the investigator, not descriptions of
    # sample behavior. Accept only imperative, non-assertive advice from the
    # investigation output; all narrative and behavior fields come from the
    # evidence-validated narrative above.
    raw_recs = investigation_output.get("recommendations", [])
    action_verbs = ("check ", "review ", "monitor ", "retain ", "contact ", "enable ",
                    "update ", "revoke ", "quarantine ", "isolate ", "block ",
                    "audit ", "inspect ", "enforce ", "continue ", "ensure ",
                    "remove ", "clean ", "sinkhole ")
    assertion_terms = ("sample did", "sample has", "was observed", "was executed",
                       "identified as", "malware established", "attacker accessed")
    safe_recs: list[str] = []
    for recommendation in raw_recs:
        text = (recommendation.get("description") or recommendation.get("action") or "") if isinstance(recommendation, dict) else str(recommendation)
        text = str(text).strip()
        low = text.casefold()
        if low.startswith(action_verbs) and not any(term in low for term in assertion_terms):
            safe_recs.append(text)

    recommendations = _generate_recommendations(
        verdict=threat_assessment.get("verdict", "SUSPICIOUS"),
        risk_score=final_state.get("risk_score", 0),
        capabilities=final_state.get("capability_tags", []),
        mitre=final_state.get("mitre_techniques", []),
        network_indicators=network_indicators,
        dynamic_output=dyn_dict,
        existing_recommendations=safe_recs,
        platform=final_state.get("platform") or (final_state.get("static_output").platform if final_state.get("static_output") else None),
        static_persistence_paths=static_persistence_paths,
        intel_family=(malware_bazaar or {}).get("signature") if malware_bazaar and malware_bazaar.get("found") else None,
    )

    # Network interpretation (from real indicators only)
    network_interpretation = None
    if network_indicators.get("ips") or network_indicators.get("domains"):
        parts: list[str] = []
        if network_indicators["ips"]:
            c2_ips = [c["ip"] for c in network_indicators["connections"] if c.get("flagged_c2")]
            parts.append(f"{len(network_indicators['ips'])} unique IP(s) extracted.")
            if c2_ips:
                parts.append(f"Flagged C2 endpoints: {', '.join(c2_ips)}.")
        if network_indicators["domains"]:
            parts.append(f"{len(network_indicators['domains'])} domain(s) identified.")
        if network_indicators["urls"]:
            parts.append(f"{len(network_indicators['urls'])} URL(s) found in binary strings.")
        network_interpretation = " ".join(parts)

    # Geo-IP interpretation (from real lookups only)
    geoip_interpretation = None
    if geo_iocs:
        countries = list(dict.fromkeys(
            g.get("country") for g in geo_iocs if g.get("country")
        ))
        hosting = [g["ip"] for g in geo_iocs if g.get("is_hosting")]
        proxy = [g["ip"] for g in geo_iocs if g.get("is_proxy")]
        parts2: list[str] = [
            f"Network actors span {len(countries)} country/countries: {', '.join(countries[:5])}."
        ]
        if hosting:
            parts2.append(f"{len(hosting)} IP(s) identified as cloud/hosting infrastructure.")
        if proxy:
            parts2.append(f"{len(proxy)} IP(s) flagged as proxy/anonymization services.")
        from .geoip import GEOIP_DISCLAIMER
        parts2.append(GEOIP_DISCLAIMER)
        geoip_interpretation = " ".join(parts2)

    # MITRE explanations from real technique list
    mitre_techniques_explained: list[str] = [
        f"{t.get('technique_id') if isinstance(t, dict) else getattr(t, 'technique_id', '')}: "
        f"{t.get('technique_name') if isinstance(t, dict) else getattr(t, 'technique_name', '')}"
        for t in final_state.get("mitre_techniques", [])
    ]

    malware_behavior = narrative or "No behavior description is available; refer to the static and dynamic evidence sections."

    dyn_dict = final_state.get("dynamic_output")
    dyn_dict = dyn_dict.model_dump() if hasattr(dyn_dict, "model_dump") else (dyn_dict if isinstance(dyn_dict, dict) else {})
    observed_count = sum(len(dyn_dict.get(key) or []) for key in (
        "network_connections", "process_tree", "api_calls", "dns_queries",
        "files_written", "registry_changes", "persistence_artifacts",
    ))
    evidence_correlation = (
        f"{observed_count} dynamic observation(s) are present in the normalized report."
        if observed_count and (dyn_dict.get("dynamic_status") or dyn_dict.get("status")) not in {
            "unavailable", "not_supported", "no_behavior_observed", "failed", "timed_out", "incomplete"
        }
        else None
    )

    return {
        "executive_summary": exec_summary,
        "malware_behavior": malware_behavior,
        "evidence_correlation": evidence_correlation,
        "threat_classification": threat_assessment.get("verdict"),
        "network_interpretation": network_interpretation,
        "geoip_interpretation": geoip_interpretation,
        "mitre_techniques_explained": mitre_techniques_explained,
        "confidence": threat_assessment.get("confidence", 0),
        "reasoning": narrative if not is_fallback else None,
        "recommendations": recommendations,
        "ai_available": not is_fallback,
        "fallback_used": is_fallback,
    }


async def analyze_and_save(
    file_path: str | Path,
    event_type: str = "static_analysis_complete",
    extra_meta: dict | None = None,
) -> dict:
    """
    Runs the full pipeline against a file already on disk: static analysis
    engine -> LangGraph agent orchestrator -> persisted case. Returns the
    case_data dict (the shape CaseDetail expects). Raises
    UnsupportedFormatError for a format the engine can't handle; any other
    failure propagates so the caller (HTTP route or queue consumer) decides
    how to report it.

    The CPU-bound stages (binary parsing, the LangGraph run) are bounced to a
    worker thread so the event loop stays free — a client polling analysis
    status sees each stage transition instead of being stalled behind the
    parser.
    """
    file_path = Path(file_path)
    stage_timestamps = {"ingestion": datetime.now(timezone.utc).isoformat(), "static": None, "intel": None, "report": None}
    suffix = file_path.suffix.lower()
    is_json = suffix == ".json"
    is_bson = suffix == ".bson"
    
    if not is_json and not is_bson:
        try:
            with open(file_path, "rb") as f:
                prefix = f.read(100).strip()
            if prefix.startswith(b"{") or prefix.startswith(b"["):
                is_json = True
            elif len(prefix) >= 4:
                bson_size = struct.unpack("<I", prefix[:4])[0]
                if bson_size == file_path.stat().st_size:
                    is_bson = True
        except Exception:
            pass

    if is_json or is_bson:
        try:
            if is_json:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                with open(file_path, "rb") as f:
                    data = decode_bson(f.read())
        except Exception as exc:
            raise UnsupportedFormatError(f"Failed to parse JSON/BSON file: {exc}")

        if not isinstance(data, dict):
            raise UnsupportedFormatError("JSON/BSON file must contain a top-level object/document.")

        # ── Branch A: SubmitSampleRequest shape ── has a "static_analysis" key ────
        if "static_analysis" in data:
            static_part: dict = data["static_analysis"] if isinstance(data["static_analysis"], dict) else {}
            dynamic_part: Optional[dict] = data.get("dynamic_analysis") if isinstance(data.get("dynamic_analysis"), dict) else None

            # Build YaraMatch objects defensively
            raw_yara = static_part.get("yara_matches") or []
            yara_objs = []
            for m in raw_yara:
                if isinstance(m, dict):
                    yara_objs.append(YaraMatch(
                        rule_name=m.get("rule_name") or "unknown",
                        category=m.get("category") or "generic",
                        severity=m.get("severity") or "medium",
                        description=m.get("description"),
                    ))

            # Build ExtractedStrings
            es_raw = static_part.get("extracted_strings") or {}
            extracted_strings = _validated_extracted_strings(es_raw)

            # Build AndroidManifestInfo if present
            android_manifest = None
            am_raw = static_part.get("android_manifest")
            if am_raw and isinstance(am_raw, dict):
                android_manifest = AndroidManifestInfo(
                    package_name=am_raw.get("package_name") or "unknown",
                    permissions=am_raw.get("permissions") or [],
                    requested_sdk=am_raw.get("requested_sdk"),
                    exported_components=am_raw.get("exported_components") or [],
                )

            # Build PEAnalysisInfo if present
            pe_analysis = None
            pe_raw = static_part.get("pe_analysis")
            if pe_raw and isinstance(pe_raw, dict):
                pe_analysis = PEAnalysisInfo(
                    imports=pe_raw.get("imports") or [],
                    sections=pe_raw.get("sections") or [],
                    compile_timestamp=pe_raw.get("compile_timestamp"),
                )

            sample_id = (
                static_part.get("sample_id")
                or static_part.get("sha256")
                or data.get("sha256")
                or compute_sha256(file_path)
            )
            sha256_val = static_part.get("sha256") or sample_id

            # Query MalwareBazaar threat intelligence first
            mb_data = None
            try:
                mb_data = await malware_bazaar.lookup_hash(sha256_val)
                if not mb_data and data.get("md5"):
                    mb_data = await malware_bazaar.lookup_hash(data["md5"])
            except Exception as e:
                _LOGGER.warning(f"MalwareBazaar lookup failed: {e}")
            stage_timestamps["intel"] = datetime.now(timezone.utc).isoformat()

            if mb_data and mb_data.get("found"):
                for yrule in (mb_data.get("yara_rules") or []):
                    yara_objs.append(YaraMatch(
                        rule_name=f"[MalwareBazaar] {yrule.get('rule_name', 'Community_Yara')}",
                        category="threat_intel",
                        severity="high",
                        description=yrule.get("description") or f"Community YARA match from MalwareBazaar (Author: {yrule.get('author', 'abuse.ch')})",
                    ))

            static_output = StaticAnalysisOutput(
                sample_id=sample_id,
                sha256=sha256_val,
                platform=static_part.get("platform") or "windows",
                file_type=static_part.get("file_type") or "exe",
                file_size_bytes=static_part.get("file_size_bytes") or file_path.stat().st_size,
                submitted_at=static_part.get("submitted_at") or datetime.now(timezone.utc).isoformat(),
                yara_matches=yara_objs,
                android_manifest=android_manifest,
                pe_analysis=pe_analysis,
                extracted_strings=extracted_strings,
            )
            stage_timestamps["static"] = datetime.now(timezone.utc).isoformat()

            task_id = (dynamic_part or {}).get("task_id") or str(uuid.uuid4())
            dyn_obj = None
            if dynamic_part:
                dyn_obj = DynamicAnalysisOutput(
                    sample_id=sample_id,
                    execution_mode=dynamic_part.get("execution_mode", "real"),
                    dynamic_status=dynamic_part.get("dynamic_status") or dynamic_part.get("status", "completed"),
                    failure_reason=dynamic_part.get("failure_reason"),
                    status=dynamic_part.get("status", "completed"),
                    message=dynamic_part.get("message"),
                    target_architecture=dynamic_part.get("target_architecture"),
                    duration_seconds=dynamic_part.get("duration_seconds"),
                    process_tree=dynamic_part.get("process_tree") or [],
                    api_calls=dynamic_part.get("api_calls") or [],
                    network_connections=dynamic_part.get("network_connections") or [],
                    dns_queries=dynamic_part.get("dns_queries") or [],
                    files_written=dynamic_part.get("files_written") or [],
                    registry_changes=dynamic_part.get("registry_changes") or [],
                    persistence_artifacts=dynamic_part.get("persistence_artifacts") or [],
                    c2_endpoints_detected=dynamic_part.get("c2_endpoints_detected") or [],
                    task_id=task_id,
                )

            # Run orchestrator graph with MB intel and intel_floor (CPU-bound → thread)
            intel_floor = 85 if (mb_data and mb_data.get("signature")) else None
            initial_state = {
                "static_output": static_output,
                "dynamic_output": dyn_obj,
                "malware_bazaar": mb_data,
                "intel_floor": intel_floor,
                "task_id": task_id,
            }
            final_state = await asyncio.to_thread(_graph.invoke, initial_state)

            if intel_floor:
                final_state["risk_score"] = max(final_state.get("risk_score", 0), intel_floor)

            # Reconstruct raw_static dict for network indicator extraction
            raw_static_dict = {
                "sha256": static_output.sha256,
                "file_type": static_output.file_type,
                "platform": static_output.platform,
                "file_size_bytes": static_output.file_size_bytes,
                "submitted_at": static_output.submitted_at,
                "yara_matches": [m.model_dump() for m in static_output.yara_matches],
                "extracted_strings": {
                    "ips": extracted_strings.ips,
                    "urls": extracted_strings.urls,
                    "suspicious_keywords": extracted_strings.suspicious_keywords,
                },
                "explained_strings": data.get("explained_strings") or [],
            }

            # Network indicators from static + dynamic
            network_indicators = _extract_network_indicators(raw_static_dict, dynamic_part)
            geo_iocs = geoip.lookup_many(network_indicators["ips"])
            ioc_intelligence = _build_ioc_intelligence(raw_static_dict, dynamic_part, network_indicators, malware_bazaar=mb_data)
            geo_iocs = _reconcile_geoip_severity(geo_iocs, ioc_intelligence)
            evidence_correlation = _build_evidence_correlations(raw_static_dict, dynamic_part, network_indicators, final_state.get("mitre_techniques", []))
            evidence_timeline = _build_evidence_timeline(static_output.submitted_at, dynamic_part, evidence_correlation, stage_timestamps)
            risk_explanation = _build_risk_explanation(static_output, final_state.get("mitre_techniques", []), final_state.get("capability_tags", []), final_state["risk_score"], malware_bazaar=mb_data, score_cap_reason=final_state.get("risk_score_cap"))

            # Threat assessment from real signals
            threat_assessment = _build_threat_assessment(
                risk_score=final_state["risk_score"],
                yara_matches=raw_static_dict["yara_matches"],
                mitre_techniques=final_state.get("mitre_techniques", []),
                capability_tags=final_state.get("capability_tags", []),
                has_dynamic=dynamic_part is not None,
                malware_bazaar=mb_data,
            )

            # AI analysis
            investigation_output = final_state.get("investigation_output") or {}
            ai_analysis = _build_ai_analysis(
                final_state=final_state,
                investigation_output=investigation_output,
                network_indicators=network_indicators,
                geo_iocs=geo_iocs,
                threat_assessment=threat_assessment,
                malware_bazaar=mb_data,
            )

            persistence_artifacts_details = _extract_persistence_artifacts(raw_static_dict, dynamic_part)
            persistence_artifacts_paths = [a["path"] for a in persistence_artifacts_details]

            # Build the frontend-compatible dynamic_analysis shape
            if dynamic_part:
                dynamic_analysis_result: Optional[dict] = {
                    "available": True,
                    "execution_mode": dynamic_part.get("execution_mode", "real"),
                    "dynamic_status": dynamic_part.get("dynamic_status") or dynamic_part.get("status", "completed"),
                    "failure_reason": dynamic_part.get("failure_reason"),
                    "status": dynamic_part.get("status") or "completed",
                    "message": dynamic_part.get("message") or dynamic_part.get("details"),
                    "task_id": task_id,
                    "sandbox_url": dynamic_part.get("sandbox_url"),
                    "target_architecture": dynamic_part.get("target_architecture"),
                    # Preserve full sandbox data for PDF rendering
                    "network_connections": dynamic_part.get("network_connections") or [],
                    "c2_endpoints_detected": dynamic_part.get("c2_endpoints_detected") or [],
                    "process_tree": dynamic_part.get("process_tree") or [],
                    "api_calls": dynamic_part.get("api_calls") or [],
                    "dns_queries": dynamic_part.get("dns_queries") or [],
                    "files_written": dynamic_part.get("files_written") or [],
                    "registry_changes": dynamic_part.get("registry_changes") or [],
                    "persistence_artifacts": persistence_artifacts_paths,
                    "duration_seconds": dynamic_part.get("duration_seconds"),
                }
            else:
                dynamic_analysis_result = None

            case_data = {
                "sample_id": final_state["sample_id"],
                "platform": static_output.platform,
                "file_type": static_output.file_type,
                "file_size_bytes": static_output.file_size_bytes,
                "risk_score": final_state["risk_score"],
                "status": risk_score_to_status(final_state["risk_score"]),
                "mitre_techniques": [t.model_dump() for t in final_state["mitre_techniques"]],
                "capability_tags": [c.model_dump() for c in final_state["capability_tags"]],
                "narrative_summary": final_state["narrative_summary"],
                "submitted_at": static_output.submitted_at,
                "sha256": static_output.sha256,
                "md5": data.get("md5"),
                "sha1": data.get("sha1"),
                "yara_matches": raw_static_dict["yara_matches"],
                "packing": data.get("packing"),
                "explained_strings": raw_static_dict["explained_strings"],
                "geo_iocs": geo_iocs,
                "network_indicators": network_indicators,
                "threat_assessment": threat_assessment,
                "ai_analysis": ai_analysis,
                "ioc_intelligence": ioc_intelligence,
                "evidence_correlation": evidence_correlation,
                "evidence_timeline": evidence_timeline,
                "risk_explanation": risk_explanation,
                "persistence_artifacts": persistence_artifacts_paths,
                "persistence_artifacts_details": persistence_artifacts_details,
                "dynamic_analysis": dynamic_analysis_result,
                "malware_bazaar": mb_data,
                "threat_intelligence": _build_threat_intelligence_summary(raw_static_dict.get("sha256") or static_output.sha256, mb_data),
            }

        # ── Branch B: Raw CaseDetail dump ── import it directly ─────────────────
        else:
            case_data = dict(data)
            case_data.setdefault("sample_id", case_data.get("sha256") or compute_sha256(file_path))
            case_data.setdefault("sha256", case_data["sample_id"])
            case_data.setdefault("platform", "windows")
            case_data.setdefault("file_type", "exe")
            case_data.setdefault("file_size_bytes", file_path.stat().st_size)
            case_data.setdefault("risk_score", 0)
            case_data.setdefault("status", risk_score_to_status(case_data["risk_score"]))
            case_data.setdefault("mitre_techniques", [])
            case_data.setdefault("capability_tags", [])
            case_data.setdefault("narrative_summary", "Imported JSON/BSON case.")
            case_data.setdefault("submitted_at", datetime.now(timezone.utc).isoformat())
            case_data.setdefault("yara_matches", [])
            case_data.setdefault("explained_strings", [])
            # Enrich geo-IP if IPs are present but geo is missing
            if "geo_iocs" not in case_data:
                ips = (case_data.get("network_indicators") or {}).get("ips") or []
                case_data["geo_iocs"] = geoip.lookup_many(ips)
            # Build threat assessment if missing
            if "threat_assessment" not in case_data:
                case_data["threat_assessment"] = _build_threat_assessment(
                    risk_score=case_data["risk_score"],
                    yara_matches=case_data.get("yara_matches") or [],
                    mitre_techniques=case_data.get("mitre_techniques") or [],
                    capability_tags=case_data.get("capability_tags") or [],
                    has_dynamic=bool(case_data.get("dynamic_analysis")),
                )
            if "threat_intelligence" not in case_data:
                case_data["threat_intelligence"] = _build_threat_intelligence_summary(
                    case_data.get("sha256"),
                    case_data.get("malware_bazaar"),
                )

        if extra_meta:
            case_data.update(extra_meta)

        _finalize_report_quality(case_data, stage_timestamps)
        await store.save_case(case_data["sample_id"], case_data, event_type=event_type)
        return case_data
    try:
        import stat
        os.chmod(file_path, stat.S_IREAD | stat.S_IWRITE)
    except Exception:
        pass

    def _analyze_with_retry(path_str: str):
        import time
        last_exc = None
        for attempt in range(5):
            try:
                return _static_engine.analyze(path_str)
            except PermissionError as pe:
                last_exc = pe
                time.sleep(0.2 * (attempt + 1))
        if last_exc:
            raise last_exc
        return _static_engine.analyze(path_str)

    raw_static = await asyncio.to_thread(_analyze_with_retry, str(file_path))

    normalized_file_type = str(raw_static.get("file_type", "unknown")).lower()
    if normalized_file_type not in _SUPPORTED_FILE_TYPES:
        raise UnsupportedFormatError(
            f"Unsupported file format '{normalized_file_type}'. Supported: APK, PE/EXE/DLL, ELF, Mach-O."
        )

    platform = raw_static.get("platform")
    if platform not in ("android", "windows", "linux", "macos"):
        platform = (
            "android" if normalized_file_type == "apk"
            else "windows" if normalized_file_type in ("pe", "exe", "dll")
            else "linux" if normalized_file_type == "elf"
            else "macos"
        )

    yara_matches = [
        YaraMatch(
            rule_name=m["rule_name"],
            category=m["category"],
            severity="medium" if m["severity"] not in ("low", "medium", "high", "critical") else m["severity"],
            description=m["description"],
        )
        for m in raw_static.get("yara_matches", [])
    ]
    extracted_strings = _validated_extracted_strings(raw_static.get("extracted_strings", {}))

    # Preserve format-specific static evidence for the MITRE/capability rules.
    # The static engine already collected it in format_details; previously this
    # handoff discarded it, leaving the mapper with no APK permissions or PE imports.
    format_details = raw_static.get("format_details") or {}
    android_manifest = None
    pe_analysis = None
    if normalized_file_type == "apk" and format_details:
        permissions = [item.get("name") for item in format_details.get("requested_permissions", []) if item.get("name")]
        exported = [item.get("name") for group in ("activities", "services", "receivers", "providers") for item in format_details.get(group, []) if item.get("exported") and item.get("name")]
        android_manifest = AndroidManifestInfo(
            package_name=format_details.get("package_name") or "unknown",
            permissions=permissions,
            requested_sdk=int(format_details["target_sdk"]) if str(format_details.get("target_sdk", "")).isdigit() else None,
            exported_components=exported,
        )
    elif normalized_file_type in ("pe", "exe", "dll") and format_details:
        imports = [name for item in format_details.get("imports", []) for name in ([item.get("library")] + list(item.get("functions", []))) if name]
        pe_analysis = PEAnalysisInfo(
            imports=imports,
            sections=[item.get("name") for item in format_details.get("sections", []) if item.get("name")],
            compile_timestamp=str(format_details.get("compile_timestamp")) if format_details.get("compile_timestamp") else None,
        )

    # Query MalwareBazaar threat intelligence first
    mb_data = None
    try:
        mb_data = await malware_bazaar.lookup_hash(raw_static.get("sha256", ""))
        if not mb_data and raw_static.get("md5"):
            mb_data = await malware_bazaar.lookup_hash(raw_static["md5"])
    except Exception as e:
        _LOGGER.warning(f"MalwareBazaar lookup failed: {e}")
    stage_timestamps["intel"] = datetime.now(timezone.utc).isoformat()

    if mb_data and mb_data.get("found"):
        for yrule in (mb_data.get("yara_rules") or []):
            yara_matches.append(
                YaraMatch(
                    rule_name=f"[MalwareBazaar] {yrule.get('rule_name', 'Community_Yara')}",
                    category="threat_intel",
                    severity="high",
                    description=yrule.get("description") or f"Community YARA match from MalwareBazaar (Author: {yrule.get('author', 'abuse.ch')})",
                )
            )
            raw_static.setdefault("yara_matches", []).append({
                "rule_name": f"[MalwareBazaar] {yrule.get('rule_name', 'Community_Yara')}",
                "category": "threat_intel",
                "severity": "high",
                "description": yrule.get("description") or f"Community YARA match from MalwareBazaar (Author: {yrule.get('author', 'abuse.ch')})",
            })

    # Run dynamic analysis / sandbox simulation before the orchestrator graph
    dynamic_out: DynamicAnalysisOutput = await sandbox.run_dynamic_analysis(
        file_path,
        platform=platform,
        file_type=normalized_file_type,
        static_data=raw_static,
        malware_bazaar=mb_data,
    )

    static_output = StaticAnalysisOutput(
        sample_id=raw_static["sha256"],  # real SHA-256 as the canonical case ID
        sha256=raw_static["sha256"],
        platform=platform,
        file_type=normalized_file_type,
        file_size_bytes=raw_static["file_size_bytes"],
        submitted_at=raw_static["submitted_at"],
        yara_matches=yara_matches,
        android_manifest=android_manifest,
        pe_analysis=pe_analysis,
        extracted_strings=extracted_strings,
        static_risk_flags=["hardcoded_c2_ip"] if any(match.category == "network_indicator" for match in yara_matches) else [],
    )
    stage_timestamps["static"] = datetime.now(timezone.utc).isoformat()

    # Run orchestrator graph with populated dynamic_output and MB intel
    task_id = getattr(dynamic_out, "task_id", None) or str(uuid.uuid4())
    intel_floor = 85 if (mb_data and mb_data.get("signature")) else None
    initial_state = {
        "static_output": static_output,
        "dynamic_output": dynamic_out,
        "malware_bazaar": mb_data,
        "intel_floor": intel_floor,
        "task_id": task_id,
    }
    final_state = await asyncio.to_thread(_graph.invoke, initial_state)

    if intel_floor:
        final_state["risk_score"] = max(final_state.get("risk_score", 0), intel_floor)

    # Extract network indicators from static + dynamic sources (no fabrication)
    network_indicators = _extract_network_indicators(raw_static, dynamic_out)

    # Geo-IP enrichment of all extracted IPs
    all_ips = network_indicators["ips"]
    geo_iocs = geoip.lookup_many(all_ips)
    ioc_intelligence = _build_ioc_intelligence(raw_static, dynamic_out, network_indicators, malware_bazaar=mb_data)
    geo_iocs = _reconcile_geoip_severity(geo_iocs, ioc_intelligence)
    evidence_correlation = _build_evidence_correlations(raw_static, dynamic_out, network_indicators, final_state.get("mitre_techniques", []))
    evidence_timeline = _build_evidence_timeline(static_output.submitted_at, dynamic_out, evidence_correlation, stage_timestamps)
    risk_explanation = _build_risk_explanation(static_output, final_state.get("mitre_techniques", []), final_state.get("capability_tags", []), final_state["risk_score"], malware_bazaar=mb_data, score_cap_reason=final_state.get("risk_score_cap"))

    # Evidence-based threat assessment (scores derived from real signals only)
    threat_assessment = _build_threat_assessment(
        risk_score=final_state["risk_score"],
        yara_matches=raw_static.get("yara_matches", []),
        mitre_techniques=final_state.get("mitre_techniques", []),
        capability_tags=final_state.get("capability_tags", []),
        has_dynamic=dynamic_out is not None,
        malware_bazaar=mb_data,
    )

    persistence_artifacts_details = _extract_persistence_artifacts(raw_static, dynamic_out)
    persistence_artifacts_paths = [a["path"] for a in persistence_artifacts_details]
    static_persistence = [a["path"] for a in persistence_artifacts_details if a.get("evidence_state") == "STATIC"]

    # Structured AI analysis from investigation engine + narrative agent output
    investigation_output = final_state.get("investigation_output") or {}
    ai_analysis = _build_ai_analysis(
        final_state=final_state,
        investigation_output=investigation_output,
        network_indicators=network_indicators,
        geo_iocs=geo_iocs,
        threat_assessment=threat_assessment,
        malware_bazaar=mb_data,
        static_persistence_paths=static_persistence,
    )

    dynamic_dict = dynamic_out.model_dump()
    dynamic_analysis_result = {
        "available": True,
        "execution_mode": dynamic_dict.get("execution_mode", "real"),
        "dynamic_status": dynamic_dict.get("dynamic_status") or dynamic_dict.get("status", "completed"),
        "failure_reason": dynamic_dict.get("failure_reason"),
        "status": dynamic_dict.get("status", "completed"),
        "message": dynamic_dict.get("message"),
        "target_architecture": dynamic_dict.get("target_architecture"),
        "duration_seconds": dynamic_dict.get("duration_seconds"),
        "task_id": dynamic_dict.get("task_id") or task_id,
        "sandbox_url": sandbox.sandbox_url(),
        "network_connections": dynamic_dict.get("network_connections", []),
        "c2_endpoints_detected": dynamic_dict.get("c2_endpoints_detected", []),
        "process_tree": dynamic_dict.get("process_tree", []),
        "api_calls": dynamic_dict.get("api_calls", []),
        "dns_queries": dynamic_dict.get("dns_queries", []),
        "files_written": dynamic_dict.get("files_written", []),
        "registry_changes": dynamic_dict.get("registry_changes", []),
        "persistence_artifacts": persistence_artifacts_paths,
    }

    case_data = {
        "sample_id": final_state["sample_id"],
        "platform": static_output.platform,
        "file_type": static_output.file_type,
        "file_size_bytes": static_output.file_size_bytes,
        "risk_score": final_state["risk_score"],
        "status": risk_score_to_status(final_state["risk_score"]),
        "mitre_techniques": [t.model_dump() for t in final_state["mitre_techniques"]],
        "capability_tags": [c.model_dump() for c in final_state["capability_tags"]],
        "narrative_summary": final_state["narrative_summary"],
        "submitted_at": static_output.submitted_at,
        # Real hashes and richer static-analysis findings
        "sha256": raw_static.get("sha256"),
        "md5": raw_static.get("md5"),
        "sha1": raw_static.get("sha1"),
        "yara_matches": raw_static.get("yara_matches", []),
        "packing": raw_static.get("packing"),
        "explained_strings": raw_static.get("explained_strings", []),
        "geo_iocs": geo_iocs,
        "network_indicators": network_indicators,
        "threat_assessment": threat_assessment,
        "ai_analysis": ai_analysis,
        "ioc_intelligence": ioc_intelligence,
        "evidence_correlation": evidence_correlation,
        "evidence_timeline": evidence_timeline,
        "risk_explanation": risk_explanation,
        "persistence_artifacts": persistence_artifacts_paths,
        "persistence_artifacts_details": persistence_artifacts_details,
        # Part 2: Network Intelligence, Geo-IP, Threat Assessment, AI Analysis
        "geo_iocs": geo_iocs,
        "network_indicators": network_indicators,
        "threat_assessment": threat_assessment,
        "ai_analysis": ai_analysis,
        "ioc_intelligence": ioc_intelligence,
        "evidence_correlation": evidence_correlation,
        "evidence_timeline": evidence_timeline,
        "risk_explanation": risk_explanation,
        "dynamic_analysis": dynamic_analysis_result,
        "malware_bazaar": mb_data,
        "threat_intelligence": _build_threat_intelligence_summary(raw_static.get("sha256") or static_output.sha256, mb_data),
    }
    if extra_meta:
        case_data.update(extra_meta)  # e.g. original_filename / mime_type captured at upload time

    _finalize_report_quality(case_data, stage_timestamps)
    await store.save_case(case_data["sample_id"], case_data, event_type=event_type)
    return case_data


def compute_sha256(file_path: str | Path) -> str:
    """Chunked SHA-256 of a file on disk (used for upload dedup + canonical id)."""
    import hashlib
    import time
    import stat
    import os

    p = Path(file_path)
    try:
        os.chmod(p, stat.S_IREAD | stat.S_IWRITE)
    except Exception:
        pass

    h = hashlib.sha256()
    last_err = None
    for attempt in range(10):
        try:
            with open(p, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest()
        except PermissionError as pe:
            last_err = pe
            time.sleep(0.1 * (attempt + 1))
        except Exception as e:
            last_err = e
            time.sleep(0.05)

    if last_err:
        raise last_err
    return h.hexdigest()
