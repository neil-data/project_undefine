"""
IOC Extractor — Extracts Indicators of Compromise from events in real-time.

Detects and enriches:
- IPs and domains from network events
- File hashes from file operations
- Email and phone patterns
- URLs and C2 infrastructure
"""

import re
import logging
from datetime import datetime
from typing import List, Optional, Dict, Set, Any
from uuid import UUID, uuid4
import ipaddress
import redis.asyncio as redis
from sqlalchemy.orm import Session

from .models.live_monitoring import (
    EnrichedEvent, IOC, IOCType, ThreatIntelligence, EventType
)
from .models.db_models import LiveIOC as LiveIOCDB

_LOGGER = logging.getLogger(__name__)


class IOCExtractor:
    """Extracts IOCs from events."""

    # Regex patterns
    IP_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )

    DOMAIN_PATTERN = re.compile(
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    )

    EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )

    PHONE_PATTERN = re.compile(
        r'(?:\+?1)?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}'
    )

    URL_PATTERN = re.compile(
        r'(?<![A-Za-z0-9_>:\*\\])https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:/[^\s\"\'<>]*)?'
    )

    # Known C2 and malicious IPs (mock data)
    KNOWN_C2_IPS = {
        "1.2.3.4",
        "10.0.0.1",
        "192.168.1.100",
    }

    KNOWN_C2_DOMAINS = {
        "malware.com",
        "c2.evil.net",
        "command.badguy.org",
    }

    def __init__(self, redis_client: redis.Redis, db_session: Session, config: Dict[str, Any]):
        self.redis = redis_client
        self.db = db_session
        self.config = config
        self.seen_iocs: Set[str] = set()  # Track seen IOCs to avoid duplicates

    async def extract_iocs(self, analysis_id: UUID, event: EnrichedEvent) -> List[IOC]:
        """Extract IOCs from event."""
        iocs = []

        if event.event_type == EventType.NETWORK:
            iocs.extend(await self._extract_network_iocs(analysis_id, event))
        elif event.event_type == EventType.FILE:
            iocs.extend(await self._extract_file_iocs(analysis_id, event))
        elif event.event_type == EventType.API:
            iocs.extend(await self._extract_api_iocs(analysis_id, event))

        # Deduplicate
        unique_iocs = {}
        for ioc in iocs:
            key = f"{ioc.ioc_type}:{ioc.ioc_value}"
            if key not in unique_iocs:
                unique_iocs[key] = ioc

        return list(unique_iocs.values())

    async def _extract_network_iocs(self, analysis_id: UUID, event: EnrichedEvent) -> List[IOC]:
        """Extract IPs, domains from network events."""
        iocs = []
        event_data = event.event_data

        # Extract destination IP
        dst_ip = event_data.get("dst_ip")
        if dst_ip and self._is_valid_ip(dst_ip):
            confidence = 100 if dst_ip in self.KNOWN_C2_IPS else 50

            threat_intel = None
            if dst_ip in self.KNOWN_C2_IPS:
                threat_intel = ThreatIntelligence(
                    known_c2=True,
                    threat_family="Emotet",
                    country="US",
                    asn="AS15169",
                    organization="Google LLC",
                    reputation_score=95
                )

            ioc = IOC(
                ioc_id=uuid4(),
                analysis_id=analysis_id,
                ioc_type=IOCType.IP,
                ioc_value=dst_ip,
                confidence=confidence,
                first_seen=event.timestamp,
                threat_intel=threat_intel,
                matching_rules=["network_event"],
            )

            iocs.append(ioc)

        # Extract domain
        domain = event_data.get("domain")
        if domain:
            confidence = 100 if domain in self.KNOWN_C2_DOMAINS else 30

            threat_intel = None
            if domain in self.KNOWN_C2_DOMAINS:
                threat_intel = ThreatIntelligence(
                    known_c2=True,
                    threat_family="Emotet",
                    reputation_score=95
                )

            ioc = IOC(
                ioc_id=uuid4(),
                analysis_id=analysis_id,
                ioc_type=IOCType.DOMAIN,
                ioc_value=domain,
                confidence=confidence,
                first_seen=event.timestamp,
                threat_intel=threat_intel,
                matching_rules=["network_event"],
            )

            iocs.append(ioc)

        return iocs

    async def _extract_file_iocs(self, analysis_id: UUID, event: EnrichedEvent) -> List[IOC]:
        """Extract file hashes from file events."""
        iocs = []
        event_data = event.event_data

        # Extract MD5
        md5 = event_data.get("hash_md5")
        if md5 and len(md5) == 32:
            ioc = IOC(
                ioc_id=uuid4(),
                analysis_id=analysis_id,
                ioc_type=IOCType.HASH,
                ioc_value=md5,
                confidence=90,
                first_seen=event.timestamp,
                matching_rules=["file_event"],
            )
            iocs.append(ioc)

        # Extract SHA256
        sha256 = event_data.get("hash_sha256")
        if sha256 and len(sha256) == 64:
            ioc = IOC(
                ioc_id=uuid4(),
                analysis_id=analysis_id,
                ioc_type=IOCType.HASH,
                ioc_value=sha256,
                confidence=90,
                first_seen=event.timestamp,
                matching_rules=["file_event"],
            )
            iocs.append(ioc)

        return iocs

    async def _extract_api_iocs(self, analysis_id: UUID, event: EnrichedEvent) -> List[IOC]:
        """Extract IOCs from API call arguments."""
        iocs = []
        event_data = event.event_data
        arguments = event_data.get("arguments", {})

        # Scan arguments for IOC patterns
        for arg_name, arg_value in arguments.items():
            if not isinstance(arg_value, str):
                continue

            # Check for IPs
            ips = self.IP_PATTERN.findall(arg_value)
            for ip in ips:
                if self._is_valid_ip(ip):
                    ioc = IOC(
                        ioc_id=uuid4(),
                        analysis_id=analysis_id,
                        ioc_type=IOCType.IP,
                        ioc_value=ip,
                        confidence=70,
                        first_seen=event.timestamp,
                        matching_rules=["api_argument"],
                    )
                    iocs.append(ioc)

            # Check for domains
            domains = self.DOMAIN_PATTERN.findall(arg_value)
            for domain in domains:
                if self._is_valid_domain(domain):
                    ioc = IOC(
                        ioc_id=uuid4(),
                        analysis_id=analysis_id,
                        ioc_type=IOCType.DOMAIN,
                        ioc_value=domain,
                        confidence=60,
                        first_seen=event.timestamp,
                        matching_rules=["api_argument"],
                    )
                    iocs.append(ioc)

            # Check for URLs
            urls = self.URL_PATTERN.findall(arg_value)
            for url in urls:
                if not self._is_valid_url(url):
                    continue
                ioc = IOC(
                    ioc_id=uuid4(),
                    analysis_id=analysis_id,
                    ioc_type=IOCType.URL,
                    ioc_value=url,
                    confidence=80,
                    first_seen=event.timestamp,
                    matching_rules=["api_argument"],
                )
                iocs.append(ioc)

            # Check for emails
            emails = self.EMAIL_PATTERN.findall(arg_value)
            for email in emails:
                ioc = IOC(
                    ioc_id=uuid4(),
                    analysis_id=analysis_id,
                    ioc_type=IOCType.EMAIL,
                    ioc_value=email,
                    confidence=85,
                    first_seen=event.timestamp,
                    matching_rules=["api_argument"],
                )
                iocs.append(ioc)

            # Check for phone numbers
            phones = self.PHONE_PATTERN.findall(arg_value)
            for phone in phones:
                ioc = IOC(
                    ioc_id=uuid4(),
                    analysis_id=analysis_id,
                    ioc_type=IOCType.PHONE,
                    ioc_value=phone,
                    confidence=70,
                    first_seen=event.timestamp,
                    matching_rules=["api_argument"],
                )
                iocs.append(ioc)

        return iocs

    async def save_ioc(self, ioc: IOC):
        """Save IOC to database."""
        try:
            # Check if already exists
            from sqlalchemy import select, and_

            stmt = select(LiveIOCDB).where(
                and_(
                    LiveIOCDB.analysis_id == ioc.analysis_id,
                    LiveIOCDB.ioc_value == ioc.ioc_value,
                    LiveIOCDB.ioc_type == ioc.ioc_type
                )
            )

            existing = self.db.execute(stmt).scalar_one_or_none()

            if existing:
                # Update last_seen
                existing.last_seen = datetime.utcnow()
            else:
                # Create new
                db_ioc = LiveIOCDB(
                    analysis_id=ioc.analysis_id,
                    ioc_id=ioc.ioc_id,
                    ioc_type=ioc.ioc_type,
                    ioc_value=ioc.ioc_value,
                    confidence=ioc.confidence,
                    first_seen=ioc.first_seen,
                    last_seen=ioc.last_seen,
                    threat_intel=ioc.threat_intel.model_dump() if ioc.threat_intel else None,
                    matching_rules=ioc.matching_rules,
                )
                self.db.add(db_ioc)

            self.db.commit()

        except Exception as e:
            _LOGGER.error(f"Error saving IOC: {e}")
            self.db.rollback()

    def _is_valid_ip(self, ip_str: str) -> bool:
        """Validate IP address, rejecting unspecified/reserved ranges and ASN.1 OID prefixes."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.version != 4:
                return False
            # Exclude unspecified (0.0.0.0), private, loopback, reserved, broadcast
            if ip.is_unspecified or ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast:
                return False
            if ip_str.startswith("0.") or ip_str == "255.255.255.255":
                return False
            # Reject common ASN.1 OID patterns like 1.3.6.1, 1.2.840...
            oids = ("1.3.6.1", "1.2.840", "2.16.840", "2.5.4", "0.9.2342", "1.3.14.3")
            if any(ip_str == prefix or ip_str.startswith(prefix + ".") for prefix in oids):
                return False
            return True
        except ValueError:
            return False

    def _is_valid_url(self, url: str) -> bool:
        """Validate URL to filter out protocol fragments or header names."""
        if len(url) < 10:
            return False
        lowered = url.lower()
        if any(lowered.startswith(bad) for bad in ("http/1.", "http/2", "httponly", "httpu", "http-equiv")):
            return False
        try:
            from urllib.parse import urlsplit
            parts = urlsplit(url)
            if parts.scheme.lower() not in ("http", "https"):
                return False
            host = parts.hostname or ""
            if not host or "." not in host or any(c in host for c in ('"', "'", "<", ">", "*", "^", "\\", "{", "}")):
                return False
            return True
        except Exception:
            return False

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain name."""
        # Exclude common false positives
        if len(domain) < 5 or domain.startswith("www"):
            return False
        if domain in ["localhost", "example.com", "test.com"]:
            return False
        return True
