"""
Event Processor — consumes events from Redis, enriches with threat intel,
writes to PostgreSQL.
"""

import logging
import asyncio
import json
from datetime import datetime
from typing import Optional, Dict, List, Any
from uuid import UUID
import redis.asyncio as redis
from sqlalchemy.orm import Session

from .models.live_monitoring import (
    EnrichedEvent, EventType, ThreatIntelligence
)
from .models.db_models import AnalysisEvent
from . import malware_bazaar

_LOGGER = logging.getLogger(__name__)


class EventProcessor:
    """Enriches events with threat intelligence."""

    def __init__(self, redis_client: redis.Redis, db_session: Session, config: Dict[str, Any]):
        self.redis = redis_client
        self.db = db_session
        self.config = config

    async def process_event(self, event: EnrichedEvent) -> EnrichedEvent:
        """Enrich event with threat intel."""
        event_type = event.event_type
        event_data = event.event_data

        # Route enrichment based on event type
        if event_type == EventType.NETWORK:
            await self._enrich_network_event(event)
        elif event_type == EventType.FILE:
            await self._enrich_file_event(event)
        elif event_type == EventType.API:
            await self._enrich_api_event(event)

        return event

    async def _enrich_network_event(self, event: EnrichedEvent):
        """Enrich network event with GeoIP, threat intel."""
        dst_ip = event.event_data.get("dst_ip")
        domain = event.event_data.get("domain")

        if dst_ip:
            threat_intel = await self._lookup_ip(dst_ip)
            event.enrichment = threat_intel

            # Map to MITRE techniques
            if threat_intel and threat_intel.known_c2:
                event.mitre_techniques.append("T1071.001")  # C2 communication
                event.severity = "critical"

        if domain:
            await self._lookup_domain(domain)

    async def _enrich_file_event(self, event: EnrichedEvent):
        """Enrich file event with YARA, hash lookup."""
        path = event.event_data.get("path", "")
        hash_sha256 = event.event_data.get("hash_sha256")

        # Check for sensitive paths
        sensitive_paths = [
            "\\system32\\",
            "\\windows\\",
            "\\program files\\",
            "\\programdata\\",
            "\\appdata\\",
            "\\temp\\",
            "\\startup\\",
        ]

        if any(sp.lower() in path.lower() for sp in sensitive_paths):
            event.severity = "warning"
            event.mitre_techniques.append("T1574.001")  # DLL side-loading

        if hash_sha256:
            threat_intel = await self._lookup_hash(hash_sha256)
            if threat_intel:
                event.enrichment = threat_intel

    async def _enrich_api_event(self, event: EnrichedEvent):
        """Enrich API call with MITRE mapping."""
        api_name = event.event_data.get("api_name", "").lower()

        # Credential theft detection - highest priority
        # Check for specific credential theft APIs first
        credential_apis = [
            "readprocessmemory",
            "queryregistryvalue",
            "getclipboarddata",
            "dumpmemory",
            "readlsasecrets",
        ]
        
        if any(api in api_name for api in credential_apis):
            event.severity = "critical"
            event.mitre_techniques.append("T1005")  # Data staged for exfil
            return

        # Check for credential-related keywords in API name
        if any(
            pattern in api_name
            for pattern in ["credential", "password", "token", "secret", "key"]
        ):
            event.severity = "critical"
            event.mitre_techniques.append("T1005")  # Data staged for exfil
            return

        # Map APIs to MITRE techniques
        api_mitre_map = {
            "createprocess": "T1106",
            "createfilew": "T1083",
            "readprocessmemory": "T1005",
            "writefile": "T1005",
            "getclipboarddata": "T1115",
            "sendmessage": "T1005",
            "regsetvalueex": "T1112",
            "createremotethread": "T1055",
        }

        for api_pattern, technique in api_mitre_map.items():
            if api_pattern in api_name:
                event.mitre_techniques.append(technique)
                event.severity = "warning"
                break

    async def _lookup_ip(self, ip: str) -> Optional[ThreatIntelligence]:
        """Lookup IP in threat intel databases."""
        try:
            # Check Redis cache first
            cache_key = f"threat_intel:ip:{ip}"
            cached = await self.redis.get(cache_key)
            if cached:
                return ThreatIntelligence.model_validate_json(cached)

            # Implement actual threat intel lookups
            # Try to fetch from configured threat intel services
            threat_intel = ThreatIntelligence(known_c2=False)
            
            # Try VirusTotal if API key is configured
            vt_api_key = self.config.get("virustotal_api_key")
            if vt_api_key:
                try:
                    import httpx
                    async with httpx.AsyncClient() as client:
                        response = await client.get(
                            f"https://www.virustotal.com/vtapi/v2/ip_addresses/report",
                            params={"apikey": vt_api_key, "ip": ip},
                            timeout=10.0
                        )
                        if response.status_code == 200:
                            vt_data = response.json()
                            if vt_data.get("response_code") == 1:
                                threat_intel.known_c2 = True
                                threat_intel.virusTotal_score = vt_data.get("positives", 0)
                except Exception as e:
                    _LOGGER.warning(f"VirusTotal lookup failed for {ip}: {e}")

            # Try AbuseIPDB if API key is configured
            abuseipdb_key = self.config.get("abuseipdb_api_key")
            if abuseipdb_key:
                try:
                    import httpx
                    async with httpx.AsyncClient() as client:
                        response = await client.get(
                            f"https://api.abuseipdb.com/api/v2/check",
                            params={"ipAddress": ip, "maxAgeInDays": 90},
                            headers={"Key": abuseipdb_key},
                            timeout=10.0
                        )
                        if response.status_code == 200:
                            abuse_data = response.json()
                            data = abuse_data.get("data", {})
                            threat_intel.reputation_score = data.get("abuseConfidenceScore", 0)
                            threat_intel.country = data.get("countryCode")
                            threat_intel.organization = data.get("isp")
                except Exception as e:
                    _LOGGER.warning(f"AbuseIPDB lookup failed for {ip}: {e}")

            # Cache for 24 hours
            await self.redis.setex(cache_key, 86400, threat_intel.model_dump_json())

            return threat_intel

        except Exception as e:
            _LOGGER.error(f"Error looking up IP {ip}: {e}")
            return None

    async def _lookup_domain(self, domain: str) -> Optional[ThreatIntelligence]:
        """Lookup domain in threat intel databases."""
        try:
            cache_key = f"threat_intel:domain:{domain}"
            cached = await self.redis.get(cache_key)
            if cached:
                return ThreatIntelligence.model_validate_json(cached)

            # TODO: Implement actual threat intel lookups
            # - WHOIS
            # - DNS resolution
            # - VirusTotal
            # - Known malicious domain blocklists

            threat_intel = ThreatIntelligence(known_c2=False)

            await self.redis.setex(cache_key, 86400, threat_intel.model_dump_json())

            return threat_intel

        except Exception as e:
            _LOGGER.error(f"Error looking up domain {domain}: {e}")
            return None

    async def _lookup_hash(self, hash_: str) -> Optional[ThreatIntelligence]:
        """Lookup file hash in threat intel databases."""
        try:
            cache_key = f"threat_intel:hash:{hash_}"
            cached = await self.redis.get(cache_key)
            if cached:
                return ThreatIntelligence.model_validate_json(cached)

            # Threat intel lookup via MalwareBazaar
            threat_intel = ThreatIntelligence(known_c2=False)
            mb_data = await malware_bazaar.lookup_hash(hash_)
            if mb_data and mb_data.get("found"):
                threat_intel.known_c2 = True
                threat_intel.threat_family = mb_data.get("signature") or (mb_data.get("tags")[0] if mb_data.get("tags") else None)
                threat_intel.country = mb_data.get("origin_country")
                threat_intel.organization = "MalwareBazaar (abuse.ch)"
                threat_intel.reputation_score = 100

            await self.redis.setex(cache_key, 86400, threat_intel.model_dump_json())

            return threat_intel

        except Exception as e:
            _LOGGER.error(f"Error looking up hash {hash_}: {e}")
            return None

    async def write_to_db(self, event: EnrichedEvent):
        """Write enriched event to PostgreSQL."""
        try:
            db_event = AnalysisEvent(
                analysis_id=event.analysis_id,
                event_id=event.event_id,
                event_type=event.event_type,
                timestamp=event.timestamp,
                event_data=event.event_data,
                enrichment=event.enrichment.model_dump() if event.enrichment else None,
                mitre_techniques=event.mitre_techniques,
                severity=event.severity,
            )

            self.db.add(db_event)
            self.db.commit()

            _LOGGER.debug(f"Wrote event {event.event_id} to database")

        except Exception as e:
            _LOGGER.error(f"Error writing event to database: {e}")
            self.db.rollback()


class EventConsumer:
    """Consumes events from Redis stream and processes them."""

    def __init__(
        self,
        redis_client: redis.Redis,
        db_session: Session,
        processor: EventProcessor,
        config: Dict[str, Any],
    ):
        self.redis = redis_client
        self.db = db_session
        self.processor = processor
        self.config = config
        self.last_ids: Dict[UUID, str] = {}  # Track last processed ID per analysis

    async def start_consuming(self, analysis_id: UUID):
        """Start consuming events for an analysis."""
        _LOGGER.info(f"Starting event consumer for {analysis_id}")
        asyncio.create_task(self._consume_loop(analysis_id))

    async def stop_consuming(self, analysis_id: UUID):
        """Stop consuming events for an analysis."""
        if analysis_id in self.last_ids:
            del self.last_ids[analysis_id]

    async def _consume_loop(self, analysis_id: UUID):
        """Consume events in a loop."""
        stream_name = f"analysis:{analysis_id}:events"
        batch_size = self.config.get("consumer_batch_size", 10)

        while True:
            try:
                # Read from last known position or from beginning
                last_id = self.last_ids.get(analysis_id, "0")

                # Read events from stream
                events = await self.redis.xread(
                    {stream_name: last_id},
                    count=batch_size,
                    block=1000,  # Block for 1 second
                )

                if not events:
                    continue

                for stream, message_list in events:
                    for message_id, message_data in message_list:
                        try:
                            # Deserialize event
                            event_json = message_data.get(b"data", b"{}").decode()
                            event = EnrichedEvent.model_validate_json(event_json)

                            # Process event
                            event = await self.processor.process_event(event)

                            # Write to database
                            await self.processor.write_to_db(event)

                            # Update last ID
                            self.last_ids[analysis_id] = message_id.decode()

                        except Exception as e:
                            _LOGGER.error(f"Error processing event: {e}")

            except asyncio.CancelledError:
                break
            except Exception as e:
                _LOGGER.error(f"Error in event consumer loop: {e}")
                await asyncio.sleep(5)
