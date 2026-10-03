"""
Network Intelligence Orchestrator — Main pipeline coordinator

Orchestrates the complete network intelligence analysis loop:
1. Start Capture (PCAP capture with Scapy)
2. DNS Parser
3. HTTP Parser
4. HTTPS Metadata Parser
5. TCP Parser
6. UDP Parser
7. TLS Fingerprints Parser
8. IOC Extractor
9. GeoIP Lookup
10. Threat Intel Integration
11. Store Results
"""

import logging
import asyncio
from typing import Optional, Dict, List, Any
from datetime import datetime
from uuid import UUID, uuid4
import redis.asyncio as redis
from sqlalchemy.orm import Session

from .capture import PacketCapture
from .parsers import (
    DNSParser, HTTPParser, HTTPSMetadataParser,
    TCPParser, UDPParser, TLSFingerprintParser
)
from ..ioc_extractor import IOCExtractor
from ..geoip import lookup as geoip_lookup
from ..event_processor import EventProcessor
from ..models.live_monitoring import EnrichedEvent, EventType
from ..models.db_models import NetworkAnalysisResult

_LOGGER = logging.getLogger(__name__)


class NetworkIntelligenceOrchestrator:
    """Orchestrates the complete network intelligence analysis pipeline."""

    def __init__(
        self,
        redis_client: redis.Redis,
        db_session: Session,
        config: Dict[str, Any],
        analysis_id: Optional[UUID] = None,
    ):
        """
        Initialize the network intelligence orchestrator.

        Args:
            redis_client: Redis client for caching and streaming
            db_session: Database session for persistence
            config: Configuration dictionary
            analysis_id: Analysis ID for this run
        """
        self.redis = redis_client
        self.db = db_session
        self.config = config
        self.analysis_id = analysis_id or uuid4()

        # Initialize pipeline components
        self.capture: Optional[PacketCapture] = None
        self.dns_parser = DNSParser()
        self.http_parser = HTTPParser()
        self.https_parser = HTTPSMetadataParser()
        self.tcp_parser = TCPParser()
        self.udp_parser = UDPParser()
        self.tls_parser = TLSFingerprintParser()

        # Initialize enrichment components
        self.ioc_extractor = IOCExtractor(redis_client, db_session, config)
        self.event_processor = EventProcessor(redis_client, db_session, config)

        # Pipeline state
        self.is_running = False
        self.processed_packets = 0
        self.results: List[Dict[str, Any]] = []

    async def start_analysis(
        self,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        filter_expression: Optional[str] = None,
        duration: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Start the network intelligence analysis pipeline.

        Args:
            interface: Network interface for live capture
            pcap_file: PCAP file for offline analysis
            filter_expression: BPF filter for packet capture
            duration: Duration in seconds for live capture (None = indefinite)

        Returns:
            Analysis results summary
        """
        _LOGGER.info(f"Starting network intelligence analysis {self.analysis_id}")

        # Step 1: Start Capture
        self.capture = PacketCapture(
            interface=interface,
            pcap_file=pcap_file,
            filter_expression=filter_expression,
            buffer_size=1000,
        )

        # Set packet callback to process packets through the pipeline
        self.capture.set_packet_callback(self._process_packet_sync)

        # Start capture
        if not self.capture.start_capture():
            return {"error": "Failed to start packet capture"}

        self.is_running = True

        # Run for specified duration or indefinitely
        if duration:
            await asyncio.sleep(duration)
            self.capture.stop_capture()
        else:
            # For PCAP files, wait for completion
            if pcap_file:
                while self.capture.is_capturing:
                    await asyncio.sleep(0.1)

        # Wait for processing to complete
        await asyncio.sleep(1)

        # Final results
        final_results = await self._generate_final_results()
        await self._store_results(final_results)

        self.is_running = False

        _LOGGER.info(f"Network intelligence analysis {self.analysis_id} completed")
        return final_results

    def _process_packet_sync(self, packet):
        """Synchronous packet processing callback."""
        # Run async processing in event loop
        loop = asyncio.get_event_loop()
        loop.create_task(self._process_packet(packet))

    async def _process_packet(self, packet):
        """Process a single packet through the complete pipeline."""
        try:
            self.processed_packets += 1

            # Step 2: DNS Parser
            dns_result = self.dns_parser.parse(packet)

            # Step 3: HTTP Parser
            http_result = self.http_parser.parse(packet)

            # Step 4: HTTPS Metadata Parser
            https_result = self.https_parser.parse(packet)

            # Step 5: TCP Parser
            tcp_result = self.tcp_parser.parse(packet)

            # Step 6: UDP Parser
            udp_result = self.udp_parser.parse(packet)

            # Step 7: TLS Fingerprints Parser
            tls_result = self.tls_parser.parse(packet)

            # Combine results
            packet_result = {
                "packet_number": self.processed_packets,
                "timestamp": datetime.now().isoformat(),
                "dns": dns_result,
                "http": http_result,
                "https": https_result,
                "tcp": tcp_result,
                "udp": udp_result,
                "tls": tls_result,
            }

            # Step 8: Extract IOCs
            await self._extract_iocs_from_packet(packet_result)

            # Step 9: GeoIP Lookup
            await self._perform_geoip_lookup(packet_result)

            # Step 10: Threat Intel Integration
            await self._enrich_with_threat_intel(packet_result)

            # Store intermediate result
            self.results.append(packet_result)

            # Log progress periodically
            if self.processed_packets % 100 == 0:
                _LOGGER.info(f"Processed {self.processed_packets} packets")

        except Exception as e:
            _LOGGER.error(f"Error processing packet: {e}")

    async def _extract_iocs_from_packet(self, packet_result: Dict[str, Any]):
        """Extract IOCs from packet analysis results."""
        try:
            # Create enriched event for IOC extraction
            for protocol, result in packet_result.items():
                if protocol in ["dns", "http", "https", "tcp", "udp", "tls"] and result:
                    # Convert to EnrichedEvent format
                    event = EnrichedEvent(
                        analysis_id=self.analysis_id,
                        event_id=uuid4(),
                        event_type=EventType.NETWORK,
                        timestamp=datetime.now(),
                        event_data=result,
                        enrichment=None,
                        mitre_techniques=[],
                        severity="info",
                    )

                    # Extract IOCs
                    iocs = await self.ioc_extractor.extract_iocs(self.analysis_id, event)

                    # Add IOCs to packet result
                    packet_result[f"{protocol}_iocs"] = [ioc.model_dump() for ioc in iocs]

        except Exception as e:
            _LOGGER.error(f"Error extracting IOCs: {e}")

    async def _perform_geoip_lookup(self, packet_result: Dict[str, Any]):
        """Perform GeoIP lookups on extracted IPs."""
        try:
            # Collect all IPs from packet results
            ips = set()

            for protocol, result in packet_result.items():
                if protocol.endswith("_iocs") and isinstance(result, list):
                    for ioc in result:
                        if ioc.get("ioc_type") == "IP":
                            ips.add(ioc.get("ioc_value"))

                # Also check protocol results
                if protocol in ["tcp", "udp"] and result:
                    src_ip = result.get("src_ip")
                    dst_ip = result.get("dst_ip")
                    if src_ip:
                        ips.add(src_ip)
                    if dst_ip:
                        ips.add(dst_ip)

            # Perform GeoIP lookups
            geoip_results = {}
            for ip in ips:
                geo_data = geoip_lookup(ip)
                if geo_data:
                    geoip_results[ip] = geo_data

            packet_result["geoip"] = geoip_results

        except Exception as e:
            _LOGGER.error(f"Error performing GeoIP lookup: {e}")

    async def _enrich_with_threat_intel(self, packet_result: Dict[str, Any]):
        """Enrich results with threat intelligence."""
        try:
            # Enrich each event with threat intel
            for protocol, result in packet_result.items():
                if protocol in ["dns", "http", "https", "tcp", "udp", "tls"] and result:
                    event = EnrichedEvent(
                        analysis_id=self.analysis_id,
                        event_id=uuid4(),
                        event_type=EventType.NETWORK,
                        timestamp=datetime.now(),
                        event_data=result,
                        enrichment=None,
                        mitre_techniques=[],
                        severity="info",
                    )

                    enriched_event = await self.event_processor.process_event(event)

                    # Update result with enrichment
                    if enriched_event.enrichment:
                        result["threat_intel"] = enriched_event.enrichment.model_dump()
                    if enriched_event.mitre_techniques:
                        result["mitre_techniques"] = enriched_event.mitre_techniques
                    if enriched_event.severity:
                        result["severity"] = enriched_event.severity

        except Exception as e:
            _LOGGER.error(f"Error enriching with threat intel: {e}")

    async def _generate_final_results(self) -> Dict[str, Any]:
        """Generate final analysis results."""
        try:
            return {
                "analysis_id": str(self.analysis_id),
                "timestamp": datetime.now().isoformat(),
                "total_packets_processed": self.processed_packets,
                "capture_stats": self.capture.get_stats() if self.capture else {},
                "dns": {
                    "total_queries": len(self.dns_parser.queries),
                    "total_responses": len(self.dns_parser.responses),
                    "extracted_domains": self.dns_parser.get_extracted_domains(),
                    "dns_tunneling_indicators": self.dns_parser.get_dns_tunneling_indicators(),
                },
                "http": {
                    "total_requests": len(self.http_parser.requests),
                    "total_responses": len(self.http_parser.responses),
                    "extracted_urls": self.http_parser.get_extracted_urls(),
                    "user_agents": self.http_parser.get_user_agents(),
                },
                "https": {
                    "total_handshakes": len(self.https_parser.handshakes),
                    "sni_domains": self.https_parser.get_sni_domains(),
                },
                "tcp": {
                    "total_connections": len(self.tcp_parser.connections),
                    "connection_summary": self.tcp_parser.get_connection_summary(),
                },
                "udp": {
                    "total_flows": len(self.udp_parser.flows),
                    "flow_summary": self.udp_parser.get_flow_summary(),
                },
                "tls": {
                    "total_fingerprints": len(self.tls_parser.fingerprints),
                    "fingerprints": self.tls_parser.get_fingerprints(),
                },
                "packet_results": self.results[-100:],  # Last 100 packets
            }

        except Exception as e:
            _LOGGER.error(f"Error generating final results: {e}")
            return {"error": str(e)}

    async def _store_results(self, results: Dict[str, Any]):
        """Step 11: Store results in database."""
        try:
            db_result = NetworkAnalysisResult(
                analysis_id=self.analysis_id,
                timestamp=datetime.now(),
                total_packets_processed=results.get("total_packets_processed", 0),
                dns_data=results.get("dns"),
                http_data=results.get("http"),
                https_data=results.get("https"),
                tcp_data=results.get("tcp"),
                udp_data=results.get("udp"),
                tls_data=results.get("tls"),
                capture_stats=results.get("capture_stats"),
                raw_results=results,
            )

            self.db.add(db_result)
            self.db.commit()

            _LOGGER.info(f"Stored network intelligence results for {self.analysis_id}")

        except Exception as e:
            _LOGGER.error(f"Error storing results: {e}")
            self.db.rollback()

    def stop_analysis(self):
        """Stop the analysis pipeline."""
        if self.capture:
            self.capture.stop_capture()
        self.is_running = False
        _LOGGER.info(f"Stopped network intelligence analysis {self.analysis_id}")

    def get_status(self) -> Dict[str, Any]:
        """Get current analysis status."""
        return {
            "analysis_id": str(self.analysis_id),
            "is_running": self.is_running,
            "processed_packets": self.processed_packets,
            "capture_stats": self.capture.get_stats() if self.capture else {},
        }
