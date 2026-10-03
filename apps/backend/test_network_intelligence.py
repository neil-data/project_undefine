"""
Test script for Network Intelligence Module (Phase 7)

This script demonstrates and tests the complete network intelligence pipeline:
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

Usage:
    python test_network_intelligence.py --pcap-file path/to/capture.pcap
    python test_network_intelligence.py --interface eth0 --duration 30
"""

import asyncio
import argparse
import logging
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

from app.network_intelligence import NetworkIntelligenceOrchestrator
from app.db import init_db, get_db
from app.main import get_redis

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
_LOGGER = logging.getLogger(__name__)


async def run_pcap_test(pcap_file: str):
    """Test network intelligence with a PCAP file."""
    _LOGGER.info(f"Testing network intelligence with PCAP file: {pcap_file}")

    # Initialize database
    await init_db()
    db = get_db()

    # Get Redis client
    redis_client = await get_redis()

    # Create orchestrator
    orchestrator = NetworkIntelligenceOrchestrator(
        redis_client=redis_client,
        db_session=db,
        config={},
    )

    # Run analysis
    try:
        results = await orchestrator.start_analysis(
            pcap_file=pcap_file,
        )

        _LOGGER.info("Analysis completed successfully!")
        _LOGGER.info(f"Total packets processed: {results.get('total_packets_processed', 0)}")
        _LOGGER.info(f"DNS queries: {results.get('dns', {}).get('total_queries', 0)}")
        _LOGGER.info(f"HTTP requests: {results.get('http', {}).get('total_requests', 0)}")
        _LOGGER.info(f"TCP connections: {results.get('tcp', {}).get('total_connections', 0)}")
        _LOGGER.info(f"UDP flows: {results.get('udp', {}).get('total_flows', 0)}")
        _LOGGER.info(f"TLS fingerprints: {results.get('tls', {}).get('total_fingerprints', 0)}")

        # Print extracted domains
        domains = results.get('dns', {}).get('extracted_domains', [])
        if domains:
            _LOGGER.info(f"Extracted domains ({len(domains)}):")
            for domain in domains[:10]:  # Print first 10
                _LOGGER.info(f"  - {domain}")

        # Print extracted URLs
        urls = results.get('http', {}).get('extracted_urls', [])
        if urls:
            _LOGGER.info(f"Extracted URLs ({len(urls)}):")
            for url in urls[:10]:  # Print first 10
                _LOGGER.info(f"  - {url}")

        return results

    except Exception as e:
        _LOGGER.error(f"Error during analysis: {e}")
        raise
    finally:
        await db.close()


async def run_live_capture_test(interface: str, duration: int):
    """Test network intelligence with live capture."""
    _LOGGER.info(f"Testing network intelligence with live capture on {interface} for {duration}s")

    # Initialize database
    await init_db()
    db = get_db()

    # Get Redis client
    redis_client = await get_redis()

    # Create orchestrator
    orchestrator = NetworkIntelligenceOrchestrator(
        redis_client=redis_client,
        db_session=db,
        config={},
    )

    # Run analysis
    try:
        results = await orchestrator.start_analysis(
            interface=interface,
            duration=duration,
        )

        _LOGGER.info("Analysis completed successfully!")
        _LOGGER.info(f"Total packets processed: {results.get('total_packets_processed', 0)}")
        _LOGGER.info(f"DNS queries: {results.get('dns', {}).get('total_queries', 0)}")
        _LOGGER.info(f"HTTP requests: {results.get('http', {}).get('total_requests', 0)}")
        _LOGGER.info(f"TCP connections: {results.get('tcp', {}).get('total_connections', 0)}")
        _LOGGER.info(f"UDP flows: {results.get('udp', {}).get('total_flows', 0)}")

        return results

    except Exception as e:
        _LOGGER.error(f"Error during analysis: {e}")
        raise
    finally:
        await db.close()


async def run_list_interfaces_test():
    """Test listing available network interfaces."""
    from app.network_intelligence.capture import PacketCapture

    interfaces = PacketCapture.list_interfaces()
    _LOGGER.info(f"Available network interfaces:")
    for iface in interfaces:
        _LOGGER.info(f"  - {iface}")


async def main():
    parser = argparse.ArgumentParser(description="Test Network Intelligence Module")
    parser.add_argument("--pcap-file", help="Path to PCAP file for offline analysis")
    parser.add_argument("--interface", help="Network interface for live capture")
    parser.add_argument("--duration", type=int, default=30, help="Duration in seconds for live capture")
    parser.add_argument("--list-interfaces", action="store_true", help="List available network interfaces")

    args = parser.parse_args()

    if args.list_interfaces:
        await run_list_interfaces_test()
    elif args.pcap_file:
        if not Path(args.pcap_file).exists():
            _LOGGER.error(f"PCAP file not found: {args.pcap_file}")
            sys.exit(1)
        await run_pcap_test(args.pcap_file)
    elif args.interface:
        await run_live_capture_test(args.interface, args.duration)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
