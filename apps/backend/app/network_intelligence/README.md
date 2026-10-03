# Network Intelligence Module — Phase 7

## Overview

The Network Intelligence Module implements a comprehensive network traffic analysis pipeline for the SentinelScan malware analysis platform. It follows the complete analysis loop specified in Phase 7:

```
Start Capture → DNS → HTTP → HTTPS Metadata → TCP → UDP → TLS Fingerprints → Extract IOC → GeoIP → Threat Intel → Store Results
```

## Architecture

### Components

1. **Packet Capture (`capture.py`)**
   - Uses Scapy for live network interface capture
   - Supports offline PCAP file analysis
   - BPF filtering support
   - Buffered packet streaming

2. **Protocol Parsers (`parsers.py`)**
   - **DNS Parser**: Extracts queries, responses, domains, detects DNS tunneling
   - **HTTP Parser**: Extracts requests, responses, URLs, headers, user agents
   - **HTTPS Metadata Parser**: Extracts TLS handshake metadata (SNI, cipher suites)
   - **TCP Parser**: Analyzes connections, flags, streams, connection state
   - **UDP Parser**: Analyzes datagrams, protocol detection (DNS, DHCP, NTP, SIP)
   - **TLS Fingerprint Parser**: Generates JA3/JA3S fingerprints for TLS detection

3. **Orchestrator (`orchestrator.py`)**
   - Coordinates the complete pipeline
   - Integrates with existing IOC extraction, GeoIP, and threat intel
   - Manages analysis lifecycle
   - Stores results in database

## Installation

### Dependencies

Add to `backend/requirements.txt`:
```
scapy>=2.5.0
```

Install dependencies:
```bash
cd backend
pip install -r requirements.txt
```

### Database Migration

The module adds a new table `network_analysis_results`. The schema is defined in `backend/app/models/db_models.py`.

## Usage

### Python API

```python
import asyncio
from app.network_intelligence import NetworkIntelligenceOrchestrator
from app.db import init_db, get_db
from app.main import get_redis

async def analyze_pcap(pcap_file: str):
    # Initialize database and Redis
    await init_db()
    db = get_db()
    redis_client = await get_redis()

    # Create orchestrator
    orchestrator = NetworkIntelligenceOrchestrator(
        redis_client=redis_client,
        db_session=db,
        config={},
    )

    # Run analysis
    results = await orchestrator.start_analysis(pcap_file=pcap_file)

    print(f"Processed {results['total_packets_processed']} packets")
    print(f"Found {len(results['dns']['extracted_domains'])} domains")
    print(f"Found {len(results['http']['extracted_urls'])} URLs")

    return results
```

### REST API

#### Start Analysis

```bash
# Analyze PCAP file
curl -X POST http://localhost:8000/api/network-intelligence/start \
  -H "Content-Type: application/json" \
  -d '{"pcap_file": "/path/to/capture.pcap"}'

# Live capture
curl -X POST http://localhost:8000/api/network-intelligence/start \
  -H "Content-Type: application/json" \
  -d '{"interface": "eth0", "duration": 60}'
```

#### Get Status

```bash
curl http://localhost:8000/api/network-intelligence/status/{analysis_id}
```

#### Get Results

```bash
curl http://localhost:8000/api/network-intelligence/results/{analysis_id}
```

#### List Interfaces

```bash
curl http://localhost:8000/api/network-intelligence/interfaces
```

### Test Script

```bash
# Test with PCAP file
python backend/test_network_intelligence.py --pcap-file path/to/capture.pcap

# Test with live capture
python backend/test_network_intelligence.py --interface eth0 --duration 30

# List available interfaces
python backend/test_network_intelligence.py --list-interfaces
```

## Pipeline Details

### 1. Start Capture

- **Live Capture**: Captures packets from network interface in real-time
- **PCAP Analysis**: Reads and processes existing PCAP files
- **Filtering**: Supports BPF filters (e.g., "tcp port 80")
- **Buffering**: Queues packets for downstream processing

### 2. DNS Parser

Extracts:
- DNS queries and responses
- Domain names from questions
- Record types (A, AAAA, MX, etc.)
- DNS tunneling indicators (long domains, high entropy)

### 3. HTTP Parser

Extracts:
- HTTP methods (GET, POST, etc.)
- URLs and paths
- Headers (User-Agent, Host, etc.)
- Response status codes
- Request/response bodies

### 4. HTTPS Metadata Parser

Extracts TLS handshake metadata without decryption:
- TLS version
- Cipher suites
- Server Name Indication (SNI)
- Extensions

### 5. TCP Parser

Analyzes:
- TCP connections (5-tuple)
- TCP flags (SYN, ACK, FIN, RST, etc.)
- Connection state tracking
- Stream statistics

### 6. UDP Parser

Analyzes:
- UDP flows
- Protocol detection (DNS, DHCP, NTP, SIP)
- Flow statistics

### 7. TLS Fingerprint Parser

Generates:
- JA3 fingerprints (client side)
- JA3S fingerprints (server side)
- Useful for malware C2 detection

### 8. IOC Extractor

Integrates with existing IOC extractor to find:
- IP addresses
- Domains
- URLs
- File hashes
- Email addresses
- Phone numbers

### 9. GeoIP Lookup

Integrates with existing GeoIP module to:
- Geolocate IP addresses
- Provide country, city, coordinates
- Requires MaxMind GeoLite2 database

### 10. Threat Intel Integration

Enriches with threat intelligence:
- Known C2 server detection
- Reputation scoring
- MITRE ATT&CK technique mapping
- Severity classification

### 11. Store Results

Persists to PostgreSQL:
- Complete analysis results
- Protocol-specific data
- Capture statistics
- Chain-of-custody information

## Output Format

```json
{
  "analysis_id": "uuid",
  "timestamp": "2026-08-06T00:00:00",
  "total_packets_processed": 1000,
  "dns": {
    "total_queries": 50,
    "total_responses": 50,
    "extracted_domains": ["example.com", "malware.org"],
    "dns_tunneling_indicators": []
  },
  "http": {
    "total_requests": 20,
    "total_responses": 20,
    "extracted_urls": ["http://example.com/path"],
    "user_agents": ["Mozilla/5.0..."]
  },
  "https": {
    "total_handshakes": 10,
    "sni_domains": ["example.com"]
  },
  "tcp": {
    "total_connections": 15,
    "connection_summary": [...]
  },
  "udp": {
    "total_flows": 30,
    "flow_summary": [...]
  },
  "tls": {
    "total_fingerprints": 10,
    "fingerprints": [...]
  }
}
```

## Integration Points

### Existing Components

- **IOC Extractor**: `backend/app/ioc_extractor.py`
- **GeoIP**: `backend/app/geoip.py`
- **Event Processor**: `backend/app/event_processor.py`
- **Database Models**: `backend/app/models/db_models.py`
- **Redis**: For caching and streaming

### Future Enhancements

- Real-time WebSocket streaming of results
- Integration with live monitoring dashboard
- Automated alerting on suspicious patterns
- PCAP generation from sandbox traffic
- Correlation with static analysis results

## Troubleshooting

### Scapy Permissions

Live packet capture requires elevated privileges:
```bash
sudo python test_network_intelligence.py --interface eth0
```

### Missing GeoIP Database

The GeoIP module requires MaxMind GeoLite2 database:
```bash
export GEOIP_DB_PATH=/path/to/GeoLite2-City.mmdb
```

### Redis Connection

Ensure Redis is running:
```bash
docker-compose up -d redis
```

## License

Part of SentinelScan — PS4 Malware Analysis Dashboard
E-Rakshak 2026 · Team HackersAPK
