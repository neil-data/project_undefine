"""
Network Protocol Parsers Module

Contains parsers for various network protocols:
- DNS Parser: Extracts DNS queries, responses, and domain information
- HTTP Parser: Extracts HTTP requests, responses, headers, and URLs
- HTTPS Metadata Parser: Extracts TLS handshake metadata without decryption
- TCP Parser: Analyzes TCP streams, flags, and connection state
- UDP Parser: Analyzes UDP datagrams and protocol-specific patterns
- TLS Fingerprint Parser: Generates JA3/JA3S fingerprints for TLS detection
"""

import logging
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
import hashlib
import struct

_LOGGER = logging.getLogger(__name__)

try:
    from scapy.all import DNS, DNSQR, DNSRR, TCP, UDP, Raw, IP, IPv6
    from scapy.packet import Packet
    from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
    from scapy.layers.tls.record import TLS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    Packet = Any  # Fallback type


class DNSParser:
    """Parses DNS packets to extract queries, responses, and domain information."""

    def __init__(self):
        self.queries: List[Dict[str, Any]] = []
        self.responses: List[Dict[str, Any]] = []

    def parse(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Parse a DNS packet."""
        if not SCAPY_AVAILABLE:
            return None

        if DNS not in packet:
            return None

        dns_layer = packet[DNS]

        result = {
            "timestamp": datetime.now().isoformat(),
            "type": "dns",
            "is_query": dns_layer.qr == 0,
            "is_response": dns_layer.qr == 1,
            "transaction_id": dns_layer.id,
            "questions": [],
            "answers": [],
            "authorities": [],
            "additionals": [],
            "flags": {
                "response": bool(dns_layer.qr),
                "opcode": dns_layer.opcode,
                "authoritative": bool(dns_layer.aa),
                "truncated": bool(dns_layer.tc),
                "recursion_desired": bool(dns_layer.rd),
                "recursion_available": bool(dns_layer.ra),
            },
        }

        # Parse questions
        if dns_layer.qd:
            for qd in dns_layer.qd:
                question = {
                    "name": qd.qname.decode('utf-8', errors='ignore') if hasattr(qd.qname, 'decode') else str(qd.qname),
                    "type": qd.qtype,
                    "class": qd.qclass,
                }
                result["questions"].append(question)

        # Parse answers
        if dns_layer.an:
            for an in dns_layer.an:
                answer = {
                    "name": an.rrname.decode('utf-8', errors='ignore') if hasattr(an.rrname, 'decode') else str(an.rrname),
                    "type": an.type,
                    "class": an.rclass,
                    "ttl": an.ttl,
                    "data": str(an.rdata) if hasattr(an, 'rdata') else None,
                }
                result["answers"].append(answer)

        # Parse authorities
        if dns_layer.ns:
            for ns in dns_layer.ns:
                authority = {
                    "name": ns.nsname.decode('utf-8', errors='ignore') if hasattr(ns.nsname, 'decode') else str(ns.nsname),
                    "type": ns.type,
                    "class": ns.nsclass,
                    "data": str(ns.nsdata) if hasattr(ns, 'nsdata') else None,
                }
                result["authorities"].append(authority)

        # Parse additionals
        if dns_layer.ar:
            for ar in dns_layer.ar:
                additional = {
                    "name": ar.rname.decode('utf-8', errors='ignore') if hasattr(ar.rname, 'decode') else str(ar.rname),
                    "type": ar.type,
                    "class": ar.rclass,
                    "data": str(ar.rdata) if hasattr(ar, 'rdata') else None,
                }
                result["additionals"].append(additional)

        # Store for later analysis
        if result["is_query"]:
            self.queries.append(result)
        else:
            self.responses.append(result)

        return result

    def get_extracted_domains(self) -> List[str]:
        """Extract all unique domains from DNS queries."""
        domains = set()
        for query in self.queries:
            for question in query.get("questions", []):
                domain = question.get("name", "").strip(".")
                if domain:
                    domains.add(domain)
        return list(domains)

    def get_dns_tunneling_indicators(self) -> List[Dict[str, Any]]:
        """Detect potential DNS tunneling based on query patterns."""
        indicators = []

        for query in self.queries:
            for question in query.get("questions", []):
                domain = question.get("name", "")

                # Check for unusually long domain names
                if len(domain) > 100:
                    indicators.append({
                        "type": "dns_tunneling",
                        "indicator": "long_domain_name",
                        "value": domain,
                        "length": len(domain),
                        "confidence": 0.7,
                    })

                # Check for high entropy (potential encoded data)
                if self._calculate_entropy(domain) > 4.5:
                    indicators.append({
                        "type": "dns_tunneling",
                        "indicator": "high_entropy_domain",
                        "value": domain,
                        "entropy": self._calculate_entropy(domain),
                        "confidence": 0.8,
                    })

        return indicators

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0.0

        from collections import Counter
        import math

        counts = Counter(string)
        total = len(string)
        entropy = 0.0

        for count in counts.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy


class HTTPParser:
    """Parses HTTP packets to extract requests, responses, headers, and URLs."""

    def __init__(self):
        self.requests: List[Dict[str, Any]] = []
        self.responses: List[Dict[str, Any]] = []

    def parse(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Parse an HTTP packet."""
        if not SCAPY_AVAILABLE:
            return None

        if Raw not in packet:
            return None

        payload = packet[Raw].load

        # Try to decode as text
        try:
            http_text = payload.decode('utf-8', errors='ignore')
        except:
            return None

        result = {
            "timestamp": datetime.now().isoformat(),
            "type": "http",
            "is_request": http_text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")),
            "is_response": http_text.startswith(("HTTP/1.0", "HTTP/1.1", "HTTP/2")),
            "data": http_text[:500],  # Truncate for storage
        }

        if result["is_request"]:
            request = self._parse_request(http_text)
            result.update(request)
            self.requests.append(result)
        elif result["is_response"]:
            response = self._parse_response(http_text)
            result.update(response)
            self.responses.append(result)

        return result

    def _parse_request(self, text: str) -> Dict[str, Any]:
        """Parse HTTP request."""
        lines = text.split('\r\n')
        if not lines:
            return {}

        first_line = lines[0].split()
        if len(first_line) < 2:
            return {}

        result = {
            "method": first_line[0],
            "url": first_line[1],
            "version": first_line[2] if len(first_line) > 2 else "HTTP/1.1",
            "headers": {},
            "body": "",
        }

        # Parse headers
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                result["headers"][key.strip()] = value.strip()
            elif line == '':
                # Empty line marks start of body
                body_start = lines.index(line) + 1
                result["body"] = '\r\n'.join(lines[body_start:])
                break

        return result

    def _parse_response(self, text: str) -> Dict[str, Any]:
        """Parse HTTP response."""
        lines = text.split('\r\n')
        if not lines:
            return {}

        first_line = lines[0].split()
        if len(first_line) < 2:
            return {}

        result = {
            "version": first_line[0],
            "status_code": int(first_line[1]) if len(first_line) > 1 and first_line[1].isdigit() else None,
            "status_message": ' '.join(first_line[2:]) if len(first_line) > 2 else "",
            "headers": {},
            "body": "",
        }

        # Parse headers
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                result["headers"][key.strip()] = value.strip()
            elif line == '':
                # Empty line marks start of body
                body_start = lines.index(line) + 1
                result["body"] = '\r\n'.join(lines[body_start:])
                break

        return result

    def get_extracted_urls(self) -> List[str]:
        """Extract all URLs from HTTP requests."""
        urls = []
        for request in self.requests:
            url = request.get("url", "")
            if url:
                urls.append(url)
        return urls

    def get_user_agents(self) -> List[str]:
        """Extract all User-Agent headers."""
        user_agents = []
        for request in self.requests:
            headers = request.get("headers", {})
            user_agent = headers.get("User-Agent", "")
            if user_agent:
                user_agents.append(user_agent)
        return user_agents


class HTTPSMetadataParser:
    """Parses TLS handshake metadata from HTTPS connections without decryption."""

    def __init__(self):
        self.handshakes: List[Dict[str, Any]] = []

    def parse(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Parse TLS handshake metadata."""
        if not SCAPY_AVAILABLE:
            return None

        # Check for TLS layer
        if TLS not in packet:
            return None

        tls_layer = packet[TLS]

        result = {
            "timestamp": datetime.now().isoformat(),
            "type": "https_metadata",
            "handshake_type": None,
            "tls_version": None,
            "cipher_suites": [],
            "extensions": [],
        }

        # Parse ClientHello
        if TLSClientHello in tls_layer:
            client_hello = tls_layer[TLSClientHello]
            result["handshake_type"] = "client_hello"
            result["tls_version"] = str(client_hello.version)

            # Extract cipher suites
            if hasattr(client_hello, 'cipher_suites'):
                result["cipher_suites"] = [str(cs) for cs in client_hello.cipher_suites]

            # Extract extensions
            if hasattr(client_hello, 'extensions'):
                result["extensions"] = [str(ext) for ext in client_hello.extensions]

        # Parse ServerHello
        elif TLSServerHello in tls_layer:
            server_hello = tls_layer[TLSServerHello]
            result["handshake_type"] = "server_hello"
            result["tls_version"] = str(server_hello.version)

            if hasattr(server_hello, 'cipher_suite'):
                result["cipher_suites"] = [str(server_hello.cipher_suite)]

        self.handshakes.append(result)
        return result

    def get_sni_domains(self) -> List[str]:
        """Extract Server Name Indication (SNI) domains from handshakes."""
        domains = []
        for handshake in self.handshakes:
            for ext in handshake.get("extensions", []):
                if "server_name" in ext.lower():
                    # Extract domain from extension string
                    try:
                        if ":" in ext:
                            domain = ext.split(":")[-1].strip()
                            if domain:
                                domains.append(domain)
                    except:
                        pass
        return domains


class TCPParser:
    """Parses TCP packets to analyze streams, flags, and connection state."""

    def __init__(self):
        self.connections: Dict[str, Dict[str, Any]] = {}
        self.tcp_streams: List[Dict[str, Any]] = []

    def parse(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Parse a TCP packet."""
        if not SCAPY_AVAILABLE:
            return None

        if TCP not in packet:
            return None

        tcp_layer = packet[TCP]
        ip_layer = packet[IP] if IP in packet else None

        if not ip_layer:
            return None

        # Create connection identifier
        connection_id = f"{ip_layer.src}:{tcp_layer.sport}-{ip_layer.dst}:{tcp_layer.dport}"

        result = {
            "timestamp": datetime.now().isoformat(),
            "type": "tcp",
            "connection_id": connection_id,
            "src_ip": ip_layer.src,
            "src_port": tcp_layer.sport,
            "dst_ip": ip_layer.dst,
            "dst_port": tcp_layer.dport,
            "flags": {
                "syn": bool(tcp_layer.flags & 0x02),
                "ack": bool(tcp_layer.flags & 0x10),
                "fin": bool(tcp_layer.flags & 0x01),
                "rst": bool(tcp_layer.flags & 0x04),
                "psh": bool(tcp_layer.flags & 0x08),
                "urg": bool(tcp_layer.flags & 0x20),
                "ece": bool(tcp_layer.flags & 0x40),
                "cwr": bool(tcp_layer.flags & 0x80),
            },
            "seq": tcp_layer.seq,
            "ack": tcp_layer.ack,
            "window": tcp_layer.window,
            "payload_size": len(tcp_layer.payload) if hasattr(tcp_layer, 'payload') else 0,
        }

        # Track connection state
        if connection_id not in self.connections:
            self.connections[connection_id] = {
                "start_time": result["timestamp"],
                "packet_count": 0,
                "bytes_sent": 0,
                "bytes_received": 0,
                "state": "new",
            }

        conn = self.connections[connection_id]
        conn["packet_count"] += 1
        conn["bytes_sent"] += result["payload_size"]

        # Determine connection state
        if result["flags"]["syn"] and not result["flags"]["ack"]:
            conn["state"] = "syn_sent"
        elif result["flags"]["syn"] and result["flags"]["ack"]:
            conn["state"] = "syn_received"
        elif result["flags"]["fin"]:
            conn["state"] = "closing"
        elif result["flags"]["rst"]:
            conn["state"] = "reset"

        result["connection_state"] = conn["state"]

        return result

    def get_connection_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all tracked connections."""
        return [
            {
                "connection_id": conn_id,
                **conn_data,
            }
            for conn_id, conn_data in self.connections.items()
        ]


class UDPParser:
    """Parses UDP packets to analyze datagrams and protocol-specific patterns."""

    def __init__(self):
        self.flows: Dict[str, Dict[str, Any]] = {}

    def parse(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Parse a UDP packet."""
        if not SCAPY_AVAILABLE:
            return None

        if UDP not in packet:
            return None

        udp_layer = packet[UDP]
        ip_layer = packet[IP] if IP in packet else None

        if not ip_layer:
            return None

        # Create flow identifier
        flow_id = f"{ip_layer.src}:{udp_layer.sport}-{ip_layer.dst}:{udp_layer.dport}"

        result = {
            "timestamp": datetime.now().isoformat(),
            "type": "udp",
            "flow_id": flow_id,
            "src_ip": ip_layer.src,
            "src_port": udp_layer.sport,
            "dst_ip": ip_layer.dst,
            "dst_port": udp_layer.dport,
            "length": udp_layer.len,
            "payload_size": len(udp_layer.payload) if hasattr(udp_layer, 'payload') else 0,
        }

        # Detect common UDP protocols
        if udp_layer.dport == 53 or udp_layer.sport == 53:
            result["protocol"] = "dns"
        elif udp_layer.dport == 67 or udp_layer.sport == 67:
            result["protocol"] = "dhcp"
        elif udp_layer.dport == 123 or udp_layer.sport == 123:
            result["protocol"] = "ntp"
        elif udp_layer.dport == 5060 or udp_layer.sport == 5060:
            result["protocol"] = "sip"
        else:
            result["protocol"] = "unknown"

        # Track flow
        if flow_id not in self.flows:
            self.flows[flow_id] = {
                "start_time": result["timestamp"],
                "packet_count": 0,
                "bytes": 0,
            }

        self.flows[flow_id]["packet_count"] += 1
        self.flows[flow_id]["bytes"] += result["payload_size"]

        return result

    def get_flow_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all tracked UDP flows."""
        return [
            {
                "flow_id": flow_id,
                **flow_data,
            }
            for flow_id, flow_data in self.flows.items()
        ]


class TLSFingerprintParser:
    """Generates JA3/JA3S fingerprints for TLS detection."""

    def __init__(self):
        self.fingerprints: List[Dict[str, Any]] = []

    def parse(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Parse TLS handshake and generate fingerprint."""
        if not SCAPY_AVAILABLE:
            return None

        if TLS not in packet:
            return None

        tls_layer = packet[TLS]

        result = {
            "timestamp": datetime.now().isoformat(),
            "type": "tls_fingerprint",
            "fingerprint": None,
            "fingerprint_type": None,
        }

        # Generate JA3 fingerprint for ClientHello
        if TLSClientHello in tls_layer:
            client_hello = tls_layer[TLSClientHello]
            ja3 = self._generate_ja3(client_hello)
            result["fingerprint"] = ja3
            result["fingerprint_type"] = "ja3"

        # Generate JA3S fingerprint for ServerHello
        elif TLSServerHello in tls_layer:
            server_hello = tls_layer[TLSServerHello]
            ja3s = self._generate_ja3s(server_hello)
            result["fingerprint"] = ja3s
            result["fingerprint_type"] = "ja3s"

        if result["fingerprint"]:
            self.fingerprints.append(result)

        return result

    def _generate_ja3(self, client_hello) -> str:
        """Generate JA3 fingerprint from ClientHello."""
        try:
            # JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
            parts = []

            # SSL Version
            version = str(client_hello.version) if hasattr(client_hello, 'version') else ""
            parts.append(version)

            # Cipher Suites
            ciphers = []
            if hasattr(client_hello, 'cipher_suites'):
                ciphers = [str(cs) for cs in client_hello.cipher_suites]
            parts.append(','.join(ciphers))

            # Extensions
            extensions = []
            if hasattr(client_hello, 'extensions'):
                extensions = [str(ext) for ext in client_hello.extensions]
            parts.append(','.join(extensions))

            # Elliptic Curves
            curves = []
            if hasattr(client_hello, 'elliptic_curves'):
                curves = [str(curve) for curve in client_hello.elliptic_curves]
            parts.append(','.join(curves))

            # Elliptic Curve Point Formats
            point_formats = []
            if hasattr(client_hello, 'ec_point_formats'):
                point_formats = [str(pf) for pf in client_hello.ec_point_formats]
            parts.append(','.join(point_formats))

            # Generate MD5 hash
            ja3_string = ','.join(parts)
            return hashlib.md5(ja3_string.encode()).hexdigest()

        except Exception as e:
            _LOGGER.error(f"Error generating JA3 fingerprint: {e}")
            return ""

    def _generate_ja3s(self, server_hello) -> str:
        """Generate JA3S fingerprint from ServerHello."""
        try:
            # JA3S format: SSLVersion,Cipher,Extension
            parts = []

            # SSL Version
            version = str(server_hello.version) if hasattr(server_hello, 'version') else ""
            parts.append(version)

            # Cipher Suite
            cipher = str(server_hello.cipher_suite) if hasattr(server_hello, 'cipher_suite') else ""
            parts.append(cipher)

            # Extension
            extensions = []
            if hasattr(server_hello, 'extensions'):
                extensions = [str(ext) for ext in server_hello.extensions]
            parts.append(','.join(extensions))

            # Generate MD5 hash
            ja3s_string = ','.join(parts)
            return hashlib.md5(ja3s_string.encode()).hexdigest()

        except Exception as e:
            _LOGGER.error(f"Error generating JA3S fingerprint: {e}")
            return ""

    def get_fingerprints(self) -> List[Dict[str, Any]]:
        """Get all collected TLS fingerprints."""
        return self.fingerprints
