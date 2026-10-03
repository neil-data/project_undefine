"""
Packet Capture Module — Uses Scapy to capture network traffic.

Supports:
- Live packet capture from network interfaces
- PCAP file reading for analysis
- Filtering based on protocols (TCP, UDP, DNS, HTTP, etc.)
- Buffered packet streaming to downstream parsers
"""

import logging
import asyncio
from typing import Optional, List, Callable, Any, TYPE_CHECKING
from pathlib import Path
from datetime import datetime
import queue
import threading

_LOGGER = logging.getLogger(__name__)

try:
    from scapy.all import sniff, rdpcap, TCP, UDP, DNS, HTTP, Raw, IP, IPv6, Ether
    from scapy.packet import Packet
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    _LOGGER.warning("Scapy not installed. Install with: pip install scapy")
    if TYPE_CHECKING:
        from scapy.packet import Packet
    else:
        Packet = object


class PacketCapture:
    """Captures network packets using Scapy."""

    def __init__(
        self,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        filter_expression: Optional[str] = None,
        buffer_size: int = 1000,
    ):
        """
        Initialize packet capture.

        Args:
            interface: Network interface to capture from (e.g., "eth0", "wlan0")
            pcap_file: Path to PCAP file for offline analysis
            filter_expression: BPF filter expression (e.g., "tcp port 80")
            buffer_size: Maximum packets to buffer before processing
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for packet capture. Install with: pip install scapy")

        self.interface = interface
        self.pcap_file = pcap_file
        self.filter_expression = filter_expression
        self.buffer_size = buffer_size

        self.packet_buffer: queue.Queue = queue.Queue(maxsize=buffer_size)
        self.is_capturing = False
        self.capture_thread: Optional[threading.Thread] = None
        self.packet_count = 0
        self.start_time: Optional[datetime] = None

        # Callback for packet processing
        self.packet_callback: Optional[Callable[[Packet], None]] = None

    def set_packet_callback(self, callback: Callable[[Packet], None]):
        """Set callback function to process captured packets."""
        self.packet_callback = callback

    def start_capture(self) -> bool:
        """Start packet capture."""
        if self.is_capturing:
            _LOGGER.warning("Capture already in progress")
            return False

        self.is_capturing = True
        self.start_time = datetime.now()
        self.packet_count = 0

        if self.pcap_file:
            # Offline capture from PCAP file
            self.capture_thread = threading.Thread(
                target=self._capture_from_file,
                daemon=True
            )
        else:
            # Live capture from interface
            self.capture_thread = threading.Thread(
                target=self._capture_live,
                daemon=True
            )

        self.capture_thread.start()
        _LOGGER.info(f"Started packet capture (interface={self.interface}, pcap={self.pcap_file})")
        return True

    def stop_capture(self):
        """Stop packet capture."""
        if not self.is_capturing:
            return

        self.is_capturing = False

        if self.capture_thread:
            self.capture_thread.join(timeout=5.0)

        duration = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        _LOGGER.info(f"Stopped capture. Captured {self.packet_count} packets in {duration:.2f}s")

    def _capture_live(self):
        """Capture packets live from network interface."""
        try:
            sniff(
                iface=self.interface,
                filter=self.filter_expression,
                prn=self._process_packet,
                stop_filter=lambda x: not self.is_capturing,
                store=False
            )
        except Exception as e:
            _LOGGER.error(f"Error during live capture: {e}")
            self.is_capturing = False

    def _capture_from_file(self):
        """Capture packets from PCAP file."""
        try:
            packets = rdpcap(self.pcap_file)
            _LOGGER.info(f"Loaded {len(packets)} packets from {self.pcap_file}")

            for packet in packets:
                if not self.is_capturing:
                    break

                self._process_packet(packet)

        except Exception as e:
            _LOGGER.error(f"Error reading PCAP file: {e}")
            self.is_capturing = False

    def _process_packet(self, packet: Packet):
        """Process a captured packet."""
        try:
            self.packet_count += 1

            # Add to buffer
            if not self.packet_buffer.full():
                self.packet_buffer.put(packet)
            else:
                _LOGGER.warning("Packet buffer full, dropping packet")

            # Call callback if set
            if self.packet_callback:
                self.packet_callback(packet)

        except Exception as e:
            _LOGGER.error(f"Error processing packet: {e}")

    def get_packet(self, timeout: float = 1.0) -> Optional[Packet]:
        """Get a packet from the buffer."""
        try:
            return self.packet_buffer.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_packets_batch(self, batch_size: int = 100, timeout: float = 1.0) -> List[Packet]:
        """Get a batch of packets from the buffer."""
        packets = []
        for _ in range(batch_size):
            try:
                packet = self.packet_buffer.get(timeout=timeout)
                if packet:
                    packets.append(packet)
            except queue.Empty:
                break
        return packets

    def get_stats(self) -> dict:
        """Get capture statistics."""
        duration = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        return {
            "is_capturing": self.is_capturing,
            "packet_count": self.packet_count,
            "duration_seconds": duration,
            "packets_per_second": self.packet_count / duration if duration > 0 else 0,
            "buffer_size": self.packet_buffer.qsize(),
            "interface": self.interface,
            "pcap_file": self.pcap_file,
            "filter": self.filter_expression,
        }

    @staticmethod
    def list_interfaces() -> List[str]:
        """List available network interfaces."""
        if not SCAPY_AVAILABLE:
            return []

        try:
            from scapy.all import get_if_list
            return get_if_list()
        except Exception as e:
            _LOGGER.error(f"Error listing interfaces: {e}")
            return []

    @staticmethod
    def validate_pcap_file(pcap_path: str) -> bool:
        """Validate if a PCAP file can be read."""
        if not SCAPY_AVAILABLE:
            return False

        try:
            path = Path(pcap_path)
            if not path.exists():
                return False

            # Try to read the file
            packets = rdpcap(pcap_path)
            return len(packets) > 0
        except Exception as e:
            _LOGGER.error(f"Error validating PCAP file: {e}")
            return False
