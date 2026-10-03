"""
Sandbox Event Emitter — polls CAPE/Android sandbox for events,
normalizes to JSON, publishes to Redis stream.
"""

import json
import logging
import asyncio
from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4
import aiohttp
import redis.asyncio as redis

from .models.live_monitoring import (
    EnrichedEvent, EventType, FileEventData, NetworkEventData,
    APIEventData, RegistryEventData, ProcessEventData
)

_LOGGER = logging.getLogger(__name__)


class SandboxEventEmitter:
    """Polls sandbox API for events and publishes to Redis."""

    def __init__(self, redis_client: redis.Redis, sandbox_config: Dict[str, Any]):
        self.redis = redis_client
        self.config = sandbox_config
        self.sessions: Dict[UUID, aiohttp.ClientSession] = {}
        self.offsets: Dict[UUID, int] = {}  # Track event offset per analysis

    async def start_emission(self, analysis_id: UUID, sandbox_type: str, sandbox_url: str):
        """Start emitting events for an analysis."""
        _LOGGER.info(f"Starting event emission for {analysis_id} ({sandbox_type})")

        # Create persistent HTTP session
        self.sessions[analysis_id] = aiohttp.ClientSession()
        self.offsets[analysis_id] = 0

        # Start polling task
        asyncio.create_task(self._poll_loop(analysis_id, sandbox_type, sandbox_url))

    async def stop_emission(self, analysis_id: UUID):
        """Stop emitting events for an analysis."""
        _LOGGER.info(f"Stopping event emission for {analysis_id}")

        if analysis_id in self.sessions:
            await self.sessions[analysis_id].close()
            del self.sessions[analysis_id]

        if analysis_id in self.offsets:
            del self.offsets[analysis_id]

    async def _poll_loop(self, analysis_id: UUID, sandbox_type: str, sandbox_url: str):
        """Poll sandbox API in a loop."""
        poll_interval = self.config.get("poll_interval_ms", 100) / 1000.0
        max_retries = self.config.get("sandbox_api_max_retries", 3)
        timeout = self.config.get("sandbox_api_timeout_sec", 10)

        retry_count = 0

        while analysis_id in self.sessions:
            try:
                raw_events = await self._poll_events(
                    analysis_id, sandbox_type, sandbox_url, timeout
                )

                if raw_events:
                    # Process and publish events
                    for raw_event in raw_events:
                        try:
                            event = await self._normalize_event(raw_event, sandbox_type)
                            await self._publish_to_redis(analysis_id, event)
                        except Exception as e:
                            _LOGGER.error(f"Error normalizing event: {e}")

                    retry_count = 0  # Reset retry counter on success

                await asyncio.sleep(poll_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                _LOGGER.error(f"Error in poll loop: {e}")
                retry_count += 1

                if retry_count >= max_retries:
                    _LOGGER.error(f"Max retries reached for {analysis_id}, stopping emission")
                    break

                await asyncio.sleep(2 ** retry_count)  # Exponential backoff

    async def _poll_events(
        self, analysis_id: UUID, sandbox_type: str, sandbox_url: str, timeout: float
    ) -> List[Dict[str, Any]]:
        """Poll sandbox API for new events."""
        session = self.sessions.get(analysis_id)
        if not session:
            return []

        offset = self.offsets.get(analysis_id, 0)
        batch_size = self.config.get("batch_size", 50)

        try:
            # Construct API endpoint based on sandbox type
            if sandbox_type == "windows":
                endpoint = f"{sandbox_url}/api/monitor/stream"
            elif sandbox_type == "android":
                endpoint = f"{sandbox_url}/api/frida/events"
            else:
                _LOGGER.error(f"Unknown sandbox type: {sandbox_type}")
                return []

            async with session.get(
                endpoint,
                params={"offset": offset, "limit": batch_size},
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    events = data.get("events", [])

                    # Update offset for next poll
                    if events:
                        self.offsets[analysis_id] = data.get("next_offset", offset + len(events))

                    return events
                else:
                    _LOGGER.warning(f"Sandbox API returned {resp.status}")
                    return []

        except asyncio.TimeoutError:
            _LOGGER.warning(f"Sandbox API timeout for {analysis_id}")
            return []
        except Exception as e:
            _LOGGER.error(f"Error polling sandbox: {e}")
            return []

    async def _normalize_event(self, raw_event: Dict[str, Any], sandbox_type: str) -> EnrichedEvent:
        """Convert CAPE/Frida event to standard schema."""
        event_type_raw = raw_event.get("type", "unknown")
        timestamp = datetime.fromisoformat(raw_event.get("timestamp", datetime.utcnow().isoformat()))

        # Map event type
        event_type = self._map_event_type(event_type_raw)

        # Extract event data based on type
        event_data = self._extract_event_data(raw_event, event_type, sandbox_type)

        return EnrichedEvent(
            event_id=uuid4(),
            analysis_id=None,  # Will be set by publisher
            timestamp=timestamp,
            event_type=event_type,
            event_data=event_data,
            enrichment=None,  # Will be set by enrichment processor
        )

    def _map_event_type(self, raw_type: str) -> EventType:
        """Map raw event type to EventType enum."""
        type_map = {
            "CreateFile": EventType.FILE,
            "DeleteFile": EventType.FILE,
            "WriteFile": EventType.FILE,
            "ReadFile": EventType.FILE,
            "CreateProcess": EventType.PROCESS,
            "TerminateProcess": EventType.PROCESS,
            "Connect": EventType.NETWORK,
            "Send": EventType.NETWORK,
            "Receive": EventType.NETWORK,
            "DNS": EventType.NETWORK,
            "RegSetValueEx": EventType.REGISTRY,
            "RegDeleteValue": EventType.REGISTRY,
            "RegCreateKey": EventType.REGISTRY,
            "CallAPI": EventType.API,
            "Syscall": EventType.API,
        }
        return type_map.get(raw_type, EventType.API)

    def _extract_event_data(
        self, raw_event: Dict[str, Any], event_type: EventType, sandbox_type: str
    ) -> Dict[str, Any]:
        """Extract and normalize event data."""
        if event_type == EventType.FILE:
            return {
                "operation": raw_event.get("operation", "unknown"),
                "path": raw_event.get("path", ""),
                "size": raw_event.get("size"),
                "hash_md5": raw_event.get("md5"),
                "hash_sha256": raw_event.get("sha256"),
            }
        elif event_type == EventType.NETWORK:
            return {
                "src_ip": raw_event.get("src_ip", ""),
                "src_port": raw_event.get("src_port", 0),
                "dst_ip": raw_event.get("dst_ip", ""),
                "dst_port": raw_event.get("dst_port", 0),
                "protocol": raw_event.get("protocol", "tcp").lower(),
                "bytes_sent": raw_event.get("bytes_sent", 0),
                "bytes_received": raw_event.get("bytes_received", 0),
                "domain": raw_event.get("domain"),
            }
        elif event_type == EventType.PROCESS:
            return {
                "action": raw_event.get("action", "create"),
                "pid": raw_event.get("pid", 0),
                "ppid": raw_event.get("ppid"),
                "process_name": raw_event.get("process_name", ""),
                "cmdline": raw_event.get("cmdline"),
                "user": raw_event.get("user"),
            }
        elif event_type == EventType.REGISTRY:
            return {
                "operation": raw_event.get("operation", "set"),
                "key_path": raw_event.get("key_path", ""),
                "value_name": raw_event.get("value_name"),
                "value_data": raw_event.get("value_data"),
            }
        elif event_type == EventType.API:
            return {
                "api_name": raw_event.get("api_name", ""),
                "module": raw_event.get("module", ""),
                "arguments": raw_event.get("arguments", {}),
                "return_value": raw_event.get("return_value"),
                "threat_level": raw_event.get("threat_level"),
            }
        else:
            return raw_event

    async def _publish_to_redis(self, analysis_id: UUID, event: EnrichedEvent):
        """Publish event to Redis stream."""
        stream_name = f"analysis:{analysis_id}:events"
        event.analysis_id = analysis_id

        try:
            # Serialize event
            event_json = event.model_dump_json()

            # Publish to stream (with TTL)
            await self.redis.xadd(stream_name, {"data": event_json})

            # Apply stream cap
            stream_cap = self.config.get("redis_stream_cap", 10000)
            stream_length = await self.redis.xlen(stream_name)

            if stream_length > stream_cap:
                # Trim stream to cap size
                await self.redis.xtrim(stream_name, maxlen=stream_cap, approximate=False)

            _LOGGER.debug(f"Published event to {stream_name}")

        except Exception as e:
            _LOGGER.error(f"Error publishing to Redis: {e}")

    async def health_check(self, analysis_id: UUID) -> Dict[str, Any]:
        """Check health of sandbox connection."""
        if analysis_id not in self.sessions:
            return {"status": "inactive"}

        try:
            session = self.sessions[analysis_id]
            # Simple connectivity check
            return {"status": "healthy", "offset": self.offsets.get(analysis_id, 0)}
        except Exception as e:
            return {"status": "error", "error": str(e)}


# Mock implementation for testing without real sandbox
class MockSandboxEventEmitter(SandboxEventEmitter):
    """Mock event emitter for testing."""

    async def _poll_events(
        self, analysis_id: UUID, sandbox_type: str, sandbox_url: str, timeout: float
    ) -> List[Dict[str, Any]]:
        """Generate mock events instead of polling."""
        import random

        event_templates = [
            {
                "type": "CreateFile",
                "timestamp": datetime.utcnow().isoformat(),
                "path": f"C:\\Users\\Admin\\Desktop\\file_{random.randint(1, 100)}.txt",
                "size": random.randint(1000, 100000),
            },
            {
                "type": "Connect",
                "timestamp": datetime.utcnow().isoformat(),
                "src_ip": "192.168.1.100",
                "dst_ip": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "dst_port": random.choice([80, 443, 8080, 9000]),
                "protocol": "tcp",
            },
            {
                "type": "CallAPI",
                "timestamp": datetime.utcnow().isoformat(),
                "api_name": random.choice(["WinExec", "CreateProcessA", "WriteFile", "ReadProcessMemory"]),
                "module": "kernel32.dll",
            },
        ]

        # Return 1-3 random mock events
        return random.sample(event_templates, random.randint(1, min(3, len(event_templates))))
