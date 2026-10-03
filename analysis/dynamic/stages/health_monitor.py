"""
health_monitor.py — Health monitoring for sandbox VMs.

Monitors VM health metrics and provides status information for the
sandbox manager. Tracks system health, agent status, and resource
availability to ensure reliable dynamic analysis.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

_LOGGER = logging.getLogger(__name__)


class HealthStatus(str, Enum):
    """Health status levels for sandbox components."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ComponentType(str, Enum):
    """Types of sandbox components to monitor."""
    VM = "vm"
    AGENT = "agent"
    NETWORK = "network"
    STORAGE = "storage"
    MONITORING = "monitoring"


@dataclass
class ComponentHealth:
    """Health status of a single sandbox component."""
    component_type: ComponentType
    component_id: str
    status: HealthStatus
    last_check: datetime
    message: str = ""
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


@dataclass
class SandboxHealth:
    """Overall health status of a sandbox instance."""
    analysis_id: UUID
    platform: str
    overall_status: HealthStatus
    components: List[ComponentHealth]
    last_updated: datetime
    uptime_seconds: float = 0.0
    
    @property
    def is_healthy(self) -> bool:
        """Quick check if overall status is healthy."""
        return self.overall_status == HealthStatus.HEALTHY
    
    @property
    def degraded_components(self) -> List[ComponentHealth]:
        """List of components with degraded or unhealthy status."""
        return [c for c in self.components if c.status != HealthStatus.HEALTHY]


class HealthMonitor:
    """
    Monitors health of sandbox components and provides status updates.
    
    Tracks VM state, agent connectivity, network status, and system resources
    to ensure the sandbox is functioning correctly for dynamic analysis.
    """
    
    def __init__(self, analysis_id: UUID, platform: str, check_interval_sec: int = 30):
        self.analysis_id = analysis_id
        self.platform = platform
        self.check_interval_sec = check_interval_sec
        
        self._components: Dict[str, ComponentHealth] = {}
        self._start_time = datetime.utcnow()
        self._monitoring_task: Optional[asyncio.Task] = None
        self._should_stop = False
        
        # Track component-specific state
        self._vm_running = False
        self._agent_connected = False
        self._network_available = False
        self._storage_available = False
    
    async def start(self) -> None:
        """Start health monitoring loop."""
        _LOGGER.info("[%s] Starting health monitor for %s platform", self.analysis_id, self.platform)
        self._should_stop = False
        self._monitoring_task = asyncio.create_task(self._monitor_loop())
    
    async def stop(self) -> None:
        """Stop health monitoring loop."""
        _LOGGER.info("[%s] Stopping health monitor", self.analysis_id)
        self._should_stop = True
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
    
    async def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while not self._should_stop:
            try:
                await self._check_all_components()
                await asyncio.sleep(self.check_interval_sec)
            except asyncio.CancelledError:
                break
            except Exception as e:
                _LOGGER.error("[%s] Health monitoring error: %s", self.analysis_id, e)
                await asyncio.sleep(self.check_interval_sec)
    
    async def _check_all_components(self) -> None:
        """Check health of all monitored components."""
        # Check VM health
        await self._check_vm_health()
        
        # Check agent health
        await self._check_agent_health()
        
        # Check network health
        await self._check_network_health()
        
        # Check storage health
        await self._check_storage_health()

    async def _check_vm_health(self) -> None:
        """Check VM/component health."""
        component_id = f"{self.platform}_vm"
        
        if self._vm_running:
            status = HealthStatus.HEALTHY
            message = "VM is running normally"
            details = {"uptime_seconds": (datetime.utcnow() - self._start_time).total_seconds()}
        else:
            status = HealthStatus.UNHEALTHY
            message = "VM is not running"
            details = {}
        
        self._update_component(ComponentType.VM, component_id, status, message, details)
    
    async def _check_agent_health(self) -> None:
        """Check monitoring agent health."""
        component_id = f"{self.platform}_agent"
        
        if self._agent_connected:
            status = HealthStatus.HEALTHY
            message = "Agent is connected and responsive"
            details = {"last_heartbeat": datetime.utcnow().isoformat()}
        else:
            status = HealthStatus.UNHEALTHY
            message = "Agent is not connected"
            details = {}
        
        self._update_component(ComponentType.AGENT, component_id, status, message, details)
    
    async def _check_network_health(self) -> None:
        """Check network connectivity health."""
        component_id = f"{self.platform}_network"
        
        if self._network_available:
            status = HealthStatus.HEALTHY
            message = "Network is available"
            details = {"configured": True}
        else:
            status = HealthStatus.DEGRADED
            message = "Network is limited or unavailable"
            details = {"configured": False}
        
        self._update_component(ComponentType.NETWORK, component_id, status, message, details)
    
    async def _check_storage_health(self) -> None:
        """Check storage availability health."""
        component_id = f"{self.platform}_storage"
        
        if self._storage_available:
            status = HealthStatus.HEALTHY
            message = "Storage is available"
            details = {"available": True}
        else:
            status = HealthStatus.UNHEALTHY
            message = "Storage is unavailable"
            details = {"available": False}
        
        self._update_component(ComponentType.STORAGE, component_id, status, message, details)
    
    def _update_component(
        self,
        component_type: ComponentType,
        component_id: str,
        status: HealthStatus,
        message: str,
        details: Dict[str, Any]
    ) -> None:
        """Update health status for a component."""
        self._components[component_id] = ComponentHealth(
            component_type=component_type,
            component_id=component_id,
            status=status,
            last_check=datetime.utcnow(),
            message=message,
            details=details
        )
    
    # Public state update methods
    
    def set_vm_running(self, running: bool) -> None:
        """Update VM running state."""
        self._vm_running = running
        _LOGGER.info("[%s] VM state updated: running=%s", self.analysis_id, running)
    
    def set_agent_connected(self, connected: bool) -> None:
        """Update agent connection state."""
        self._agent_connected = connected
        _LOGGER.info("[%s] Agent state updated: connected=%s", self.analysis_id, connected)
    
    def set_network_available(self, available: bool) -> None:
        """Update network availability state."""
        self._network_available = available
        _LOGGER.info("[%s] Network state updated: available=%s", self.analysis_id, available)
    
    def set_storage_available(self, available: bool) -> None:
        """Update storage availability state."""
        self._storage_available = available
        _LOGGER.info("[%s] Storage state updated: available=%s", self.analysis_id, available)
    
    # Public query methods
    
    def get_health_snapshot(self) -> SandboxHealth:
        """Get current health snapshot."""
        return SandboxHealth(
            analysis_id=self.analysis_id,
            platform=self.platform,
            overall_status=self._calculate_overall_status(),
            components=list(self._components.values()),
            last_updated=datetime.utcnow(),
            uptime_seconds=(datetime.utcnow() - self._start_time).total_seconds()
        )
    
    def _calculate_overall_status(self) -> HealthStatus:
        """
        Derive overall health from the component states, on demand.

        Deliberately computed rather than cached. A stored copy has to be
        refreshed by every path that changes a component, and the version that
        existed here previously — an `_update_overall_status()` called from the
        check loop — assigned its result to a local and discarded it, so it had
        looked like it was maintaining state for as long as it existed.

        UNKNOWN is returned before the first check has run: "not yet checked"
        and "checked and fine" must never be the same answer.
        """
        if not self._components:
            return HealthStatus.UNKNOWN

        statuses = [c.status for c in self._components.values()]
        
        if all(s == HealthStatus.HEALTHY for s in statuses):
            return HealthStatus.HEALTHY
        elif any(s == HealthStatus.UNHEALTHY for s in statuses):
            return HealthStatus.UNHEALTHY
        else:
            return HealthStatus.DEGRADED
    
    def is_healthy(self) -> bool:
        """Quick health check."""
        return self._calculate_overall_status() == HealthStatus.HEALTHY
    
    def get_component_health(self, component_type: ComponentType) -> Optional[ComponentHealth]:
        """Get health status for a specific component type."""
        for component in self._components.values():
            if component.component_type == component_type:
                return component
        return None