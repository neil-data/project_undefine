"""
resource_monitor.py — Resource monitoring for sandbox VMs.

Monitors system resource usage (CPU, memory, disk, network) during
dynamic analysis to detect resource exhaustion attacks and ensure
proper resource allocation.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

_LOGGER = logging.getLogger(__name__)


class ResourceStatus(str, Enum):
    """Resource usage status levels."""
    NORMAL = "normal"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"


class ResourceType(str, Enum):
    """Types of resources to monitor."""
    CPU = "cpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"


@dataclass
class ResourceMetric:
    """Single resource measurement."""
    resource_type: ResourceType
    value: float
    unit: str
    timestamp: datetime
    status: ResourceStatus
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


@dataclass
class ResourceSnapshot:
    """Snapshot of all resource metrics at a point in time."""
    analysis_id: UUID
    platform: str
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    disk_percent: float
    network_sent_kb: float
    network_recv_kb: float
    overall_status: ResourceStatus


class ResourceMonitor:
    """
    Monitors resource usage during dynamic analysis.
    
    Tracks CPU, memory, disk, and network usage to detect resource
    exhaustion attacks and ensure the sandbox remains functional.
    """
    
    # Thresholds for resource status
    CPU_ELEVATED_THRESHOLD = 50.0
    CPU_HIGH_THRESHOLD = 75.0
    CPU_CRITICAL_THRESHOLD = 90.0
    
    MEMORY_ELEVATED_THRESHOLD = 60.0
    MEMORY_HIGH_THRESHOLD = 80.0
    MEMORY_CRITICAL_THRESHOLD = 95.0
    
    DISK_ELEVATED_THRESHOLD = 70.0
    DISK_HIGH_THRESHOLD = 85.0
    DISK_CRITICAL_THRESHOLD = 95.0
    
    def __init__(
        self,
        analysis_id: UUID,
        platform: str,
        sample_interval_sec: int = 5,
        history_size: int = 60
    ):
        self.analysis_id = analysis_id
        self.platform = platform
        self.sample_interval_sec = sample_interval_sec
        self.history_size = history_size
        
        self._metrics: List[ResourceMetric] = []
        self._monitoring_task: Optional[asyncio.Task] = None
        self._should_stop = False
        
        # Simulated resource tracking (would connect to actual hypervisor API in production)
        self._cpu_usage = 10.0
        self._memory_usage = 30.0
        self._disk_usage = 40.0
        self._network_sent = 0.0
        self._network_recv = 0.0
    
    async def start(self) -> None:
        """Start resource monitoring loop."""
        _LOGGER.info("[%s] Starting resource monitor for %s platform", self.analysis_id, self.platform)
        self._should_stop = False
        self._monitoring_task = asyncio.create_task(self._monitor_loop())
    
    async def stop(self) -> None:
        """Stop resource monitoring loop."""
        _LOGGER.info("[%s] Stopping resource monitor", self.analysis_id)
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
                await self._collect_metrics()
                await asyncio.sleep(self.sample_interval_sec)
            except asyncio.CancelledError:
                break
            except Exception as e:
                _LOGGER.error("[%s] Resource monitoring error: %s", self.analysis_id, e)
                await asyncio.sleep(self.sample_interval_sec)
    
    async def _collect_metrics(self) -> None:
        """Collect current resource metrics."""
        timestamp = datetime.utcnow()
        
        # Simulate realistic resource usage patterns
        # In production, this would call hypervisor APIs
        self._simulate_resource_usage()
        
        # Collect CPU metric
        cpu_status = self._evaluate_cpu_status(self._cpu_usage)
        cpu_metric = ResourceMetric(
            resource_type=ResourceType.CPU,
            value=self._cpu_usage,
            unit="percent",
            timestamp=timestamp,
            status=cpu_status,
            details={"cores": 4}
        )
        
        # Collect memory metric
        memory_status = self._evaluate_memory_status(self._memory_usage)
        memory_metric = ResourceMetric(
            resource_type=ResourceType.MEMORY,
            value=self._memory_usage,
            unit="percent",
            timestamp=timestamp,
            status=memory_status,
            details={"used_mb": self._memory_usage * 8}  # Assume 8GB total
        )
        
        # Collect disk metric
        disk_status = self._evaluate_disk_status(self._disk_usage)
        disk_metric = ResourceMetric(
            resource_type=ResourceType.DISK,
            value=self._disk_usage,
            unit="percent",
            timestamp=timestamp,
            status=disk_status,
            details={"used_gb": self._disk_usage * 0.5}  # Assume 50GB total
        )
        
        # Add metrics to history
        self._add_metric(cpu_metric)
        self._add_metric(memory_metric)
        self._add_metric(disk_metric)
        
        # Trim history to max size
        if len(self._metrics) > self.history_size * 3:  # 3 metrics per sample
            self._metrics = self._metrics[-(self.history_size * 3):]
    
    def _simulate_resource_usage(self) -> None:
        """Simulate realistic resource usage patterns."""
        import random
        
        # Add some randomness to simulate real usage
        self._cpu_usage = max(5.0, min(95.0, self._cpu_usage + random.uniform(-5, 5)))
        self._memory_usage = max(20.0, min(90.0, self._memory_usage + random.uniform(-2, 2)))
        self._disk_usage = max(30.0, min(80.0, self._disk_usage + random.uniform(-1, 1)))
        
        # Simulate network traffic
        self._network_sent += random.uniform(0, 10)
        self._network_recv += random.uniform(0, 15)
    
    def _add_metric(self, metric: ResourceMetric) -> None:
        """Add a metric to the history."""
        self._metrics.append(metric)
    
    def _evaluate_cpu_status(self, usage: float) -> ResourceStatus:
        """Evaluate CPU usage status."""
        if usage >= self.CPU_CRITICAL_THRESHOLD:
            return ResourceStatus.CRITICAL
        elif usage >= self.CPU_HIGH_THRESHOLD:
            return ResourceStatus.HIGH
        elif usage >= self.CPU_ELEVATED_THRESHOLD:
            return ResourceStatus.ELEVATED
        else:
            return ResourceStatus.NORMAL
    
    def _evaluate_memory_status(self, usage: float) -> ResourceStatus:
        """Evaluate memory usage status."""
        if usage >= self.MEMORY_CRITICAL_THRESHOLD:
            return ResourceStatus.CRITICAL
        elif usage >= self.MEMORY_HIGH_THRESHOLD:
            return ResourceStatus.HIGH
        elif usage >= self.MEMORY_ELEVATED_THRESHOLD:
            return ResourceStatus.ELEVATED
        else:
            return ResourceStatus.NORMAL
    
    def _evaluate_disk_status(self, usage: float) -> ResourceStatus:
        """Evaluate disk usage status."""
        if usage >= self.DISK_CRITICAL_THRESHOLD:
            return ResourceStatus.CRITICAL
        elif usage >= self.DISK_HIGH_THRESHOLD:
            return ResourceStatus.HIGH
        elif usage >= self.DISK_ELEVATED_THRESHOLD:
            return ResourceStatus.ELEVATED
        else:
            return ResourceStatus.NORMAL
    
    # Public query methods
    
    def get_current_snapshot(self) -> ResourceSnapshot:
        """Get current resource usage snapshot."""
        # Get latest metrics for each resource type
        cpu_metric = self._get_latest_metric(ResourceType.CPU)
        memory_metric = self._get_latest_metric(ResourceType.MEMORY)
        disk_metric = self._get_latest_metric(ResourceType.DISK)
        
        overall_status = self._calculate_overall_status([
            cpu_metric.status if cpu_metric else ResourceStatus.NORMAL,
            memory_metric.status if memory_metric else ResourceStatus.NORMAL,
            disk_metric.status if disk_metric else ResourceStatus.NORMAL,
        ])
        
        return ResourceSnapshot(
            analysis_id=self.analysis_id,
            platform=self.platform,
            timestamp=datetime.utcnow(),
            cpu_percent=cpu_metric.value if cpu_metric else 0.0,
            memory_percent=memory_metric.value if memory_metric else 0.0,
            memory_used_mb=memory_metric.details.get("used_mb", 0.0) if memory_metric else 0.0,
            disk_percent=disk_metric.value if disk_metric else 0.0,
            network_sent_kb=self._network_sent,
            network_recv_kb=self._network_recv,
            overall_status=overall_status
        )
    
    def _get_latest_metric(self, resource_type: ResourceType) -> Optional[ResourceMetric]:
        """Get the most recent metric for a resource type."""
        for metric in reversed(self._metrics):
            if metric.resource_type == resource_type:
                return metric
        return None
    
    def _calculate_overall_status(self, statuses: List[ResourceStatus]) -> ResourceStatus:
        """Calculate overall resource status."""
        if not statuses:
            return ResourceStatus.NORMAL
        
        if any(s == ResourceStatus.CRITICAL for s in statuses):
            return ResourceStatus.CRITICAL
        elif any(s == ResourceStatus.HIGH for s in statuses):
            return ResourceStatus.HIGH
        elif any(s == ResourceStatus.ELEVATED for s in statuses):
            return ResourceStatus.ELEVATED
        else:
            return ResourceStatus.NORMAL
    
    def get_metrics_history(
        self,
        resource_type: Optional[ResourceType] = None,
        since: Optional[datetime] = None
    ) -> List[ResourceMetric]:
        """Get historical metrics, optionally filtered."""
        metrics = self._metrics
        
        if resource_type:
            metrics = [m for m in metrics if m.resource_type == resource_type]
        
        if since:
            metrics = [m for m in metrics if m.timestamp >= since]
        
        return metrics
    
    def is_resource_exhaustion_detected(self) -> bool:
        """Check if any resource is in critical state."""
        snapshot = self.get_current_snapshot()
        return snapshot.overall_status == ResourceStatus.CRITICAL
    
    def get_resource_alerts(self) -> List[str]:
        """Get list of current resource alerts."""
        alerts = []
        snapshot = self.get_current_snapshot()
        
        if snapshot.cpu_percent >= self.CPU_CRITICAL_THRESHOLD:
            alerts.append(f"CRITICAL: CPU usage at {snapshot.cpu_percent:.1f}%")
        elif snapshot.cpu_percent >= self.CPU_HIGH_THRESHOLD:
            alerts.append(f"HIGH: CPU usage at {snapshot.cpu_percent:.1f}%")
        
        if snapshot.memory_percent >= self.MEMORY_CRITICAL_THRESHOLD:
            alerts.append(f"CRITICAL: Memory usage at {snapshot.memory_percent:.1f}%")
        elif snapshot.memory_percent >= self.MEMORY_HIGH_THRESHOLD:
            alerts.append(f"HIGH: Memory usage at {snapshot.memory_percent:.1f}%")
        
        if snapshot.disk_percent >= self.DISK_CRITICAL_THRESHOLD:
            alerts.append(f"CRITICAL: Disk usage at {snapshot.disk_percent:.1f}%")
        elif snapshot.disk_percent >= self.DISK_HIGH_THRESHOLD:
            alerts.append(f"HIGH: Disk usage at {snapshot.disk_percent:.1f}%")
        
        return alerts