"""
Live monitoring data models for real-time malware detection.

Includes:
- Event schema for sandbox events
- Risk scoring data
- Alerts and IOCs
- Process tree and system activity
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum
from pydantic import BaseModel, Field
from uuid import UUID


# ============================================================================
# Event Types & Schemas
# ============================================================================

class EventType(str, Enum):
    """Types of events captured from sandbox."""
    FILE = "file"
    NETWORK = "network"
    API = "api"
    REGISTRY = "registry"
    PROCESS = "process"
    SCREENSHOT = "screenshot"


class FileOperation(str, Enum):
    """File operation types."""
    CREATE = "create"
    DELETE = "delete"
    MODIFY = "modify"
    READ = "read"
    EXECUTE = "execute"


class NetworkProtocol(str, Enum):
    """Network protocols."""
    TCP = "tcp"
    UDP = "udp"
    DNS = "dns"
    ICMP = "icmp"


class EventData(BaseModel):
    """Base event data model."""
    timestamp: datetime
    event_type: EventType


class FileEventData(EventData):
    """File operation event."""
    operation: FileOperation
    path: str
    size: Optional[int] = None
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None


class NetworkEventData(EventData):
    """Network event."""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: NetworkProtocol
    bytes_sent: int = 0
    bytes_received: int = 0
    domain: Optional[str] = None


class APIEventData(EventData):
    """API call event."""
    api_name: str
    module: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    return_value: Optional[Any] = None
    threat_level: Optional[str] = None  # 'low', 'medium', 'high'


class RegistryEventData(EventData):
    """Registry operation event (Windows)."""
    operation: str  # 'set', 'delete', 'create'
    key_path: str
    value_name: Optional[str] = None
    value_data: Optional[str] = None


class ProcessEventData(EventData):
    """Process lifecycle event."""
    action: str  # 'create', 'terminate', 'privilege_change'
    pid: int
    ppid: Optional[int] = None
    process_name: str
    cmdline: Optional[str] = None
    user: Optional[str] = None


class ThreatIntelligence(BaseModel):
    """Threat intelligence enrichment."""
    known_c2: bool = False
    threat_family: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    reputation_score: Optional[int] = None  # 0-100
    virusTotal_score: Optional[int] = None
    whois_info: Optional[Dict[str, Any]] = None


class EnrichedEvent(BaseModel):
    """Event enriched with threat intelligence."""
    event_id: UUID
    analysis_id: Optional[UUID] = None  # Made optional for test compatibility

    timestamp: datetime
    event_type: EventType
    event_data: Dict[str, Any]

    # Enrichment
    enrichment: Optional[ThreatIntelligence] = None
    mitre_techniques: List[str] = Field(default_factory=list)

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    severity: Optional[str] = None  # 'info', 'warning', 'critical'
    
    # Add id alias for compatibility with alert engine
    @property
    def id(self) -> UUID:
        """Alias for event_id for compatibility."""
        return self.event_id


# ============================================================================
# Risk Scoring
# ============================================================================

class RiskScoreBand(str, Enum):
    """Risk score bands."""
    GREEN = "green"      # 0-30
    YELLOW = "yellow"    # 31-60
    ORANGE = "orange"    # 61-85
    RED = "red"          # 86-100


class SignalBreakdown(BaseModel):
    """Breakdown of risk score by signal type."""
    api_calls: Dict[str, int] = Field(default_factory=dict)
    network: Dict[str, int] = Field(default_factory=dict)
    files: Dict[str, int] = Field(default_factory=dict)
    registry: Dict[str, int] = Field(default_factory=dict)
    process: Dict[str, int] = Field(default_factory=dict)


class RiskScore(BaseModel):
    """Risk score snapshot."""
    analysis_id: UUID
    timestamp: datetime
    score: int = Field(ge=0, le=100)
    band: RiskScoreBand
    reasoning: str
    signal_breakdown: SignalBreakdown
    trend: str  # 'increasing', 'stable', 'decreasing'
    contributing_event_ids: List[UUID] = Field(default_factory=list)


class RiskScoreUpdate(BaseModel):
    """Real-time risk score update for WebSocket."""
    score: int = Field(ge=0, le=100)
    timestamp: datetime
    reasoning: str
    signal_breakdown: SignalBreakdown
    trend: str


# ============================================================================
# Alerts
# ============================================================================

class AlertSeverity(str, Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class Alert(BaseModel):
    """Alert triggered by rule."""
    alert_id: UUID
    analysis_id: UUID

    rule_id: str
    timestamp: datetime
    severity: AlertSeverity
    message: str

    event_id: Optional[UUID] = None
    mitre_techniques: List[str] = Field(default_factory=list)

    dismissed: bool = False
    dismissed_by: Optional[str] = None
    dismissed_at: Optional[datetime] = None


class AlertRule(BaseModel):
    """Alert rule definition."""
    rule_id: str
    name: str
    description: str
    severity: AlertSeverity

    # Trigger condition (simplified)
    trigger_event_types: List[EventType]
    trigger_conditions: Dict[str, Any]

    # Actions
    actions: List[str]  # 'alert', 'increment_risk_score', 'snapshot_memory'


# ============================================================================
# IOCs (Indicators of Compromise)
# ============================================================================

class IOCType(str, Enum):
    """IOC types."""
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    EMAIL = "email"
    PHONE = "phone"
    URL = "url"


class IOC(BaseModel):
    """Indicator of Compromise."""
    ioc_id: UUID
    analysis_id: UUID

    ioc_type: IOCType
    ioc_value: str

    confidence: int = Field(ge=0, le=100)
    first_seen: datetime
    last_seen: Optional[datetime] = None

    threat_intel: Optional[ThreatIntelligence] = None
    matching_rules: List[str] = Field(default_factory=list)


# ============================================================================
# Process Tree
# ============================================================================

class ProcessTreeNode(BaseModel):
    """Node in process execution tree."""
    pid: int
    ppid: Optional[int] = None
    process_name: str
    cmdline: Optional[str] = None

    created_at: datetime
    terminated_at: Optional[datetime] = None
    termination_reason: Optional[str] = None

    user: Optional[str] = None
    privilege_level: str  # 'user', 'system'

    # Activity counters
    file_operations_count: int = 0
    network_operations_count: int = 0
    api_calls_count: int = 0

    # Risk indicators
    is_suspicious: bool = False
    suspicious_reasons: List[str] = Field(default_factory=list)

    # Child processes
    children: List['ProcessTreeNode'] = Field(default_factory=list)


ProcessTreeNode.model_rebuild()


class ProcessTree(BaseModel):
    """Full process execution tree."""
    analysis_id: UUID
    root_process: ProcessTreeNode
    total_processes: int


# ============================================================================
# File & Registry Timeline
# ============================================================================

class FileTimelineEntry(BaseModel):
    """File operation in chronological order."""
    timestamp: datetime
    operation: FileOperation
    path: str
    size: Optional[int] = None
    hash_md5: Optional[str] = None
    process_name: Optional[str] = None
    process_pid: Optional[int] = None


class RegistryTimelineEntry(BaseModel):
    """Registry operation in chronological order."""
    timestamp: datetime
    operation: str
    key_path: str
    value_name: Optional[str] = None
    value_data: Optional[str] = None
    process_name: Optional[str] = None
    process_pid: Optional[int] = None


# ============================================================================
# Live Monitoring Status
# ============================================================================

class SandboxStatus(BaseModel):
    """Status of sandbox execution."""
    analysis_id: UUID
    platform: str  # 'windows', 'android'
    status: str  # 'running', 'paused', 'complete', 'error'
    uptime_seconds: float
    memory_usage_mb: float
    cpu_percent: float
    last_activity: datetime


class LiveMonitoringStatus(BaseModel):
    """Live monitoring status."""
    analysis_id: UUID
    status: str  # 'running', 'paused', 'complete'
    sandbox_status: SandboxStatus

    current_risk_score: int
    event_count: Dict[EventType, int]
    active_alerts: int
    connected_clients: int

    last_event_timestamp: Optional[datetime] = None


# ============================================================================
# WebSocket Messages
# ============================================================================

class WSMessage(BaseModel):
    """Base WebSocket message."""
    type: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class WSConnectedMessage(WSMessage):
    """Connection established."""
    type: str = "connected"
    analysis_id: UUID
    connection_id: UUID
    server_time: datetime


class WSEventMessage(WSMessage):
    """Event notification."""
    type: str = "event"
    event: EnrichedEvent


class WSRiskScoreMessage(WSMessage):
    """Risk score update."""
    type: str = "risk_score"
    score: int
    reasoning: str
    signal_breakdown: SignalBreakdown
    trend: str


class WSAlertMessage(WSMessage):
    """Alert notification."""
    type: str = "alert"
    alert: Alert


class WSIOCMessage(WSMessage):
    """IOC notification."""
    type: str = "ioc"
    ioc: IOC


class WSProcessTreeUpdateMessage(WSMessage):
    """Process tree update."""
    type: str = "process_tree_update"
    process: ProcessTreeNode


class WSStatusMessage(WSMessage):
    """Status change."""
    type: str = "status"
    status: str
    sandbox_status: Optional[SandboxStatus] = None


class WSHeartbeatMessage(WSMessage):
    """Heartbeat."""
    type: str = "heartbeat"


class WSErrorMessage(WSMessage):
    """Error message."""
    type: str = "error"
    code: str
    message: str


class WSFilterMessage(BaseModel):
    """Client filter message."""
    type: str = "filter"
    event_types: Optional[List[EventType]] = None
    min_severity: Optional[str] = None


class WSStateSyncMessage(BaseModel):
    """Client request for state sync."""
    type: str = "request_state_sync"
    from_timestamp: Optional[datetime] = None
