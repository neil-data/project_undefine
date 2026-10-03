"""
SQLAlchemy ORM models for live monitoring tables.

These models map to the PostgreSQL schema defined in PHASE_2_ARCHITECTURE.md
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, BigInteger,
    Text, Boolean, ForeignKey, Index, ARRAY, UUID as SQL_UUID,
    func, Enum as SQLEnum
)
# JSONB is a Postgres-dialect type, not a generic one — importing it from the
# `sqlalchemy` root raises ImportError and made this module (and therefore the
# whole test suite) fail to import.
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import relationship
from uuid import uuid4

# Single source of truth for these enums — live_monitoring.py holds the API-side
# definitions and imports nothing from this module, so there is no cycle.
from .live_monitoring import AlertSeverity, EventType, IOCType

Base = declarative_base()


# Re-exported under their old names so existing imports keep working. These
# used to be separate classes declared here with members identical to the ones
# in live_monitoring.py — which meant event_processor.write_to_db() handed a
# live_monitoring.EventType member to a column typed with the local
# EventTypeEnum. SQLAlchemy validates against the exact class it was given, so
# the sibling member was not recognised and the insert raised LookupError.
# One definition, one source of truth.
EventTypeEnum = EventType
AlertSeverityEnum = AlertSeverity
IOCTypeEnum = IOCType


def _pg_enum(enum_cls, name: str) -> SQLEnum:
    """
    A Postgres ENUM column storing the enum's *values* ("file"), not its member
    names ("FILE").

    SQLAlchemy persists member names by default, which would put uppercase
    labels in the database while the API models, the WebSocket payloads and the
    frontend all speak the lowercase values — so a value would change spelling
    purely by making a round trip through storage. values_callable keeps one
    spelling end to end.
    """
    return SQLEnum(enum_cls, name=name, values_callable=lambda e: [m.value for m in e])


class AnalysisEvent(Base):
    """Raw events from sandbox."""
    __tablename__ = "analysis_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    analysis_id = Column(SQL_UUID, nullable=False, index=True)
    event_id = Column(SQL_UUID, nullable=False, unique=True, default=uuid4)

    event_type = Column(_pg_enum(EventType, "event_type"), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)

    # Raw event payload
    event_data = Column(JSONB, nullable=False)

    # Enrichment data (threat intel, GeoIP, YARA matches)
    enrichment = Column(JSONB, nullable=True)

    # MITRE techniques
    mitre_techniques = Column(ARRAY(String), nullable=True, default=list)

    # Severity
    severity = Column(String(16), nullable=True)

    # Metadata
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())

    # Index names are unique per *schema* in Postgres, not per table, so every
    # index here is prefixed with its table name. Seven tables in this module
    # previously declared an index literally called 'idx_analysis_timestamp';
    # create_all() would create the first and then abort with
    # "relation idx_analysis_timestamp already exists", leaving the remaining
    # tables uncreated.
    __table_args__ = (
        Index('idx_analysis_events_analysis_timestamp', 'analysis_id', 'timestamp', postgresql_using='btree'),
        Index('idx_analysis_events_type_timestamp', 'event_type', 'timestamp', postgresql_using='btree'),
    )


class RiskScore(Base):
    """Risk score snapshots."""
    __tablename__ = "risk_scores"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    analysis_id = Column(SQL_UUID, nullable=False, index=True)

    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    score = Column(Integer, nullable=False)

    reasoning = Column(Text, nullable=False)
    signal_breakdown = Column(JSONB, nullable=False)  # API calls, network, files, etc.

    trend = Column(String(16), nullable=True)  # 'increasing', 'stable', 'decreasing'
    contributing_events = Column(ARRAY(BigInteger), nullable=True, default=list)

    created_at = Column(DateTime(timezone=True), default=func.now())

    __table_args__ = (
        Index('idx_risk_scores_analysis_timestamp', 'analysis_id', 'timestamp', postgresql_using='btree'),
    )


class Alert(Base):
    """Alerts triggered during analysis."""
    __tablename__ = "alerts"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    analysis_id = Column(SQL_UUID, nullable=False, index=True)
    alert_id = Column(SQL_UUID, nullable=False, unique=True, default=uuid4)

    rule_id = Column(String(64), nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)

    severity = Column(_pg_enum(AlertSeverity, "alert_severity"), nullable=False)
    message = Column(Text, nullable=False)

    event_id = Column(BigInteger, ForeignKey('analysis_events.id'), nullable=True)
    mitre_techniques = Column(ARRAY(String), nullable=True, default=list)

    dismissed = Column(Boolean, default=False, index=True)
    dismissed_by = Column(String(64), nullable=True)
    dismissed_at = Column(DateTime(timezone=True), nullable=True)

    deduplicated_from = Column(BigInteger, ForeignKey('alerts.id'), nullable=True)

    created_at = Column(DateTime(timezone=True), default=func.now())

    __table_args__ = (
        Index('idx_alerts_analysis_timestamp', 'analysis_id', 'timestamp', postgresql_using='btree'),
        Index('idx_alerts_dismissed', 'dismissed_by', 'dismissed_at', postgresql_using='btree'),
    )


class LiveIOC(Base):
    """IOCs extracted live during analysis."""
    __tablename__ = "live_iocs"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    analysis_id = Column(SQL_UUID, nullable=False, index=True)
    ioc_id = Column(SQL_UUID, nullable=False, unique=True, default=uuid4)

    ioc_type = Column(_pg_enum(IOCType, "ioc_type"), nullable=False)
    ioc_value = Column(String(255), nullable=False, index=True)

    confidence = Column(Integer, nullable=False)  # 0-100
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=True)

    threat_intel = Column(JSONB, nullable=True)
    matching_rules = Column(ARRAY(String), nullable=True, default=list)

    created_at = Column(DateTime(timezone=True), default=func.now())

    __table_args__ = (
        Index('idx_live_iocs_analysis_ioc_type', 'analysis_id', 'ioc_type', postgresql_using='btree'),
        Index('idx_live_iocs_value', 'ioc_value', postgresql_using='btree'),
    )


class ProcessNode(Base):
    """Process execution tree nodes."""
    __tablename__ = "process_nodes"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    analysis_id = Column(SQL_UUID, nullable=False, index=True)

    pid = Column(Integer, nullable=False)
    ppid = Column(Integer, nullable=True)
    process_name = Column(String(255), nullable=False)
    cmdline = Column(Text, nullable=True)

    created_at_ts = Column(DateTime(timezone=True), nullable=False)
    terminated_at = Column(DateTime(timezone=True), nullable=True)
    termination_reason = Column(String(64), nullable=True)

    user = Column(String(64), nullable=True)
    privilege_level = Column(String(16), default='user')

    file_operations_count = Column(Integer, default=0)
    network_operations_count = Column(Integer, default=0)
    api_calls_count = Column(Integer, default=0)

    is_suspicious = Column(Boolean, default=False)
    suspicious_reasons = Column(ARRAY(String), nullable=True, default=list)

    created_at = Column(DateTime(timezone=True), default=func.now())

    __table_args__ = (
        Index('idx_process_nodes_analysis_pid', 'analysis_id', 'pid', postgresql_using='btree'),
    )


class FileTimeline(Base):
    """File operations timeline."""
    __tablename__ = "file_timeline"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    analysis_id = Column(SQL_UUID, nullable=False, index=True)

    timestamp = Column(DateTime(timezone=True), nullable=False)
    operation = Column(String(32), nullable=False)  # create, delete, modify, read, execute
    path = Column(Text, nullable=False)
    size = Column(BigInteger, nullable=True)
    hash_md5 = Column(String(32), nullable=True)
    hash_sha256 = Column(String(64), nullable=True)

    process_name = Column(String(255), nullable=True)
    process_pid = Column(Integer, nullable=True)

    created_at = Column(DateTime(timezone=True), default=func.now())

    __table_args__ = (
        Index('idx_file_timeline_analysis_timestamp', 'analysis_id', 'timestamp', postgresql_using='btree'),
    )


class RegistryTimeline(Base):
    """Registry operations timeline (Windows)."""
    __tablename__ = "registry_timeline"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    analysis_id = Column(SQL_UUID, nullable=False, index=True)

    timestamp = Column(DateTime(timezone=True), nullable=False)
    operation = Column(String(32), nullable=False)  # set, delete, create
    key_path = Column(Text, nullable=False)
    value_name = Column(String(255), nullable=True)
    value_data = Column(Text, nullable=True)

    process_name = Column(String(255), nullable=True)
    process_pid = Column(Integer, nullable=True)

    created_at = Column(DateTime(timezone=True), default=func.now())

    __table_args__ = (
        Index('idx_registry_timeline_analysis_timestamp', 'analysis_id', 'timestamp', postgresql_using='btree'),
    )


class NetworkAnalysisResult(Base):
    """Network intelligence analysis results."""
    __tablename__ = "network_analysis_results"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    analysis_id = Column(SQL_UUID, nullable=False, unique=True, index=True)

    timestamp = Column(DateTime(timezone=True), nullable=False)
    total_packets_processed = Column(Integer, nullable=False)

    # Protocol-specific data
    dns_data = Column(JSONB, nullable=True)
    http_data = Column(JSONB, nullable=True)
    https_data = Column(JSONB, nullable=True)
    tcp_data = Column(JSONB, nullable=True)
    udp_data = Column(JSONB, nullable=True)
    tls_data = Column(JSONB, nullable=True)

    # Capture statistics
    capture_stats = Column(JSONB, nullable=True)

    # Complete results
    raw_results = Column(JSONB, nullable=True)

    created_at = Column(DateTime(timezone=True), default=func.now())

    __table_args__ = (
        Index('idx_network_results_analysis_timestamp', 'analysis_id', 'timestamp', postgresql_using='btree'),
    )


class LiveMonitoringSession(Base):
    """Live monitoring session tracking."""
    __tablename__ = "live_monitoring_sessions"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    analysis_id = Column(SQL_UUID, nullable=False, index=True)
    session_id = Column(SQL_UUID, nullable=False, unique=True, default=uuid4)

    user_id = Column(String(64), nullable=False)
    started_at = Column(DateTime(timezone=True), default=func.now())
    ended_at = Column(DateTime(timezone=True), nullable=True)

    is_active = Column(Boolean, default=True)

    created_at = Column(DateTime(timezone=True), default=func.now())

    __table_args__ = (
        Index('idx_live_sessions_analysis_active', 'analysis_id', 'is_active', postgresql_using='btree'),
    )


class LiveMonitoringAuditLog(Base):
    """Audit trail for live monitoring actions."""
    __tablename__ = "live_monitoring_audit_log"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    analysis_id = Column(SQL_UUID, nullable=False, index=True)

    user_id = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)  # 'pause', 'resume', 'kill', 'view_alert'
    details = Column(JSONB, nullable=True)

    timestamp = Column(DateTime(timezone=True), default=func.now())

    __table_args__ = (
        Index('idx_live_audit_analysis_timestamp', 'analysis_id', 'timestamp', postgresql_using='btree'),
    )


class AnalysisJob(Base):
    """Pipeline status tracking for per-sample analysis jobs."""
    __tablename__ = "analysis_jobs"

    analysis_id = Column(String(64), primary_key=True)
    user_email = Column(String(255), nullable=True)
    original_filename = Column(Text, nullable=True)
    file_size_bytes = Column(BigInteger, nullable=True)
    mime_type = Column(String(120), nullable=True)
    file_type = Column(String(10), nullable=True)

    status = Column(String(20), nullable=False, default="UPLOADED", index=True)
    stage = Column(Text, nullable=True)
    dynamic_status = Column(Text, nullable=True)
    error = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index('idx_analysis_jobs_status', 'status', postgresql_using='btree'),
        Index('idx_analysis_jobs_updated_at', 'updated_at', postgresql_using='btree'),
    )

