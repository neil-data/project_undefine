"""
backend/app/models/api_models.py — Request/response schemas for the API.

These wrap the agent-layer's schema.py types into API-friendly
request/response models. Kept separate from agents/orchestrator/schema.py
because API contracts (what the frontend sees) and internal pipeline
contracts (what agents pass to each other) can evolve independently.
"""

from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator

from agents.orchestrator.schema import (
    StaticAnalysisOutput,
    DynamicAnalysisOutput,
    MitreTechnique,
    CapabilityTag,
)


class YaraMatchDetail(BaseModel):
    """A single rule-engine match, as returned by the static-analysis engine."""
    model_config = {"extra": "ignore"}
    rule_name: str = "unknown"
    category: Optional[str] = "generic"
    severity: Optional[str] = "medium"
    description: Optional[str] = ""


class PackingInfo(BaseModel):
    """Packing detection + best-effort unpacking result (see static-analysis's packing/ package)."""
    model_config = {"extra": "ignore"}
    is_packed: bool = False
    packer_name: Optional[str] = None
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)
    unpack_attempted: bool = False
    unpack_succeeded: bool = False
    unpack_method: Optional[str] = None
    unpack_error: Optional[str] = None
    unpacked_sha256: Optional[str] = None


class ExplainedStringDetail(BaseModel):
    """A single extracted string with its plain-language explanation (see strings/explain.py)."""
    model_config = {"extra": "ignore"}
    value: str = ""
    type: Optional[str] = "string"
    category: Optional[str] = "info"
    explanation: Optional[str] = ""
    severity: Optional[str] = "info"


class GeoIocDetail(BaseModel):
    """A single IP indicator resolved to a detailed geographic + ASN attribution."""
    model_config = {"extra": "ignore"}
    ip: str = "0.0.0.0"
    country: Optional[str] = None
    country_iso: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    postal_code: Optional[str] = None
    timezone: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_radius: Optional[int] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    isp: Optional[str] = None
    is_hosting: Optional[bool] = None
    is_proxy: Optional[bool] = None
    threat_level: Optional[str] = None
    disclaimer: Optional[str] = None


class NetworkIndicators(BaseModel):
    """Deduplicated network observables extracted from static + dynamic analysis."""
    model_config = {"extra": "ignore"}
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    dns_queries: list[str] = Field(default_factory=list)
    connections: list[dict] = Field(default_factory=list)  # {ip, port, protocol, flagged_c2}


class ThreatAssessment(BaseModel):
    """Evidence-based threat assessment derived from the analysis pipeline."""
    model_config = {"extra": "ignore"}
    risk_score: int = 0
    threat_level: str = "LOW"
    verdict: str = "CLEAN"
    confidence: int = 0
    key_findings: list[str] = Field(default_factory=list)


class AiAnalysisOutput(BaseModel):
    """Structured AI analysis output from the narrative/investigation agents."""
    model_config = {"extra": "ignore"}
    executive_summary: str = ""
    malware_behavior: Optional[str] = None
    evidence_correlation: Optional[str] = None
    threat_classification: Optional[str] = None
    network_interpretation: Optional[str] = None
    geoip_interpretation: Optional[str] = None
    mitre_techniques_explained: list[str] = Field(default_factory=list)
    confidence: int = 0
    reasoning: Optional[str] = None
    recommendations: list[str] = Field(default_factory=list)
    ai_available: bool = True
    fallback_used: bool = False


class SubmitSampleRequest(BaseModel):
    model_config = {"extra": "ignore"}
    static_analysis: StaticAnalysisOutput
    dynamic_analysis: Optional[DynamicAnalysisOutput] = None


class CaseSummary(BaseModel):
    model_config = {"extra": "ignore"}
    sample_id: str
    platform: str = "windows"
    file_type: str = "exe"
    risk_score: int = 0
    status: str = "clean"
    submitted_at: str = ""
    original_filename: Optional[str] = None

    @field_validator("sample_id", "platform", "file_type", "status", "submitted_at", mode="before")
    @classmethod
    def coerce_str(cls, v: Any) -> Any:
        return str(v) if v is not None else v


class CaseDetail(BaseModel):
    """Full case detail — matches the agent-layer output contract."""
    model_config = {"extra": "ignore"}
    sample_id: str
    platform: str = "windows"
    file_type: str = "exe"
    risk_score: int = 0
    status: str = "clean"
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    capability_tags: list[CapabilityTag] = Field(default_factory=list)
    narrative_summary: str = ""
    submitted_at: str = ""
    file_size_bytes: Optional[int] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    yara_matches: list[YaraMatchDetail] = Field(default_factory=list)
    packing: Optional[PackingInfo] = None
    explained_strings: list[ExplainedStringDetail] = Field(default_factory=list)
    geo_iocs: list[GeoIocDetail] = Field(default_factory=list)
    # Analysis-pipeline state
    original_filename: Optional[str] = None
    mime_type: Optional[str] = None
    analysis_status: Optional[str] = None
    dynamic_analysis: Optional[dict] = None
    # Part 2: Network Intelligence, Threat Assessment, AI Analysis
    network_indicators: Optional[NetworkIndicators] = None
    threat_assessment: Optional[ThreatAssessment] = None
    ai_analysis: Optional[AiAnalysisOutput] = None
    ioc_intelligence: list[dict] = Field(default_factory=list)
    evidence_correlation: list[dict] = Field(default_factory=list)
    evidence_timeline: list[dict] = Field(default_factory=list)
    risk_explanation: Optional[dict] = None
    malware_bazaar: Optional[dict] = None

    @field_validator(
        "sample_id", "platform", "file_type", "status", "submitted_at",
        "sha256", "md5", "sha1", "original_filename", "mime_type", "analysis_status",
        mode="before"
    )
    @classmethod
    def coerce_str_fields(cls, v: Any) -> Any:
        return str(v) if v is not None else v


class AnalysisStartResponse(BaseModel):
    """Returned by POST /api/cases/upload — analysis runs in the background and
    the client polls GET /api/cases/{analysis_id}/status for real progress."""
    analysis_id: str
    sample_id: str
    original_filename: str
    file_type: str
    mime_type: str
    sha256: str
    file_size_bytes: int
    status: str  # pipeline status (UPLOADED / COMPLETED when a duplicate sample exists)
    stage: Optional[str] = None
    message: Optional[str] = None


class AnalysisStatus(BaseModel):
    """Real backend pipeline progress used by the upload status poller."""
    analysis_id: str
    status: str
    stage: Optional[str] = None
    dynamic_status: Optional[str] = None
    error: Optional[str] = None
    file_type: Optional[str] = None
    updated_at: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    sandbox_online: bool
    version: str
    # False means the API is running on the in-memory fallback store and every
    # write is being discarded on restart (see backend/app/db.py init_db()).
    # Surfaced here because that failure is otherwise invisible from outside.
    database_online: bool = False


def risk_score_to_status(score: int) -> str:
    """Shared logic for turning a numeric score into a dashboard status badge."""
    if score >= 60:
        return "malicious"
    elif score >= 25:
        return "suspicious"
    return "clean"


def threat_level_from_score(score: int) -> str:
    """Map a 0-100 risk score to a named threat level per the E-Rakshak scale."""
    if score >= 90:
        return "SEVERE"
    elif score >= 70:
        return "CRITICAL"
    elif score >= 40:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    return "LOW"


def verdict_from_score(score: int) -> str:
    """Map a 0-100 risk score to a verdict string."""
    if score >= 60:
        return "MALICIOUS"
    elif score >= 20:
        return "SUSPICIOUS"
    return "CLEAN"


def confidence_from_signals(yara_count: int, mitre_count: int, has_dynamic: bool) -> int:
    """Estimate analysis confidence 0-100 based on breadth of evidence collected."""
    base = 30
    base += min(yara_count * 8, 30)
    base += min(mitre_count * 5, 20)
    if has_dynamic:
        base += 20
    return min(base, 100)