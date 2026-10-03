"""
schema.py — Shared data contracts for the LangGraph orchestrator.

This defines the shape of data flowing between pipeline stages:
Static Analysis -> Dynamic Sandbox -> Agent Orchestrator -> MITRE Mapper
-> Capability Classifier -> Narrative Agent

Week 2 status: only StaticAnalysisOutput is "real" (proposed to Member 1
for confirmation). DynamicAnalysisOutput is a placeholder shape that will
be confirmed with Member 2 once the sandbox is live in Week 3.
"""

from __future__ import annotations
from typing import Optional, Literal, TypedDict
from pydantic import BaseModel, Field, ConfigDict


class YaraMatch(BaseModel):
    rule_name: str
    category: str
    severity: Literal["low", "medium", "high", "critical"]
    description: str


class AndroidManifestInfo(BaseModel):
    package_name: str
    permissions: list[str] = Field(default_factory=list)
    requested_sdk: Optional[int] = None
    exported_components: list[str] = Field(default_factory=list)


class PEAnalysisInfo(BaseModel):
    """Used for Windows PE format — both .exe and .dll share this shape."""
    imports: list[str] = Field(default_factory=list)
    sections: list[str] = Field(default_factory=list)
    compile_timestamp: Optional[str] = None


class BinaryAnalysisInfo(BaseModel):
    """
    Generic binary analysis for non-PE formats: ELF (Linux) and
    Mach-O (macOS). Windows EXE/DLL use PEAnalysisInfo instead —
    this keeps the two format families cleanly separated rather than
    forcing one bloated "works for everything" struct.
    """
    format: Literal["ELF", "MachO"]
    imports: list[str] = Field(default_factory=list)
    sections: list[str] = Field(default_factory=list)   # ELF sections / Mach-O segments
    architecture: Optional[str] = None                    # e.g. "x86_64", "arm64"
    is_signed: Optional[bool] = None                      # relevant for Mach-O code signing checks


class ExtractedStrings(BaseModel):
    urls: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    suspicious_keywords: list[str] = Field(default_factory=list)


class MLClassifierResult(BaseModel):
    model: str
    anomaly_score: float
    classification: Literal["benign", "suspicious", "likely_malicious"]


class StaticAnalysisOutput(BaseModel):
    """Proposed contract for Member 1's static-analysis module output."""
    sample_id: str
    sha256: str
    platform: Literal["android", "windows", "linux", "macos"]
    file_type: str          # e.g. "apk", "exe", "dll", "elf", "macho"
    file_size_bytes: int
    submitted_at: str

    yara_matches: list[YaraMatch] = Field(default_factory=list)
    android_manifest: Optional[AndroidManifestInfo] = None
    pe_analysis: Optional[PEAnalysisInfo] = None            # Windows: .exe and .dll
    binary_analysis: Optional[BinaryAnalysisInfo] = None     # Linux ELF / macOS Mach-O
    extracted_strings: ExtractedStrings
    ml_classifier: Optional[MLClassifierResult] = None
    static_risk_flags: list[str] = Field(default_factory=list)


class DynamicAnalysisOutput(BaseModel):
    model_config = ConfigDict(extra="allow")

    sample_id: str = "sample"
    execution_mode: str = "real"
    available: bool = True
    status: Optional[str] = "completed"
    dynamic_status: Optional[str] = "completed"  # "completed" | "failed" | "unavailable" | "no_behavior_observed"
    failure_reason: Optional[str] = None
    task_id: Optional[str] = None
    sandbox_url: Optional[str] = None
    message: Optional[str] = None
    target_architecture: Optional[str] = None
    duration_seconds: Optional[int] = None
    process_tree: list[dict] = Field(default_factory=list)
    api_calls: list[str] = Field(default_factory=list)
    network_connections: list[dict] = Field(default_factory=list)
    dns_queries: list[str] = Field(default_factory=list)
    files_written: list[str] = Field(default_factory=list)
    registry_changes: list[str] = Field(default_factory=list)          # Windows-specific
    persistence_artifacts: list[str] = Field(default_factory=list)      # cross-platform: cron entries, launchd plists, systemd units, etc.
    c2_endpoints_detected: list[str] = Field(default_factory=list)
    behavior_chains: list[dict] = Field(default_factory=list)          # Phase 3+: Behavior chains from hook engine

    def __getitem__(self, item: str):
        return getattr(self, item)

    def get(self, item: str, default=None):
        return getattr(self, item, default)



class MitreTechnique(BaseModel):
    technique_id: str        # e.g. "T1517"
    technique_name: str
    confidence: float


class CapabilityTag(BaseModel):
    capability: str          # e.g. "sms_otp_theft", "keylogging", "gps_tracking"
    confidence: float
    evidence: list[str] = Field(default_factory=list)
    evidence_state: Optional[Literal["OBSERVED", "STATIC", "INTEL", "observed", "static", "intel"]] = "STATIC"


class OrchestratorState(TypedDict, total=False):
    """
    The LangGraph shared state object. Each node reads/writes into this
    dict as the graph executes.
    """
    sample_id: str
    task_id: Optional[str]
    static_output: Optional[StaticAnalysisOutput]
    dynamic_output: Optional[DynamicAnalysisOutput]
    mitre_techniques: list[MitreTechnique]
    capability_tags: list[CapabilityTag]
    risk_score: Optional[int]
    intel_floor: Optional[int]
    victim_impact: Optional[str]
    malware_bazaar: Optional[dict]
    narrative_summary: Optional[str]
    # Phase 10: Investigation Engine
    investigation_output: Optional[dict]