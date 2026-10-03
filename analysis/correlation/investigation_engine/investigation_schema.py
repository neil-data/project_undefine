"""
investigation_schema.py — Data contracts for the AI Investigation Engine.

Defines the schema for the investigation workflow state and outputs.
"""

from __future__ import annotations
from typing import Optional, Literal, TypedDict, List
from pydantic import BaseModel, Field
from datetime import datetime


class TimelineEvent(BaseModel):
    """A single event in the malware execution timeline."""
    timestamp: str
    event_type: Literal["static", "dynamic", "network", "file", "registry", "process"]
    description: str
    severity: Literal["info", "warning", "critical"]
    evidence: List[str] = Field(default_factory=list)


class MalwareExplanation(BaseModel):
    """AI-generated explanation of what the malware does."""
    summary: str
    technical_details: str
    capabilities_identified: List[str] = Field(default_factory=list)
    confidence_level: float = Field(ge=0.0, le=1.0)


class VictimImpact(BaseModel):
    """Analysis of how the victim is affected."""
    data_accessed: List[str] = Field(default_factory=list)
    privacy_risks: List[str] = Field(default_factory=list)
    financial_risks: List[str] = Field(default_factory=list)
    device_integrity: List[str] = Field(default_factory=list)
    overall_impact: Literal["low", "medium", "high", "critical"]
    explanation: str


class ExfiltrationAnalysis(BaseModel):
    """Analysis of data exfiltration patterns."""
    data_types: List[str] = Field(default_factory=list)
    destinations: List[str] = Field(default_factory=list)
    timing_patterns: str
    encryption_status: str
    estimated_volume: str
    risk_assessment: str


class Recommendation(BaseModel):
    """A specific recommendation for the investigator."""
    priority: Literal["immediate", "high", "medium", "low"]
    category: Literal["containment", "evidence", "investigation", "victim"]
    action: str
    rationale: str


class InvestigationSummary(BaseModel):
    """Final investigation summary."""
    executive_summary: str
    key_findings: List[str] = Field(default_factory=list)
    timeline_summary: str
    risk_assessment: str
    next_steps: List[str] = Field(default_factory=list)
    generated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class InvestigationState(TypedDict, total=False):
    """
    The Investigation Engine state object. Each node reads/writes into this
    dict as the investigation workflow executes.
    """
    sample_id: str
    static_output: Optional[dict]
    dynamic_output: Optional[dict]
    mitre_techniques: Optional[List[dict]]
    capability_tags: Optional[List[dict]]
    risk_score: Optional[int]
    
    # Investigation-specific state
    timeline_events: List[TimelineEvent]
    malware_explanation: Optional[MalwareExplanation]
    victim_impact: Optional[VictimImpact]
    exfiltration_analysis: Optional[ExfiltrationAnalysis]
    recommendations: List[Recommendation]
    investigation_summary: Optional[InvestigationSummary]
