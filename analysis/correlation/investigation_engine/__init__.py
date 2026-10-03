"""
investigation_engine — Phase 10 AI Investigation Engine.

This module provides AI-powered investigation workflow that processes all
collected evidence and generates a comprehensive investigation report.
"""

from .investigation_schema import (
    InvestigationState,
    TimelineEvent,
    MalwareExplanation,
    VictimImpact,
    ExfiltrationAnalysis,
    Recommendation,
    InvestigationSummary,
)
from .chain_verification import (
    ChainVerifier,
    ChainLink,
    VerificationStatus,
    ChainLinkType,
    VerificationResult,
    verify_chain,
    verify_integrity,
)

__all__ = [
    "InvestigationState",
    "TimelineEvent",
    "MalwareExplanation",
    "VictimImpact",
    "ExfiltrationAnalysis",
    "Recommendation",
    "InvestigationSummary",
    "ChainVerifier",
    "ChainLink",
    "VerificationStatus",
    "ChainLinkType",
    "VerificationResult",
    "verify_chain",
    "verify_integrity",
]
