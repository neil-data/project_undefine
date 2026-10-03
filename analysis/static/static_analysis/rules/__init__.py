"""Shared, format-agnostic rule engine reusable by all static analyzers."""

from static_analysis.rules.contracts import Rule
from static_analysis.rules.engine import RuleEngine
from static_analysis.rules.models import (
    RiskScore,
    RuleCategory,
    RuleContext,
    RuleEngineResult,
    RuleMatch,
)
from static_analysis.rules.registry import RuleRegistry
from static_analysis.rules.settings import RuleEngineSettings

__all__ = (
    "RiskScore",
    "Rule",
    "RuleCategory",
    "RuleContext",
    "RuleEngine",
    "RuleEngineResult",
    "RuleEngineSettings",
    "RuleMatch",
    "RuleRegistry",
)
