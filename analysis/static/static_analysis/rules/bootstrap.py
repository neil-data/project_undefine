"""Composition helper for the shared rule engine."""

from static_analysis.rules.builtin import default_rules
from static_analysis.rules.engine import RuleEngine
from static_analysis.rules.registry import RuleRegistry
from static_analysis.rules.settings import RuleEngineSettings


def create_rule_engine(settings: RuleEngineSettings | None = None) -> RuleEngine:
    """Assemble the rule engine with every built-in rule registered."""
    registry = RuleRegistry()
    for rule in default_rules():
        registry.register(lambda rule=rule: rule)
    return RuleEngine(rules=registry.rules(), settings=settings)
