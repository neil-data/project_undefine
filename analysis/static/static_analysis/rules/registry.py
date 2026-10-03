"""Registry for rule plugins; mirrors `detection.registry.FileDetectorRegistry`."""

from collections.abc import Callable

from static_analysis.rules.contracts import Rule

RuleFactory = Callable[[], Rule]


class DuplicateRuleError(ValueError):
    """Raised when a rule identifier is registered more than once."""


class RuleRegistry:
    """Maintains rule factories without coupling to any analyzer format."""

    def __init__(self) -> None:
        self._factories: dict[str, RuleFactory] = {}

    def register(self, factory: RuleFactory) -> None:
        """Register a rule factory after validating its unique identifier."""
        rule = factory()
        if rule.identifier in self._factories:
            raise DuplicateRuleError(f"Rule already registered: {rule.identifier}")
        self._factories[rule.identifier] = factory

    def rules(self) -> tuple[Rule, ...]:
        """Create rules in deterministic, identifier-sorted order."""
        return tuple(factory() for _, factory in sorted(self._factories.items()))
