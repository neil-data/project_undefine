"""Extension contracts implemented by individual, independently testable rules."""

from abc import ABC, abstractmethod

from static_analysis.rules.models import RuleContext, RuleMatch


class Rule(ABC):
    """A single, focused heuristic evaluated against a normalized `RuleContext`."""

    @property
    @abstractmethod
    def identifier(self) -> str:
        """Return the stable rule identifier used for provenance and scoring."""

    @abstractmethod
    def evaluate(self, context: RuleContext) -> RuleMatch | None:
        """Return a match if the rule's condition holds, otherwise None."""
