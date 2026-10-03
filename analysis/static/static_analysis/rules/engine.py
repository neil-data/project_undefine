"""Modular rule engine reusable by any format-specific analyzer."""

from collections.abc import Sequence

from static_analysis.rules.contracts import Rule
from static_analysis.rules.models import RiskScore, RuleContext, RuleEngineResult, RuleMatch
from static_analysis.rules.settings import RuleEngineSettings


class RuleEngine:
    """Evaluates a fixed set of rules against a normalized context."""

    def __init__(self, rules: Sequence[Rule], settings: RuleEngineSettings | None = None) -> None:
        self._rules = tuple(rules)
        self._settings = settings or RuleEngineSettings()

    def evaluate(self, context: RuleContext) -> RuleEngineResult:
        """Run every rule and return matches alongside a bounded risk score."""
        matches = tuple(match for rule in self._rules if (match := self._safe_evaluate(rule, context)) is not None)
        return RuleEngineResult(matches=matches, risk_score=self._score(matches))

    def score(self, matches: Sequence[RuleMatch]) -> RiskScore:
        """Compute a bounded risk score for a caller-assembled set of matches.

        Lets callers (e.g. the unified engine) combine matches gathered from
        several `RuleContext` evaluations — one per format analyzer plus the
        shared format-agnostic context — into a single explainable score
        without re-running rule evaluation.
        """
        return self._score(tuple(matches))

    def _safe_evaluate(self, rule: Rule, context: RuleContext) -> RuleMatch | None:
        """Evaluate one rule, isolating a malformed or misbehaving rule from the rest."""
        try:
            return rule.evaluate(context)
        except Exception:  # noqa: BLE001 - a single bad rule must not fail the engine
            return None

    def _score(self, matches: tuple[RuleMatch, ...]) -> RiskScore:
        total = 0.0
        for match in matches:
            total += self._settings.weight_for(match.severity, match.confidence)
        bounded = max(0, min(self._settings.max_score, round(total)))
        return RiskScore(
            value=bounded,
            band=self._settings.band_for(bounded),
            contributing_rules=tuple(match.rule_id for match in matches),
        )
