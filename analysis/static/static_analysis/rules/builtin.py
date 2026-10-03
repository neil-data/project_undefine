"""Built-in, format-agnostic rules shipped with the engine."""

from static_analysis.detection.models import ConfidenceLevel
from static_analysis.domain.enums import Severity
from static_analysis.rules.contracts import Rule
from static_analysis.rules.models import RuleCategory, RuleContext, RuleMatch
from static_analysis.strings.explain import KEYWORD_EXPLANATIONS
from static_analysis.strings.models import StringType

# Single source of truth for suspicious command/API keywords lives in
# strings/explain.py so the rule engine and the per-string explanations
# shown to investigators can never drift apart.
_SUSPICIOUS_STRING_KEYWORDS = tuple(keyword for keyword, *_ in KEYWORD_EXPLANATIONS)
_EXPLANATION_BY_KEYWORD = {keyword: explanation for keyword, _category, _severity, explanation in KEYWORD_EXPLANATIONS}

_NETWORK_STRING_TYPES = frozenset({StringType.URL, StringType.IPV4, StringType.IPV6, StringType.DOMAIN})


class SuspiciousImportsRule(Rule):
    """Flags known dangerous or anti-analysis API/library imports."""

    @property
    def identifier(self) -> str:
        return "builtin.suspicious_imports"

    def evaluate(self, context: RuleContext) -> RuleMatch | None:
        if not context.suspicious_apis:
            return None
        return RuleMatch(
            rule_id=self.identifier,
            title="Suspicious imports or APIs referenced",
            category=RuleCategory.SUSPICIOUS_IMPORT,
            severity=Severity.HIGH,
            confidence=ConfidenceLevel.HIGH,
            description="The binary references APIs commonly associated with process injection, evasion, or remote execution.",
            evidence=tuple(sorted(set(context.suspicious_apis))[:20]),
        )


class DangerousPermissionsRule(Rule):
    """Flags requested permissions considered dangerous or privacy-sensitive."""

    @property
    def identifier(self) -> str:
        return "builtin.dangerous_permissions"

    def evaluate(self, context: RuleContext) -> RuleMatch | None:
        if not context.dangerous_permissions:
            return None
        return RuleMatch(
            rule_id=self.identifier,
            title="Dangerous permissions requested",
            category=RuleCategory.DANGEROUS_PERMISSION,
            severity=Severity.MEDIUM,
            confidence=ConfidenceLevel.HIGH,
            description="The target requests permissions capable of sensitive data access or device control.",
            evidence=tuple(sorted(set(context.dangerous_permissions))[:20]),
        )


class HighEntropyRule(Rule):
    """Flags sections whose byte entropy suggests compression or encryption."""

    @property
    def identifier(self) -> str:
        return "builtin.high_entropy"

    def evaluate(self, context: RuleContext) -> RuleMatch | None:
        flagged = tuple(
            f"{name}={entropy:.2f}"
            for name, entropy in sorted(context.section_entropies.items())
            if entropy >= context.high_entropy_threshold
        )
        if not flagged:
            return None
        return RuleMatch(
            rule_id=self.identifier,
            title="High-entropy sections detected",
            category=RuleCategory.HIGH_ENTROPY,
            severity=Severity.MEDIUM,
            confidence=ConfidenceLevel.MEDIUM,
            description="One or more sections have entropy consistent with compressed, encrypted, or packed content.",
            evidence=flagged[:20],
        )


class PackedBinaryRule(Rule):
    """Flags analyzer-supplied packing heuristics."""

    @property
    def identifier(self) -> str:
        return "builtin.packed_binary"

    def evaluate(self, context: RuleContext) -> RuleMatch | None:
        if not context.packed_indicators:
            return None
        return RuleMatch(
            rule_id=self.identifier,
            title="Packing indicators present",
            category=RuleCategory.PACKED_BINARY,
            severity=Severity.HIGH,
            confidence=ConfidenceLevel.MEDIUM,
            description="Structural characteristics suggest the binary may be packed or obfuscated.",
            evidence=tuple(sorted(set(context.packed_indicators)))[:20],
        )


class SuspiciousStringsRule(Rule):
    """Flags extracted strings matching known suspicious command/API keywords."""

    @property
    def identifier(self) -> str:
        return "builtin.suspicious_strings"

    def evaluate(self, context: RuleContext) -> RuleMatch | None:
        matched = set()
        for item in context.strings:
            lowered = item.value.lower()
            for keyword in _SUSPICIOUS_STRING_KEYWORDS:
                if keyword in lowered:
                    value = item.value.strip()[:120]
                    matched.add(f"{value} — {_EXPLANATION_BY_KEYWORD[keyword]}")
                    break
        if not matched:
            return None
        return RuleMatch(
            rule_id=self.identifier,
            title="Suspicious strings found",
            category=RuleCategory.SUSPICIOUS_STRING,
            severity=Severity.MEDIUM,
            confidence=ConfidenceLevel.LOW,
            description="Extracted strings reference shell execution, living-off-the-land tools, or download primitives.",
            evidence=tuple(sorted(matched))[:20],
        )


class EmbeddedNetworkIndicatorsRule(Rule):
    """Flags embedded URLs, IP addresses, or domains found in extracted strings."""

    @property
    def identifier(self) -> str:
        return "builtin.network_indicators"

    def evaluate(self, context: RuleContext) -> RuleMatch | None:
        values = tuple(
            sorted({item.value for item in context.strings if item.string_type in _NETWORK_STRING_TYPES})
        )
        if not values:
            return None
        return RuleMatch(
            rule_id=self.identifier,
            title="Embedded network indicators present",
            category=RuleCategory.NETWORK_INDICATOR,
            severity=Severity.LOW,
            confidence=ConfidenceLevel.MEDIUM,
            description="The target embeds URLs, IP addresses, or domain names that may indicate C2 or exfiltration endpoints.",
            evidence=values[:20],
        )


class ExecutableWritableSectionsRule(Rule):
    """Flags sections mapped as both writable and executable."""

    @property
    def identifier(self) -> str:
        return "builtin.executable_writable_sections"

    def evaluate(self, context: RuleContext) -> RuleMatch | None:
        if not context.executable_writable_sections:
            return None
        return RuleMatch(
            rule_id=self.identifier,
            title="Writable and executable sections present",
            category=RuleCategory.EXECUTABLE_WRITABLE_SECTION,
            severity=Severity.HIGH,
            confidence=ConfidenceLevel.HIGH,
            description="Sections mapped as both writable and executable are commonly used for self-modifying or shellcode-staging code.",
            evidence=tuple(sorted(set(context.executable_writable_sections))),
        )


class UnsignedBinaryRule(Rule):
    """Flags binaries known not to carry a valid code signature."""

    @property
    def identifier(self) -> str:
        return "builtin.unsigned_binary"

    def evaluate(self, context: RuleContext) -> RuleMatch | None:
        if context.is_signed is not False:
            return None
        return RuleMatch(
            rule_id=self.identifier,
            title="Binary is unsigned",
            category=RuleCategory.UNSIGNED_BINARY,
            severity=Severity.LOW,
            confidence=ConfidenceLevel.HIGH,
            description="The binary does not carry a recognized digital signature or code signing block.",
        )


class SuspiciousMetadataRule(Rule):
    """Flags miscellaneous analyzer-supplied metadata anomalies."""

    @property
    def identifier(self) -> str:
        return "builtin.suspicious_metadata"

    def evaluate(self, context: RuleContext) -> RuleMatch | None:
        flags = list(context.suspicious_metadata)
        if context.is_stripped:
            flags.append("stripped_symbol_table")
        if context.suspicious_section_names:
            flags.extend(f"suspicious_section:{name}" for name in context.suspicious_section_names)
        if not flags:
            return None
        return RuleMatch(
            rule_id=self.identifier,
            title="Suspicious metadata characteristics",
            category=RuleCategory.SUSPICIOUS_METADATA,
            severity=Severity.LOW,
            confidence=ConfidenceLevel.LOW,
            description="The target exhibits structural or metadata anomalies commonly seen in tampered or hand-crafted binaries.",
            evidence=tuple(sorted(set(flags)))[:20],
        )


def default_rules() -> tuple[Rule, ...]:
    """Return one instance of every built-in rule in a deterministic order."""
    return (
        SuspiciousImportsRule(),
        DangerousPermissionsRule(),
        HighEntropyRule(),
        PackedBinaryRule(),
        SuspiciousStringsRule(),
        EmbeddedNetworkIndicatorsRule(),
        ExecutableWritableSectionsRule(),
        UnsignedBinaryRule(),
        SuspiciousMetadataRule(),
    )
