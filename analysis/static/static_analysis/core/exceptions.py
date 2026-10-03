"""Domain-specific errors emitted by foundational infrastructure."""


class StaticAnalysisError(Exception):
    """Base exception for engine failures."""


class DuplicateAnalyzerError(StaticAnalysisError):
    """Raised when an analyzer identifier is registered more than once."""


class RegistryCapacityError(StaticAnalysisError):
    """Raised when a registry exceeds its configured capacity."""
