"""Immutable configuration for engine assembly."""

from dataclasses import dataclass

from static_analysis.constants import DEFAULT_MAX_REGISTERED_ANALYZERS


@dataclass(frozen=True, slots=True)
class RegistrySettings:
    """Limits and policies for analyzer registration."""

    max_registered_analyzers: int = DEFAULT_MAX_REGISTERED_ANALYZERS

    def __post_init__(self) -> None:
        if self.max_registered_analyzers < 1:
            raise ValueError("max_registered_analyzers must be positive")


@dataclass(frozen=True, slots=True)
class EngineSettings:
    """Top-level settings supplied when assembling an engine instance."""

    registry: RegistrySettings = RegistrySettings()
