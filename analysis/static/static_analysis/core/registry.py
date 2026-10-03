"""Registry for analyzer extensions; it never inspects target content."""

from collections.abc import Callable, Iterable
from typing import Protocol

from static_analysis.analyzers.base import Analyzer
from static_analysis.config.settings import RegistrySettings
from static_analysis.core.exceptions import DuplicateAnalyzerError, RegistryCapacityError
from static_analysis.domain.enums import TargetFormat

AnalyzerFactory = Callable[[], Analyzer]


class AnalyzerPlugin(Protocol):
    """Optional plugin boundary for packages that register several analyzers."""

    def register(self, registry: "AnalyzerRegistry") -> None:
        """Register the plugin's analyzers with the supplied registry."""


class AnalyzerRegistry:
    """Owns analyzer factories and exposes immutable discovery views."""

    def __init__(self, settings: RegistrySettings | None = None) -> None:
        # Defaulted so `AnalyzerRegistry()` works: the engine constructs one
        # directly when no registry is supplied, and requiring settings there
        # made `StaticAnalysisEngine()` raise TypeError for every caller that
        # did not go through create_engine().
        self._settings = settings or RegistrySettings()
        self._factories: dict[str, AnalyzerFactory] = {}

    def register(self, factory: AnalyzerFactory) -> None:
        """Register a factory after validating its descriptor."""
        analyzer = factory()
        identifier = analyzer.descriptor.identifier
        if identifier in self._factories:
            raise DuplicateAnalyzerError(f"Analyzer already registered: {identifier}")
        if len(self._factories) >= self._settings.max_registered_analyzers:
            raise RegistryCapacityError("Analyzer registry capacity reached")
        self._factories[identifier] = factory

    def load_plugin(self, plugin: AnalyzerPlugin) -> None:
        """Allow a plugin package to perform its own registrations."""
        plugin.register(self)

    def create(self, identifier: str) -> Analyzer:
        """Create a fresh analyzer instance by stable identifier."""
        return self._factories[identifier]()

    def identifiers(self) -> tuple[str, ...]:
        """Return registered identifiers in deterministic order."""
        return tuple(sorted(self._factories))

    def for_format(self, target_format: TargetFormat) -> Iterable[Analyzer]:
        """Instantiate analyzers that declare support for a given known format."""
        for identifier in self.identifiers():
            analyzer = self.create(identifier)
            if target_format in analyzer.descriptor.supported_formats:
                yield analyzer
