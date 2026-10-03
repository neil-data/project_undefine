"""Service contracts for packer detection and unpacking used by the engine."""

from pathlib import Path
from typing import Protocol

from static_analysis.packing.models import PackerFinding, UnpackResult


class PackerDetectionService(Protocol):
    """Classifies a packer family from already-computed format indicators."""

    def detect(
        self,
        *,
        is_packed: bool,
        suspicious_section_names: tuple[str, ...] = (),
        high_entropy_sections: tuple[str, ...] = (),
    ) -> PackerFinding:
        """Return a packing verdict for the supplied indicators."""


class UnpackingService(Protocol):
    """Attempts to recover the underlying binary of a packed sample."""

    def unpack(self, source: str | Path) -> UnpackResult:
        """Return a structured outcome; never raises regardless of failure mode."""
