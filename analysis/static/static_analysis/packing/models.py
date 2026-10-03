"""Structured outcomes for packer detection and unpacking attempts."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PackerFinding:
    """Packing verdict derived from already-computed format indicators."""

    is_packed: bool
    packer_name: str | None = None
    confidence: float = 0.0
    evidence: tuple[str, ...] = ()

    @classmethod
    def not_packed(cls) -> "PackerFinding":
        return cls(is_packed=False)


@dataclass(frozen=True, slots=True)
class UnpackResult:
    """Outcome of one best-effort unpacking attempt — never raises to the caller."""

    attempted: bool
    succeeded: bool
    method: str | None = None
    output_path: str | None = None
    sha256: str | None = None
    error: str | None = None

    @classmethod
    def not_attempted(cls) -> "UnpackResult":
        return cls(attempted=False, succeeded=False)
