"""Service contract for hash providers used by future analyzers."""

from pathlib import Path
from typing import Protocol

from static_analysis.hashing.models import HashResult


class HashService(Protocol):
    """Computes the standard analysis hashes for a local file."""

    def calculate(self, path: str | Path) -> HashResult:
        """Return a structured result for the supplied path."""
