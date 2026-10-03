"""Composition helper for the default hash service."""

from static_analysis.hashing.engine import HashEngine


def create_hash_engine(chunk_size: int | None = None) -> HashEngine:
    """Create the default hash service with an optional bounded read size."""
    return HashEngine() if chunk_size is None else HashEngine(chunk_size=chunk_size)
