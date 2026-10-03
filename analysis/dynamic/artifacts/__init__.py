"""Custody and post-processing for artifacts produced by a detonation run."""

from .memory import (
    STATIC_ENGINE_AVAILABLE,
    MemoryAnalysis,
    MemoryDumpAnalyzer,
)
from .memory_forensics import (
    MemoryForensicsAnalyzer,
    MemoryForensicsResult,
    MemoryRegion,
    ProcessInfo,
    ShellcodeMatch,
    CredentialMatch,
    analyze_memory_dump,
)
from .store import Artifact, ArtifactError, ArtifactStore, sha256_of

__all__ = (
    "Artifact",
    "ArtifactError",
    "ArtifactStore",
    "MemoryAnalysis",
    "MemoryDumpAnalyzer",
    "STATIC_ENGINE_AVAILABLE",
    "sha256_of",
    # Phase 5: Memory Forensics
    "MemoryForensicsAnalyzer",
    "MemoryForensicsResult",
    "MemoryRegion",
    "ProcessInfo",
    "ShellcodeMatch",
    "CredentialMatch",
    "analyze_memory_dump",
)
