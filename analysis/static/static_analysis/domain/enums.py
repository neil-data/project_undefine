"""Closed vocabularies shared by all future analyzers."""

from enum import Enum


class TargetFormat(str, Enum):
    APK = "apk"
    EXE = "exe"
    DLL = "dll"
    ELF = "elf"
    MACH_O = "mach_o"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
