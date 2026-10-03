"""Immutable contracts returned by signature-based file detection."""

from dataclasses import dataclass
from enum import Enum

from static_analysis.domain.enums import TargetFormat


class DetectedFileType(str, Enum):
    ANDROID_PACKAGE = "android_package"
    WINDOWS_EXECUTABLE = "windows_executable"
    WINDOWS_DYNAMIC_LIBRARY = "windows_dynamic_library"
    ELF_EXECUTABLE = "elf_executable"
    ELF_SHARED_OBJECT = "elf_shared_object"
    MACH_O_EXECUTABLE = "mach_o_executable"
    MACH_O_DYNAMIC_LIBRARY = "mach_o_dynamic_library"
    MACH_O_BUNDLE = "mach_o_bundle"
    UNKNOWN = "unknown"


class FileFormat(str, Enum):
    APK = "apk"
    PE = "pe"
    ELF = "elf"
    MACH_O = "mach_o"
    UNKNOWN = "unknown"


class Platform(str, Enum):
    ANDROID = "android"
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class Architecture(str, Enum):
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    UNIVERSAL = "universal"
    UNKNOWN = "unknown"


class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """Classification based solely on container signatures and binary headers."""

    file_type: DetectedFileType
    file_format: FileFormat
    mime_type: str | None
    architecture: Architecture | None
    platform: Platform
    confidence: ConfidenceLevel
    target_format: TargetFormat | None
    detector_id: str | None = None

    @classmethod
    def unknown(cls) -> "DetectionResult":
        """Return the stable result for unsupported, unreadable, or invalid input."""
        return cls(
            file_type=DetectedFileType.UNKNOWN,
            file_format=FileFormat.UNKNOWN,
            mime_type=None,
            architecture=None,
            platform=Platform.UNKNOWN,
            confidence=ConfidenceLevel.NONE,
            target_format=None,
        )
