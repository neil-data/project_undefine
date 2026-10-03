"""Structured generic metadata for any file accepted by the engine."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from static_analysis.detection.models import (
    Architecture,
    DetectedFileType,
    FileFormat,
    Platform,
)
from static_analysis.hashing.models import HashResult


class MetadataStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class MetadataFailure(str, Enum):
    FILE_NOT_FOUND = "file_not_found"
    NOT_A_FILE = "not_a_file"
    NOT_READABLE = "not_readable"
    EMPTY_FILE = "empty_file"
    READ_ERROR = "read_error"


@dataclass(frozen=True, slots=True)
class MetadataResult:
    """Common filesystem, classification, and hash data for one source file."""

    source: str
    status: MetadataStatus
    file_name: str | None = None
    absolute_path: str | None = None
    file_extension: str | None = None
    file_size: int | None = None
    mime_type: str | None = None
    detected_file_type: DetectedFileType | None = None
    file_format: FileFormat | None = None
    platform: Platform | None = None
    architecture: Architecture | None = None
    creation_time: datetime | None = None
    last_modified_time: datetime | None = None
    last_accessed_time: datetime | None = None
    hashes: HashResult | None = None
    failure: MetadataFailure | None = None

    @classmethod
    def failed(cls, source: str, failure: MetadataFailure) -> "MetadataResult":
        """Create a safe, structured failure response for invalid input."""
        return cls(source=source, status=MetadataStatus.FAILED, failure=failure)
