"""Structured outcomes for file hash operations."""

from dataclasses import dataclass
from enum import Enum


class HashStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"


class HashFailure(str, Enum):
    FILE_NOT_FOUND = "file_not_found"
    NOT_A_FILE = "not_a_file"
    READ_ERROR = "read_error"


@dataclass(frozen=True, slots=True)
class HashResult:
    """Hashes and operational status for one requested file."""

    source: str
    status: HashStatus
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    bytes_processed: int = 0
    failure: HashFailure | None = None

    @classmethod
    def failed(cls, source: str, failure: HashFailure) -> "HashResult":
        """Create a failure result without exposing an exception to callers."""
        return cls(source=source, status=HashStatus.FAILED, failure=failure)
