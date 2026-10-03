"""Streaming hash implementation using Python's standard cryptographic library."""

import hashlib
import logging
from pathlib import Path

from static_analysis.hashing.models import HashFailure, HashResult, HashStatus

_DEFAULT_CHUNK_SIZE = 1024 * 1024
_LOGGER = logging.getLogger(__name__)


class HashEngine:
    """Computes MD5, SHA-1, and SHA-256 in one bounded-memory file pass."""

    def __init__(self, chunk_size: int = _DEFAULT_CHUNK_SIZE) -> None:
        if chunk_size < 1:
            raise ValueError("chunk_size must be positive")
        self._chunk_size = chunk_size

    def calculate(self, path: str | Path) -> HashResult:
        """Hash a regular file, returning a failure result for inaccessible input."""
        source = Path(path)
        source_name = str(source)
        try:
            if not source.exists():
                return HashResult.failed(source_name, HashFailure.FILE_NOT_FOUND)
            if not source.is_file():
                return HashResult.failed(source_name, HashFailure.NOT_A_FILE)
        except OSError:
            _LOGGER.warning("Unable to validate file for hashing: %s", source_name, exc_info=True)
            return HashResult.failed(source_name, HashFailure.READ_ERROR)

        md5 = hashlib.md5(usedforsecurity=False)
        sha1 = hashlib.sha1(usedforsecurity=False)
        sha256 = hashlib.sha256()
        bytes_processed = 0
        try:
            with source.open("rb") as stream:
                while block := stream.read(self._chunk_size):
                    md5.update(block)
                    sha1.update(block)
                    sha256.update(block)
                    bytes_processed += len(block)
        except OSError:
            _LOGGER.warning("Unable to read file for hashing: %s", source_name, exc_info=True)
            return HashResult.failed(source_name, HashFailure.READ_ERROR)

        return HashResult(
            source=source_name,
            status=HashStatus.COMPLETED,
            md5=md5.hexdigest(),
            sha1=sha1.hexdigest(),
            sha256=sha256.hexdigest(),
            bytes_processed=bytes_processed,
        )
