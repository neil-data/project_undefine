"""Filesystem metadata extraction composed with detection and hashing services."""

import logging
from datetime import datetime, timezone
from pathlib import Path

from static_analysis.detection.service import FileTypeDetectionService
from static_analysis.hashing.contracts import HashService
from static_analysis.hashing.models import HashStatus
from static_analysis.metadata.models import MetadataFailure, MetadataResult, MetadataStatus

_LOGGER = logging.getLogger(__name__)


class MetadataExtractionService:
    """Extracts analyzer-neutral file facts after validating local file access."""

    def __init__(self, detector: FileTypeDetectionService, hasher: HashService) -> None:
        self._detector = detector
        self._hasher = hasher

    def extract(self, path: str | Path) -> MetadataResult:
        """Collect filesystem fields and shared-service output for a non-empty file."""
        source = Path(path)
        source_name = str(source)
        try:
            if not source.exists():
                return MetadataResult.failed(source_name, MetadataFailure.FILE_NOT_FOUND)
            if not source.is_file():
                return MetadataResult.failed(source_name, MetadataFailure.NOT_A_FILE)
            file_stat = source.stat()
            if file_stat.st_size == 0:
                return MetadataResult.failed(source_name, MetadataFailure.EMPTY_FILE)
            with source.open("rb") as stream:
                stream.read(1)
            absolute_path = str(source.resolve())
        except PermissionError:
            _LOGGER.warning("File is not readable for metadata extraction: %s", source_name, exc_info=True)
            return MetadataResult.failed(source_name, MetadataFailure.NOT_READABLE)
        except OSError:
            _LOGGER.warning("Unable to read file metadata: %s", source_name, exc_info=True)
            return MetadataResult.failed(source_name, MetadataFailure.READ_ERROR)

        detection = self._detector.detect(source)
        hashes = self._hasher.calculate(source)
        status = MetadataStatus.COMPLETED if hashes.status is HashStatus.COMPLETED else MetadataStatus.PARTIAL
        return MetadataResult(
            source=source_name,
            status=status,
            file_name=source.name,
            absolute_path=absolute_path,
            file_extension=source.suffix or None,
            file_size=file_stat.st_size,
            mime_type=detection.mime_type,
            detected_file_type=detection.file_type,
            file_format=detection.file_format,
            platform=detection.platform,
            architecture=detection.architecture,
            creation_time=datetime.fromtimestamp(file_stat.st_ctime, tz=timezone.utc),
            last_modified_time=datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc),
            last_accessed_time=datetime.fromtimestamp(file_stat.st_atime, tz=timezone.utc),
            hashes=hashes,
        )
