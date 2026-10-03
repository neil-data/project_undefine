"""
intake.py — Receiving a sample and turning it into a job.

WHAT INTAKE IS RESPONSIBLE FOR
------------------------------
Deciding, before any guest is touched, three things a wrong answer to is
expensive:

**Is this the same sample we already have?** The SHA-256 is the identity. The
same APK arrives as `challan.apk`, `e-challan(1).apk` and `IMG_20260114.apk`
from three districts; detonating it three times wastes forty-five minutes of
sandbox time each and produces three unlinked case records instead of one
sample with three submissions.

**Which guest can run it?** Decided from the file's own bytes, never its
extension. A `.pdf` that is really a PE is the ordinary case, not the unusual
one, and routing it to a Windows guest is the entire point of looking.

**Should it be queued at all?** An empty file, a directory, or something no
guest can execute is rejected here with a reason, rather than consuming a
snapshot restore to discover the same thing eight minutes later.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Optional
from zipfile import BadZipFile, ZipFile

from .models import AnalysisJob, JobPriority, JobState, Platform

_LOGGER = logging.getLogger(__name__)

_HASH_CHUNK = 1024 * 1024
MAX_SAMPLE_BYTES = 512 * 1024 * 1024


class SampleRejected(ValueError):
    """Raised when a submission cannot become a job."""


def sha256_of(path: str | Path) -> str:
    """Stream a file's SHA-256 without loading it."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(_HASH_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def detect_platform(path: str | Path) -> Platform:
    """
    Decide which guest a sample needs, from its bytes.

    Deliberately independent of the static analysis engine's detector: this
    runs on the detonation plane, which is network-isolated and does not
    install the static package. The question here is also narrower — not "what
    format is this" but "which guest can execute it" — so a small,
    self-contained sniffer is the right amount of machinery.
    """
    source = Path(path)
    try:
        with source.open("rb") as stream:
            head = stream.read(8)
    except OSError:
        return Platform.UNKNOWN

    if head[:2] == b"MZ":
        return Platform.WINDOWS
    if head[:4] == b"\x7fELF":
        return Platform.LINUX
    if head[:4] == b"dex\n":
        return Platform.ANDROID

    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        # A zip is an APK only if it carries an Android manifest. A JAR, an
        # AAB and a plain archive all share the same magic bytes.
        try:
            with ZipFile(source) as archive:
                names = set(archive.namelist())
            if "AndroidManifest.xml" in names or "classes.dex" in names:
                return Platform.ANDROID
        except (OSError, BadZipFile):
            return Platform.UNKNOWN

    return Platform.UNKNOWN


def receive_sample(
    sample_path: str | Path,
    *,
    priority: JobPriority = JobPriority.NORMAL,
    profile: str = "standard",
    submitted_by: str = "",
    case_reference: str = "",
    platform: Optional[Platform] = None,
    max_bytes: int = MAX_SAMPLE_BYTES,
) -> AnalysisJob:
    """
    Validate a submission and build the job for it.

    Raises SampleRejected with a stated reason rather than returning a job in
    a rejected state — a caller that forgets to check a status field would
    otherwise queue something unrunnable.
    """
    source = Path(sample_path)

    if not source.exists():
        raise SampleRejected(f"Sample not found: {source}")
    if not source.is_file():
        raise SampleRejected(f"Not a regular file: {source}")

    size = source.stat().st_size
    if size == 0:
        raise SampleRejected("Sample is empty (0 bytes)")
    if size > max_bytes:
        raise SampleRejected(
            f"Sample is {size} bytes, above the {max_bytes}-byte intake limit"
        )

    resolved_platform = platform or detect_platform(source)
    if resolved_platform is Platform.UNKNOWN:
        raise SampleRejected(
            "No sandbox can execute this file: its contents match no supported "
            "executable format (PE, ELF, DEX or APK)"
        )

    job = AnalysisJob(
        sample_path=str(source.resolve()),
        sha256=sha256_of(source),
        platform=resolved_platform,
        profile=profile,
        priority=priority,
        file_name=source.name,
        file_size=size,
        submitted_by=submitted_by,
        case_reference=case_reference,
    )
    job.transition(JobState.QUEUED, f"Received {source.name} ({size} bytes)")
    _LOGGER.info(
        "Job %s queued for %s: %s (%s)",
        job.job_id, resolved_platform.value, job.file_name, job.sha256[:12],
    )
    return job
