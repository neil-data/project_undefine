"""
Container member iteration.

WHY THIS EXISTS
---------------
An APK is a zip, and a zip stores its members deflate-compressed. Scanning the
raw file therefore sees compressed bytes: the DEX never appears, the manifest
never appears, and every signature written against Android strings silently
matches nothing. A test fixture built with `writestr` defaults to ZIP_STORED
and hides the problem completely — the rules pass their tests and detect
nothing in the field.

So container members are decompressed and scanned individually. That also
buys per-member attribution, which is better evidence: "the C2 URL is in
`assets/config.json`" is a statement an investigator can act on in a way that
"the C2 URL is somewhere in the APK" is not.

DECOMPRESSION BOMBS
-------------------
Anything that decompresses attacker-controlled data has to assume the archive
is hostile. Three independent limits apply: per-member size, total extracted
size, and member count. A 42KB zip that expands to 4.5PB is a real technique,
and the sample being analyzed is by definition untrusted.

UNSUPPORTED FORMATS
--------------------
The code handles various archive formats gracefully:
- ZIP family (APK, JAR, AAB, plain zip): Primary supported format
- Encrypted archives: Skipped with appropriate logging
- Unsupported compression methods: Skipped without aborting analysis
- Corrupted archives: Handled gracefully with error logging
- Non-archive files: Return empty iterator without errors
"""

from __future__ import annotations

import logging
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

_LOGGER = logging.getLogger(__name__)

MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_MEMBERS = 400

# Members whose contents cannot carry signatures or indicators worth the
# decompression cost. Images and fonts dominate an APK's member count.
_SKIPPED_SUFFIXES = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".ttf", ".otf",
    ".woff", ".woff2", ".mp3", ".mp4", ".ogg", ".wav", ".m4a", ".webm",
})

# Always read these even if large: they carry the code and the configuration.
_PRIORITY_NAMES = ("androidmanifest.xml", "classes.dex", "resources.arsc")


@dataclass(frozen=True, slots=True)
class ContainerMember:
    """One decompressed entry, with the name an investigator will see quoted."""

    name: str
    data: bytes
    compressed_size: int
    original_size: int

    @property
    def compression_ratio(self) -> float:
        if self.compressed_size <= 0:
            return 0.0
        return self.original_size / self.compressed_size


def is_container(path: str | Path) -> bool:
    """True for zip-family containers (APK, JAR, AAB, plain zip)."""
    try:
        return zipfile.is_zipfile(Path(path))
    except OSError:
        return False


def _priority(name: str) -> int:
    lowered = name.lower().rsplit("/", 1)[-1]
    for index, priority_name in enumerate(_PRIORITY_NAMES):
        if lowered == priority_name:
            return index
    return len(_PRIORITY_NAMES)


def iter_members(
    path: str | Path,
    max_member_bytes: int = MAX_MEMBER_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
    max_members: int = MAX_MEMBERS,
) -> Iterator[ContainerMember]:
    """
    Yield decompressed members, most analytically valuable first.

    Ordering matters because the limits are real: if a sample is padded with
    four hundred junk entries, the manifest and the DEX must still be among
    the ones that get read.
    """
    source = Path(path)
    try:
        archive = zipfile.ZipFile(source)
    except (OSError, zipfile.BadZipFile) as error:
        _LOGGER.warning("Cannot open container %s: %s", source, error)
        return

    total = 0
    emitted = 0
    with archive:
        try:
            entries = [item for item in archive.infolist() if not item.is_dir()]
        except (OSError, zipfile.BadZipFile) as error:
            _LOGGER.warning("Cannot list container %s: %s", source, error)
            return

        entries.sort(key=lambda item: (_priority(item.filename), item.filename))

        for entry in entries:
            if emitted >= max_members or total >= max_total_bytes:
                _LOGGER.info("Container limits reached while reading %s", source)
                return

            name = entry.filename
            if _priority(name) == len(_PRIORITY_NAMES):
                suffix = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
                if suffix in _SKIPPED_SUFFIXES:
                    continue

            if entry.file_size > max_member_bytes:
                _LOGGER.info("Skipping oversized member %s in %s", name, source)
                continue
            if total + entry.file_size > max_total_bytes:
                continue

            try:
                data = archive.read(name)
            except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
                # Encrypted or unsupported-compression members are common in
                # deliberately awkward samples; skipping one must not abort
                # the analysis of the rest.
                _LOGGER.info("Unreadable member %s in %s: %s", name, source, error)
                continue

            total += len(data)
            emitted += 1
            yield ContainerMember(
                name=name,
                data=data,
                compressed_size=entry.compress_size,
                original_size=entry.file_size,
            )
