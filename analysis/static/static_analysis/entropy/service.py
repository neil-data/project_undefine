"""
Byte-entropy analysis.

WHAT ENTROPY IS AND IS NOT EVIDENCE OF
--------------------------------------
"High entropy means packed" is the single most over-applied heuristic in
static analysis. An APK is a zip archive, so every APK ever built measures
above 7.5 bits per byte. A PNG, an MP4, a signed installer and a compressed
backup all do the same. Reporting those as packed produces a tool that flags
everything and therefore says nothing.

Entropy becomes evidence when it appears where the file's own structure says
it should not:

  • A near-random run past the end of the last declared section — a second
    stage appended to a dropper, invisible to section-level entropy because it
    belongs to no section.
  • A container member whose contents contradict its own name: a `.jpg` in
    `assets/` that is not a JPEG and measures 7.9 is an encrypted payload
    waiting for the loader, which is how a large share of Android droppers
    carry their real code past store review.
  • A single window of ciphertext inside otherwise ordinary code.

So this module measures the whole file, then measures it again in windows, and
reports the *contradictions* rather than the raw number.
"""

from __future__ import annotations

import logging
import math
import zipfile
from collections import Counter
from pathlib import Path

from static_analysis.entropy.models import (
    CODE_CEILING,
    COMPRESSED_CEILING,
    ENCRYPTED_FLOOR,
    EmbeddedBlob,
    EntropyClass,
    EntropyRegion,
    EntropyResult,
    EntropyStatus,
    EntropyWindow,
    PACKED_FLOOR,
    TEXT_CEILING,
)

_LOGGER = logging.getLogger(__name__)

_DEFAULT_WINDOW_SIZE = 8192
_MAX_WINDOWS = 4096                     # Bounds work on a very large sample
_MIN_BLOB_SIZE = 4096                   # Below this, entropy is not meaningful
_MAX_MEMBER_READ = 32 * 1024 * 1024

# Extensions whose contents are *expected* to be near-random. A high-entropy
# member with one of these names is unremarkable; the finding is a high-entropy
# member claiming to be something compressible.
_NATURALLY_HIGH_ENTROPY = frozenset({
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "mp3", "mp4", "m4a",
    "aac", "ogg", "webm", "avi", "mov", "zip", "gz", "bz2", "xz", "7z", "rar",
    "jar", "apk", "aab", "so", "dex", "odex", "vdex", "art", "pdf", "woff",
    "woff2", "ttf", "otf", "arsc", "bin", "dat", "pak", "crx",
})

# Extensions that promise compressible, structured content. Near-random bytes
# under one of these names is a deliberate disguise.
_EXPECTED_LOW_ENTROPY = frozenset({
    "txt", "json", "xml", "html", "htm", "css", "js", "csv", "md", "yml",
    "yaml", "properties", "ini", "cfg", "conf", "sql", "db", "sqlite", "log",
    "srt", "vtt", "po", "pot", "graphql", "proto",
})

_MAGIC_PREFIXES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"GIF8", "gif"),
    (b"RIFF", "riff"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"dex\n", "dex"),
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\x1f\x8b", "gzip"),
    (b"ID3", "mp3"),
)


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy of `data` in bits per byte (0.0–8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def classify_entropy(value: float) -> EntropyClass:
    """Map an entropy value onto what it most likely indicates."""
    if value <= 0.0:
        return EntropyClass.EMPTY
    if value < TEXT_CEILING:
        return EntropyClass.TEXT
    if value < CODE_CEILING:
        return EntropyClass.CODE
    if value < COMPRESSED_CEILING:
        return EntropyClass.COMPRESSED
    return EntropyClass.PACKED_OR_ENCRYPTED


def _declared_kind(name: str) -> str:
    suffix = Path(name).suffix.lstrip(".").lower()
    return suffix or "no extension"


def _sniff_magic(head: bytes) -> str | None:
    for prefix, kind in _MAGIC_PREFIXES:
        if head.startswith(prefix):
            return kind
    return None


class EntropyAnalysisService:
    """Measures whole-file, windowed and container-member entropy."""

    def __init__(
        self,
        window_size: int = _DEFAULT_WINDOW_SIZE,
        high_entropy_threshold: float = PACKED_FLOOR,
    ) -> None:
        if window_size < 256:
            raise ValueError("window_size must be at least 256 bytes")
        self._window_size = window_size
        self._threshold = high_entropy_threshold

    def analyze(self, path: str | Path,
                component_entropies: dict[str, float] | None = None) -> EntropyResult:
        """Return the full entropy picture, degrading to FAILED on unreadable input."""
        source = Path(path)
        try:
            return self._analyze(source, component_entropies or {})
        except (OSError, ValueError) as error:
            _LOGGER.warning("Entropy analysis failed for %s: %s", source, error)
            return EntropyResult(
                source=str(source),
                status=EntropyStatus.FAILED,
                error=str(error),
            )

    # -- internals ---------------------------------------------------------

    def _analyze(self, source: Path, components: dict[str, float]) -> EntropyResult:
        size = source.stat().st_size
        if size == 0:
            return EntropyResult(source=str(source), status=EntropyStatus.COMPLETED,
                                 file_size=0, classification=EntropyClass.EMPTY)

        # One streaming pass: whole-file distribution and per-window values are
        # both derived from the same read, so a large sample is never held in
        # memory and never read twice.
        window_size = self._effective_window_size(size)
        totals: Counter[int] = Counter()
        windows: list[EntropyWindow] = []

        with source.open("rb") as stream:
            offset = 0
            while chunk := stream.read(window_size):
                totals.update(chunk)
                value = shannon_entropy(chunk)
                windows.append(EntropyWindow(
                    offset=offset,
                    size=len(chunk),
                    entropy=value,
                    classification=classify_entropy(value),
                ))
                offset += len(chunk)

        overall = self._entropy_from_counts(totals, size)
        regions = self._high_entropy_regions(windows, size)
        is_container = self._is_container(source)
        blobs = self._embedded_blobs(source) if is_container else ()

        merged = dict(components)
        return EntropyResult(
            source=str(source),
            status=EntropyStatus.COMPLETED,
            overall_entropy=round(overall, 4),
            classification=classify_entropy(overall),
            file_size=size,
            windows=tuple(windows),
            high_entropy_regions=regions,
            embedded_blobs=blobs,
            is_container=is_container,
            component_entropies=merged,
        )

    @staticmethod
    def _is_container(source: Path) -> bool:
        try:
            return zipfile.is_zipfile(source)
        except OSError:
            return False

    def _effective_window_size(self, size: int) -> int:
        """Grow the window on large files so the pass stays bounded."""
        if size <= self._window_size * _MAX_WINDOWS:
            return self._window_size
        return max(self._window_size, (size // _MAX_WINDOWS) + 1)

    @staticmethod
    def _entropy_from_counts(counts: Counter[int], length: int) -> float:
        if length <= 0:
            return 0.0
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    def _high_entropy_regions(
        self, windows: list[EntropyWindow], file_size: int
    ) -> tuple[EntropyRegion, ...]:
        regions: list[EntropyRegion] = []
        run: list[EntropyWindow] = []

        def close_run() -> None:
            if not run:
                return
            start = run[0].offset
            end = run[-1].offset + run[-1].size
            mean = sum(w.entropy for w in run) / len(run)
            regions.append(EntropyRegion(
                start_offset=start,
                end_offset=end,
                mean_entropy=round(mean, 4),
                window_count=len(run),
                reaches_end_of_file=end >= file_size,
            ))

        for window in windows:
            if window.entropy >= self._threshold:
                run.append(window)
            else:
                close_run()
                run = []
        close_run()

        return tuple(region for region in regions if region.size >= _MIN_BLOB_SIZE)

    def _embedded_blobs(self, source: Path) -> tuple[EmbeddedBlob, ...]:
        """
        Find container members whose contents contradict their own name.

        Only meaningful for zip-family containers (APK, JAR, AAB); the caller
        gates on `_is_container` before reaching here.
        """
        blobs: list[EmbeddedBlob] = []
        try:
            with zipfile.ZipFile(source) as archive:
                for member in archive.infolist():
                    if member.is_dir() or member.file_size < _MIN_BLOB_SIZE:
                        continue
                    if member.file_size > _MAX_MEMBER_READ:
                        continue
                    kind = _declared_kind(member.filename)
                    if kind in _NATURALLY_HIGH_ENTROPY:
                        continue

                    try:
                        payload = archive.read(member.filename)
                    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
                        # Handle various archive member read failures gracefully:
                        # - OSError: I/O errors, permission issues
                        # - BadZipFile: Corrupted zip structure
                        # - RuntimeError: General zip processing errors
                        # - NotImplementedError: Unsupported compression methods
                        # These are common in deliberately awkward samples; skipping one
                        # member must not abort the analysis of the rest.
                        _LOGGER.info("Unreadable member %s in %s: %s", member.filename, source, error)
                        continue

                    value = shannon_entropy(payload)
                    # Deflate-compressed data reaches ~7.4; only ciphertext and
                    # well-packed code sit above this and stay there.
                    if value < ENCRYPTED_FLOOR:
                        continue

                    actual = _sniff_magic(payload[:16])
                    if actual is not None and actual == kind:
                        continue

                    reason = self._blob_reason(kind, actual)
                    blobs.append(EmbeddedBlob(
                        name=member.filename,
                        size=member.file_size,
                        entropy=round(value, 4),
                        declared_kind=kind,
                        reason=reason,
                    ))
        except (OSError, zipfile.BadZipFile) as error:
            _LOGGER.warning("Container entropy scan failed for %s: %s", source, error)
            return ()

        blobs.sort(key=lambda blob: (-blob.entropy, blob.name))
        return tuple(blobs[:50])

    @staticmethod
    def _blob_reason(declared: str, actual: str | None) -> str:
        if actual is not None:
            return (
                f"its first bytes identify it as {actual}, not {declared}, and the "
                f"rest is indistinguishable from random data"
            )
        if declared in _EXPECTED_LOW_ENTROPY:
            return (
                "a file of this type should be readable and compressible; near-random "
                "contents mean it is encrypted, and something in the app decrypts it"
            )
        return (
            "it matches no known file format and is indistinguishable from random "
            "data, which is what an encrypted second stage looks like"
        )
