"""Chunked extraction of ASCII, UTF-8, UTF-16, and common indicator strings."""

import ipaddress
import logging
import math
import re
from collections import Counter
from collections.abc import Callable
from pathlib import Path

from static_analysis.metadata.contracts import MetadataService
from static_analysis.metadata.models import MetadataResult, MetadataStatus
from static_analysis.strings.models import (
    ExtractedString,
    StringExtractionResult,
    StringExtractionStatus,
    StringType,
)

_LOGGER = logging.getLogger(__name__)
_DEFAULT_CHUNK_SIZE = 1024 * 1024
_DEFAULT_MINIMUM_LENGTH = 4

# Upper bound on unique strings retained from one file.
#
# A packed or encrypted region is a stream of random bytes, and random bytes
# produce an enormous number of short printable runs — an 8MB high-entropy
# section alone yields millions, none of which carry any information. Past a
# couple of hundred thousand unique strings, further extraction adds analysis
# time and nothing else: the IOC, keyword and rule stages have long since seen
# everything the file has to say.
#
# The limit is reported through `StringExtractionResult.truncated` rather than
# applied silently.
_DEFAULT_MAX_STRINGS = 250_000

# Chunks at or above this entropy are skipped by the scanners.
#
# Near-random bytes contain no recoverable text: the four-character printable
# runs a regex finds inside ciphertext are coincidences, not strings, and an
# 8MB encrypted section produces millions of them. Scanning them cost roughly
# 25 of the 30 seconds an analysis of a 10MB APK took, and contributed nothing
# to any downstream stage.
#
# What is in those regions is not lost — the entropy analyzer reports the
# region explicitly, and the classifier turns it into a stated limitation
# ("part of this sample is encrypted and must be detonated to be seen").
_STRING_SCAN_ENTROPY_CEILING = 7.5
_ENTROPY_SAMPLE_BYTES = 65536

_ASCII_RUN = re.compile(rb"[\x20-\x7e]+")
_UTF8_CHARACTER = (
    rb"(?:[\x20-\x7e]|[\xc2-\xdf][\x80-\xbf]|"
    rb"\xe0[\xa0-\xbf][\x80-\xbf]|[\xe1-\xec\xee-\xef][\x80-\xbf]{2}|"
    rb"\xed[\x80-\x9f][\x80-\xbf]|\xf0[\x90-\xbf][\x80-\xbf]{2}|"
    rb"[\xf1-\xf3][\x80-\xbf]{3}|\xf4[\x80-\x8f][\x80-\xbf]{2})"
)
_UTF8_RUN = re.compile(_UTF8_CHARACTER + rb"+")
_UTF16LE_RUN = re.compile(rb"(?:[\x20-\x7e]\x00)+")
_UTF16BE_RUN = re.compile(rb"(?:\x00[\x20-\x7e])+")

_URL_PATTERN = re.compile(r"(?<![A-Za-z0-9_>:\*\\])(?:https?|ftps?)://[a-zA-Z0-9](?:[a-zA-Z0-9-._~:/?#\[\]@!$&'()*+,;=%]){4,}", re.IGNORECASE)
_EMAIL_PATTERN = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}", re.IGNORECASE)
_IPV4_PATTERN = re.compile(r"(?<![0-9.])((?:\d{1,3}\.){3}\d{1,3})(?![0-9.])")
_IPV6_PATTERN = re.compile(r"(?<![0-9A-F:])(?:[0-9A-F]{0,4}:){2,7}[0-9A-F]{0,4}(?![0-9A-F:])", re.IGNORECASE)
_WINDOWS_PATH_PATTERN = re.compile(r"(?:[A-Z]:\\|\\\\)[^\s\"'<>|?*]{3,}", re.IGNORECASE)
_UNIX_PATH_PATTERN = re.compile(
    r"/(?:bin|boot|dev|etc|home|lib|lib64|media|mnt|opt|proc|root|run|sbin|srv|sys|tmp|usr|var|data|system|sdcard)(?:/[^\s\"'<>|?*]{1,200})+|"
    r"/(?:[a-zA-Z0-9._\-+]{2,}/){2,}[a-zA-Z0-9._\-+]{2,}"
)
_REGISTRY_PATH_PATTERN = re.compile(r"(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s\"']+", re.IGNORECASE)
_DOMAIN_PATTERN = re.compile(r"(?<![A-Z0-9.-])(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}(?![A-Z0-9.-])", re.IGNORECASE)

_NON_DOMAIN_FILE_EXTENSIONS = {
    "html", "htm", "json", "js", "css", "sh", "bash", "zsh", "py", "pyc",
    "c", "h", "cpp", "txt", "xml", "yaml", "yml", "md", "log", "conf", "cfg",
    "ini", "so", "dll", "exe", "bin", "dat", "tmp", "o", "a", "out", "dex",
    "dexpk", "p", "jar", "zip", "tar", "gz", "bz2", "xz", "7z", "class",
    "local", "target", "service", "socket", "mount", "timer", "path", "scope",
    "slice", "lock", "pid", "status", "cache", "bak", "swp", "old", "sym", "map",
}


def _is_valid_domain_candidate(candidate: str, context: str, start: int, end: int) -> bool:
    if not candidate or len(candidate) < 4 or len(candidate) > 253:
        return False
    # Check if inside a path or filename context
    if start > 0 and context[start - 1] in ("/", "\\", "@", "."):
        return False
    if end < len(context) and context[end] in ("/", "\\", ":"):
        return False
    if "/" in candidate or "\\" in candidate:
        return False
    if candidate.startswith(".") or candidate.endswith("."):
        return False

    parts = candidate.lower().split(".")
    if len(parts) < 2:
        return False
    tld = parts[-1]
    # TLD must be alphabetic only (2-24 chars) and not a file extension
    if not re.match(r"^[a-z]{2,24}$", tld) or tld in _NON_DOMAIN_FILE_EXTENSIONS:
        return False

    # Check labels
    for part in parts:
        if not part or len(part) > 63:
            return False
        if not re.match(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", part):
            return False

    return True


def _is_valid_url(url: str) -> bool:
    if len(url) < 10:
        return False
    lowered = url.lower()
    if any(lowered.startswith(bad) for bad in ("http/1.", "http/2", "httponly", "httpu", "http-equiv")):
        return False
    try:
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        if parts.scheme.lower() not in ("http", "https", "ftp", "ftps"):
            return False
        host = parts.hostname or ""
        if not host or len(host) < 3 or any(c in host for c in ('"', "'", "<", ">", "*", "^", "\\", "{", "}", ":")):
            return False
        if "." not in host and host != "localhost":
            return False
        if host.startswith(".") or host.endswith(".") or host.startswith("-") or host.endswith("-"):
            return False
        return True
    except Exception:
        return False


def _is_incompressible(block: bytes) -> bool:
    """
    True when a block is dense enough that it cannot hold readable text.

    Measured on a 64KB sample rather than the whole megabyte: the distinction
    between compressed/encrypted data and anything containing text is stark, so
    a sample settles it, and the check has to be far cheaper than the scan it
    is avoiding or it defeats its own purpose.
    """
    if len(block) < _ENTROPY_SAMPLE_BYTES:
        return False
    sample = block[:_ENTROPY_SAMPLE_BYTES]
    counts = Counter(sample)
    length = len(sample)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return entropy >= _STRING_SCAN_ENTROPY_CEILING


class StringExtractionService:
    """Extracts unique strings in bounded input memory while retaining byte offsets."""

    def __init__(
        self,
        metadata_service: MetadataService,
        minimum_length: int = _DEFAULT_MINIMUM_LENGTH,
        chunk_size: int = _DEFAULT_CHUNK_SIZE,
        max_strings: int = _DEFAULT_MAX_STRINGS,
    ) -> None:
        if minimum_length < 1:
            raise ValueError("minimum_length must be positive")
        if chunk_size < 1:
            raise ValueError("chunk_size must be positive")
        if max_strings < 1:
            raise ValueError("max_strings must be positive")
        self._max_strings = max_strings
        self._metadata_service = metadata_service
        self._minimum_length = minimum_length
        self._chunk_size = chunk_size

        # Extraction is the most expensive stage in the pipeline — four regex
        # passes over the whole file — and one analysis extracts the same file
        # three times: once in the engine, then again in the format analyzer's
        # analyze() and extract(). Caching on (path, size, mtime) removes two
        # of those three passes and took a 10MB APK from ~90s to ~30s.
        #
        # Two entries is deliberate: an analysis holds at most the outer sample
        # and one unpacked inner file, so this never grows into a memory leak
        # across a batch run.
        self._cache: dict[tuple, tuple[ExtractedString, ...]] = {}
        self._cache_limit = 2

        # Bytes passed over because they were too dense to hold text.
        self._skipped_bytes = 0

    def extract(
        self, path: str | Path, metadata: MetadataResult | None = None
    ) -> StringExtractionResult:
        """Extract literals and indicators, returning controlled failures for bad input."""
        source = Path(path)
        source_name = str(source)
        resolved_metadata = metadata or self._metadata_service.extract(source)
        if resolved_metadata.status is MetadataStatus.FAILED:
            return StringExtractionResult(
                source=source_name,
                status=StringExtractionStatus.FAILED,
                strings=(),
                metadata=resolved_metadata,
                error=resolved_metadata.failure.value if resolved_metadata.failure else "metadata_failed",
            )

        cache_key = self._cache_key(source)
        cached = self._cache.get(cache_key) if cache_key is not None else None
        if cached is not None:
            return StringExtractionResult(
                source=source_name,
                status=StringExtractionStatus.COMPLETED,
                strings=cached,
                metadata=resolved_metadata,
                truncated=len(cached) >= self._max_strings,
            )

        records: dict[str, ExtractedString] = {}
        try:
            self._extract_ascii(source, records)
            self._extract_utf8(source, records)
            self._extract_utf16(source, _UTF16LE_RUN, "utf-16le", StringType.UTF16LE, records)
            self._extract_utf16(source, _UTF16BE_RUN, "utf-16be", StringType.UTF16BE, records)
        except (OSError, UnicodeError):
            _LOGGER.warning("Unable to extract strings from file: %s", source_name, exc_info=True)
            return StringExtractionResult(
                source=source_name,
                status=StringExtractionStatus.FAILED,
                strings=(),
                metadata=resolved_metadata,
                error="read_error",
            )

        ordered = tuple(sorted(records.values(), key=lambda item: (item.offset, item.string_type.value, item.value)))
        if cache_key is not None:
            self._remember(cache_key, ordered)
        return StringExtractionResult(
            source=source_name,
            status=StringExtractionStatus.COMPLETED,
            strings=ordered,
            metadata=resolved_metadata,
            truncated=len(ordered) >= self._max_strings,
        )

    def extract_from_bytes(self, name: str, data: bytes) -> tuple[ExtractedString, ...]:
        """
        Extract strings from an in-memory buffer — a decompressed member.

        Offsets are relative to the member, not the containing file, which is
        the more useful frame: "at offset 0x420 of classes.dex" locates
        something; an offset into a zip's compressed stream does not.
        """
        records: dict[str, ExtractedString] = {}
        if not data or _is_incompressible(data):
            return ()

        for pattern, encoding, string_type, require_non_ascii in (
            (_ASCII_RUN, "ascii", StringType.ASCII, False),
            (_UTF8_RUN, "utf-8", StringType.UTF8, True),
            (_UTF16LE_RUN, "utf-16le", StringType.UTF16LE, False),
            (_UTF16BE_RUN, "utf-16be", StringType.UTF16BE, False),
        ):
            for match in pattern.finditer(data):
                if len(records) >= self._max_strings:
                    break
                self._record_run(match.group(0), match.start(), encoding,
                                 string_type, records, require_non_ascii)

        return tuple(sorted(
            records.values(),
            key=lambda item: (item.offset, item.string_type.value, item.value),
        ))

    def _cache_key(self, source: Path) -> tuple | None:
        """
        Identify file content cheaply.

        Size plus modification time, not a hash: hashing would re-read the file
        and give back the cost this cache exists to remove. A sample being
        rewritten in place mid-analysis is not a case this engine supports.
        """
        try:
            stat = source.stat()
        except OSError:
            return None
        return (str(source.resolve()), stat.st_size, stat.st_mtime_ns, self._minimum_length)

    def _remember(self, key: tuple, strings: tuple[ExtractedString, ...]) -> None:
        if len(self._cache) >= self._cache_limit:
            self._cache.pop(next(iter(self._cache)))
        self._cache[key] = strings

    def _extract_ascii(self, source: Path, records: dict[str, ExtractedString]) -> None:
        self._scan_runs(source, _ASCII_RUN, "ascii", StringType.ASCII, records)

    def _extract_utf8(self, source: Path, records: dict[str, ExtractedString]) -> None:
        self._scan_runs(source, _UTF8_RUN, "utf-8", StringType.UTF8, records, require_non_ascii=True)

    def _extract_utf16(
        self,
        source: Path,
        pattern: re.Pattern[bytes],
        encoding: str,
        string_type: StringType,
        records: dict[str, ExtractedString],
    ) -> None:
        self._scan_runs(source, pattern, encoding, string_type, records)

    def _scan_runs(
        self,
        source: Path,
        pattern: re.Pattern[bytes],
        encoding: str,
        string_type: StringType,
        records: dict[str, ExtractedString],
        require_non_ascii: bool = False,
    ) -> None:
        pending = b""
        pending_offset = 0
        next_offset = 0
        with source.open("rb") as stream:
            while block := stream.read(self._chunk_size):
                if len(records) >= self._max_strings:
                    return
                if _is_incompressible(block):
                    # Advance past the region without scanning it; a pending
                    # run cannot continue across bytes we are not reading.
                    self._skipped_bytes += len(block)
                    pending = b""
                    next_offset += len(block)
                    continue
                data = pending + block
                data_offset = pending_offset if pending else next_offset
                matches = list(pattern.finditer(data))
                pending = b""
                for index, match in enumerate(matches):
                    if match.end() == len(data):
                        pending = match.group(0)
                        pending_offset = data_offset + match.start()
                        break
                    self._record_run(
                        match.group(0), data_offset + match.start(), encoding, string_type, records, require_non_ascii
                    )
                next_offset += len(block)
            if pending:
                self._record_run(pending, pending_offset, encoding, string_type, records, require_non_ascii)

    def _record_run(
        self,
        raw_value: bytes,
        offset: int,
        encoding: str,
        string_type: StringType,
        records: dict[str, ExtractedString],
        require_non_ascii: bool,
    ) -> None:
        try:
            value = raw_value.decode(encoding, errors="strict")
        except UnicodeDecodeError:
            return
        if len(value) < self._minimum_length or not value.isprintable():
            return
        if require_non_ascii and value.isascii():
            return
        self._record_indicators(value, offset, encoding, records)
        self._add_record(value, string_type, offset, encoding, records)

    def _record_indicators(
        self, value: str, offset: int, encoding: str, records: dict[str, ExtractedString]
    ) -> None:
        patterns: tuple[tuple[re.Pattern[str], StringType], ...] = (
            (_URL_PATTERN, StringType.URL),
            (_EMAIL_PATTERN, StringType.EMAIL),
            (_IPV4_PATTERN, StringType.IPV4),
            (_IPV6_PATTERN, StringType.IPV6),
            (_WINDOWS_PATH_PATTERN, StringType.WINDOWS_PATH),
            (_UNIX_PATH_PATTERN, StringType.UNIX_PATH),
            (_REGISTRY_PATH_PATTERN, StringType.REGISTRY_PATH),
            (_DOMAIN_PATTERN, StringType.DOMAIN),
        )
        for pattern, string_type in patterns:
            for match in pattern.finditer(value):
                candidate = match.group(0).rstrip(".,);:'\"<>*")
                if string_type is StringType.URL and not _is_valid_url(candidate):
                    continue
                if string_type in (StringType.IPV4, StringType.IPV6) and not self._valid_ip(candidate, string_type):
                    continue
                if string_type is StringType.UNIX_PATH and len(candidate) < 5:
                    continue
                if string_type is StringType.DOMAIN and not _is_valid_domain_candidate(candidate, value, match.start(), match.end()):
                    continue
                candidate_offset = offset + len(value[: match.start()].encode(encoding))
                self._add_record(candidate, string_type, candidate_offset, encoding, records)

    @staticmethod
    def _valid_ip(value: str, string_type: StringType) -> bool:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return False
        if string_type is StringType.IPV4:
            if parsed.version != 4 or parsed.is_unspecified or value.startswith("0.") or value == "255.255.255.255":
                return False
            # Reject ASN.1 OID prefixes like 1.3.6.1, 1.2.840...
            _oids = ("1.3.6.1", "1.2.840", "2.16.840", "2.5.4", "0.9.2342", "1.3.14.3", "1.2.")
            if any(value == prefix or value.startswith(prefix + ".") or value.startswith(prefix) for prefix in _oids):
                return False
            return True
        return string_type is StringType.IPV6 and parsed.version == 6

    @staticmethod
    def _add_record(
        value: str,
        string_type: StringType,
        offset: int,
        encoding: str,
        records: dict[str, ExtractedString],
    ) -> None:
        if value not in records:
            records[value] = ExtractedString(
                value=value,
                string_type=string_type,
                offset=offset,
                length=len(value),
                encoding=encoding,
            )
