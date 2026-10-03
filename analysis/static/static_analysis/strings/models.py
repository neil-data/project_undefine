"""Data contracts for extracted binary strings and derived indicators."""

from dataclasses import dataclass
from enum import Enum

from static_analysis.metadata.models import MetadataResult


class StringType(str, Enum):
    ASCII = "ascii"
    UTF8 = "utf8"
    UTF16LE = "utf16le"
    UTF16BE = "utf16be"
    URL = "url"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    EMAIL = "email"
    WINDOWS_PATH = "windows_path"
    UNIX_PATH = "unix_path"
    REGISTRY_PATH = "registry_path"
    DOMAIN = "domain"


class StringExtractionStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ExtractedString:
    """A unique string or derived indicator located in the source file."""

    value: str
    string_type: StringType
    offset: int
    length: int
    encoding: str


@dataclass(frozen=True, slots=True)
class StringExtractionResult:
    """Extraction output plus metadata shared by all future analyzer families."""

    source: str
    status: StringExtractionStatus
    strings: tuple[ExtractedString, ...]
    metadata: MetadataResult
    error: str | None = None

    # True when the extraction limit was reached and scanning stopped early.
    # Reported rather than hidden: a truncated string list means the IOC and
    # keyword stages saw part of the file, and an investigator is entitled to
    # know that before concluding a sample is clean.
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class StringExplanation:
    """A human-readable, investigator-facing explanation for one extracted string.

    Distinct from `ExtractedString`: that model records *where* a string was
    found; this one records *why it matters* — the plain-language reason an
    investigator should care, plus a closed-vocabulary category for grouping.
    """

    value: str
    string_type: StringType
    category: str
    explanation: str
    severity: str
