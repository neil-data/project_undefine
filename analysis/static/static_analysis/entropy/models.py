"""Data contracts for byte-entropy analysis."""

from dataclasses import dataclass, field
from enum import Enum

# Shannon entropy over bytes, in bits per byte. The bands below are empirical
# rather than theoretical: English text and source code sit well under 5,
# machine code around 6, deflate-compressed data just above 7, and anything
# encrypted or well-packed presses against the 8-bit ceiling.
TEXT_CEILING = 4.5
CODE_CEILING = 6.5
COMPRESSED_CEILING = 7.2
PACKED_FLOOR = 7.2
ENCRYPTED_FLOOR = 7.8


class EntropyClass(str, Enum):
    """What a measured entropy value most likely indicates."""

    EMPTY = "empty"                     # No data, or a single repeated byte
    TEXT = "text"                       # Human-readable content, config, markup
    CODE = "code"                       # Compiled instructions, structured data
    COMPRESSED = "compressed"           # Deflate, zip, media containers
    PACKED_OR_ENCRYPTED = "packed_or_encrypted"


@dataclass(frozen=True, slots=True)
class EntropyWindow:
    """Entropy of one fixed-size window, used to locate hidden payloads."""

    offset: int
    size: int
    entropy: float
    classification: EntropyClass


@dataclass(frozen=True, slots=True)
class EntropyRegion:
    """A contiguous run of high-entropy windows."""

    start_offset: int
    end_offset: int
    mean_entropy: float
    window_count: int

    # Set when the run reaches the end of the file. An encrypted blob appended
    # past the last declared section is the classic way a dropper carries its
    # second stage, and it is invisible to section-level entropy alone.
    reaches_end_of_file: bool = False

    @property
    def size(self) -> int:
        return self.end_offset - self.start_offset


@dataclass(frozen=True, slots=True)
class EmbeddedBlob:
    """A container member whose entropy contradicts what its name claims."""

    name: str
    size: int
    entropy: float
    declared_kind: str          # From the file extension: 'jpg', 'txt', 'db'
    reason: str


class EntropyStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class EntropyResult:
    """Complete entropy picture for one sample."""

    source: str
    status: EntropyStatus

    overall_entropy: float = 0.0
    classification: EntropyClass = EntropyClass.EMPTY
    file_size: int = 0

    windows: tuple[EntropyWindow, ...] = ()
    high_entropy_regions: tuple[EntropyRegion, ...] = ()
    embedded_blobs: tuple[EmbeddedBlob, ...] = ()

    # Zip-family container (APK, JAR, AAB). This changes what the numbers mean:
    # a container's last member is compressed data sitting at the end of the
    # file by construction, so "high entropy running to EOF" — decisive in a PE
    # or ELF — is the normal case here and says nothing at all.
    is_container: bool = False

    # Section/member name -> entropy, merged from the format analyzer where one
    # ran, so PE sections and APK members are reported through one field.
    component_entropies: dict[str, float] = field(default_factory=dict)

    error: str | None = None

    @property
    def is_likely_packed(self) -> bool:
        """
        True when entropy alone justifies calling the sample packed.

        Deliberately not "overall entropy is high": an APK is a zip, so every
        APK scores above 7.5 and that fact carries no information. What matters
        is a high-entropy region where one does not belong, or a member whose
        contents contradict its own name.

        For a container, only the member-level finding counts — the trailing
        region test would otherwise fire on every APK whose last entry happens
        to be a PNG, which is most of them.
        """
        if self.embedded_blobs:
            return True
        if self.is_container:
            return False
        return any(
            region.reaches_end_of_file and region.size >= 4096
            for region in self.high_entropy_regions
        )

    @property
    def packing_evidence(self) -> tuple[str, ...]:
        """Plain-language reasons supporting the packing verdict."""
        evidence: list[str] = []
        for blob in self.embedded_blobs:
            evidence.append(
                f"{blob.name} claims to be {blob.declared_kind} but has entropy "
                f"{blob.entropy:.2f} — {blob.reason}"
            )
        for region in self.high_entropy_regions:
            if self.is_container:
                continue
            if region.reaches_end_of_file and region.size >= 4096:
                evidence.append(
                    f"{region.size} bytes of near-random data at the end of the file "
                    f"(entropy {region.mean_entropy:.2f}), past where the declared "
                    f"structure ends"
                )
        return tuple(evidence)
