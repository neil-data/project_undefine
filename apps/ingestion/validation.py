"""
ingestion/validation.py — Intake-layer file validation for the Ingestion Gateway.

The gateway previously hashed and persisted whatever bytes it was handed. That
made the intake layer a write-amplification vector: a multi-gigabyte upload, or
a file in a format nothing downstream can parse, still got read fully into
memory, hashed, written to SAMPLES_DIR, and queued — where it would only fail
much later inside analyze_and_save(). This module moves that decision to the
front door, so a sample is rejected *before* it costs disk or a queue slot.

Three checks, in the order they run:

  1. Size bounds     — reject empty//truncated files and oversized uploads
  2. Magic header    — the file must actually be one of the formats the
                       pipeline supports (APK, PE/EXE/DLL, ELF, Mach-O)
  3. MIME derivation — the canonical MIME type comes from the detected magic,
                       never from the client-declared Content-Type

Deliberately self-contained (stdlib only). ingestion/Dockerfile copies only
`ingestion/` and installs only ingestion/requirements.txt, so this module must
not import `static_analysis` — the gateway is its own small container, per the
architecture diagram's separate "Ingestion Gateway" box.

That means the signatures here intentionally duplicate a subset of
static-analysis/src/static_analysis/detection/detectors.py. The duplication is
bounded and deliberate: this is a cheap *gate* that reads headers only, while
the authoritative deep parse (section tables, imports, architecture) still
happens downstream in the static-analysis engine. Keep the two in sync when a
new format is added to TargetFormat.
"""

from __future__ import annotations

import os
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Optional

__all__ = [
    "ValidationError",
    "EmptyFileError",
    "FileTooSmallError",
    "FileTooLargeError",
    "UnsupportedFormatError",
    "ValidationResult",
    "max_sample_bytes",
    "validate_sample",
    "detect_format",
]


# ---------------------------------------------------------------------------
# Size policy
# ---------------------------------------------------------------------------

# 256 MiB default. Comfortably above real-world APK/PE samples (the largest
# Play Store APKs run ~150 MB) while still bounding what a single unauthenticated
# request can force the gateway to hash and persist.
_DEFAULT_MAX_SAMPLE_BYTES = 256 * 1024 * 1024

# The smallest input any supported detector can even reach a verdict on: the
# ELF detector needs 20 header bytes, the PE detector needs to seek to 0x3C and
# read 24 more. 64 bytes is below every real executable and above every
# accidental empty/truncated upload.
MIN_SAMPLE_BYTES = 64


def max_sample_bytes() -> int:
    """
    Upper size bound, read from INGESTION_MAX_SAMPLE_BYTES at call time.

    Read per-call rather than captured at import so the limit can be changed
    via environment without rebuilding the image, and so tests can adjust it
    with monkeypatch.setenv without reloading the module.
    """
    raw = os.environ.get("INGESTION_MAX_SAMPLE_BYTES")
    if not raw:
        return _DEFAULT_MAX_SAMPLE_BYTES
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_MAX_SAMPLE_BYTES
    return value if value > 0 else _DEFAULT_MAX_SAMPLE_BYTES


# ---------------------------------------------------------------------------
# Errors — each carries the HTTP status the gateway should surface
# ---------------------------------------------------------------------------

class ValidationError(Exception):
    """Base class for intake rejections. `status_code` is the HTTP response code."""

    status_code = 400
    code = "invalid_sample"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message

    def as_detail(self) -> dict:
        """Machine-readable body for the HTTPException the gateway raises."""
        return {"error": self.code, "message": self.message}


class EmptyFileError(ValidationError):
    status_code = 400
    code = "empty_file"


class FileTooSmallError(ValidationError):
    status_code = 400
    code = "file_too_small"


class FileTooLargeError(ValidationError):
    # 413 Content Too Large — the correct code for a body exceeding server limits.
    status_code = 413
    code = "file_too_large"


class UnsupportedFormatError(ValidationError):
    # 415 Unsupported Media Type — the bytes are readable but not an analyzable format.
    status_code = 415
    code = "unsupported_format"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ValidationResult:
    """Outcome of a successful validation."""

    file_format: str      # apk | exe | dll | elf | mach_o — matches TargetFormat
    platform: str         # android | windows | linux | macos
    mime_type: str        # derived from magic bytes, never from the client
    size_bytes: int

    declared_filename: Optional[str] = None
    declared_content_type: Optional[str] = None

    # False when the filename's extension disagrees with the detected format.
    # NOT a rejection reason — see validate_sample() for why.
    extension_matches: bool = True

    @property
    def extension_mismatch(self) -> bool:
        return not self.extension_matches


# Canonical MIME + platform per detected format. Mirrors the mime_type values
# the static-analysis detectors report, so a sample carries one consistent
# MIME string from intake through to the report.
_FORMAT_METADATA = {
    "apk": ("application/vnd.android.package-archive", "android"),
    "exe": ("application/vnd.microsoft.portable-executable", "windows"),
    "dll": ("application/vnd.microsoft.portable-executable", "windows"),
    "elf": ("application/x-elf", "linux"),
    "mach_o": ("application/x-mach-binary", "macos"),
    "json": ("application/json", "cross-platform"),
    "bson": ("application/bson", "cross-platform"),
}

# Extensions conventionally used for each format. Used only to report a
# mismatch, never to decide the format.
_FORMAT_EXTENSIONS = {
    "apk": {".apk", ".xapk", ".apks"},
    "exe": {".exe", ".scr", ".com"},
    "dll": {".dll", ".ocx", ".sys"},
    "elf": {".elf", ".so", ".bin", ""},
    "mach_o": {".dylib", ".bundle", ".macho", ""},
    "json": {".json"},
    "bson": {".bson"},
}

_MACH_O_THIN_MAGICS = {
    b"\xfe\xed\xfa\xce": (">", False),
    b"\xce\xfa\xed\xfe": ("<", False),
    b"\xfe\xed\xfa\xcf": (">", True),
    b"\xcf\xfa\xed\xfe": ("<", True),
}
_MACH_O_FAT_MAGICS = {b"\xca\xfe\xba\xbe": ">", b"\xbe\xba\xfe\xca": "<"}

_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def _read_at(handle: BinaryIO, offset: int, length: int) -> bytes:
    """Positioned read that returns short rather than raising at EOF."""
    try:
        handle.seek(offset)
    except OSError:
        return b""
    return handle.read(length)


def _detect_apk(handle: BinaryIO, path: Path) -> Optional[str]:
    """
    An APK is a structurally valid ZIP containing AndroidManifest.xml.

    The manifest check is what separates an APK from an arbitrary ZIP — without
    it, any .zip would be accepted here and then rejected downstream. Reading
    only the central directory (namelist) does not inflate any entry, so a zip
    bomb cannot detonate during validation.
    """
    if _read_at(handle, 0, 4) not in _ZIP_MAGICS:
        return None
    try:
        with zipfile.ZipFile(path) as archive:
            if "AndroidManifest.xml" not in archive.namelist():
                return None
    except (OSError, zipfile.BadZipFile):
        return None
    return "apk"


def _detect_pe(handle: BinaryIO) -> Optional[str]:
    """MZ stub -> e_lfanew -> PE\\0\\0 signature; DLL vs EXE from COFF characteristics."""
    if _read_at(handle, 0, 2) != b"MZ":
        return None
    offset_data = _read_at(handle, 0x3C, 4)
    if len(offset_data) != 4:
        return None
    pe_offset = struct.unpack("<I", offset_data)[0]
    header = _read_at(handle, pe_offset, 24)
    if len(header) != 24 or header[:4] != b"PE\x00\x00":
        return None
    # COFF header: machine, sections, timestamp, symtab ptr, symbols, opt hdr size, characteristics
    _, _, _, _, _, _, characteristics = struct.unpack("<HHIIIHH", header[4:])
    return "dll" if characteristics & 0x2000 else "exe"


def _detect_elf(handle: BinaryIO) -> Optional[str]:
    """\\x7fELF plus a sane class/encoding/version, restricted to ET_EXEC and ET_DYN."""
    header = _read_at(handle, 0, 20)
    if len(header) != 20 or header[:4] != b"\x7fELF":
        return None
    byte_order = {1: "<", 2: ">"}.get(header[5])
    # header[4] = EI_CLASS (32/64-bit), header[6] = EI_VERSION (must be 1)
    if header[4] not in (1, 2) or byte_order is None or header[6] != 1:
        return None
    elf_type, _machine = struct.unpack(f"{byte_order}HH", header[16:20])
    if elf_type not in (2, 3):  # ET_EXEC, ET_DYN — relocatables/core dumps aren't samples
        return None
    return "elf"


def _detect_mach_o(handle: BinaryIO) -> Optional[str]:
    """Thin (32/64-bit, either endianness) and universal/fat Mach-O images."""
    prefix = _read_at(handle, 0, 32)
    if len(prefix) < 8:
        return None
    magic = prefix[:4]

    if magic in _MACH_O_FAT_MAGICS:
        count = struct.unpack(f"{_MACH_O_FAT_MAGICS[magic]}I", prefix[4:8])[0]
        return "mach_o" if count >= 1 else None

    if magic not in _MACH_O_THIN_MAGICS:
        return None
    _byte_order, is_64_bit = _MACH_O_THIN_MAGICS[magic]
    if len(prefix) < (28 if is_64_bit else 24):
        return None
    return "mach_o"


def _detect_json(handle: BinaryIO, path: Optional[Path] = None) -> Optional[str]:
    """Check if the file content starts with '{' or '[' (ignoring leading whitespace/BOM) or has .json extension."""
    prefix = _read_at(handle, 0, 100).lstrip(b"\xef\xbb\xbf \t\r\n")
    if prefix.startswith(b"{") or prefix.startswith(b"["):
        return "json"
    if path and path.suffix.lower() == ".json":
        return "json"
    return None


def _detect_bson(handle: BinaryIO, path: Path) -> Optional[str]:
    """Check if the file content could be BSON."""
    size_bytes = path.stat().st_size
    if size_bytes < 5:
        return None
    header = _read_at(handle, 0, 4)
    if len(header) != 4:
        return None
    try:
        bson_size = struct.unpack("<I", header)[0]
        if bson_size == size_bytes:
            last_byte = _read_at(handle, size_bytes - 1, 1)
            if last_byte == b"\x00":
                return "bson"
    except Exception:
        pass
    # Secondary check: if the filename extension is .bson, accept it
    if path.suffix.lower() == ".bson":
        return "bson"
    return None


def detect_format(path: Path) -> Optional[str]:
    """
    Return the detected format key, or None if the bytes match no supported format.

    Order mirrors the detector priorities in static-analysis: APK is checked
    first because it is the most specific (a ZIP that must also contain a
    manifest). The magic prefixes are otherwise mutually exclusive, so the
    remaining order does not affect the verdict.
    """
    with path.open("rb") as handle:
        return (
            _detect_apk(handle, path)
            or _detect_pe(handle)
            or _detect_elf(handle)
            or _detect_mach_o(handle)
            or _detect_json(handle, path)
            or _detect_bson(handle, path)
        )


def _extension_matches(filename: Optional[str], file_format: str) -> bool:
    if not filename:
        # No filename declared at all — nothing to contradict the magic bytes.
        return True
    suffix = Path(filename).suffix.lower()
    return suffix in _FORMAT_EXTENSIONS.get(file_format, set())


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def validate_sample(
    path: Path,
    declared_filename: Optional[str] = None,
    declared_content_type: Optional[str] = None,
) -> ValidationResult:
    """
    Validate an already-buffered upload at `path`.

    Raises a ValidationError subclass on rejection; returns a ValidationResult
    describing the sample on success.

    On the deliberate non-rejection of extension mismatch: a Windows trojan
    named `invoice.pdf` is exactly the kind of sample this platform exists to
    analyze. Refusing it because its extension lies would discard evidence, so
    the detected magic is authoritative and the disagreement is reported as a
    signal (`extension_matches=False`) for the case record instead. The same
    reasoning applies to the client-declared Content-Type, which is attacker-
    controlled and therefore never used to decide the format.
    """
    if not path.exists():
        raise ValidationError(f"Sample file not found at {path}")

    size_bytes = path.stat().st_size

    if size_bytes == 0:
        raise EmptyFileError("Uploaded file is empty (0 bytes).")

    if size_bytes < MIN_SAMPLE_BYTES:
        raise FileTooSmallError(
            f"Uploaded file is {size_bytes} bytes; the minimum analyzable size is "
            f"{MIN_SAMPLE_BYTES} bytes. The file is likely truncated."
        )

    limit = max_sample_bytes()
    if size_bytes > limit:
        raise FileTooLargeError(
            f"Uploaded file is {size_bytes} bytes, exceeding the {limit}-byte limit. "
            "Raise INGESTION_MAX_SAMPLE_BYTES if a larger sample must be accepted."
        )

    file_format = detect_format(path)
    if file_format is None:
        raise UnsupportedFormatError(
            "File does not match any supported format. Supported: APK (ZIP with "
            "AndroidManifest.xml), PE/EXE/DLL, ELF, Mach-O."
        )

    mime_type, platform = _FORMAT_METADATA[file_format]

    return ValidationResult(
        file_format=file_format,
        platform=platform,
        mime_type=mime_type,
        size_bytes=size_bytes,
        declared_filename=declared_filename,
        declared_content_type=declared_content_type,
        extension_matches=_extension_matches(declared_filename, file_format),
    )
