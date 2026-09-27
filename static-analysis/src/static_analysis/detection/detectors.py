"""Built-in signature detectors for supported executable and package formats."""

import struct
import zipfile

from static_analysis.detection.contracts import FileDetector
from static_analysis.detection.models import (
    Architecture,
    ConfidenceLevel,
    DetectedFileType,
    DetectionResult,
    FileFormat,
    Platform,
)
from static_analysis.detection.source import BinarySource
from static_analysis.domain.enums import TargetFormat


_PE_MACHINE_ARCHITECTURES = {
    0x014C: Architecture.X86,
    0x8664: Architecture.X86_64,
    0x01C0: Architecture.ARM,
    0xAA64: Architecture.ARM64,
}
_ELF_MACHINE_ARCHITECTURES = {
    3: Architecture.X86,
    62: Architecture.X86_64,
    40: Architecture.ARM,
    183: Architecture.ARM64,
}
_MACH_CPU_ARCHITECTURES = {
    7: Architecture.X86,
    0x01000007: Architecture.X86_64,
    12: Architecture.ARM,
    0x0100000C: Architecture.ARM64,
}


class ApkDetector(FileDetector):
    """Recognize an Android APK as a structurally valid ZIP with its manifest entry."""

    @property
    def identifier(self) -> str:
        return "builtin.apk"

    @property
    def priority(self) -> int:
        return 100

    def detect(self, source: BinarySource) -> DetectionResult | None:
        if source.read_at(0, 4) not in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
            return None
        try:
            with zipfile.ZipFile(source.path) as archive:
                if "AndroidManifest.xml" not in archive.namelist():
                    return None
        except (OSError, zipfile.BadZipFile):
            return None
        return DetectionResult(
            file_type=DetectedFileType.ANDROID_PACKAGE,
            file_format=FileFormat.APK,
            mime_type="application/vnd.android.package-archive",
            architecture=None,
            platform=Platform.ANDROID,
            confidence=ConfidenceLevel.HIGH,
            target_format=TargetFormat.APK,
            detector_id=self.identifier,
        )


class PeDetector(FileDetector):
    """Recognize PE images and classify executables from DLLs via COFF flags."""

    @property
    def identifier(self) -> str:
        return "builtin.pe"

    def detect(self, source: BinarySource) -> DetectionResult | None:
        if source.read_at(0, 2) != b"MZ":
            return None
        offset_data = source.read_at(0x3C, 4)
        if len(offset_data) != 4:
            return None
        pe_offset = struct.unpack("<I", offset_data)[0]
        header = source.read_at(pe_offset, 24)
        if len(header) != 24 or header[:4] != b"PE\x00\x00":
            return None
        machine, _, _, _, _, _, characteristics = struct.unpack("<HHIIIHH", header[4:])
        architecture = _PE_MACHINE_ARCHITECTURES.get(machine)
        is_dll = bool(characteristics & 0x2000)
        return DetectionResult(
            file_type=(DetectedFileType.WINDOWS_DYNAMIC_LIBRARY if is_dll else DetectedFileType.WINDOWS_EXECUTABLE),
            file_format=FileFormat.PE,
            mime_type="application/vnd.microsoft.portable-executable",
            architecture=architecture,
            platform=Platform.WINDOWS,
            confidence=ConfidenceLevel.HIGH if architecture else ConfidenceLevel.MEDIUM,
            target_format=TargetFormat.DLL if is_dll else TargetFormat.EXE,
            detector_id=self.identifier,
        )


class ElfDetector(FileDetector):
    """Recognize ELF headers and classify ET_EXEC and ET_DYN binary types."""

    @property
    def identifier(self) -> str:
        return "builtin.elf"

    def detect(self, source: BinarySource) -> DetectionResult | None:
        header = source.read_at(0, 20)
        if len(header) < 4 or header[:4] != b"\x7fELF":
            return None
        data_encoding = header[5] if len(header) > 5 else 1
        byte_order = {1: "<", 2: ">"}.get(data_encoding, "<")
        elf_type = 2
        machine = 0
        if len(header) >= 20:
            try:
                elf_type, machine = struct.unpack(f"{byte_order}HH", header[16:20])
            except Exception:
                pass
        if elf_type == 3:
            file_type = DetectedFileType.ELF_SHARED_OBJECT
        else:
            file_type = DetectedFileType.ELF_EXECUTABLE
        arch = _ELF_MACHINE_ARCHITECTURES.get(machine)
        return DetectionResult(
            file_type=file_type,
            file_format=FileFormat.ELF,
            mime_type="application/x-elf",
            architecture=arch,
            platform=Platform.LINUX,
            confidence=ConfidenceLevel.HIGH if arch is not None else ConfidenceLevel.MEDIUM,
            target_format=TargetFormat.ELF,
            detector_id=self.identifier,
        )


class MachODetector(FileDetector):
    """Recognize thin and universal Mach-O images from their binary headers."""

    _THIN_MAGICS = {
        b"\xfe\xed\xfa\xce": (">", False),
        b"\xce\xfa\xed\xfe": ("<", False),
        b"\xfe\xed\xfa\xcf": (">", True),
        b"\xcf\xfa\xed\xfe": ("<", True),
    }
    _FAT_MAGICS = {b"\xca\xfe\xba\xbe": ">", b"\xbe\xba\xfe\xca": "<"}

    @property
    def identifier(self) -> str:
        return "builtin.mach_o"

    def detect(self, source: BinarySource) -> DetectionResult | None:
        prefix = source.read_at(0, 32)
        if len(prefix) < 8:
            return None
        magic = prefix[:4]
        if magic in self._FAT_MAGICS:
            return self._detect_universal(prefix, self._FAT_MAGICS[magic])
        if magic not in self._THIN_MAGICS:
            return None
        byte_order, is_64_bit = self._THIN_MAGICS[magic]
        required_length = 28 if is_64_bit else 24
        if len(prefix) < required_length:
            return None
        cpu_type, _, file_type = struct.unpack(f"{byte_order}iiI", prefix[4:16])
        return self._result(_MACH_CPU_ARCHITECTURES.get(cpu_type), file_type)

    def _detect_universal(self, prefix: bytes, byte_order: str) -> DetectionResult | None:
        if len(prefix) < 8:
            return None
        count = struct.unpack(f"{byte_order}I", prefix[4:8])[0]
        if count < 1:
            return None
        return self._result(Architecture.UNIVERSAL, 2)

    def _result(self, architecture: Architecture | None, file_type: int) -> DetectionResult:
        detected_type = {
            2: DetectedFileType.MACH_O_EXECUTABLE,
            6: DetectedFileType.MACH_O_DYNAMIC_LIBRARY,
            8: DetectedFileType.MACH_O_BUNDLE,
        }.get(file_type, DetectedFileType.MACH_O_EXECUTABLE)
        return DetectionResult(
            file_type=detected_type,
            file_format=FileFormat.MACH_O,
            mime_type="application/x-mach-binary",
            architecture=architecture,
            platform=Platform.MACOS,
            confidence=ConfidenceLevel.HIGH if architecture else ConfidenceLevel.MEDIUM,
            target_format=TargetFormat.MACH_O,
            detector_id=self.identifier,
        )
