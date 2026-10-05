"""Bounded, non-executing format parser facade over E-Rakshak's native parsers.

LIEF and androguard are optional dependencies and are not installed in this
environment. Existing defensive format parsers provide best-effort facts.
"""
from dataclasses import asdict
from datetime import datetime
import importlib.util
import json
import struct
import zipfile
from io import BytesIO

from static_analysis.elf.parser import ElfParser
from static_analysis.pe.parser import PeParser
from static_analysis.mach_o.parser import MachOParser


MAX_INPUT_BYTES = 64 * 1024 * 1024


def _common(fmt, **fields):
    return {"format": fmt, "parse_status": "success", "reason": None, "source_type": "STATIC", "confidence": 0.5, "packing": "unknown", **fields}


def parse_binary(data, format_hint=None):
    """Parse a byte buffer without executing it or retaining it after return."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return _failed("unknown", "input is not bytes")
    data = bytes(data)
    if len(data) > MAX_INPUT_BYTES:
        return _failed("unknown", "input exceeds parser size cap")
    hint = str(format_hint or "").upper().replace("-", "")
    try:
        if data.startswith(b"\x7fELF") or hint == "ELF":
            return _elf(data)
        if data.startswith(b"MZ") or hint in {"PE", "EXE", "DLL"}:
            return _pe(data)
        if data[:4] in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"} or hint == "MACHO":
            return _macho(data)
        if data.startswith(b"PK\x03\x04") or hint == "APK":
            return _apk(data)
        return _failed("unknown", "unrecognized magic")
    except (ValueError, struct.error, OverflowError, IndexError) as exc:
        return _failed(hint or "unknown", str(exc)[:240] or "parse failure")


def _elf(data):
    info = ElfParser().parse(data)
    h = info.header
    sections = [asdict(x) for x in info.sections[:512]]
    libs = list(info.imported_libraries[:512])
    raw = _common("ELF", architecture=info.architecture, bitness=32 if h.ei_class == "ELF32" else 64,
                  endianness=h.ei_data, file_type=info.file_type, entry_point=info.entry_point,
                  sections=sections, linked_libraries=libs, imports=libs,
                  stripped=info.indicators.stripped,
                  packing="detected" if (info.indicators.packed or info.indicators.suspicious_section_names) else "unknown")
    raw["go_build_info"] = _go_build_info(data)
    return raw


def _pe(data):
    info = PeParser().parse(data)
    sections = [asdict(x) for x in info.sections[:512]]
    return _common("PE", architecture=info.machine, bitness=64 if info.optional_header_magic == 0x20B else 32,
                   endianness="little", file_type=info.file_type, subsystem=info.subsystem,
                   compile_timestamp=info.compile_timestamp.isoformat() if isinstance(info.compile_timestamp, datetime) else None,
                   entry_point=info.entry_point, sections=sections,
                   imports=[asdict(x) for x in info.imports[:512]], linked_libraries=[x.library for x in info.imports[:512]],
                   signed=info.security.has_digital_signature, stripped=None,
                   packing="detected" if (info.indicators.packed or any(section.suspicious for section in info.sections)) else "unknown", go_build_info=_go_build_info(data))


def _macho(data):
    info = MachOParser().parse(data)
    slices = []
    for arch in info.architectures[:32]:
        h = arch.header
        slices.append({"architecture": h.cpu_type, "bitness": 64 if h.is_64_bit else 32,
                       "endianness": "big" if int(h.magic, 16) in {0xFEEDFACE, 0xFEEDFACF} else "little",
                       "file_type": h.file_type, "entry_point": arch.entry_point,
                       "segments": [asdict(x) for x in arch.segments[:512]],
                       "imports": [x.name for x in arch.linked_libraries[:512]],
                       "linked_libraries": [x.name for x in arch.linked_libraries[:512]],
                       "signed": arch.code_signature.present,
                       "packing": "detected" if arch.indicators.packed else "unknown"})
    return _common("Mach-O", file_type=info.file_type, slices=slices, universal=info.is_universal,
                   architecture=slices[0]["architecture"] if slices else "unknown",
                   bitness=slices[0]["bitness"] if slices else None,
                   endianness=slices[0]["endianness"] if slices else None,
                   imports=slices[0]["imports"] if slices else [],
                   linked_libraries=slices[0]["linked_libraries"] if slices else [],
                   signed=any(x["signed"] for x in slices),
                   packing="detected" if any(x["packing"] == "detected" for x in slices) else "unknown",
                   go_build_info=_go_build_info(data))


def _apk(data):
    if not zipfile.is_zipfile(BytesIO(data)):
        return _failed("APK", "invalid APK zip container")
    if importlib.util.find_spec("androguard") is None:
        return {**_common("APK"), "parse_status": "partial", "reason": "androguard is not installed; MobSF static data unavailable",
                "manifest": None, "permissions": [], "components": [], "signing": None}
    return {**_common("APK"), "parse_status": "partial", "reason": "androguard adapter is not implemented", "manifest": None}


def _go_build_info(data):
    marker = b"Go buildinf:"
    return {"present": marker in data, "source": "marker"} if marker in data else None


def _failed(fmt, reason):
    return {"format": fmt, "parse_status": "failed", "reason": str(reason)[:240], "source_type": "STATIC", "confidence": 0.0, "packing": "unknown"}


def parser_evidence_hints(parsed):
    """Convert bounded parser metadata to low-confidence STATIC findings."""
    if parsed.get("parse_status") == "failed":
        return []
    from analysis.scoring.orchestrator.schema import EvidenceFinding
    facts = {key: parsed.get(key) for key in ("format", "architecture", "bitness", "endianness", "file_type", "subsystem", "entry_point", "packing", "signed", "go_build_info") if parsed.get(key) is not None}
    return [EvidenceFinding(source_type="STATIC", evidence_state="STATIC", state="STATIC", source="parser", confidence=min(0.5, max(0.0, float(parsed.get("confidence", 0.5)))), evidence=json.dumps(facts, sort_keys=True), description="Best-effort static parser metadata")]
