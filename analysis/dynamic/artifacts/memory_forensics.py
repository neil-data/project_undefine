"""
memory_forensics.py — Advanced memory forensics analysis for E-Rakshak.

This module provides comprehensive memory analysis capabilities beyond basic
string extraction, including process analysis, DLL analysis, injected code
detection, shellcode detection, credential harvesting, and memory IOC extraction.

PHASE 5 ENHANCEMENTS:
- Process memory structure analysis
- DLL/module enumeration and validation
- Handle table analysis
- Injected code detection via memory region analysis
- Shellcode detection via entropy and pattern analysis
- Credential detection in memory
- Enhanced memory IOC extraction
- Memory dump validation
"""

from __future__ import annotations

import logging
import math
import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import hashlib

_LOGGER = logging.getLogger(__name__)

# Memory analysis constants
_PAGE_SIZE = 4096
_SCAN_WINDOW_BYTES = 16 * 1024 * 1024
_MAX_SCAN_BYTES = 512 * 1024 * 1024
_MIN_STRING_LENGTH = 6

# Windows memory protection constants
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000

PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08

# PE signature
PE_SIGNATURE = b'MZ'


class MemoryRegionType(Enum):
    """Types of memory regions."""
    UNKNOWN = "unknown"
    IMAGE = "image"  # Loaded DLL/EXE
    HEAP = "heap"
    STACK = "stack"
    MAPPED = "mapped"
    PRIVATE = "private"
    INJECTED = "injected"


class MemoryProtection(Enum):
    """Memory protection types."""
    UNKNOWN = "unknown"
    NOACCESS = "noaccess"
    READONLY = "readonly"
    READWRITE = "readwrite"
    WRITECOPY = "writecopy"
    EXECUTE = "execute"
    EXECUTE_READ = "execute_read"
    EXECUTE_READWRITE = "execute_readwrite"
    EXECUTE_WRITECOPY = "execute_writecopy"


@dataclass
class MemoryRegion:
    """Represents a memory region in the process address space."""
    base_address: int
    size: int
    protection: MemoryProtection
    region_type: MemoryRegionType
    module_name: Optional[str] = None
    is_suspicious: bool = False
    suspicion_reason: Optional[str] = None
    entropy: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_address": f"0x{self.base_address:X}",
            "size": self.size,
            "protection": self.protection.value,
            "region_type": self.region_type.value,
            "module_name": self.module_name,
            "is_suspicious": self.is_suspicious,
            "suspicion_reason": self.suspicion_reason,
            "entropy": round(self.entropy, 4),
        }


@dataclass
class ProcessInfo:
    """Information about a process from memory analysis."""
    pid: int
    name: str
    base_address: int
    image_path: Optional[str] = None
    parent_pid: Optional[int] = None
    memory_regions: List[MemoryRegion] = field(default_factory=list)
    injected_code_regions: List[MemoryRegion] = field(default_factory=list)
    unsigned_modules: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "name": self.name,
            "base_address": f"0x{self.base_address:X}",
            "image_path": self.image_path,
            "parent_pid": self.parent_pid,
            "memory_regions": [r.to_dict() for r in self.memory_regions],
            "injected_code_regions": [r.to_dict() for r in self.injected_code_regions],
            "unsigned_modules": self.unsigned_modules,
        }


@dataclass
class ShellcodeMatch:
    """Represents a detected shellcode pattern."""
    offset: int
    size: int
    pattern_type: str
    confidence: float
    description: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "offset": f"0x{self.offset:X}",
            "size": self.size,
            "pattern_type": self.pattern_type,
            "confidence": round(self.confidence, 4),
            "description": self.description,
        }


@dataclass
class CredentialMatch:
    """Represents a detected credential pattern."""
    offset: int
    credential_type: str
    value: str
    context: str
    confidence: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "offset": f"0x{self.offset:X}",
            "credential_type": self.credential_type,
            "value": self.value[:100] if len(self.value) > 100 else self.value,  # Truncate for display
            "context": self.context[:200] if len(self.context) > 200 else self.context,
            "confidence": round(self.confidence, 4),
        }


@dataclass
class MemoryForensicsResult:
    """Comprehensive memory forensics analysis result."""
    dump_path: str
    status: str  # completed | failed | validation_failed
    dump_size_bytes: int
    dump_hash: str
    
    processes: List[ProcessInfo] = field(default_factory=list)
    suspicious_regions: List[MemoryRegion] = field(default_factory=list)
    shellcode_matches: List[ShellcodeMatch] = field(default_factory=list)
    credential_matches: List[CredentialMatch] = field(default_factory=list)
    memory_iocs: List[Dict[str, Any]] = field(default_factory=list)
    
    # Summary statistics
    total_regions_analyzed: int = 0
    total_rwx_regions: int = 0
    total_injected_regions: int = 0
    high_entropy_regions: int = 0
    
    error: Optional[str] = None
    
    @property
    def has_suspicious_activity(self) -> bool:
        """Check if any suspicious activity was detected."""
        # bool(...) is required: chaining `or` over lists returns the first
        # truthy list, not a bool, which breaks callers and to_dict() output.
        return bool(
            self.suspicious_regions or
            self.shellcode_matches or
            self.credential_matches or
            self.total_injected_regions > 0
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "dump_path": self.dump_path,
            "status": self.status,
            "dump_size_bytes": self.dump_size_bytes,
            "dump_hash": self.dump_hash,
            "processes": [p.to_dict() for p in self.processes],
            "suspicious_regions": [r.to_dict() for r in self.suspicious_regions],
            "shellcode_matches": [s.to_dict() for s in self.shellcode_matches],
            "credential_matches": [c.to_dict() for c in self.credential_matches],
            "memory_iocs": self.memory_iocs,
            "total_regions_analyzed": self.total_regions_analyzed,
            "total_rwx_regions": self.total_rwx_regions,
            "total_injected_regions": self.total_injected_regions,
            "high_entropy_regions": self.high_entropy_regions,
            "has_suspicious_activity": self.has_suspicious_activity,
            "error": self.error,
        }


class MemoryForensicsAnalyzer:
    """
    Advanced memory forensics analyzer.
    
    Performs comprehensive analysis of memory dumps including:
    - Process enumeration and analysis
    - Memory region classification
    - Injected code detection
    - Shellcode detection
    - Credential harvesting
    - IOC extraction
    """
    
    def __init__(self):
        self._credential_patterns = self._build_credential_patterns()
        self._shellcode_patterns = self._build_shellcode_patterns()
    
    def analyze(self, dump_path: str | Path) -> MemoryForensicsResult:
        """
        Perform comprehensive memory forensics analysis.
        
        Args:
            dump_path: Path to the memory dump file
            
        Returns:
            MemoryForensicsResult with analysis findings
        """
        source = Path(dump_path)
        
        if not source.is_file():
            return MemoryForensicsResult(
                dump_path=str(source),
                status="failed",
                dump_size_bytes=0,
                dump_hash="",
                error=f"Memory dump not found: {source}"
            )
        
        try:
            # Validate dump
            if not self._validate_dump(source):
                return MemoryForensicsResult(
                    dump_path=str(source),
                    status="validation_failed",
                    dump_size_bytes=source.stat().st_size,
                    dump_hash=self._calculate_hash(source),
                    error="Memory dump validation failed"
                )
            
            # Calculate dump hash
            dump_hash = self._calculate_hash(source)
            dump_size = source.stat().st_size
            
            result = MemoryForensicsResult(
                dump_path=str(source),
                status="completed",
                dump_size_bytes=dump_size,
                dump_hash=dump_hash
            )
            
            # Perform analysis
            self._analyze_memory_regions(source, result)
            self._detect_injected_code(source, result)
            self._detect_shellcode(source, result)
            self._detect_credentials(source, result)
            self._extract_memory_iocs(source, result)
            
            return result
            
        except Exception as error:
            _LOGGER.error("Memory forensics analysis failed: %s", error)
            return MemoryForensicsResult(
                dump_path=str(source),
                status="failed",
                dump_size_bytes=source.stat().st_size if source.is_file() else 0,
                dump_hash="",
                error=str(error)
            )
    
    def _validate_dump(self, dump_path: Path) -> bool:
        """
        Validate memory dump integrity.
        
        Basic validation checks:
        - File exists and is readable
        - File size is reasonable (> 1MB)
        - File contains some memory content (not all zeros)
        """
        if not dump_path.is_file():
            return False
        
        size = dump_path.stat().st_size
        if size < 1024 * 1024:  # Less than 1MB is suspicious
            return False
        
        # Check if file contains non-zero content
        try:
            with dump_path.open("rb") as f:
                sample = f.read(4096)
                if all(b == 0 for b in sample):
                    return False
        except Exception:
            return False
        
        return True
    
    def _calculate_hash(self, dump_path: Path) -> str:
        """Calculate SHA256 hash of the memory dump."""
        sha256 = hashlib.sha256()
        with dump_path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _analyze_memory_regions(self, dump_path: Path, result: MemoryForensicsResult):
        """
        Analyze memory regions for suspicious characteristics.
        
        This is a simplified analysis that works on raw memory dumps
        without requiring full Windows memory structure parsing.
        """
        with dump_path.open("rb") as f:
            offset = 0
            scanned = 0
            
            while scanned < _MAX_SCAN_BYTES and (window := f.read(_SCAN_WINDOW_BYTES)):
                scanned += len(window)
                
                # Scan for PE headers to identify modules
                pe_matches = self._find_pe_headers(window, offset)
                
                # Analyze regions between PE headers
                for i, (pe_offset, pe_size) in enumerate(pe_matches):
                    region_start = pe_offset if i == 0 else pe_matches[i-1][0] + pe_matches[i-1][1]
                    region_end = pe_offset
                    region_size = region_end - region_start
                    
                    if region_size > _PAGE_SIZE:
                        region_data = window[region_start - offset:region_end - offset]
                        entropy = self._calculate_entropy(region_data)
                        
                        region = MemoryRegion(
                            base_address=region_start,
                            size=region_size,
                            protection=MemoryProtection.UNKNOWN,
                            region_type=MemoryRegionType.UNKNOWN,
                            entropy=entropy
                        )
                        
                        # Mark suspicious regions
                        if entropy > 7.0:
                            region.is_suspicious = True
                            region.suspicion_reason = "High entropy"
                            result.high_entropy_regions += 1
                            result.suspicious_regions.append(region)
                        elif region_size % _PAGE_SIZE == 0 and region_size > 1024 * 1024:
                            # Large aligned region might be RWX
                            region.is_suspicious = True
                            region.suspicion_reason = "Large aligned region"
                            result.suspicious_regions.append(region)
                        
                        result.total_regions_analyzed += 1
                
                offset += len(window)
    
    def _find_pe_headers(self, data: bytes, base_offset: int) -> List[Tuple[int, int]]:
        """Find PE headers in memory data."""
        pe_matches = []
        offset = 0
        
        while offset < len(data) - 2:
            if data[offset:offset+2] == PE_SIGNATURE:
                # Check for PE header at offset 0x3C
                if offset + 0x3C + 4 < len(data):
                    pe_offset = struct.unpack_from("<I", data, offset + 0x3C)[0]
                    if offset + pe_offset < len(data) - 4:
                        if data[offset + pe_offset:offset + pe_offset + 4] == b'PE\0\0':
                            # Valid PE found
                            pe_matches.append((base_offset + offset, 4096))  # Approximate size
                            offset += pe_offset  # Skip past this PE
                            continue
            offset += 1
        
        return pe_matches
    
    def _detect_injected_code(self, dump_path: Path, result: MemoryForensicsResult):
        """
        Detect injected code by analyzing memory regions.
        
        Injected code typically:
        - Resides in regions without backing modules
        - Has RWX permissions
        - Has high entropy
        - Contains shellcode patterns
        """
        with dump_path.open("rb") as f:
            offset = 0
            scanned = 0
            
            while scanned < _MAX_SCAN_BYTES and (window := f.read(_SCAN_WINDOW_BYTES)):
                scanned += len(window)
                
                # Scan for suspicious RWX-like regions
                # In a real implementation, this would parse VAD trees
                # Here we use heuristics on raw memory
                
                for i in range(0, len(window) - 4096, 4096):
                    chunk = window[i:i+4096]
                    entropy = self._calculate_entropy(chunk)
                    
                    # High entropy executable-like region
                    if entropy > 6.5 and self._has_executable_patterns(chunk):
                        region = MemoryRegion(
                            base_address=offset + i,
                            size=4096,
                            protection=MemoryProtection.EXECUTE_READWRITE,
                            region_type=MemoryRegionType.INJECTED,
                            is_suspicious=True,
                            suspicion_reason="High entropy with executable patterns",
                            entropy=entropy
                        )
                        result.injected_code_regions.append(region)
                        result.total_injected_regions += 1
                
                offset += len(window)
    
    def _has_executable_patterns(self, data: bytes) -> bool:
        """Check if data has executable code patterns."""
        # Simple heuristic: check for common x86 instructions
        common_opcodes = [
            b'\x55',  # push ebp
            b'\x89',  # mov
            b'\x8B',  # mov
            b'\xE8',  # call
            b'\xFF',  # call/jmp
            b'\x68',  # push imm32
            b'\x6A',  # push imm8
        ]
        
        if not data:
            return False

        count = 0
        for opcode in common_opcodes:
            count += data.count(opcode)

        # Use opcode *density* rather than an absolute count: an absolute
        # threshold behaves inconsistently across differently sized buffers
        # (it never triggers on small ones and trivially triggers on large
        # ones). Uniformly random data sits near 7/256 ~= 0.027, so 0.1
        # leaves a wide margin above noise.
        return (count / len(data)) > 0.1
    
    def _detect_shellcode(self, dump_path: Path, result: MemoryForensicsResult):
        """Detect shellcode patterns in memory."""
        with dump_path.open("rb") as f:
            offset = 0
            scanned = 0
            
            while scanned < _MAX_SCAN_BYTES and (window := f.read(_SCAN_WINDOW_BYTES)):
                scanned += len(window)
                
                for pattern_name, pattern_bytes in self._shellcode_patterns.items():
                    pattern_offset = 0
                    while True:
                        idx = window.find(pattern_bytes, pattern_offset)
                        if idx == -1:
                            break
                        
                        result.shellcode_matches.append(ShellcodeMatch(
                            offset=offset + idx,
                            size=len(pattern_bytes),
                            pattern_type=pattern_name,
                            confidence=0.8,
                            description=f"Detected {pattern_name} pattern"
                        ))
                        
                        pattern_offset = idx + 1
                
                offset += len(window)
    
    def _detect_credentials(self, dump_path: Path, result: MemoryForensicsResult):
        """Detect credential patterns in memory."""
        with dump_path.open("rb") as f:
            offset = 0
            scanned = 0
            
            while scanned < _MAX_SCAN_BYTES and (window := f.read(_SCAN_WINDOW_BYTES)):
                scanned += len(window)
                
                # Extract strings from window
                strings = self._extract_strings(window)
                
                for string_offset, string_value in strings:
                    abs_offset = offset + string_offset

                    # Credential patterns are compiled as bytes patterns, so the
                    # extracted (str) string must be encoded before matching.
                    string_bytes = string_value.encode('ascii', errors='ignore')

                    # Check against credential patterns
                    for cred_type, pattern in self._credential_patterns.items():
                        if pattern.search(string_bytes):
                            # Get context around the match
                            context_start = max(0, string_offset - 50)
                            context_end = min(len(window), string_offset + len(string_value) + 50)
                            context = window[context_start:context_end]
                            
                            try:
                                context_str = context.decode('ascii', errors='ignore')
                            except:
                                context_str = str(context)
                            
                            result.credential_matches.append(CredentialMatch(
                                offset=abs_offset,
                                credential_type=cred_type,
                                value=string_value,
                                context=context_str,
                                confidence=0.7
                            ))
                
                offset += len(window)
    
    def _extract_memory_iocs(self, dump_path: Path, result: MemoryForensicsResult):
        """Extract IOCs from memory (IPs, URLs, domains)."""
        ip_pattern = re.compile(
            rb'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            rb'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        url_pattern = re.compile(
            rb'https?://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        
        domain_pattern = re.compile(
            rb'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
            rb'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b'
        )
        
        with dump_path.open("rb") as f:
            offset = 0
            scanned = 0
            
            while scanned < _MAX_SCAN_BYTES and (window := f.read(_SCAN_WINDOW_BYTES)):
                scanned += len(window)
                
                # Extract IPs
                for match in ip_pattern.finditer(window):
                    result.memory_iocs.append({
                        "type": "ip",
                        "value": match.group().decode('ascii'),
                        "offset": f"0x{offset + match.start():X}",
                    })
                
                # Extract URLs
                for match in url_pattern.finditer(window):
                    result.memory_iocs.append({
                        "type": "url",
                        "value": match.group().decode('ascii', errors='ignore'),
                        "offset": f"0x{offset + match.start():X}",
                    })
                
                offset += len(window)
    
    def _extract_strings(self, data: bytes) -> List[Tuple[int, str]]:
        """Extract printable strings from binary data."""
        strings = []
        current = bytearray()
        start_offset = 0
        
        for i, byte in enumerate(data):
            if 0x20 <= byte <= 0x7E:
                if not current:
                    start_offset = i
                current.append(byte)
            else:
                if len(current) >= _MIN_STRING_LENGTH:
                    strings.append((start_offset, current.decode('ascii', errors='ignore')))
                current.clear()
        
        if len(current) >= _MIN_STRING_LENGTH:
            strings.append((start_offset, current.decode('ascii', errors='ignore')))
        
        return strings
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _build_credential_patterns(self) -> Dict[str, re.Pattern]:
        """Build regex patterns for credential detection."""
        return {
            "password": re.compile(rb'password\s*[:=]\s*[^\s]{4,}', re.IGNORECASE),
            "api_key": re.compile(rb'api[_-]?key\s*[:=]\s*[^\s]{16,}', re.IGNORECASE),
            "token": re.compile(rb'token\s*[:=]\s*[^\s]{16,}', re.IGNORECASE),
            "secret": re.compile(rb'secret\s*[:=]\s*[^\s]{16,}', re.IGNORECASE),
            "credential": re.compile(rb'credential\s*[:=]\s*[^\s]{8,}', re.IGNORECASE),
            "auth": re.compile(rb'auth\s*[:=]\s*[^\s]{8,}', re.IGNORECASE),
            "bearer": re.compile(rb'bearer\s+[^\s]{20,}', re.IGNORECASE),
            "basic_auth": re.compile(rb'basic\s+[a-zA-Z0-9+/=]{20,}', re.IGNORECASE),
        }
    
    def _build_shellcode_patterns(self) -> Dict[str, bytes]:
        """Build byte patterns for shellcode detection."""
        return {
            "xor_decrypt": b'\x33\xC0',  # xor eax, eax
            "push_esp": b'\x54',  # push esp
            "call_esp": b'\xFF\xD4',  # call esp
            "pop_ebp": b'\x5D',  # pop ebp
            "pop_ebx": b'\x5B',  # pop ebx
            "pop_esi": b'\x5E',  # pop esi
            "pop_edi": b'\x5F',  # pop edi
            "ret": b'\xC3',  # ret
            "int3": b'\xCC',  # int3 (breakpoint)
            "nop_sled": b'\x90' * 10,  # NOP sled
        }


def analyze_memory_dump(dump_path: str | Path) -> MemoryForensicsResult:
    """
    Convenience function to analyze a memory dump.
    
    Args:
        dump_path: Path to the memory dump file
        
    Returns:
        MemoryForensicsResult with analysis findings
    """
    analyzer = MemoryForensicsAnalyzer()
    return analyzer.analyze(dump_path)