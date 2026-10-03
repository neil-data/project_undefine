"""
test_memory_forensics.py — Memory forensics analysis tests for Phase 5.

Tests the comprehensive memory forensics capabilities including:
- Memory dump validation
- Memory region analysis
- Injected code detection
- Shellcode detection
- Credential detection
- Memory IOC extraction
- Process analysis
- DLL analysis
"""

import struct

import pytest
from pathlib import Path
from uuid import uuid4

from artifacts.memory_forensics import (
    MemoryForensicsAnalyzer,
    MemoryForensicsResult,
    MemoryRegion,
    MemoryRegionType,
    MemoryProtection,
    ProcessInfo,
    ShellcodeMatch,
    CredentialMatch,
    analyze_memory_dump,
)


class TestMemoryRegion:
    """Test MemoryRegion dataclass."""
    
    def test_memory_region_creation(self):
        """Test creating a memory region."""
        region = MemoryRegion(
            base_address=0x400000,
            size=4096,
            protection=MemoryProtection.READWRITE,
            region_type=MemoryRegionType.IMAGE,
            module_name="kernel32.dll"
        )
        
        assert region.base_address == 0x400000
        assert region.size == 4096
        assert region.protection == MemoryProtection.READWRITE
        assert region.region_type == MemoryRegionType.IMAGE
        assert region.module_name == "kernel32.dll"
        assert region.is_suspicious is False
    
    def test_memory_region_to_dict(self):
        """Test converting memory region to dictionary."""
        region = MemoryRegion(
            base_address=0x400000,
            size=4096,
            protection=MemoryProtection.EXECUTE_READWRITE,
            region_type=MemoryRegionType.INJECTED,
            is_suspicious=True,
            suspicion_reason="High entropy",
            entropy=7.5
        )
        
        result = region.to_dict()
        
        assert result["base_address"] == "0x400000"
        assert result["size"] == 4096
        assert result["protection"] == "execute_readwrite"
        assert result["region_type"] == "injected"
        assert result["is_suspicious"] is True
        assert result["suspicion_reason"] == "High entropy"
        assert result["entropy"] == 7.5


class TestProcessInfo:
    """Test ProcessInfo dataclass."""
    
    def test_process_info_creation(self):
        """Test creating process info."""
        process = ProcessInfo(
            pid=1234,
            name="malware.exe",
            base_address=0x400000,
            image_path="C:\\Users\\victim\\Desktop\\malware.exe",
            parent_pid=1000
        )
        
        assert process.pid == 1234
        assert process.name == "malware.exe"
        assert process.base_address == 0x400000
        assert process.image_path == "C:\\Users\\victim\\Desktop\\malware.exe"
        assert process.parent_pid == 1000
    
    def test_process_info_to_dict(self):
        """Test converting process info to dictionary."""
        process = ProcessInfo(
            pid=1234,
            name="malware.exe",
            base_address=0x400000,
            image_path="C:\\Users\\victim\\Desktop\\malware.exe"
        )
        
        result = process.to_dict()
        
        assert result["pid"] == 1234
        assert result["name"] == "malware.exe"
        assert result["base_address"] == "0x400000"
        assert result["image_path"] == "C:\\Users\\victim\\Desktop\\malware.exe"


class TestMemoryForensicsResult:
    """Test MemoryForensicsResult dataclass."""
    
    def test_result_creation(self):
        """Test creating memory forensics result."""
        result = MemoryForensicsResult(
            dump_path="/tmp/memdump.raw",
            status="completed",
            dump_size_bytes=1024 * 1024 * 100,
            dump_hash="abc123"
        )
        
        assert result.dump_path == "/tmp/memdump.raw"
        assert result.status == "completed"
        assert result.dump_size_bytes == 1024 * 1024 * 100
        assert result.dump_hash == "abc123"
        assert result.has_suspicious_activity is False
    
    def test_result_with_suspicious_activity(self):
        """Test result with suspicious activity."""
        result = MemoryForensicsResult(
            dump_path="/tmp/memdump.raw",
            status="completed",
            dump_size_bytes=1024 * 1024 * 100,
            dump_hash="abc123"
        )
        
        # Add suspicious regions
        result.suspicious_regions.append(MemoryRegion(
            base_address=0x1000000,
            size=4096,
            protection=MemoryProtection.EXECUTE_READWRITE,
            region_type=MemoryRegionType.INJECTED,
            is_suspicious=True
        ))
        
        assert result.has_suspicious_activity is True
    
    def test_result_to_dict(self):
        """Test converting result to dictionary."""
        result = MemoryForensicsResult(
            dump_path="/tmp/memdump.raw",
            status="completed",
            dump_size_bytes=1024 * 1024 * 100,
            dump_hash="abc123",
            total_regions_analyzed=100,
            total_rwx_regions=5,
            total_injected_regions=2,
            high_entropy_regions=3
        )
        
        result_dict = result.to_dict()
        
        assert result_dict["dump_path"] == "/tmp/memdump.raw"
        assert result_dict["status"] == "completed"
        assert result_dict["total_regions_analyzed"] == 100
        assert result_dict["total_rwx_regions"] == 5
        assert result_dict["total_injected_regions"] == 2
        assert result_dict["high_entropy_regions"] == 3


class TestMemoryForensicsAnalyzer:
    """Test MemoryForensicsAnalyzer."""
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = MemoryForensicsAnalyzer()
        
        assert analyzer is not None
        assert analyzer._credential_patterns is not None
        assert analyzer._shellcode_patterns is not None
    
    def test_validate_dump_missing_file(self, tmp_path):
        """Test dump validation with missing file."""
        analyzer = MemoryForensicsAnalyzer()
        missing_file = tmp_path / "missing.raw"
        
        assert analyzer._validate_dump(missing_file) is False
    
    def test_validate_dump_too_small(self, tmp_path):
        """Test dump validation with too small file."""
        analyzer = MemoryForensicsAnalyzer()
        small_file = tmp_path / "small.raw"
        small_file.write_bytes(b"small")
        
        assert analyzer._validate_dump(small_file) is False
    
    def test_validate_dump_all_zeros(self, tmp_path):
        """Test dump validation with all zeros."""
        analyzer = MemoryForensicsAnalyzer()
        zero_file = tmp_path / "zero.raw"
        # Must exceed the 1MB minimum so this actually exercises the
        # all-zeros check rather than short-circuiting on the size check.
        zero_file.write_bytes(b'\x00' * (2 * 1024 * 1024))
        
        assert analyzer._validate_dump(zero_file) is False
    
    def test_validate_dump_valid(self, tmp_path):
        """Test dump validation with valid file."""
        analyzer = MemoryForensicsAnalyzer()
        valid_file = tmp_path / "valid.raw"
        # Must exceed the 1MB minimum enforced by _validate_dump.
        valid_file.write_bytes(
            b'MZ' + b'\x00' * 100 + b'PE\0\0' + b'\x00' * (2 * 1024 * 1024)
        )
        
        assert analyzer._validate_dump(valid_file) is True
    
    def test_calculate_entropy(self):
        """Test entropy calculation."""
        analyzer = MemoryForensicsAnalyzer()
        
        # Zero bytes have zero entropy
        zero_entropy = analyzer._calculate_entropy(b'\x00' * 100)
        assert zero_entropy == 0.0
        
        # Random bytes have high entropy
        import random
        random_bytes = bytes(random.getrandbits(8) for _ in range(100))
        random_entropy = analyzer._calculate_entropy(random_bytes)
        assert random_entropy > 6.0
    
    def test_extract_strings(self):
        """Test string extraction."""
        analyzer = MemoryForensicsAnalyzer()
        
        # Each string must be at least _MIN_STRING_LENGTH (6) characters to
        # be extracted; shorter runs are intentionally discarded as noise.
        data = b'HelloThere\x00WorldWide\x00TestCase\x00'
        strings = analyzer._extract_strings(data)

        assert len(strings) == 3
        assert "HelloThere" in [s[1] for s in strings]
        assert "WorldWide" in [s[1] for s in strings]
        assert "TestCase" in [s[1] for s in strings]
    
    def test_find_pe_headers(self):
        """Test PE header detection."""
        analyzer = MemoryForensicsAnalyzer()
        
        # Create data with MZ header
        # e_lfanew lives at offset 0x3C (60), so pad with 58 bytes after "MZ"
        # to place the 4-byte PE offset there and the "PE\0\0" signature at 64.
        data = b'MZ' + b'\x00' * 58 + struct.pack('<I', 64) + b'PE\0\0' + b'\x00' * 100

        pe_matches = analyzer._find_pe_headers(data, 0)
        
        assert len(pe_matches) > 0
    
    def test_has_executable_patterns(self):
        """Test executable pattern detection."""
        analyzer = MemoryForensicsAnalyzer()
        
        # Data with common opcodes
        data = b'\x55\x89\xE5\x8B\x45\x08\xE8\x00\x00\x00\x00'
        
        assert analyzer._has_executable_patterns(data) is True
        
        # Random data
        import random
        random_data = bytes(random.getrandbits(8) for _ in range(100))
        assert analyzer._has_executable_patterns(random_data) is False
    
    def test_build_credential_patterns(self):
        """Test credential pattern building."""
        analyzer = MemoryForensicsAnalyzer()
        
        patterns = analyzer._credential_patterns
        
        assert "password" in patterns
        assert "api_key" in patterns
        assert "token" in patterns
        assert "secret" in patterns
    
    def test_build_shellcode_patterns(self):
        """Test shellcode pattern building."""
        analyzer = MemoryForensicsAnalyzer()
        
        patterns = analyzer._shellcode_patterns
        
        assert "xor_decrypt" in patterns
        assert "push_esp" in patterns
        assert "call_esp" in patterns
        assert "ret" in patterns


class TestMemoryForensicsIntegration:
    """Integration tests for memory forensics."""
    
    def test_analyze_memory_dump_valid(self, tmp_path):
        """Test analyzing a valid memory dump."""
        # Create a test memory dump with some patterns
        dump_file = tmp_path / "test_dump.raw"
        
        # Create a larger file with PE headers and some content
        content = b'MZ' + b'\x00' * 58 + struct.pack('<I', 64) + b'PE\0\0'
        content += b'\x00' * 1000
        content += b'password=secret123'
        content += b'\x00' * 1000
        content += b'\x55\x89\xE5'  # Common opcodes
        content += b'\x00' * (16 * 1024 * 1024 - len(content))  # Make it 16MB

        dump_file.write_bytes(content)
        
        result = analyze_memory_dump(dump_file)
        
        assert result.status == "completed"
        assert result.dump_size_bytes > 0
        assert result.dump_hash is not None
    
    def test_analyze_memory_dump_missing(self, tmp_path):
        """Test analyzing a missing memory dump."""
        missing_file = tmp_path / "missing.raw"
        
        result = analyze_memory_dump(missing_file)
        
        assert result.status == "failed"
        assert result.error is not None
    
    def test_convenience_function(self, tmp_path):
        """Test the convenience function."""
        dump_file = tmp_path / "test_dump.raw"
        dump_file.write_bytes(b'MZ' + b'\x00' * 8192)
        
        result = analyze_memory_dump(dump_file)
        
        assert isinstance(result, MemoryForensicsResult)


class TestArtifactStoreIntegration:
    """Test integration with ArtifactStore."""
    
    def test_store_memory_forensics_analysis(self, tmp_path):
        """Test storing memory forensics analysis in artifact store."""
        from artifacts.store import ArtifactStore, Artifact
        
        analysis_id = uuid4()
        store = ArtifactStore(tmp_path, analysis_id)
        
        # Create a test memory dump
        dump_file = tmp_path / "test_dump.raw"
        dump_file.write_bytes(b'MZ' + b'\x00' * 8192)
        
        # Register as artifact
        artifact = store.register(
            dump_file,
            "memdump",
            name="memory_dump.raw",
            description="Test memory dump"
        )
        
        # Analyze memory forensics
        result = store.analyze_memory_forensics(artifact)
        
        assert "memory_forensics" in artifact.analysis
        assert "status" in result


class TestCredentialDetection:
    """Test credential detection patterns."""
    
    def test_password_pattern(self):
        """Test password pattern detection."""
        analyzer = MemoryForensicsAnalyzer()
        
        test_string = b"password=MySecretPassword123"
        pattern = analyzer._credential_patterns["password"]
        
        assert pattern.search(test_string) is not None
    
    def test_api_key_pattern(self):
        """Test API key pattern detection."""
        analyzer = MemoryForensicsAnalyzer()
        
        test_string = b"api_key=abcdefghijklmnopqrstuvwxyz123456"
        pattern = analyzer._credential_patterns["api_key"]
        
        assert pattern.search(test_string) is not None
    
    def test_token_pattern(self):
        """Test token pattern detection."""
        analyzer = MemoryForensicsAnalyzer()
        
        test_string = b"token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        pattern = analyzer._credential_patterns["token"]
        
        assert pattern.search(test_string) is not None


class TestShellcodeDetection:
    """Test shellcode detection patterns."""
    
    def test_xor_decrypt_pattern(self):
        """Test XOR decrypt pattern."""
        analyzer = MemoryForensicsAnalyzer()
        
        pattern = analyzer._shellcode_patterns["xor_decrypt"]
        assert pattern == b'\x33\xC0'
    
    def test_call_esp_pattern(self):
        """Test call ESP pattern."""
        analyzer = MemoryForensicsAnalyzer()
        
        pattern = analyzer._shellcode_patterns["call_esp"]
        assert pattern == b'\xFF\xD4'
    
    def test_nop_sled_pattern(self):
        """Test NOP sled pattern."""
        analyzer = MemoryForensicsAnalyzer()
        
        pattern = analyzer._shellcode_patterns["nop_sled"]
        assert pattern == b'\x90' * 10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])