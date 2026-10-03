"""
test_chain_verification.py — Tests for chain verification functionality.
"""

import pytest
from agents.investigation_engine.chain_verification import (
    ChainVerifier,
    ChainLink,
    VerificationStatus,
    ChainLinkType,
    VerificationResult,
    verify_chain,
    verify_integrity,
)


@pytest.fixture
def verifier():
    """Create a chain verifier with test secret key."""
    return ChainVerifier(secret_key="test_secret_key")


@pytest.fixture
def sample_data():
    """Sample data for testing."""
    return {
        "sample_id": "test_001",
        "static_output": {"sha256": "a" * 64, "platform": "android"},  # Keys matching verify_integrity expectations
        "dynamic_output": {"process_tree": [{"name": "test.exe"}]},
        "mitre_techniques": [{"technique_id": "T1112"}],
        "capability_tags": [{"capability": "sms_theft"}],
        "risk_score": 75,
        "narrative_summary": "Test summary",
        "investigation_output": {"timeline_events": []},
    }


class TestChainVerifier:
    """Test suite for ChainVerifier."""
    
    def test_compute_hash(self, verifier):
        """Test hash computation."""
        data = {"test": "data"}
        hash1 = verifier.compute_hash(data)
        hash2 = verifier.compute_hash(data)
        
        assert hash1 == hash2  # Same data should produce same hash
        assert len(hash1) == 64  # SHA256 produces 64 hex characters
        
        # Different data should produce different hash
        different_data = {"test": "different"}
        hash3 = verifier.compute_hash(different_data)
        assert hash1 != hash3
    
    def test_compute_hmac(self, verifier):
        """Test HMAC computation."""
        data = "test_data"
        signature = verifier.compute_hmac(data)
        
        assert signature is not None
        assert len(signature) == 64  # SHA256 HMAC produces 64 hex characters
        
        # Same data should produce same signature
        signature2 = verifier.compute_hmac(data)
        assert signature == signature2
    
    def test_verify_hmac(self, verifier):
        """Test HMAC verification."""
        data = "test_data"
        signature = verifier.compute_hmac(data)
        
        # Valid signature should verify
        assert verifier.verify_hmac(data, signature) is True
        
        # Invalid signature should not verify
        assert verifier.verify_hmac(data, "invalid_signature") is False
        
        # Wrong data should not verify
        assert verifier.verify_hmac("wrong_data", signature) is False
    
    def test_create_chain_link(self, verifier):
        """Test chain link creation."""
        link = verifier.create_chain_link(
            link_type=ChainLinkType.STATIC_ANALYSIS,
            data={"test": "data"},
            previous_hash="0" * 64,
            metadata={"test": "metadata"}
        )
        
        assert link.link_type == ChainLinkType.STATIC_ANALYSIS
        assert link.data_hash is not None
        assert link.previous_hash == "0" * 64
        assert link.signature is not None  # Should have signature with secret key
        assert link.metadata == {"test": "metadata"}
    
    def test_create_chain_link_without_secret(self):
        """Test chain link creation without secret key."""
        verifier = ChainVerifier(secret_key=None)
        link = verifier.create_chain_link(
            link_type=ChainLinkType.STATIC_ANALYSIS,
            data={"test": "data"},
            previous_hash="0" * 64
        )
        
        assert link.signature is None  # No signature without secret key
    
    def test_verify_chain_link(self, verifier):
        """Test single chain link verification."""
        link = verifier.create_chain_link(
            link_type=ChainLinkType.STATIC_ANALYSIS,
            data={"test": "data"},
            previous_hash="0" * 64
        )
        
        # Should verify with correct previous hash
        assert verifier.verify_chain_link(link, "0" * 64) is True
        
        # Should not verify with wrong previous hash
        assert verifier.verify_chain_link(link, "1" * 64) is False
    
    def test_verify_valid_chain(self, verifier, sample_data):
        """Test verification of a valid chain."""
        chain = []
        previous_hash = "0" * 64
        
        # Map link types to sample data keys
        link_data_map = {
            ChainLinkType.STATIC_ANALYSIS: "static_output",
            ChainLinkType.DYNAMIC_ANALYSIS: "dynamic_output",
            ChainLinkType.MITRE_MAPPING: "mitre_techniques",
            ChainLinkType.CAPABILITY_CLASSIFICATION: "capability_tags",
            ChainLinkType.RISK_SCORING: "risk_score",
            ChainLinkType.NARRATIVE_GENERATION: "narrative_summary",
            ChainLinkType.INVESTIGATION_ENGINE: "investigation_output",
        }
        
        # Create a complete chain
        for link_type in ChainLinkType:
            data_key = link_data_map.get(link_type)
            data = sample_data.get(data_key) if data_key else None
            if data is not None:
                link = verifier.create_chain_link(
                    link_type=link_type,
                    data=data,
                    previous_hash=previous_hash
                )
                chain.append(link)
                previous_hash = link.data_hash
        
        result = verifier.verify_chain(chain)
        
        assert result.status == VerificationStatus.VALID
        assert result.is_valid is True
        assert result.verified_links == len(chain)
        assert result.total_links == len(chain)
        assert len(result.tampered_links) == 0
        assert len(result.errors) == 0
    
    def test_verify_tampered_chain(self, verifier):
        """Test verification of a tampered chain."""
        chain = []
        previous_hash = "0" * 64
        
        # Create chain
        for i, link_type in enumerate(list(ChainLinkType)[:3]):
            link = verifier.create_chain_link(
                link_type=link_type,
                data={"index": i},
                previous_hash=previous_hash
            )
            chain.append(link)
            previous_hash = link.data_hash
        
        # Tamper with middle link
        chain[1].data_hash = "0" * 64
        
        result = verifier.verify_chain(chain)
        
        assert result.status == VerificationStatus.TAMPERED
        assert result.is_valid is False
        assert len(result.tampered_links) > 0
    
    def test_verify_incomplete_chain(self, verifier):
        """Test verification of incomplete chain."""
        chain = []
        previous_hash = "0" * 64
        
        # Create chain with missing link types
        link = verifier.create_chain_link(
            link_type=ChainLinkType.STATIC_ANALYSIS,
            data={"test": "data"},
            previous_hash=previous_hash
        )
        chain.append(link)
        
        result = verifier.verify_chain(chain)
        
        assert result.status == VerificationStatus.INCOMPLETE
        assert result.is_valid is False
        assert len(result.missing_links) > 0
    
    def test_verify_empty_chain(self, verifier):
        """Test verification of empty chain."""
        result = verifier.verify_chain([])
        
        assert result.status == VerificationStatus.INCOMPLETE
        assert result.is_valid is False
        assert len(result.errors) > 0
    
    def test_verify_integrity_creates_chain(self, verifier, sample_data):
        """Test verify_integrity creates chain when none provided."""
        result, chain = verifier.verify_integrity(sample_data, chain=None)
        
        assert chain is not None
        assert len(chain) > 0
        assert result.status == VerificationStatus.VALID
        assert result.is_valid is True
    
    def test_verify_integrity_with_existing_chain(self, verifier, sample_data):
        """Test verify_integrity with existing chain."""
        # Create chain first
        _, original_chain = verifier.verify_integrity(sample_data, chain=None)
        
        # Verify with existing chain
        result, verified_chain = verifier.verify_integrity(sample_data, chain=original_chain)
        
        assert result.status == VerificationStatus.VALID
        assert result.is_valid is True
        assert len(verified_chain) == len(original_chain)
    
    def test_verify_integrity_detects_tampering(self, verifier, sample_data):
        """Test verify_integrity detects data tampering."""
        # Create chain
        _, original_chain = verifier.verify_integrity(sample_data, chain=None)
        
        # Tamper with data
        tampered_data = sample_data.copy()
        tampered_data["risk_score"] = 999
        
        # Verify with tampered data
        result, _ = verifier.verify_integrity(tampered_data, chain=original_chain)
        
        assert result.is_valid is False
        assert result.status == VerificationStatus.TAMPERED
    
    def test_export_and_import_chain(self, verifier):
        """Test chain export and import."""
        chain = []
        previous_hash = "0" * 64
        
        for i, link_type in enumerate(list(ChainLinkType)[:2]):
            link = verifier.create_chain_link(
                link_type=link_type,
                data={"index": i},
                previous_hash=previous_hash
            )
            chain.append(link)
            previous_hash = link.data_hash
        
        # Export
        exported = verifier.export_chain(chain)
        assert isinstance(exported, str)
        
        # Import
        imported_chain = verifier.import_chain(exported)
        assert len(imported_chain) == len(chain)
        
        # Verify imported chain
        for original, imported in zip(chain, imported_chain):
            assert original.link_type == imported.link_type
            assert original.data_hash == imported.data_hash
            assert original.previous_hash == imported.previous_hash


class TestConvenienceFunctions:
    """Test suite for convenience functions."""
    
    def test_verify_chain_convenience(self):
        """Test verify_chain convenience function."""
        verifier = ChainVerifier(secret_key="test_key")
        chain = []
        previous_hash = "0" * 64
        
        link = verifier.create_chain_link(
            link_type=ChainLinkType.STATIC_ANALYSIS,
            data={"test": "data"},
            previous_hash=previous_hash
        )
        chain.append(link)
        
        result = verify_chain(chain, secret_key="test_key")
        
        # Should be incomplete since we only have one link
        assert result.status == VerificationStatus.INCOMPLETE
        assert result.verified_links == 1
    
    def test_verify_integrity_convenience(self):
        """Test verify_integrity convenience function."""
        sample_data = {
            "static_output": {"test": "data"},
            "dynamic_output": {"test": "data"},
        }
        
        result, chain = verify_integrity(sample_data, secret_key="test_key")
        
        # Should be incomplete since we're missing most fields
        assert result.status == VerificationStatus.INCOMPLETE
        assert result.verified_links == 2
        assert chain is not None


class TestChainLinkTypes:
    """Test all chain link types."""
    
    def test_all_link_types_exist(self):
        """Test that all required link types are defined."""
        required_types = [
            "STATIC_ANALYSIS",
            "DYNAMIC_ANALYSIS",
            "MITRE_MAPPING",
            "CAPABILITY_CLASSIFICATION",
            "RISK_SCORING",
            "NARRATIVE_GENERATION",
            "INVESTIGATION_ENGINE",
        ]
        
        for type_name in required_types:
            assert hasattr(ChainLinkType, type_name)


def test_verifier_without_secret_key():
    """Test verifier behavior without secret key."""
    verifier = ChainVerifier(secret_key=None)
    
    # Should still compute hashes
    data = {"test": "data"}
    hash_value = verifier.compute_hash(data)
    assert hash_value is not None
    
    # Should create links without signatures
    link = verifier.create_chain_link(
        link_type=ChainLinkType.STATIC_ANALYSIS,
        data=data,
        previous_hash="0" * 64
    )
    assert link.signature is None
    
    # Should still verify chain integrity (without signature verification)
    assert verifier.verify_chain_link(link, "0" * 64) is True


def test_hmac_binds_artifact_manifest_and_sandbox_fields():
    """Verify that HMAC signature strictly binds artifact hashes and sandbox fields."""
    verifier = ChainVerifier(secret_key="top_secret_hmac_key")
    meta = {
        "sample_id": "test_sample_123",
        "task_id": "task_uuid_abc",
        "sandbox_id": "sandbox_node_1",
        "execution_mode": "real",
        "dynamic_status": "completed",
        "evidence_state": "OBSERVED",
        "intel_floor": 0,
        "strace_hash": "11" * 32,
        "pcap_hash": "22" * 32,
        "fs_diff_hash": "33" * 32,
    }
    link = verifier.create_chain_link(
        link_type=ChainLinkType.DYNAMIC_ANALYSIS,
        data={"behavior": "execve"},
        previous_hash="0" * 64,
        metadata=meta,
    )
    assert link.signature is not None
    assert verifier.verify_chain_link(link, "0" * 64) is True

    # Tampering with any artifact hash breaks signature verification
    tampered_link = ChainLink(
        link_type=link.link_type,
        timestamp=link.timestamp,
        data_hash=link.data_hash,
        previous_hash=link.previous_hash,
        signature=link.signature,
        metadata={**meta, "strace_hash": "ff" * 32},
    )
    assert verifier.verify_chain_link(tampered_link, "0" * 64) is False

    # Tampering with dynamic_status breaks signature verification
    tampered_status = ChainLink(
        link_type=link.link_type,
        timestamp=link.timestamp,
        data_hash=link.data_hash,
        previous_hash=link.previous_hash,
        signature=link.signature,
        metadata={**meta, "dynamic_status": "failed"},
    )
    assert verifier.verify_chain_link(tampered_status, "0" * 64) is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

