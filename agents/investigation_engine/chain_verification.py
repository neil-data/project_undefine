"""
chain_verification.py — Evidence chain integrity verification for Phase 10 AI Investigation Engine.

This module provides cryptographic verification of the investigation chain to ensure
evidence integrity and maintain chain of custody for legal proceedings.
"""

import hashlib
import json
import hmac
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum


class VerificationStatus(Enum):
    """Status of chain verification."""
    VALID = "valid"
    INVALID = "invalid"
    TAMPERED = "tampered"
    INCOMPLETE = "incomplete"
    ERROR = "error"


class ChainLinkType(Enum):
    """Types of links in the investigation chain."""
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    MITRE_MAPPING = "mitre_mapping"
    CAPABILITY_CLASSIFICATION = "capability_classification"
    RISK_SCORING = "risk_scoring"
    NARRATIVE_GENERATION = "narrative_generation"
    INVESTIGATION_ENGINE = "investigation_engine"


@dataclass
class ChainLink:
    """A single link in the investigation chain."""
    link_type: ChainLinkType
    timestamp: str
    data_hash: str
    previous_hash: str
    signature: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "link_type": self.link_type.value,
            "timestamp": self.timestamp,
            "data_hash": self.data_hash,
            "previous_hash": self.previous_hash,
            "signature": self.signature,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ChainLink':
        """Create from dictionary."""
        return cls(
            link_type=ChainLinkType(data["link_type"]),
            timestamp=data["timestamp"],
            data_hash=data["data_hash"],
            previous_hash=data["previous_hash"],
            signature=data.get("signature"),
            metadata=data.get("metadata", {})
        )


@dataclass
class VerificationResult:
    """Result of chain verification."""
    status: VerificationStatus
    is_valid: bool
    verified_links: int
    total_links: int
    tampered_links: List[str] = field(default_factory=list)
    missing_links: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    verified_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status": self.status.value,
            "is_valid": self.is_valid,
            "verified_links": self.verified_links,
            "total_links": self.total_links,
            "tampered_links": self.tampered_links,
            "missing_links": self.missing_links,
            "errors": self.errors,
            "verified_at": self.verified_at
        }


class ChainVerifier:
    """
    Verifies the integrity of the investigation chain using cryptographic hashing.
    
    This ensures that:
    1. Each analysis step is cryptographically linked to the previous step
    2. No step has been tampered with after creation
    3. The chain of custody is unbroken
    4. All required analysis steps are present
    """
    
    def __init__(self, secret_key: Optional[str] = None):
        """
        Initialize the chain verifier.
        
        Args:
            secret_key: Optional secret key for HMAC signing. If not provided,
                       verification will only check hash integrity, not signatures.
        """
        self.secret_key = secret_key
        self.hash_algorithm = "sha256"
    
    def compute_hash(self, data: Any) -> str:
        """
        Compute cryptographic hash of data.
        
        Args:
            data: Data to hash (will be JSON serialized)
            
        Returns:
            Hexadecimal hash string
        """
        if isinstance(data, (dict, list)):
            # Sort keys for consistent hashing
            data_str = json.dumps(data, sort_keys=True)
        else:
            data_str = str(data)
        
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def compute_hmac(self, data: str) -> str:
        """
        Compute HMAC signature for data.
        
        Args:
            data: Data to sign
            
        Returns:
            Hexadecimal HMAC signature
        """
        if not self.secret_key:
            raise ValueError("Secret key required for HMAC signing")
        
        return hmac.new(
            self.secret_key.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def verify_hmac(self, data: str, signature: str) -> bool:
        """
        Verify HMAC signature.
        
        Args:
            data: Original data
            signature: Signature to verify
            
        Returns:
            True if signature is valid
        """
        if not self.secret_key:
            return True  # Skip verification if no key provided
        
        try:
            expected = self.compute_hmac(data)
            return hmac.compare_digest(expected, signature)
        except Exception:
            return False
    
    def create_chain_link(
        self,
        link_type: ChainLinkType,
        data: Any,
        previous_hash: str = "0" * 64,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ChainLink:
        """
        Create a new chain link.
        
        Args:
            link_type: Type of analysis step
            data: Analysis output data
            previous_hash: Hash of previous link in chain
            metadata: Optional metadata about the analysis
            
        Returns:
            ChainLink object
        """
        data_hash = self.compute_hash(data)
        timestamp = datetime.utcnow().isoformat()
        metadata = metadata or {}
        
        # Create signature if secret key is available
        signature = None
        if self.secret_key:
            sample_id = str(metadata.get("sample_id", ""))
            sample_sha256 = str(metadata.get("sample_sha256", ""))
            task_id = str(metadata.get("task_id", ""))
            sandbox_id = str(metadata.get("sandbox_id", ""))
            exec_mode = str(metadata.get("execution_mode", ""))
            dynamic_status = str(metadata.get("dynamic_status", ""))
            evidence_state = str(metadata.get("evidence_state", ""))
            intel_floor = str(metadata.get("intel_floor", ""))
            strace_hash = str(metadata.get("strace_hash", ""))
            pcap_hash = str(metadata.get("pcap_hash", ""))
            fs_diff_hash = str(metadata.get("fs_diff_hash", ""))
            link_data = (
                f"{link_type.value}:{timestamp}:{data_hash}:{previous_hash}:"
                f"{sample_id}:{sample_sha256}:{task_id}:{sandbox_id}:{exec_mode}:{dynamic_status}:"
                f"{evidence_state}:{intel_floor}:{strace_hash}:{pcap_hash}:{fs_diff_hash}"
            )
            signature = self.compute_hmac(link_data)
        
        return ChainLink(
            link_type=link_type,
            timestamp=timestamp,
            data_hash=data_hash,
            previous_hash=previous_hash,
            signature=signature,
            metadata=metadata
        )
    
    def verify_chain_link(self, link: ChainLink, expected_previous_hash: str) -> bool:
        """
        Verify a single chain link.
        
        Args:
            link: Chain link to verify
            expected_previous_hash: Expected hash of previous link
            
        Returns:
            True if link is valid
        """
        # Check previous hash
        if link.previous_hash != expected_previous_hash:
            return False
        
        # Verify signature if present
        if link.signature and self.secret_key:
            meta = link.metadata or {}
            sample_id = str(meta.get("sample_id", ""))
            sample_sha256 = str(meta.get("sample_sha256", ""))
            task_id = str(meta.get("task_id", ""))
            sandbox_id = str(meta.get("sandbox_id", ""))
            exec_mode = str(meta.get("execution_mode", ""))
            dynamic_status = str(meta.get("dynamic_status", ""))
            evidence_state = str(meta.get("evidence_state", ""))
            intel_floor = str(meta.get("intel_floor", ""))
            strace_hash = str(meta.get("strace_hash", ""))
            pcap_hash = str(meta.get("pcap_hash", ""))
            fs_diff_hash = str(meta.get("fs_diff_hash", ""))
            
            primary_data = (
                f"{link.link_type.value}:{link.timestamp}:{link.data_hash}:{link.previous_hash}:"
                f"{sample_id}:{sample_sha256}:{task_id}:{sandbox_id}:{exec_mode}:{dynamic_status}:"
                f"{evidence_state}:{intel_floor}:{strace_hash}:{pcap_hash}:{fs_diff_hash}"
            )
            if self.verify_hmac(primary_data, link.signature):
                return True
            
            # Backward compatible checks
            fallback_patterns = [
                f"{link.link_type.value}:{link.timestamp}:{link.data_hash}:{link.previous_hash}:{sample_id}:{task_id}:{sandbox_id}:{exec_mode}:{dynamic_status}:{evidence_state}:{intel_floor}:{strace_hash}:{pcap_hash}:{fs_diff_hash}",
                f"{link.link_type.value}:{link.timestamp}:{link.data_hash}:{link.previous_hash}:{sample_id}:{task_id}:{exec_mode}:{evidence_state}:{intel_floor}",
                f"{link.link_type.value}:{link.timestamp}:{link.data_hash}:{link.previous_hash}:{exec_mode}",
                f"{link.link_type.value}:{link.timestamp}:{link.data_hash}:{link.previous_hash}",
            ]
            if any(self.verify_hmac(p, link.signature) for p in fallback_patterns):
                return True
            return False
        
        return True
    
    def verify_chain(self, chain: List[ChainLink]) -> VerificationResult:
        """
        Verify the complete investigation chain.
        
        Args:
            chain: List of chain links in order
            
        Returns:
            VerificationResult with detailed status
        """
        result = VerificationResult(
            status=VerificationStatus.VALID,
            is_valid=True,
            verified_links=0,
            total_links=len(chain)
        )
        
        if not chain:
            result.status = VerificationStatus.INCOMPLETE
            result.is_valid = False
            result.errors.append("Chain is empty")
            return result
        
        # Check for required link types
        required_types = {
            ChainLinkType.STATIC_ANALYSIS,
            ChainLinkType.DYNAMIC_ANALYSIS,
            ChainLinkType.MITRE_MAPPING,
            ChainLinkType.CAPABILITY_CLASSIFICATION,
            ChainLinkType.RISK_SCORING,
            ChainLinkType.NARRATIVE_GENERATION,
            ChainLinkType.INVESTIGATION_ENGINE,
        }
        
        present_types = {link.link_type for link in chain}
        missing_types = required_types - present_types
        
        if missing_types:
            result.status = VerificationStatus.INCOMPLETE
            result.is_valid = False
            result.missing_links.extend([t.value for t in missing_types])
            result.errors.append(f"Missing required chain links: {', '.join([t.value for t in missing_types])}")
        
        # Verify each link in sequence
        previous_hash = "0" * 64  # Genesis hash
        
        for i, link in enumerate(chain):
            if not self.verify_chain_link(link, previous_hash):
                result.status = VerificationStatus.TAMPERED
                result.is_valid = False
                result.tampered_links.append(f"{link.link_type.value} (position {i})")
                result.errors.append(f"Chain broken at {link.link_type.value}")
            else:
                result.verified_links += 1
            
            previous_hash = link.data_hash
        
        # Update final status
        if result.is_valid and result.verified_links == result.total_links:
            result.status = VerificationStatus.VALID
        elif not result.is_valid and not result.tampered_links:
            result.status = VerificationStatus.INCOMPLETE
        elif not result.is_valid:
            result.status = VerificationStatus.TAMPERED
        
        return result
    
    def verify_integrity(
        self,
        investigation_state: Dict[str, Any],
        chain: Optional[List[ChainLink]] = None
    ) -> Tuple[VerificationResult, Optional[List[ChainLink]]]:
        """
        Verify the integrity of investigation state and optionally create/verify chain.
        
        This is the main entry point for verification. It can:
        1. Verify an existing chain
        2. Create a new chain from investigation state
        3. Verify state against expected hash
        
        Args:
            investigation_state: Complete investigation state
            chain: Optional existing chain to verify. If None, creates new chain.
            
        Returns:
            Tuple of (VerificationResult, chain)
        """
        # Extract key components from investigation state
        components = {
            ChainLinkType.STATIC_ANALYSIS: investigation_state.get("static_output"),
            ChainLinkType.DYNAMIC_ANALYSIS: investigation_state.get("dynamic_output"),
            ChainLinkType.MITRE_MAPPING: investigation_state.get("mitre_techniques"),
            ChainLinkType.CAPABILITY_CLASSIFICATION: investigation_state.get("capability_tags"),
            ChainLinkType.RISK_SCORING: investigation_state.get("risk_score"),
            ChainLinkType.NARRATIVE_GENERATION: investigation_state.get("narrative_summary"),
            ChainLinkType.INVESTIGATION_ENGINE: investigation_state.get("investigation_output"),
        }
        
        # If no chain provided, create one
        if chain is None:
            chain = []
            previous_hash = "0" * 64
            
            for link_type in ChainLinkType:
                data = components.get(link_type)
                if data is not None:
                    link = self.create_chain_link(
                        link_type=link_type,
                        data=data,
                        previous_hash=previous_hash,
                        metadata={
                            "has_data": True,
                            "sample_id": investigation_state.get("sample_id", ""),
                            "sample_sha256": investigation_state.get("sample_sha256", "") or investigation_state.get("sha256", ""),
                            "task_id": investigation_state.get("task_id", ""),
                            "sandbox_id": investigation_state.get("sandbox_id", ""),
                            "execution_mode": investigation_state.get("execution_mode", ""),
                            "dynamic_status": investigation_state.get("dynamic_status", ""),
                            "evidence_state": investigation_state.get("evidence_state", ""),
                            "intel_floor": investigation_state.get("intel_floor", 0),
                            "strace_hash": investigation_state.get("strace_hash", "") or (investigation_state.get("artifact_hashes") or {}).get("strace.log", ""),
                            "pcap_hash": investigation_state.get("pcap_hash", "") or (investigation_state.get("artifact_hashes") or {}).get("capture.pcap", ""),
                            "fs_diff_hash": investigation_state.get("fs_diff_hash", "") or (investigation_state.get("artifact_hashes") or {}).get("fs_diff.json", ""),
                        }
                    )
                    chain.append(link)
                    previous_hash = link.data_hash
            
            # Verify the newly created chain
            result = self.verify_chain(chain)
            return result, chain
        
        # Verify existing chain
        result = self.verify_chain(chain)
        
        # Optionally verify that chain hashes match current state
        if result.is_valid:
            for i, link in enumerate(chain):
                expected_data = components.get(link.link_type)
                if expected_data is not None:
                    current_hash = self.compute_hash(expected_data)
                    if current_hash != link.data_hash:
                        result.is_valid = False
                        result.status = VerificationStatus.TAMPERED
                        result.tampered_links.append(f"{link.link_type.value} (data mismatch)")
                        result.errors.append(f"Data hash mismatch for {link.link_type.value}")
        
        return result, chain
    
    def export_chain(self, chain: List[ChainLink]) -> str:
        """
        Export chain to JSON string for storage/transmission.
        
        Args:
            chain: Chain to export
            
        Returns:
            JSON string
        """
        chain_data = [link.to_dict() for link in chain]
        return json.dumps(chain_data, indent=2)
    
    def import_chain(self, chain_json: str) -> List[ChainLink]:
        """
        Import chain from JSON string.
        
        Args:
            chain_json: JSON string containing chain data
            
        Returns:
            List of ChainLink objects
        """
        chain_data = json.loads(chain_json)
        return [ChainLink.from_dict(data) for data in chain_data]


def verify_chain(chain: List[ChainLink], secret_key: Optional[str] = None) -> VerificationResult:
    """
    Convenience function to verify a chain.
    
    Args:
        chain: Chain to verify
        secret_key: Optional secret key for signature verification
        
    Returns:
        VerificationResult
    """
    verifier = ChainVerifier(secret_key=secret_key)
    return verifier.verify_chain(chain)


def verify_integrity(
    investigation_state: Dict[str, Any],
    chain: Optional[List[ChainLink]] = None,
    secret_key: Optional[str] = None
) -> Tuple[VerificationResult, Optional[List[ChainLink]]]:
    """
    Convenience function to verify investigation integrity.
    
    Args:
        investigation_state: Investigation state to verify
        chain: Optional existing chain
        secret_key: Optional secret key for signature verification
        
    Returns:
        Tuple of (VerificationResult, chain)
    """
    verifier = ChainVerifier(secret_key=secret_key)
    return verifier.verify_integrity(investigation_state, chain)
