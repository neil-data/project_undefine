from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from analysis.scoring.orchestrator.schema import EvidenceFinding


class DynamicState(str, Enum):
    COMPLETED = "COMPLETED"
    NO_RESULT = "NO_RESULT"
    NOT_SUPPORTED_PLATFORM = "NOT_SUPPORTED_PLATFORM"
    SUBMISSION_DISABLED = "SUBMISSION_DISABLED"
    KEY_MISSING = "KEY_MISSING"
    KEY_RESTRICTED = "KEY_RESTRICTED"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    INVALID_RESPONSE = "INVALID_RESPONSE"


@dataclass
class ProviderObservation:
    process: list[dict] = field(default_factory=list)
    network: list[dict] = field(default_factory=list)
    dns: list[dict] = field(default_factory=list)
    file: list[dict] = field(default_factory=list)
    registry: list[dict] = field(default_factory=list)
    api_call: list[dict] = field(default_factory=list)
    signature: list[dict] = field(default_factory=list)
    mitre: list[dict] = field(default_factory=list)
    limitation: list[str] = field(default_factory=list)

    def has_behavior(self):
        return any(getattr(self, name) for name in ("process", "network", "dns", "file", "registry", "api_call", "signature", "mitre"))


@dataclass
class NormalizedProviderResult:
    state: DynamicState
    observation: ProviderObservation = field(default_factory=ProviderObservation)
    provenance: dict = field(default_factory=dict)
    findings: list[EvidenceFinding] = field(default_factory=list)
    verdict: EvidenceFinding | None = None
    reason: str | None = None
    narrative: str | None = None
    report_line: str | None = None
    correlations: list[dict] = field(default_factory=list)
    classified_iocs: list[Any] = field(default_factory=list)


def invalid_response():
    return NormalizedProviderResult(DynamicState.INVALID_RESPONSE, reason="invalid response", narrative="Dynamic analysis not performed: invalid response")


class ProviderAdapter(ABC):
    name = "provider"

    @abstractmethod
    def lookup_by_hash(self, sha256: str) -> Any: ...

    @abstractmethod
    def submit(self, sample_ref: Any) -> Any: ...

    @abstractmethod
    def get_status(self, task_id: str) -> Any: ...

    @abstractmethod
    def get_report(self, task_id: str) -> Any: ...

    @abstractmethod
    def normalize(self, raw: Any) -> dict: ...
