"""Data contracts for indicators of compromise extracted from a sample."""

from dataclasses import dataclass, field
from enum import Enum

from static_analysis.detection.models import ConfidenceLevel


class IocType(str, Enum):
    """Closed vocabulary of indicator kinds this engine can extract."""

    URL = "url"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    EMAIL = "email"
    ONION_ADDRESS = "onion_address"
    BITCOIN_ADDRESS = "bitcoin_address"
    ETHEREUM_ADDRESS = "ethereum_address"
    UPI_ID = "upi_id"
    INDIAN_PHONE = "indian_phone"
    TELEGRAM_HANDLE = "telegram_handle"
    WINDOWS_PATH = "windows_path"
    UNIX_PATH = "unix_path"
    REGISTRY_KEY = "registry_key"


# Indicator kinds an investigator can pivot on directly — these are what an
# exported IOC feed should contain. Paths and registry keys are evidence, not
# pivots: they describe what the sample touched on one machine, not a
# destination someone else can be checked against.
NETWORK_IOC_TYPES = frozenset({
    IocType.URL,
    IocType.DOMAIN,
    IocType.IPV4,
    IocType.IPV6,
    IocType.ONION_ADDRESS,
})

PAYMENT_IOC_TYPES = frozenset({
    IocType.BITCOIN_ADDRESS,
    IocType.ETHEREUM_ADDRESS,
    IocType.UPI_ID,
})

# Ways to reach the operator. Worth pursuing in this context specifically:
# a mobile number or Telegram handle embedded in a scam APK is something a
# cyber-crime unit can act on directly, in a way a C2 domain often is not.
CONTACT_IOC_TYPES = frozenset({
    IocType.INDIAN_PHONE,
    IocType.TELEGRAM_HANDLE,
    IocType.EMAIL,
})


class IocScope(str, Enum):
    """
    Where an indicator points, which decides whether it is worth pursuing.

    An IOC list that mixes `schemas.android.com` (in every APK ever built),
    `127.0.0.1` (points nowhere) and a live C2 domain is not an IOC list — the
    investigator has to re-do the triage the tool was supposed to do.
    """

    EXTERNAL = "external"                # A real remote destination: pursue it
    INTERNAL = "internal"                # Private, loopback, link-local, reserved
    KNOWN_INFRASTRUCTURE = "known_infrastructure"   # Platform/SDK/standards noise


@dataclass(frozen=True, slots=True)
class Indicator:
    """One deduplicated indicator with the evidence supporting it."""

    value: str
    ioc_type: IocType
    scope: IocScope
    confidence: ConfidenceLevel

    # Defanged rendering (hxxp://, [.]) for reports, emails and tickets, so an
    # investigator's own tooling cannot resolve or open a live malicious host
    # by accident.
    defanged: str

    occurrences: int = 1
    first_offset: int | None = None

    # Why this indicator matters, in plain language, for the report.
    note: str = ""

    # Parent indicator (a domain or IP derived from a URL, for instance).
    derived_from: str | None = None

    @property
    def is_actionable(self) -> bool:
        """True when this is a destination an investigator can act on."""
        return self.scope is IocScope.EXTERNAL and self.ioc_type in (
            NETWORK_IOC_TYPES | PAYMENT_IOC_TYPES | CONTACT_IOC_TYPES
        )


class IocExtractionStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class IocExtractionResult:
    """Complete indicator inventory for one analyzed sample."""

    source: str
    status: IocExtractionStatus
    indicators: tuple[Indicator, ...] = ()
    error: str | None = None

    # Counts by type, retained even when the indicator list is truncated for
    # reporting, so "3 of 412 domains shown" is expressible.
    counts_by_type: dict[str, int] = field(default_factory=dict)

    @property
    def actionable(self) -> tuple[Indicator, ...]:
        """External network and payment destinations, highest confidence first."""
        order = {ConfidenceLevel.HIGH: 0, ConfidenceLevel.MEDIUM: 1,
                 ConfidenceLevel.LOW: 2, ConfidenceLevel.NONE: 3}
        return tuple(sorted(
            (i for i in self.indicators if i.is_actionable),
            key=lambda i: (order.get(i.confidence, 9), -i.occurrences, i.value),
        ))

    def by_type(self, ioc_type: IocType) -> tuple[Indicator, ...]:
        return tuple(i for i in self.indicators if i.ioc_type is ioc_type)
