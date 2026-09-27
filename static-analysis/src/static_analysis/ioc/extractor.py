"""
Indicator extraction — turning extracted strings into a usable IOC list.

WHY THIS IS A MODULE AND NOT A LIST COMPREHENSION
-------------------------------------------------
Pulling anything that looks like a URL out of a binary is trivial and close to
useless. A mid-size APK yields several hundred "domains", nearly all of which
are `schemas.android.com`, `www.w3.org`, SDK endpoints and strings like
`libssl.so` that a naive domain regex is happy to accept. An investigator
handed that list has to redo the triage the tool was supposed to do, and the
one C2 domain that mattered is on line 214.

So extraction here is mostly *rejection*:

  • TLDs are validated against a real suffix set, which is what stops
    `libc.so`, `System.Data.dll` and `index.php` from being reported as hosts.
  • Bitcoin addresses are Base58Check-verified — the checksum turns a
    high-noise pattern into one with essentially no false positives.
  • Ethereum addresses without EIP-55 mixed-case checksums are downgraded, not
    dropped: every 40-hex string matches that pattern.
  • Private, loopback and reserved IPs are kept but scoped INTERNAL. They are
    real evidence (a hardcoded 10.x address says something) and they are not
    destinations anyone can pursue.
  • Platform and SDK hosts are scoped KNOWN_INFRASTRUCTURE rather than deleted,
    because "the sample talks to Firebase" is occasionally the finding.

Everything that survives is defanged for the report, deduplicated with an
occurrence count, and carries the reason it is worth an investigator's time.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
from collections import Counter
from collections.abc import Sequence
from urllib.parse import urlsplit

from static_analysis.detection.models import ConfidenceLevel
from static_analysis.ioc.contracts import IocExtractor
from static_analysis.ioc.keccak import keccak_256_hex
from static_analysis.ioc.models import (
    Indicator,
    IocExtractionResult,
    IocExtractionStatus,
    IocScope,
    IocType,
)
from static_analysis.strings.models import ExtractedString, StringType

_LOGGER = logging.getLogger(__name__)


# ============================================================================
# Vocabulary
# ============================================================================

# Deliberately a curated set rather than the full IANA list. The full list
# contains `.zip`, `.mov`, `.sh`, `.py` and `.dev`, which would readmit exactly
# the filename noise this set exists to exclude. Everything relevant to this
# problem statement is here, `.in` and `.co.in` included.
_VALID_TLDS = frozenset({
    # Generic
    "com", "net", "org", "info", "biz", "xyz", "top", "site", "online", "club",
    "pro", "app", "cloud", "digital", "live", "life", "world", "today", "store",
    "shop", "tech", "space", "website", "link", "click", "fun", "icu", "cfd",
    "vip", "cc", "tv", "io", "ai", "me", "co", "ly", "gg", "sbs", "buzz", "rest",
    # Sponsored / restricted
    "gov", "edu", "mil", "int",
    # India — the ccTLD set this problem statement lives in
    "in", "bharat", "asia",
    # Country codes seen in samples and infrastructure
    "uk", "us", "ca", "au", "de", "fr", "nl", "it", "es", "pl", "ru", "su",
    "cn", "jp", "kr", "hk", "sg", "my", "id", "ph", "th", "vn", "pk", "bd",
    "lk", "np", "ae", "sa", "il", "tr", "ir", "za", "ng", "ke", "br", "ar",
    "mx", "cl", "pe", "ch", "at", "be", "se", "no", "dk", "fi", "cz", "sk",
    # `.md` (Moldova) is deliberately absent: every repository ships README.md
    # and CHANGES.md, and Moldovan hosts are not what this engine is looking
    # for. The same reasoning keeps `.sh`, `.py`, `.zip` and `.dev` out.
    "hu", "ro", "bg", "gr", "pt", "ie", "nz", "ua", "by", "kz", "ge",
    "am", "az", "uz", "tj", "tm", "kg", "mn", "tw", "ml", "ga", "cf", "tk",
    "gq", "pw", "ws", "to", "nu", "cx", "im", "je", "gs", "st", "sc", "vc",
})

# Second-level suffixes that must not be mistaken for the registrable name.
_MULTI_LABEL_SUFFIXES = frozenset({
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in",
    "nic.in", "ac.in", "edu.in", "res.in", "mil.in",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "com.br", "com.cn", "com.sg", "com.my", "com.pk", "com.bd", "co.za",
})

# Hosts that appear in essentially every build of their platform. Scoped, not
# discarded — an APK talking to Firebase is sometimes the point.
_KNOWN_INFRASTRUCTURE_SUFFIXES = (
    "schemas.android.com", "android.com", "googleapis.com", "gstatic.com",
    "google.com", "googleusercontent.com", "googlesource.com", "goo.gl",
    "firebaseio.com", "firebase.google.com", "crashlytics.com", "doubleclick.net",
    "w3.org", "xmlpull.org", "apache.org", "eclipse.org", "gnu.org", "fsf.org",
    "oracle.com", "java.sun.com", "sun.com", "openjdk.org",
    "microsoft.com", "windows.com", "msdn.com", "live.com", "office.com",
    "mozilla.org", "openssl.org", "sqlite.org", "zlib.net", "python.org",
    "kotlinlang.org", "jetbrains.com", "github.com", "githubusercontent.com",
    "gradle.org", "maven.org", "sonatype.org", "bintray.com",
    "facebook.com", "fbcdn.net", "apple.com", "icloud.com", "verisign.com",
    "digicert.com", "letsencrypt.org", "globalsign.com", "entrust.net",
    "godaddy.com", "sectigo.com", "comodoca.com", "unicode.org", "iana.org",
    "ietf.org", "rfc-editor.org", "example.com", "localhost",
    # The bare messaging hosts. The channel or bot token extracted from them
    # is the indicator; `t.me` on its own says only "Telegram was used".
    "t.me", "telegram.me", "telegram.dog", "telegram.org",
)

# UPI handles. An email regex matches every one of these, so the handle set is
# what separates "payee@okhdfcbank" from an ordinary address — which matters
# because a UPI ID in a sample is where defrauded money actually lands.
_UPI_HANDLES = frozenset({
    "okhdfcbank", "okicici", "okaxis", "oksbi", "okbizaxis",
    "ybl", "ibl", "axl", "apl", "upi", "paytm", "ptyes", "ptsbi", "ptaxis",
    "hdfcbank", "icici", "axisbank", "sbi", "kotak", "yesbank", "indus",
    "airtel", "freecharge", "jupiteraxis", "fbl", "rbl", "idfcbank", "barodampay",
})

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Words whose presence makes a bare ten-digit number a phone number rather than
# a timestamp, an ID, or part of a hash.
_PHONE_CONTEXT_TERMS = ("phone", "mobile", "sms", "tel", "call", "whatsapp",
                        "contact", "otp", "msisdn", "number")


# ============================================================================
# Patterns
# ============================================================================

_URL_RE = re.compile(r"(?<![A-Za-z0-9_>:\*\\])(?:https?|ftps?)://[^\s\"'<>\\]{4,2048}", re.IGNORECASE)
_HOST_RE = re.compile(
    r"(?<![A-Za-z0-9.@-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})(?![A-Za-z0-9-])"
)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}")
_UPI_RE = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9][A-Za-z0-9._-]{1,63})@([A-Za-z]{2,20})(?![A-Za-z0-9.-])")
_ONION_RE = re.compile(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b", re.IGNORECASE)
_BTC_RE = re.compile(r"(?<![A-Za-z0-9])(bc1[023456789acdefghjklmnpqrstuvwxyz]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34})(?![A-Za-z0-9])")
_ETH_RE = re.compile(r"(?<![A-Za-z0-9])0x([0-9a-fA-F]{40})(?![0-9a-fA-F])")
_IN_PHONE_RE = re.compile(r"(?<![0-9])(?:\+91[\-\s]?|0091[\-\s]?|91)?([6-9][0-9]{9})(?![0-9])")
_TELEGRAM_LINK_RE = re.compile(r"(?:https?://)?(?:t\.me|telegram\.me|telegram\.dog)/([A-Za-z0-9_+]{3,64})", re.IGNORECASE)
_TELEGRAM_BOT_TOKEN_RE = re.compile(r"(?<![0-9])([0-9]{8,10}:[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])")
_REGISTRY_RE = re.compile(
    r"(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s\"'<>|*?]{3,512}", re.IGNORECASE
)
_WINDOWS_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|\\\\)[^\s\"'<>|?*]{3,512}")
_UNIX_PATH_RE = re.compile(r"/(?:usr|etc|var|tmp|opt|bin|sbin|home|root|data|system|sdcard|proc|dev)(?:/[^\s\"'<>|?*]{1,200})+")


# ============================================================================
# Validation helpers
# ============================================================================

def registrable_suffix(host: str) -> str:
    """Return the effective TLD of a hostname ('co.in' for 'pay.gov.co.in')."""
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 2:
        candidate = ".".join(labels[-2:])
        if candidate in _MULTI_LABEL_SUFFIXES:
            return candidate
    return labels[-1] if labels else ""


def is_plausible_host(host: str) -> bool:
    """
    True when a dotted string is really a hostname.

    This single check removes the overwhelming majority of IOC noise: every
    `.so`, `.dll`, `.dex`, `.php`, `.json` and `.properties` filename in the
    binary matches a domain regex and none of them are hosts.
    """
    if not host or len(host) > 253:
        return False
    host = host.strip(".").lower()
    labels = host.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        return False
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        return False

    suffix = registrable_suffix(host)
    tld = suffix.split(".")[-1]
    if tld not in _VALID_TLDS:
        return False
    # A hostname whose registrable label is numeric is an IP fragment or a
    # version string, not a domain.
    registrable_label = labels[-(suffix.count(".") + 2)] if len(labels) > suffix.count(".") + 1 else ""
    return not registrable_label.isdigit()


def is_known_infrastructure(host: str) -> bool:
    lowered = host.lower().strip(".")
    return any(
        lowered == suffix or lowered.endswith(f".{suffix}")
        for suffix in _KNOWN_INFRASTRUCTURE_SUFFIXES
    )


def _base58_decode(value: str) -> bytes | None:
    number = 0
    for character in value:
        index = _BASE58_ALPHABET.find(character)
        if index < 0:
            return None
        number = number * 58 + index
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    padding = len(value) - len(value.lstrip("1"))
    return b"\x00" * padding + raw


def is_valid_bitcoin_address(value: str) -> bool:
    """
    Base58Check-verify a legacy address; accept bech32 on structure alone.

    The four-byte checksum is what makes this indicator trustworthy: without
    it, `[13][A-Za-z0-9]{25,34}` matches build hashes and identifiers all over
    a normal binary.
    """
    if value.lower().startswith("bc1"):
        return 14 <= len(value) <= 74 and value[3:].islower()

    decoded = _base58_decode(value)
    if decoded is None or len(decoded) != 25:
        return False
    payload, checksum = decoded[:21], decoded[21:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return checksum == expected


def has_eip55_checksum(hex_body: str) -> bool:
    """
    True when a 40-hex Ethereum body carries a valid EIP-55 mixed-case checksum.

    Any 40-hex run matches the address pattern, so an all-lowercase match is
    reported at low confidence and a checksummed one at high.
    """
    # All-lowercase is the canonical *un*checksummed form, and a body with no
    # letters carries no case information to check. An all-uppercase body is
    # still checked: EIP-55 addresses whose letters all happen to fall on the
    # uppercase side are valid, and a random hex run will not survive the test.
    if hex_body == hex_body.lower() or not any(c.isalpha() for c in hex_body):
        return False
    # Keccak-256, not hashlib.sha3_256 — see ioc/keccak.py.
    digest = keccak_256_hex(hex_body.lower().encode("ascii"))
    for character, nibble in zip(hex_body, digest):
        if character.isalpha():
            expected_upper = int(nibble, 16) >= 8
            if character.isupper() != expected_upper:
                return False
    return True


def defang(value: str, ioc_type: IocType) -> str:
    """Render an indicator unclickable and unresolvable for report copy-paste."""
    if ioc_type in (IocType.URL, IocType.DOMAIN, IocType.IPV4, IocType.ONION_ADDRESS):
        return (
            value.replace("http://", "hxxp://")
            .replace("https://", "hxxps://")
            .replace("ftp://", "fxp://")
            .replace(".", "[.]")
        )
    if ioc_type is IocType.EMAIL:
        return value.replace("@", "[at]").replace(".", "[.]")
    return value


_OID_PREFIXES = ("1.3.6.1", "1.2.840", "2.16.840", "2.5.4", "0.9.2342", "1.3.14.3", "1.2.")

def _is_oid_pattern(value: str, text: str = "") -> bool:
    """Detect ASN.1 Object Identifier (OID) patterns and avoid misclassifying them as IPv4."""
    if any(value == prefix or value.startswith(prefix + ".") or value.startswith(prefix) for prefix in _OID_PREFIXES):
        return True
    if text:
        escaped = re.escape(value)
        # Preceded or followed by dots and numbers e.g. .1.3.6.1 or 1.3.6.1.4
        if re.search(r'(?:\d+\.)+' + escaped, text) or re.search(escaped + r'(?:\.\d+)+', text):
            return True
        # Preceded by OID keywords in context
        if re.search(r'(?i)\b(?:oid|urn:oid|asn1|mib|iso)\b[^\w\n]{0,15}' + escaped, text):
            return True
    return False


def _ip_scope(value: str, text: str = "") -> IocScope | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.version != 4:
        if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_unspecified or address.is_multicast:
            return IocScope.INTERNAL
        return IocScope.EXTERNAL

    # Strict IPv4 IOC validation:
    # 0.0.0.0 or 0.x.x.x is unspecified / non-routable, not a real target IOC
    if address.is_unspecified or value.startswith("0.") or value == "255.255.255.255":
        return None
    # Filter out ASN.1 OIDs (e.g. 1.3.6.1, 1.2.840...)
    if _is_oid_pattern(value, text):
        return None

    if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast:
        return IocScope.INTERNAL
    return IocScope.EXTERNAL


# ============================================================================
# Extractor
# ============================================================================

class StringIocExtractor(IocExtractor):
    """Derives, validates, scopes and deduplicates indicators from strings."""

    def __init__(self, max_indicators_per_type: int = 500) -> None:
        if max_indicators_per_type < 1:
            raise ValueError("max_indicators_per_type must be positive")
        self._cap = max_indicators_per_type

    def extract(self, source: str, strings: Sequence[ExtractedString]) -> IocExtractionResult:
        """Return the classified indicator inventory for one sample."""
        try:
            return self._extract(source, strings)
        except Exception as error:  # noqa: BLE001 - extraction must never fail an analysis
            _LOGGER.warning("IOC extraction failed for %s: %s", source, error, exc_info=True)
            return IocExtractionResult(
                source=source,
                status=IocExtractionStatus.FAILED,
                error=str(error),
            )

    # -- internals ---------------------------------------------------------

    def _extract(self, source: str, strings: Sequence[ExtractedString]) -> IocExtractionResult:
        # value -> [type, scope, confidence, note, derived_from, first_offset]
        found: dict[tuple[str, IocType], Indicator] = {}
        counts: Counter[tuple[str, IocType]] = Counter()

        for item in strings:
            text = item.value
            offset = item.offset
            lowered = text.lower()

            for url in _URL_RE.findall(text):
                self._add_url(found, counts, url.rstrip(".,);:'\""), offset)

            for match in _ONION_RE.finditer(text):
                self._record(found, counts, match.group(0).lower(), IocType.ONION_ADDRESS,
                             IocScope.EXTERNAL, ConfidenceLevel.HIGH, offset,
                             note="Tor hidden service — a destination chosen to be untraceable.")

            for match in _HOST_RE.finditer(text):
                self._add_host(found, counts, match.group(1), offset)

            for candidate in _EMAIL_RE.findall(text):
                self._add_email(found, counts, candidate, offset)

            for match in _UPI_RE.finditer(text):
                if match.group(2).lower() in _UPI_HANDLES:
                    self._record(found, counts, match.group(0).lower(), IocType.UPI_ID,
                                 IocScope.EXTERNAL, ConfidenceLevel.HIGH, offset,
                                 note="UPI collection ID — where defrauded payments land.")

            self._add_ips(found, counts, text, offset)

            for candidate in _BTC_RE.findall(text):
                if is_valid_bitcoin_address(candidate):
                    self._record(found, counts, candidate, IocType.BITCOIN_ADDRESS,
                                 IocScope.EXTERNAL, ConfidenceLevel.HIGH, offset,
                                 note="Bitcoin address (checksum verified) — ransom or payout destination.")

            for body in _ETH_RE.findall(text):
                checksummed = has_eip55_checksum(body)
                self._record(found, counts, f"0x{body}", IocType.ETHEREUM_ADDRESS,
                             IocScope.EXTERNAL,
                             ConfidenceLevel.HIGH if checksummed else ConfidenceLevel.LOW,
                             offset,
                             note=("Ethereum address (EIP-55 checksum valid)." if checksummed
                                   else "Ethereum-shaped value; no checksum, may be an unrelated hex blob."))

            for handle in _TELEGRAM_LINK_RE.findall(text):
                self._record(found, counts, f"t.me/{handle}", IocType.TELEGRAM_HANDLE,
                             IocScope.EXTERNAL, ConfidenceLevel.HIGH, offset,
                             note="Telegram channel or contact — common C2 and victim-contact channel.")

            for token in _TELEGRAM_BOT_TOKEN_RE.findall(text):
                self._record(found, counts, token, IocType.TELEGRAM_HANDLE,
                             IocScope.EXTERNAL, ConfidenceLevel.HIGH, offset,
                             note="Telegram bot token — grants direct access to the operator's own bot.")

            self._add_phones(found, counts, text, lowered, offset)

            for key in _REGISTRY_RE.findall(text):
                self._record(found, counts, key, IocType.REGISTRY_KEY,
                             IocScope.INTERNAL, ConfidenceLevel.MEDIUM, offset,
                             note="Registry path referenced by the sample.")

            for path in _WINDOWS_PATH_RE.findall(text):
                self._record(found, counts, path, IocType.WINDOWS_PATH,
                             IocScope.INTERNAL, ConfidenceLevel.LOW, offset,
                             note="Filesystem path referenced by the sample.")

            for path in _UNIX_PATH_RE.findall(text):
                self._record(found, counts, path, IocType.UNIX_PATH,
                             IocScope.INTERNAL, ConfidenceLevel.LOW, offset,
                             note="Filesystem path referenced by the sample.")

        indicators = self._finalize(found, counts)
        counts_by_type: Counter[str] = Counter(i.ioc_type.value for i in indicators)
        return IocExtractionResult(
            source=source,
            status=IocExtractionStatus.COMPLETED,
            indicators=indicators,
            counts_by_type=dict(counts_by_type),
        )

    def _add_url(self, found, counts, url: str, offset: int) -> None:
        url = url.strip().rstrip(".,);:'\"<>*")
        if len(url) < 10:
            return
        lowered = url.lower()
        if any(lowered.startswith(bad) for bad in ("http/1.", "http/2", "httponly", "httpu", "http-equiv")):
            return
        try:
            parts = urlsplit(url)
        except Exception:
            return
        if parts.scheme.lower() not in ("http", "https", "ftp", "ftps"):
            return
        host = parts.hostname or ""
        if not host or len(host) < 3 or any(c in host for c in ('"', "'", "<", ">", "*", "^", "\\", "{", "}", ":")):
            return
        # Host must have at least one dot or be localhost/onion or valid IP
        if "." not in host and host != "localhost":
            return
        if host.startswith(".") or host.endswith(".") or host.startswith("-") or host.endswith("-"):
            return

        scope = IocScope.EXTERNAL
        note = "Endpoint the sample is built to contact."
        if host.lower().endswith(".onion"):
            note = "Tor hidden-service URL — a destination chosen to be untraceable."
        elif _ip_scope(host) is IocScope.INTERNAL:
            scope = IocScope.INTERNAL
            note = "URL pointing at a private or loopback address."
        elif is_known_infrastructure(host):
            scope = IocScope.KNOWN_INFRASTRUCTURE
            note = "Platform or SDK endpoint present in most builds."
        elif not is_plausible_host(host) and _ip_scope(host) is None:
            return

        self._record(found, counts, url, IocType.URL, scope, ConfidenceLevel.HIGH, offset, note=note)

        # Surface the host separately: an investigator blocks a domain, not a
        # full URL with its query string.
        if _ip_scope(host) is not None:
            self._add_ips(found, counts, host, offset, derived_from=url)
        elif host.lower().endswith(".onion"):
            self._record(found, counts, host.lower(), IocType.ONION_ADDRESS, scope,
                         ConfidenceLevel.HIGH, offset, derived_from=url,
                         note="Tor hidden service extracted from a URL.")
        else:
            self._add_host(found, counts, host, offset, derived_from=url)

    def _add_host(self, found, counts, host: str, offset: int,
                  derived_from: str | None = None) -> None:
        host = host.strip(".").lower()
        if not is_plausible_host(host):
            return
        if is_known_infrastructure(host):
            self._record(found, counts, host, IocType.DOMAIN, IocScope.KNOWN_INFRASTRUCTURE,
                         ConfidenceLevel.HIGH, offset, derived_from=derived_from,
                         note="Platform or SDK host present in most builds of this format.")
            return
        self._record(found, counts, host, IocType.DOMAIN, IocScope.EXTERNAL,
                     ConfidenceLevel.MEDIUM if derived_from is None else ConfidenceLevel.HIGH,
                     offset, derived_from=derived_from,
                     note="Remote host referenced by the sample.")

    def _add_email(self, found, counts, candidate: str, offset: int) -> None:
        domain = candidate.rsplit("@", 1)[-1]
        if not is_plausible_host(domain):
            return
        scope = (IocScope.KNOWN_INFRASTRUCTURE if is_known_infrastructure(domain)
                 else IocScope.EXTERNAL)
        self._record(found, counts, candidate.lower(), IocType.EMAIL, scope,
                     ConfidenceLevel.MEDIUM, offset,
                     note="Address embedded in the sample — operator contact or exfiltration target.")

    def _add_ips(self, found, counts, text: str, offset: int,
                 derived_from: str | None = None) -> None:
        for candidate in re.findall(r"(?<![0-9.])((?:\d{1,3}\.){3}\d{1,3})(?![0-9.])", text):
            scope = _ip_scope(candidate, text)
            if scope is None:
                continue
            note = ("Hardcoded remote address — contacted directly, with no DNS lookup to observe."
                    if scope is IocScope.EXTERNAL
                    else "Private, loopback or reserved address; evidence, not a destination.")
            self._record(found, counts, candidate, IocType.IPV4, scope,
                         ConfidenceLevel.HIGH if scope is IocScope.EXTERNAL else ConfidenceLevel.LOW,
                         offset, derived_from=derived_from, note=note)

        for candidate in re.findall(r"(?<![0-9A-Fa-f:])((?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4})(?![0-9A-Fa-f:])", text):
            scope = _ip_scope(candidate)
            if scope is None:
                continue
            self._record(found, counts, candidate.lower(), IocType.IPV6, scope,
                         ConfidenceLevel.MEDIUM, offset, derived_from=derived_from,
                         note="IPv6 address referenced by the sample.")

    def _add_phones(self, found, counts, text: str, lowered: str, offset: int) -> None:
        has_context = any(term in lowered for term in _PHONE_CONTEXT_TERMS)
        for match in _IN_PHONE_RE.finditer(text):
            explicit_country_code = match.group(0) != match.group(1)
            if not explicit_country_code and not has_context:
                # A bare ten-digit run is a timestamp or an ID far more often
                # than it is a phone number.
                continue
            number = match.group(1)
            self._record(found, counts, f"+91{number}", IocType.INDIAN_PHONE,
                         IocScope.EXTERNAL,
                         ConfidenceLevel.HIGH if explicit_country_code else ConfidenceLevel.LOW,
                         offset,
                         note="Indian mobile number embedded in the sample — SMS destination or operator contact.")

    def _record(self, found: dict, counts: Counter, value: str, ioc_type: IocType,
                scope: IocScope, confidence: ConfidenceLevel, offset: int,
                note: str = "", derived_from: str | None = None) -> None:
        key = (value, ioc_type)
        counts[key] += 1
        if key in found:
            return
        found[key] = Indicator(
            value=value,
            ioc_type=ioc_type,
            scope=scope,
            confidence=confidence,
            defanged=defang(value, ioc_type),
            occurrences=1,
            first_offset=offset,
            note=note,
            derived_from=derived_from,
        )

    def _finalize(self, found: dict, counts: Counter) -> tuple[Indicator, ...]:
        by_type: dict[IocType, list[Indicator]] = {}
        for key, indicator in found.items():
            resolved = Indicator(
                value=indicator.value,
                ioc_type=indicator.ioc_type,
                scope=indicator.scope,
                confidence=indicator.confidence,
                defanged=indicator.defanged,
                occurrences=counts[key],
                first_offset=indicator.first_offset,
                note=indicator.note,
                derived_from=indicator.derived_from,
            )
            by_type.setdefault(indicator.ioc_type, []).append(resolved)

        ordered: list[Indicator] = []
        for ioc_type in IocType:
            bucket = by_type.get(ioc_type, [])
            # Most-repeated first: a host referenced forty times is the one the
            # sample is built around, not the one mentioned in a comment.
            bucket.sort(key=lambda item: (-item.occurrences, item.value))
            ordered.extend(bucket[: self._cap])
        return tuple(ordered)
