"""
tests/test_ioc_extraction.py — Indicator extraction.

Most of these are rejection tests. Pulling URL-shaped strings out of a binary
is easy; the module earns its place by *not* reporting `libssl.so`,
`index.php`, `127.0.0.1` and `schemas.android.com` as leads an investigator
should chase. Every false positive here is a minute of someone's time in a
real case, so the noise cases are tested as carefully as the detections.
"""

from __future__ import annotations

import pytest

from static_analysis.detection.models import ConfidenceLevel
from static_analysis.ioc import (
    IocScope,
    IocType,
    create_ioc_extractor,
    defang,
    has_eip55_checksum,
    is_known_infrastructure,
    is_plausible_host,
    is_valid_bitcoin_address,
)
from static_analysis.ioc.keccak import keccak_256_hex
from static_analysis.strings.models import ExtractedString, StringType


def make_string(value: str, offset: int = 0) -> ExtractedString:
    return ExtractedString(
        value=value,
        string_type=StringType.ASCII,
        offset=offset,
        length=len(value),
        encoding="ascii",
    )


def extract(*values: str):
    return create_ioc_extractor().extract("sample", [make_string(v, i * 100)
                                                     for i, v in enumerate(values)])


def values_of(result, ioc_type: IocType) -> set[str]:
    return {indicator.value for indicator in result.by_type(ioc_type)}


# ============================================================================
# Keccak-256 — the primitive EIP-55 depends on
# ============================================================================

class TestKeccak:
    """
    Verified against the published Keccak-256 vectors.

    `hashlib.sha3_256` is *not* this function — the padding differs — so an
    untested implementation here would silently fail every real address.
    """

    @pytest.mark.parametrize("data,expected", [
        (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
        (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
        (b"The quick brown fox jumps over the lazy dog",
         "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"),
    ])
    def test_known_vectors(self, data, expected):
        assert keccak_256_hex(data) == expected

    def test_multi_block_input(self):
        """Inputs longer than the 136-byte rate must absorb across blocks."""
        assert len(keccak_256_hex(b"a" * 500)) == 64


# ============================================================================
# Host validation — where most of the noise is removed
# ============================================================================

class TestHostValidation:

    @pytest.mark.parametrize("host", [
        "c2.badactor.in", "pay.gov.in", "example.com", "a.b.c.co.uk", "scam-site.xyz",
    ])
    def test_real_hosts_accepted(self, host):
        assert is_plausible_host(host)

    @pytest.mark.parametrize("filename", [
        "libssl.so",            # every ELF and APK carries several
        "System.Data.dll",
        "index.php",
        "config.properties",
        "classes.dex",
        "styles.css",
        "app.js",
        "readme.md",
        "1.2.3.4.5",            # version string
        "..",
        "a.b",                  # two-character TLD that is not a real one
    ])
    def test_filename_noise_rejected(self, filename):
        assert not is_plausible_host(filename)

    def test_platform_hosts_are_recognized(self):
        assert is_known_infrastructure("schemas.android.com")
        assert is_known_infrastructure("www.w3.org")
        assert not is_known_infrastructure("c2.badactor.in")


# ============================================================================
# Payment indicators
# ============================================================================

class TestPaymentIndicators:

    def test_valid_bitcoin_address_accepted(self):
        assert is_valid_bitcoin_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

    def test_corrupted_bitcoin_address_rejected(self):
        """One changed character breaks the checksum — that is the whole point."""
        assert not is_valid_bitcoin_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfaa")

    def test_random_base58_run_rejected(self):
        """
        A base58-shaped identifier is not an address.

        Without the checksum this pattern matches build IDs and hashes all
        over a normal binary; with it, they fail.
        """
        assert not is_valid_bitcoin_address("1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")

    def test_p2sh_address_accepted(self):
        assert is_valid_bitcoin_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")

    def test_bech32_address_accepted(self):
        assert is_valid_bitcoin_address("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")

    @pytest.mark.parametrize("body,expected", [
        ("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", True),
        ("fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", True),
        ("52908400098527886E0F7030069857D2E4169EE7", True),
        ("5aAeb6053F3E94C9b9A09f33669435E7Ef1Beaed", False),   # one case flipped
        ("de709f2102306220921060314715629080e2fb77", False),   # unchecksummed form
    ])
    def test_eip55_checksum(self, body, expected):
        assert has_eip55_checksum(body) is expected

    def test_unchecksummed_ethereum_is_low_confidence_not_dropped(self):
        result = extract("wallet 0xde709f2102306220921060314715629080e2fb77")
        indicator = next(iter(result.by_type(IocType.ETHEREUM_ADDRESS)))
        assert indicator.confidence is ConfidenceLevel.LOW

    def test_upi_id_extracted_with_handle_validation(self):
        result = extract("payee scamcollect@okhdfcbank amount 4999")
        assert "scamcollect@okhdfcbank" in values_of(result, IocType.UPI_ID)

    def test_ordinary_email_is_not_a_upi_id(self):
        result = extract("support@example.com")
        assert not result.by_type(IocType.UPI_ID)
        assert "support@example.com" in values_of(result, IocType.EMAIL)


# ============================================================================
# Network indicators and scoping
# ============================================================================

class TestNetworkIndicators:

    def test_url_yields_both_url_and_host(self):
        result = extract("https://c2.badactor.in/gate.php?id=1")
        assert "https://c2.badactor.in/gate.php?id=1" in values_of(result, IocType.URL)
        assert "c2.badactor.in" in values_of(result, IocType.DOMAIN)

    def test_private_address_is_internal_not_actionable(self):
        result = extract("server 192.168.1.50")
        indicator = next(iter(result.by_type(IocType.IPV4)))
        assert indicator.scope is IocScope.INTERNAL
        assert not indicator.is_actionable

    def test_public_address_is_actionable(self):
        result = extract("connect 45.13.223.9")
        indicator = next(iter(result.by_type(IocType.IPV4)))
        assert indicator.scope is IocScope.EXTERNAL
        assert indicator.is_actionable

    @pytest.mark.parametrize("oid", [
        "1.3.6.1",
        "1.3.6.1.4.1",
        "1.2.840.113549",
        "OID: 1.3.6.1",
    ])
    def test_asn1_oid_rejected_as_ipv4(self, oid):
        result = extract(f"Certificate extension {oid}")
        assert not result.by_type(IocType.IPV4)

    @pytest.mark.parametrize("ip_noise", [
        "0.0.0.0",
        "0.1.2.3",
        "255.255.255.255",
    ])
    def test_unspecified_and_broadcast_ips_rejected(self, ip_noise):
        result = extract(f"listen address {ip_noise}")
        assert not result.by_type(IocType.IPV4)

    @pytest.mark.parametrize("garbled_url", [
        ">httpu",
        ":httpu\"",
        "*http2.TH9",
        "httponlyL",
        "9http",
        "8httpu3A",
        "http/1.1H9",
        "http://",
        "http://a",
    ])
    def test_garbled_urls_rejected(self, garbled_url):
        result = extract(garbled_url)
        assert not result.by_type(IocType.URL)

    def test_platform_host_is_scoped_out_of_the_actionable_list(self):
        result = extract("http://schemas.android.com/apk/res/android")
        assert result.actionable == ()

    def test_onion_address_detected(self):
        result = extract("http://expyuzz4wqqyqhjn.onion/panel")
        assert result.by_type(IocType.ONION_ADDRESS)

    def test_telegram_bot_token_is_captured(self):
        token = "123456789:AAFdsjklfdsjklfdsjklfdsjklfdsjkl123"
        result = extract(f"api.telegram.org/bot{token}/sendMessage")
        assert token in values_of(result, IocType.TELEGRAM_HANDLE)

    def test_bare_telegram_host_is_not_reported_as_a_lead(self):
        """`t.me` alone says only 'Telegram was used'; the handle is the lead."""
        result = extract("https://t.me/loanrecovery")
        assert "t.me/loanrecovery" in values_of(result, IocType.TELEGRAM_HANDLE)
        domain = next(i for i in result.by_type(IocType.DOMAIN) if i.value == "t.me")
        assert domain.scope is IocScope.KNOWN_INFRASTRUCTURE


# ============================================================================
# Phone numbers — a high-noise pattern held to a context requirement
# ============================================================================

class TestPhoneNumbers:

    def test_country_coded_number_accepted(self):
        result = extract("operator +919876543210")
        assert "+919876543210" in values_of(result, IocType.INDIAN_PHONE)

    def test_bare_ten_digits_without_context_rejected(self):
        """A ten-digit run is a timestamp or an ID far more often than a number."""
        result = extract("build 9876543210 complete")
        assert not result.by_type(IocType.INDIAN_PHONE)

    def test_bare_ten_digits_with_phone_context_accepted(self):
        result = extract("contact mobile 9876543210")
        assert "+919876543210" in values_of(result, IocType.INDIAN_PHONE)


# ============================================================================
# Aggregation and presentation
# ============================================================================

class TestAggregation:

    def test_repeats_are_counted_not_duplicated(self):
        result = extract(
            "https://c2.badactor.in/a", "https://c2.badactor.in/a", "https://c2.badactor.in/a"
        )
        urls = result.by_type(IocType.URL)
        assert len(urls) == 1
        assert urls[0].occurrences == 3

    def test_defanging_makes_indicators_unclickable(self):
        assert defang("https://evil.test/x", IocType.URL) == "hxxps://evil[.]test/x"
        assert defang("1.2.3.4", IocType.IPV4) == "1[.]2[.]3[.]4"
        assert defang("a@b.com", IocType.EMAIL) == "a[at]b[.]com"

    def test_counts_by_type_reported(self):
        result = extract("https://a.badactor.in/x", "45.13.223.9")
        assert result.counts_by_type[IocType.URL.value] == 1
        assert result.counts_by_type[IocType.IPV4.value] == 1

    def test_actionable_excludes_paths_and_registry_keys(self):
        result = extract(
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
            r"C:\Users\Public\payload.exe",
        )
        assert result.indicators
        assert result.actionable == ()

    def test_extraction_never_raises_on_hostile_input(self):
        result = extract("\x00" * 10, "@@@@", "http://", "0x", "....", "@ok")
        assert result.status.value == "completed"
