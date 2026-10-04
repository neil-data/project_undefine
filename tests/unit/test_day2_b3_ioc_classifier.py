"""
Unit tests for Day 2 — B3 IoC Classifier & Allowlists.
Asserts proper classification, glued hex stripping, offline PSL validation,
Go symbol / base64 / system library rejections, and whitelist integrity.
"""
import pytest

from packages.shared.ioc_classifier import IoCClassifier, strip_glued_hex, validate_domain
from packages.shared.allowlist import (
    PUBLIC_DNS_RESOLVERS,
    LEGITIMATE_BENIGN_DOMAINS,
    SYSTEMD_SUFFIXES,
    COMMON_FILE_EXTENSIONS,
    GO_PACKAGE_PREFIXES,
    SYSTEM_LIBRARIES,
)


class TestGluedHexStripping:
    def test_strips_leading_and_trailing_hex(self):
        assert strip_glued_hex("0x4ahttp://example.com/payload") == "http://example.com/payload"
        assert strip_glued_hex("http://example.com/payload0x2f") == "http://example.com/payload"
        assert strip_glued_hex("0xdeadbeefhttps://test.org0x12") == "https://test.org"

    def test_leaves_clean_url_intact(self):
        url = "https://malware.site/c2.php?id=12"
        assert strip_glued_hex(url) == url


class TestDomainValidation:
    def test_valid_domains_pass(self):
        valid, reason = validate_domain("malware-c2.com")
        assert valid, reason

        valid, reason = validate_domain("sub.domain.co.uk")
        assert valid, reason

    def test_short_sld_rejected(self):
        valid, reason = validate_domain("jC.bn")
        assert not valid
        assert "SLD" in reason

    def test_short_domains_allowed_only_with_observed_dns_or_url_context(self):
        assert not validate_domain("t.co")[0]
        assert not validate_domain("x.com")[0]
        assert IoCClassifier.classify("t.co", hint_type="DOMAIN", is_dynamic_observed=True).type == "DOMAIN"
        assert IoCClassifier.classify("x.com", hint_type="DOMAIN", is_dynamic_observed=True).type == "DOMAIN"
        assert IoCClassifier.classify("https://t.co/a", hint_type="URL").type == "URL"
        assert IoCClassifier.classify("https://x.com/a", hint_type="URL").type == "URL"

        valid, reason = validate_domain("XB.kr")
        assert not valid
        assert "SLD" in reason

    def test_mixed_case_tld_rejected(self):
        valid, reason = validate_domain("QMrS.lg")
        assert not valid or "TLD" in reason or "SLD" in reason

    def test_file_extension_rejected_as_domain(self):
        for ext in [".dll", ".exe", ".so", ".sh", ".json", ".service"]:
            valid, reason = validate_domain(f"mycomponent{ext}")
            assert not valid
            assert "extension" in reason.lower() or "systemd" in reason.lower() or "not in public suffix" in reason.lower()


class TestIoCClassifier:
    def test_public_dns_resolvers_classified_as_system_infrastructure(self):
        for resolver in ["8.8.8.8", "1.1.1.1", "9.9.9.9"]:
            res = IoCClassifier.classify(resolver)
            assert res.type == "SYSTEM_INFRASTRUCTURE"
            assert "resolver" in res.intel_note.lower()
            assert res.confidence == "LOW"

    def test_benign_vendor_hosts_classified_as_benign(self):
        for host in ["go.dev", "microsoft.com", "android.googlesource.com"]:
            res = IoCClassifier.classify(host)
            assert res.type == "SYSTEM_INFRASTRUCTURE"
            assert res.classification == "BENIGN"

    def test_go_symbols_classified_as_symbol(self):
        for sym in ["fmt.pp", "go.shape", "io.pipe", "os.file", "runtime.main"]:
            res = IoCClassifier.classify(sym)
            assert res.type == "SYMBOL"

    def test_base64_blob_classified_as_base64_not_path(self):
        b64 = "aW52YWxpZGJhc2U2NGJsb2J0aGF0aXNsb25nZXJ0aGFuMzJjaGFycw=="
        res = IoCClassifier.classify(b64)
        assert res.type == "BASE64"
        assert res.type != "PATH"
        assert res.type != "FILE_PATH"

    def test_system_libraries_classified_as_library_not_install_path(self):
        for lib in ["kernel32.dll", "ntdll.dll", "user32.dll", "libc.so.6"]:
            res = IoCClassifier.classify(lib)
            assert res.type == "LIBRARY"
            assert res.type != "INSTALL_PATH"
            assert res.type != "PERSISTENCE_PATH"

    def test_valid_c2_url_classified_with_glued_hex_stripped(self):
        res = IoCClassifier.classify("0x4ahttp://evil-c2.com/gate.php0x00")
        assert res.type == "URL"
        assert res.indicator == "http://evil-c2.com/gate.php"

    def test_truncation_marker(self):
        truncated = "http://evil-domain.com/path/to/payload…(34 more)"
        res = IoCClassifier.classify(truncated)
        assert "…(" not in res.indicator
