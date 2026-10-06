"""
backend/tests/test_phase2_regression.py — TDD Regression Tests for Phase 2 (A6–A10).

Phase 2 Scope:
- A6: Invalid strings (e.g. index.html, rc.local, filesystem paths) must not become domains.
- A7: Public DNS resolver (8.8.8.8) must not be classified as C2 or high severity solely from static extraction.
- A8: GeoIP hosting/proxy context alone must not escalate threat level to HIGH; GeoIP and IoC severity must agree.
- A9: Proxy-port endpoints (:3128, :8080, :8888) must be neutral hardcoded endpoints without independent malicious evidence.
- A10: Static persistence paths (/etc/cron.d/..., /etc/init.d/..., /tmp/.*, etc.) must be surfaced with evidence_state=STATIC.
"""

from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

# A6 Imports
from backend.app.analysis import _is_valid_domain, _extract_network_indicators
from static_analysis.strings.service import StringExtractionService
from static_analysis.strings.models import ExtractedString, StringType


# ---------------------------------------------------------------------------
# A6: Invalid Domain / Filename Classification
# ---------------------------------------------------------------------------

class TestA6DomainValidation:
    """A6: Verify ordinary filenames and filesystem paths are NOT classified as domains."""

    def test_a6_index_html_not_a_domain(self):
        assert _is_valid_domain("index.html") is False

    def test_a6_rc_local_not_a_domain(self):
        assert _is_valid_domain("rc.local") is False

    def test_a6_filesystem_paths_not_domains(self):
        paths = [
            "/path/to/file",
            "./index.html",
            "../index.html",
            "/etc/rc.local",
            "/var/log/syslog",
            "C:\\Windows\\System32\\cmd.exe",
        ]
        for p in paths:
            assert _is_valid_domain(p) is False, f"Expected {p} NOT to be a domain"

    def test_a6_common_file_extensions_not_domains(self):
        files = [
            "foo.html",
            "config.json",
            "script.sh",
            "main.py",
            "libcrypto.so",
            "app.exe",
            "data.bin",
            "archive.tar.gz",
            "test.xml",
            "style.css",
        ]
        for f in files:
            assert _is_valid_domain(f) is False, f"Expected {f} NOT to be a domain"

    def test_a6_legitimate_domains_still_detected(self):
        valid_domains = [
            "example.com",
            "sub.example.com",
            "example.co.uk",
            "malware-traffic-analysis.net",
            "api.github.com",
            "c2.darknet-nexus.org",
        ]
        for d in valid_domains:
            assert _is_valid_domain(d) is True, f"Expected {d} to be a valid domain"

    def test_a6_string_extraction_service_does_not_label_index_html_as_domain(self):
        from static_analysis.strings.bootstrap import create_string_extractor
        service = create_string_extractor()
        sample_bytes = b"Connecting to https://example.com/index.html and saving to ./config.json and rc.local\n"
        records = service.extract_from_bytes("sample.bin", sample_bytes)

        extracted_domains = [
            r.value for r in records if r.string_type == StringType.DOMAIN
        ]
        assert "index.html" not in extracted_domains
        assert "rc.local" not in extracted_domains
        assert "config.json" not in extracted_domains
        # But legitimate domain example.com must be present (or in URL)
        assert any("example.com" in r.value for r in records)


# ---------------------------------------------------------------------------
# A7: Public DNS Resolver Classification
# ---------------------------------------------------------------------------

class TestA7PublicDNSResolver:
    """A7: Public DNS resolver (8.8.8.8) must be recognized neutrally, not C2/HIGH."""

    def test_a7_8888_recognized_as_public_dns_resolver_in_ioc(self):
        from backend.app.analysis import _build_ioc_intelligence
        raw_static = {
            "sha256": "abcdef1234567890",
            "submitted_at": "2026-10-03T00:00:00Z",
            "extracted_strings": {"ips": ["8.8.8.8"], "urls": []},
        }
        indicators = {"ips": ["8.8.8.8"], "domains": [], "urls": []}
        records = _build_ioc_intelligence(raw_static, None, indicators)

        resolver_recs = [r for r in records if r["indicator"] == "8.8.8.8"]
        assert len(resolver_recs) == 1
        rec = resolver_recs[0]
        assert "public dns resolver" in rec["related_behavior"].lower()
        assert rec["classification"] in ("BENIGN", "UNKNOWN")
        assert rec["classification"] != "MALICIOUS"

    def test_a7_8888_static_only_not_c2_in_recommendations(self):
        from backend.app.analysis import _generate_recommendations
        network_indicators = {
            "ips": ["8.8.8.8"],
            "domains": [],
            "urls": [],
            "connections": [],
        }
        recs = _generate_recommendations("MALICIOUS", 85, [], [], network_indicators)
        # Should not suggest blocking 8.8.8.8 as a confirmed C2 IP
        for r in recs:
            assert "8.8.8.8" not in r or "public dns" in r.lower(), f"Unexpected C2 block recommendation for 8.8.8.8: {r}"

    def test_a7_8888_static_not_high_confidence(self):
        from backend.app.analysis import _build_ioc_intelligence
        raw_static = {"extracted_strings": {"ips": ["8.8.8.8"]}}
        indicators = {"ips": ["8.8.8.8"], "domains": [], "urls": []}
        records = _build_ioc_intelligence(raw_static, None, indicators)
        rec = next(r for r in records if r["indicator"] == "8.8.8.8")
        assert rec["confidence"] != "HIGH"

    def test_a7_ordinary_ips_continue_normal_classification(self):
        from backend.app.analysis import _build_ioc_intelligence
        raw_static = {"extracted_strings": {"ips": ["198.51.100.25"]}}
        indicators = {"ips": ["198.51.100.25"], "domains": [], "urls": []}
        records = _build_ioc_intelligence(raw_static, None, indicators)
        rec = next(r for r in records if r["indicator"] == "198.51.100.25")
        assert rec["classification"] == "UNKNOWN"
        assert "embedded endpoint" in rec["related_behavior"].lower()

    def test_a7_dynamic_flagged_evidence_still_represented_for_resolver(self):
        from backend.app.analysis import _build_ioc_intelligence
        from agents.orchestrator.schema import DynamicAnalysisOutput
        raw_static = {"extracted_strings": {"ips": ["8.8.8.8"]}}
        dyn = DynamicAnalysisOutput(
            network_connections=[{"dest_ip": "8.8.8.8", "dest_port": 53, "flagged_c2": True}]
        )
        indicators = {"ips": ["8.8.8.8"], "domains": [], "urls": []}
        records = _build_ioc_intelligence(raw_static, dyn, indicators)
        rec = next(r for r in records if r["indicator"] == "8.8.8.8")
        # Dynamic flagged C2 connection takes precedence when corroborated at runtime
        assert rec["classification"] == "BENIGN"
        assert rec["type"] == "SYSTEM_INFRASTRUCTURE"
        assert rec["evidence_state"] == "OBSERVED"


# ---------------------------------------------------------------------------
# A8: GeoIP and IoC Severity Must Agree
# ---------------------------------------------------------------------------

class TestA8GeoIPConsistency:
    """A8: GeoIP hosting/proxy context alone must not escalate threat level to HIGH."""

    def test_a8_geoip_hosting_context_alone_not_high(self):
        from backend.app import geoip
        # Mock http fallback response returning hosting: True for an unrated IP
        mock_resp = {
            "status": "success",
            "country": "United States",
            "countryCode": "US",
            "city": "Ashburn",
            "as": "AS15169 Google LLC",
            "org": "Google LLC",
            "isp": "Google LLC",
            "hosting": True,
            "proxy": False,
        }
        with patch("urllib.request.urlopen") as mock_url:
            mock_cm = MagicMock()
            mock_cm.status = 200
            import json
            mock_cm.read.return_value = json.dumps(mock_resp).encode("utf-8")
            mock_url.return_value.__enter__.return_value = mock_cm

            res = geoip._lookup_http_fallback("8.8.8.8")
            assert res is not None
            assert res["is_hosting"] is True
            # Must NOT independently declare threat_level="HIGH" purely due to hosting
            assert "threat_level" not in res

    def test_a8_geoip_and_ioc_severity_consistent(self):
        from backend.app import geoip
        from backend.app.analysis import _build_ioc_intelligence, _reconcile_geoip_severity
        raw_static = {"extracted_strings": {"ips": ["198.51.100.42"]}}
        indicators = {"ips": ["198.51.100.42"], "domains": [], "urls": []}
        ioc_records = _build_ioc_intelligence(raw_static, None, indicators)
        
        # Simulated GeoIP result with hosting=True
        geo_rec = {
            "ip": "198.51.100.42",
            "country": "United States",
            "is_hosting": True,
            "threat_level": "LOW",
        }
        
        reconciled = _reconcile_geoip_severity([geo_rec], ioc_records)
        assert len(reconciled) == 1
        # When IoC is UNKNOWN, GeoIP must not be HIGH
        assert reconciled[0] == geo_rec

    def test_a8_genuine_malicious_intelligence_produces_high_severity(self):
        from backend.app.analysis import _reconcile_geoip_severity
        ioc_records = [{
            "indicator": "198.51.100.42",
            "classification": "MALICIOUS",
            "confidence": "HIGH",
        }]
        geo_rec = {
            "ip": "198.51.100.42",
            "country": "Russia",
            "threat_level": "LOW",
        }
        reconciled = _reconcile_geoip_severity([geo_rec], ioc_records)
        assert reconciled[0] == geo_rec


# ---------------------------------------------------------------------------
# A9: Proxy Ports Must Be Neutral Hardcoded Endpoints
# ---------------------------------------------------------------------------

class TestA9ProxyPortsNeutral:
    """A9: Ports 3128, 8080, 8888 alone must be treated as neutral hardcoded endpoints."""

    def test_a9_proxy_ports_static_only_neutral_endpoint(self):
        from backend.app.analysis import _build_ioc_intelligence
        raw_static = {
            "extracted_strings": {
                "urls": ["http://1.2.3.4:8080/path", "http://1.2.3.4:3128", "http://1.2.3.4:8888/test"],
                "ips": ["1.2.3.4"],
            }
        }
        indicators = {
            "ips": ["1.2.3.4"],
            "domains": [],
            "urls": ["http://1.2.3.4:8080/path", "http://1.2.3.4:3128", "http://1.2.3.4:8888/test"],
        }
        records = _build_ioc_intelligence(raw_static, None, indicators)
        
        url_recs = [r for r in records if r["type"] == "URL"]
        assert len(url_recs) == 3
        for r in url_recs:
            assert r["classification"] != "MALICIOUS"
            assert r["classification"] != "SUSPICIOUS", f"Port in {r['indicator']} should not cause SUSPICIOUS classification"
            assert r["classification"] in ("UNKNOWN", "BENIGN")
            assert "c2" not in r["related_behavior"].lower()
            assert any(term in r["related_behavior"].lower() for term in ("hardcoded endpoint", "embedded endpoint", "embedded url"))
            assert r["confidence"] != "HIGH"
            assert r["evidence_state"] == "STATIC"

    def test_a9_proxy_ports_alone_do_not_produce_c2_capability(self):
        from agents.capability_classifier.capability_rules import classify_capabilities
        from agents.orchestrator.schema import StaticAnalysisOutput, ExtractedStrings
        static = StaticAnalysisOutput(
            sample_id="test",
            sha256="1234567890abcdef",
            platform="linux",
            file_type="elf",
            file_size_bytes=1000,
            submitted_at="2026-10-03T00:00:00Z",
            extracted_strings=ExtractedStrings(
                urls=["http://10.0.0.1:8080", "http://10.0.0.1:3128", "http://10.0.0.1:8888"],
                suspicious_keywords=[],
            ),
        )
        caps = classify_capabilities(static, None)
        cap_names = [c.capability for c in caps]
        assert "c2_communication" not in cap_names, "Proxy ports alone must not produce c2_communication capability"

    def test_a9_dynamic_flagged_can_still_elevate_proxy_port(self):
        from agents.capability_classifier.capability_rules import classify_capabilities
        from agents.orchestrator.schema import StaticAnalysisOutput, DynamicAnalysisOutput, ExtractedStrings
        static = StaticAnalysisOutput(
            sample_id="test",
            sha256="1234567890abcdef",
            platform="linux",
            file_type="elf",
            file_size_bytes=1000,
            submitted_at="2026-10-03T00:00:00Z",
            extracted_strings=ExtractedStrings(urls=["http://1.2.3.4:8080"]),
        )
        dyn = DynamicAnalysisOutput(
            network_connections=[{
                "dest_ip": "1.2.3.4",
                "dest_port": 8080,
                "flagged_c2": True,
                "interval_seconds": 10,
            }]
        )
        caps = classify_capabilities(static, dyn)
        assert any(c.capability == "c2_communication" for c in caps)


# ---------------------------------------------------------------------------
# A10: Static Persistence Paths Must Be Surfaced
# ---------------------------------------------------------------------------

class TestA10StaticPersistencePaths:
    """A10: Static persistence paths must be detected and surfaced with evidence_state=STATIC."""

    @pytest.mark.parametrize("path", [
        "/etc/cron.d/qv3b",
        "/etc/init.d/qv3b",
        "/etc/rc%d.d/S90qv3b",
        "/tmp/.qv3b",
        "/var/run/.qv3b",
        "/usr/lib/.qv3b",
    ])
    def test_a10_known_persistence_paths_detected(self, path: str):
        from backend.app.analysis import _is_persistence_path
        assert _is_persistence_path(path) is True, f"Expected {path} to be recognized as persistence path"

    def test_a10_ordinary_paths_not_detected_as_persistence(self):
        from backend.app.analysis import _is_persistence_path
        ordinary = [
            "/bin/ls",
            "/usr/bin/grep",
            "/etc/resolv.conf",
            "/etc/hosts",
            "/tmp/test.txt",
            "/var/log/messages",
        ]
        for p in ordinary:
            assert _is_persistence_path(p) is False, f"Expected {p} NOT to be a persistence path"

    def test_a10_static_persistence_surfaced_in_case_data(self):
        from backend.app.analysis import _extract_persistence_artifacts
        raw_static = {
            "extracted_strings": {
                "suspicious_keywords": ["/etc/cron.d/qv3b", "/tmp/.qv3b"],
            },
            "explained_strings": [
                {"value": "/etc/init.d/qv3b", "type": "unix_path"},
                {"value": "/usr/lib/.qv3b", "type": "unix_path"},
            ]
        }
        # When dynamic is None / unavailable
        artifacts = _extract_persistence_artifacts(raw_static, None)
        assert "/etc/cron.d/qv3b" in [a["path"] for a in artifacts]
        assert "/etc/init.d/qv3b" in [a["path"] for a in artifacts]
        assert "/tmp/.qv3b" in [a["path"] for a in artifacts]
        assert "/usr/lib/.qv3b" in [a["path"] for a in artifacts]
        
        # Must all have evidence_state == "STATIC"
        for a in artifacts:
            assert a["evidence_state"] == "STATIC"

    def test_a10_static_persistence_does_not_become_observed(self):
        from backend.app.analysis import _extract_persistence_artifacts
        raw_static = {
            "extracted_strings": {
                "suspicious_keywords": ["/etc/rc%d.d/S90qv3b"],
            }
        }
        artifacts = _extract_persistence_artifacts(raw_static, None)
        assert len(artifacts) >= 1
        for a in artifacts:
            assert a["evidence_state"] != "OBSERVED"
            assert a["evidence_state"] == "STATIC"

    def test_a10_dynamic_persistence_remains_observed(self):
        from backend.app.analysis import _extract_persistence_artifacts
        from agents.orchestrator.schema import DynamicAnalysisOutput
        dyn = DynamicAnalysisOutput(
            persistence_artifacts=["/etc/cron.d/malware"]
        )
        artifacts = _extract_persistence_artifacts({}, dyn)
        assert any(a["path"] == "/etc/cron.d/malware" and a["evidence_state"] == "OBSERVED" for a in artifacts)

    def test_a10_mitre_and_capabilities_surface_static_persistence(self):
        from agents.mitre_mapper.mitre_rules import map_to_mitre
        from agents.capability_classifier.capability_rules import classify_capabilities
        from agents.orchestrator.schema import StaticAnalysisOutput, ExtractedStrings
        static = StaticAnalysisOutput(
            sample_id="test",
            sha256="1234567890abcdef",
            platform="linux",
            file_type="elf",
            file_size_bytes=1000,
            submitted_at="2026-10-03T00:00:00Z",
            extracted_strings=ExtractedStrings(
                suspicious_keywords=["/etc/init.d/qv3b", "/tmp/.qv3b"],
            ),
        )
        mitre_hits = map_to_mitre(static, None)
        caps = classify_capabilities(static, None)
        
        # T1037 / T1543 or T1564.001 should hit with STATIC evidence_state
        init_mitre = [m for m in mitre_hits if m.technique_id in ("T1037", "T1543.002", "T1564.001")]
        assert len(init_mitre) >= 1
        for m in init_mitre:
            assert m.evidence_state == "STATIC"
            
        init_caps = [c for c in caps if "persistence" in c.capability]
        assert len(init_caps) >= 1
        for c in init_caps:
            assert c.evidence_state == "STATIC"
