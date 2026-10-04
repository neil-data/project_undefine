from packages.shared.ioc_classifier import IoCClassifier, validate_domain
from packages.shared.vendor_verdict_labels import is_clean_vendor_label, is_malicious_vendor_label, is_unrated_vendor_label


def test_vendor_label_mapping_covers_requested_categories():
    assert all(is_unrated_vendor_label(v) for v in ("not_supported", "unknown", None, "NotCategorized"))
    assert all(is_clean_vendor_label(v) for v in ("clean", "clean1", "Legit File", "No threats detected"))
    assert all(is_malicious_vendor_label(v) for v in ("malware2", "Mirai", "Amos", "KNOWN", "suspicious", "MacOS.Infostealer.X"))


def test_short_domain_requires_context_but_accepts_url_or_dns_context():
    assert not validate_domain("t.co")[0]
    assert not validate_domain("x.com")[0]
    assert not validate_domain("jC.bn")[0]
    assert IoCClassifier.classify("https://t.co/a", hint_type="URL").type == "URL"
    assert IoCClassifier.classify("t.co", hint_type="DOMAIN", is_dynamic_observed=True).type == "DOMAIN"
    assert IoCClassifier.classify("x.com", hint_type="DOMAIN", is_dynamic_observed=True).type == "DOMAIN"
