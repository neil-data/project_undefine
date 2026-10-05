"""Unit tests for MobSF-backed APK parser and fallback behavior."""
import zipfile
from io import BytesIO

from analysis.static.static_analysis.unified_parser import parse_binary, parser_evidence_hints


def test_apk_parser_uses_verified_mobsf_data():
    # Build minimal valid ZIP container for APK
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<fake-manifest>")
        zf.writestr("classes.dex", b"<fake-dex>")
    apk_bytes = buf.getvalue()

    mobsf_facts = {
        "package": "org.example.mobsf.app",
        "version": "2.1.0",
        "min_sdk": "24",
        "target_sdk": "34",
        "permissions": ["android.permission.INTERNET"],
        "dangerous_permissions": [],
        "exported_components": ["org.example.mobsf.app.MainActivity"],
        "certificate": {"is_debug_or_self_signed": False},
    }

    parsed = parse_binary(apk_bytes, format_hint="APK", mobsf_data=mobsf_facts)
    assert parsed["parse_status"] == "success"
    assert parsed["format"] == "APK"
    assert parsed["manifest"]["package_name"] == "org.example.mobsf.app"
    assert parsed["manifest"]["target_sdk"] == "34"
    assert "android.permission.INTERNET" in parsed["permissions"]

    hints = parser_evidence_hints(parsed)
    assert len(hints) == 1
    assert hints[0].source_type == "STATIC"
    assert hints[0].evidence_state == "STATIC"
    assert hints[0].confidence <= 0.5


def test_apk_parser_without_androguard_or_mobsf_returns_partial():
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("classes.dex", b"dex")
    apk_bytes = buf.getvalue()

    parsed = parse_binary(apk_bytes, format_hint="APK")
    assert parsed["parse_status"] == "partial"
    assert "androguard is not installed" in parsed["reason"]
