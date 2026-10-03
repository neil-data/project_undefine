"""
tests/test_apk_extraction.py — End-to-end test of the full APK
analyzer (detection + manifest parsing + permission extraction),
using the real create_apk_analyzer() factory — not mocked pieces.
"""

import zipfile
import pytest

from static_analysis.apk.bootstrap import create_apk_analyzer


MANIFEST_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.quickloan.easyapp">
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.RECEIVE_SMS" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <application android:label="Quick Loan Instant Cash">
        <activity android:name=".MainActivity" />
        <receiver android:name=".SmsReceiver" />
    </application>
</manifest>
"""


@pytest.fixture
def sample_apk(tmp_path):
    apk_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("AndroidManifest.xml", MANIFEST_XML)
        z.writestr("classes.dex", "fake payload with http://185.220.101.45/collect inside")
    return apk_path


class TestApkExtractionEndToEnd:
    def test_extraction_succeeds(self, sample_apk):
        analyzer = create_apk_analyzer()
        result = analyzer.extract(str(sample_apk))
        assert result.error is None

    def test_package_name_extracted(self, sample_apk):
        analyzer = create_apk_analyzer()
        result = analyzer.extract(str(sample_apk))
        assert result.info.package_name == "com.quickloan.easyapp"

    def test_application_label_extracted(self, sample_apk):
        analyzer = create_apk_analyzer()
        result = analyzer.extract(str(sample_apk))
        assert result.info.application_label == "Quick Loan Instant Cash"

    def test_all_permissions_extracted(self, sample_apk):
        analyzer = create_apk_analyzer()
        result = analyzer.extract(str(sample_apk))
        perm_names = {p.name for p in result.info.requested_permissions}
        assert perm_names == {
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.ACCESS_FINE_LOCATION",
        }

    def test_dangerous_permissions_flagged(self, sample_apk):
        analyzer = create_apk_analyzer()
        result = analyzer.extract(str(sample_apk))
        dangerous = {p.name for p in result.info.requested_permissions if p.is_dangerous}
        assert "android.permission.READ_SMS" in dangerous
        assert "android.permission.RECEIVE_SMS" in dangerous
        assert "android.permission.ACCESS_FINE_LOCATION" in dangerous

    def test_security_flags_summary(self, sample_apk):
        analyzer = create_apk_analyzer()
        result = analyzer.extract(str(sample_apk))
        flags = result.info.security_flags
        assert flags.uses_sms is True
        assert flags.uses_location is True

    def test_non_apk_file_returns_error_not_crash(self, tmp_path):
        """A plain text file should fail gracefully with an error code, not raise."""
        f = tmp_path / "not_an_apk.txt"
        f.write_text("just some text")
        analyzer = create_apk_analyzer()
        result = analyzer.extract(str(f))
        assert result.error == "unsupported_apk"
        assert result.info is None
