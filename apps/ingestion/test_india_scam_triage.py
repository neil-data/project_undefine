"""
ingestion/test_india_scam_triage.py — Tests for the pre-triage
heuristic module.
"""

from ingestion.india_scam_triage import triage_sample


class TestLoanAppDetection:
    def test_flags_loan_app_by_package_name(self):
        result = triage_sample(package_name="com.quickloan.easyapp")
        assert result.is_flagged
        assert result.category == "loan_app_scam"

    def test_flags_loan_app_by_label_when_package_generic(self):
        result = triage_sample(package_name="com.abc.xyz123", app_label="Instant Cash Loan")
        assert result.is_flagged
        assert result.category == "loan_app_scam"

    def test_high_priority_when_permissions_confirm(self):
        result = triage_sample(
            package_name="com.quickloan.easyapp",
            permissions=["android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW"],
        )
        assert result.priority == "high"
        assert result.confidence >= 0.7
        assert len(result.matched_permissions) == 2

    def test_lower_confidence_without_permissions(self):
        with_perms = triage_sample(
            package_name="com.quickloan.easyapp",
            permissions=["android.permission.READ_SMS"],
        )
        without_perms = triage_sample(package_name="com.quickloan.easyapp")
        assert with_perms.confidence > without_perms.confidence


class TestEchallanDetection:
    def test_flags_echallan_app(self):
        result = triage_sample(package_name="com.fake.echallan.pay")
        assert result.is_flagged
        assert result.category == "echallan_scam"

    def test_flags_rto_keyword(self):
        result = triage_sample(package_name="com.rto.vahan.service")
        assert result.is_flagged
        assert result.category == "echallan_scam"


class TestUtilityBillDetection:
    def test_flags_bijli_keyword(self):
        result = triage_sample(package_name="com.bijli.paynow")
        assert result.is_flagged
        assert result.category == "utility_bill_scam"

    def test_flags_electricity_bill_keyword(self):
        result = triage_sample(package_name="com.fast.electricitybill")
        assert result.is_flagged
        assert result.category == "utility_bill_scam"


class TestNoFalsePositives:
    def test_benign_app_not_flagged(self):
        result = triage_sample(
            package_name="com.example.calculator",
            app_label="Simple Calculator",
            permissions=["android.permission.INTERNET"],
        )
        assert not result.is_flagged
        assert result.category is None
        assert result.confidence == 0.0

    def test_unrelated_permissions_alone_do_not_flag(self):
        """High-risk permissions alone, with no keyword match, should not flag —
        triage is keyword-first, permissions only raise confidence once flagged."""
        result = triage_sample(
            package_name="com.somebank.officialapp",
            permissions=["android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW"],
        )
        assert not result.is_flagged


class TestConfidenceBounds:
    def test_confidence_never_exceeds_one(self):
        result = triage_sample(
            package_name="com.quickloan.fastcash.instant.emi",
            app_label="Quick Loan Fast Cash Instant EMI Advance",
            permissions=list(
                {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
                 "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.READ_CONTACTS",
                 "android.permission.READ_CALL_LOG"}
            ),
        )
        assert result.confidence <= 1.0

    def test_confidence_is_zero_when_not_flagged(self):
        result = triage_sample(package_name="com.example.notes")
        assert result.confidence == 0.0