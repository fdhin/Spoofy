# tests/test_mta_sts.py

"""Tests for MTA-STS and TLS-RPT module."""

import unittest
from unittest.mock import patch, MagicMock
from modules.mta_sts import MTASTS


class TestMTASTS(unittest.TestCase):
    """Tests for MTASTS class."""

    @patch.object(MTASTS, '__init__', lambda self, *a, **kw: None)
    def _make_instance(self, **attrs):
        """Create a bare MTASTS instance with specified attributes."""
        obj = MTASTS.__new__(MTASTS)
        obj.domain = attrs.get("domain", "example.com")
        obj.dns_server = attrs.get("dns_server", None)
        obj.mta_sts_txt = attrs.get("mta_sts_txt", None)
        obj.mta_sts_id = attrs.get("mta_sts_id", None)
        obj.policy_raw = attrs.get("policy_raw", None)
        obj.policy_mode = attrs.get("policy_mode", None)
        obj.policy_max_age = attrs.get("policy_max_age", None)
        obj.policy_mx_patterns = attrs.get("policy_mx_patterns", [])
        obj.tls_rpt_record = attrs.get("tls_rpt_record", None)
        obj.tls_rpt_rua = attrs.get("tls_rpt_rua", None)
        return obj

    # --- to_dict tests ---

    def test_to_dict_empty(self):
        """No MTA-STS or TLS-RPT records returns all None/empty."""
        obj = self._make_instance()
        d = obj.to_dict()
        self.assertIsNone(d["MTA_STS_TXT"])
        self.assertIsNone(d["MTA_STS_MODE"])
        self.assertIsNone(d["MTA_STS_MAX_AGE"])
        self.assertIsNone(d["TLS_RPT_RECORD"])

    def test_to_dict_full(self):
        """Full MTA-STS and TLS-RPT results."""
        obj = self._make_instance(
            mta_sts_txt="v=STSv1; id=20240101",
            mta_sts_id="20240101",
            policy_mode="enforce",
            policy_max_age=604800,
            policy_mx_patterns=["*.mail.protection.outlook.com"],
            tls_rpt_record="v=TLSRPTv1; rua=mailto:tls@example.com",
            tls_rpt_rua="mailto:tls@example.com",
        )
        d = obj.to_dict()
        self.assertEqual(d["MTA_STS_TXT"], "v=STSv1; id=20240101")
        self.assertEqual(d["MTA_STS_MODE"], "enforce")
        self.assertEqual(d["MTA_STS_MAX_AGE"], 604800)
        self.assertEqual(d["TLS_RPT_RECORD"], "v=TLSRPTv1; rua=mailto:tls@example.com")
        self.assertEqual(d["TLS_RPT_RUA"], "mailto:tls@example.com")

    def test_to_dict_testing_mode(self):
        """MTA-STS in testing mode."""
        obj = self._make_instance(
            mta_sts_txt="v=STSv1; id=20240101",
            policy_mode="testing",
            policy_max_age=86400,
        )
        d = obj.to_dict()
        self.assertEqual(d["MTA_STS_MODE"], "testing")

    # --- validate_mx_against_policy tests ---

    def test_validate_mx_no_policy(self):
        """No policy: no mismatches reported."""
        obj = self._make_instance()
        result = obj.validate_mx_against_policy(["mx1.example.com"])
        self.assertEqual(result, [])

    def test_validate_mx_wildcard_match(self):
        """MX hosts match wildcard pattern."""
        obj = self._make_instance(
            policy_mode="enforce",
            policy_mx_patterns=["*.mail.protection.outlook.com"],
        )
        result = obj.validate_mx_against_policy([
            "mx1.mail.protection.outlook.com",
            "mx2.mail.protection.outlook.com",
        ])
        self.assertEqual(result, [])

    def test_validate_mx_exact_match(self):
        """Exact MX host matches."""
        obj = self._make_instance(
            policy_mode="enforce",
            policy_mx_patterns=["mail.example.com"],
        )
        result = obj.validate_mx_against_policy(["mail.example.com"])
        self.assertEqual(result, [])

    def test_validate_mx_mismatch(self):
        """MX host doesn't match any pattern."""
        obj = self._make_instance(
            policy_mode="enforce",
            policy_mx_patterns=["*.example.com"],
        )
        result = obj.validate_mx_against_policy(["mail.otherdomain.com"])
        self.assertEqual(len(result), 1)
        self.assertIn("mail.otherdomain.com", result[0])

    def test_validate_mx_no_patterns(self):
        """No patterns set: validation returns empty (nothing to check)."""
        obj = self._make_instance(
            policy_mx_patterns=[],
        )
        result = obj.validate_mx_against_policy(["mail.otherdomain.com"])
        self.assertEqual(result, [])

    # --- Scoring integration tests ---

    def test_scoring_mta_sts_enforce(self):
        """MTA-STS enforce mode gives full MTA-STS score."""
        from modules.scoring import SecurityScore
        result = {
            "SPF": "v=spf1 -all",
            "SPF_MULTIPLE_ALLS": "-all",
            "DMARC": "v=DMARC1; p=reject; rua=mailto:d@e.com",
            "DMARC_POLICY": "reject",
            "DMARC_AGGREGATE_REPORT": "mailto:d@e.com",
            "DKIM": None,
            "BIMI_RECORD": None,
            "SPOOFING_POSSIBLE": False,
            "MTA_STS_TXT": "v=STSv1; id=123",
            "MTA_STS_MODE": "enforce",
            "TLS_RPT_RECORD": "v=TLSRPTv1; rua=mailto:t@e.com",
            "TLS_RPT_RUA": "mailto:t@e.com",
            "MX_RECORDS": [],
            "MX_COUNT": 0,
        }
        score = SecurityScore(result)
        self.assertEqual(score.breakdown["mta_sts"]["score"], 10)

    def test_scoring_mta_sts_none(self):
        """No MTA-STS records yields 0 points."""
        from modules.scoring import SecurityScore
        result = {
            "SPF": None, "DMARC": None, "DKIM": None, "BIMI_RECORD": None,
            "SPOOFING_POSSIBLE": True,
            "MTA_STS_TXT": None, "MTA_STS_MODE": None,
            "TLS_RPT_RECORD": None,
            "MX_RECORDS": [], "MX_COUNT": 0,
        }
        score = SecurityScore(result)
        self.assertEqual(score.breakdown["mta_sts"]["score"], 0)

    def test_scoring_mta_sts_testing(self):
        """MTA-STS testing mode gives partial credit."""
        from modules.scoring import SecurityScore
        result = {
            "SPF": None, "DMARC": None, "DKIM": None, "BIMI_RECORD": None,
            "SPOOFING_POSSIBLE": True,
            "MTA_STS_TXT": "v=STSv1; id=1",
            "MTA_STS_MODE": "testing",
            "TLS_RPT_RECORD": None,
            "MX_RECORDS": [], "MX_COUNT": 0,
        }
        score = SecurityScore(result)
        self.assertEqual(score.breakdown["mta_sts"]["score"], 5)  # 2 (txt) + 3 (testing)

    # --- Remediation integration tests ---

    def test_remediation_no_mta_sts(self):
        """Missing MTA-STS generates recommendation."""
        from modules.remediation import RemediationEngine
        result = {
            "DOMAIN": "test.com",
            "SPF": "v=spf1 -all", "SPF_MULTIPLE_ALLS": "-all",
            "DMARC": "v=DMARC1; p=reject", "DMARC_POLICY": "reject",
            "DMARC_AGGREGATE_REPORT": "mailto:d@t.com",
            "DKIM": "selector1", "BIMI_RECORD": None,
            "SPOOFING_POSSIBLE": False,
            "MTA_STS_TXT": None, "MTA_STS_MODE": None,
            "TLS_RPT_RECORD": None,
        }
        engine = RemediationEngine(result)
        categories = [r.category for r in engine.recommendations]
        self.assertIn("MTA-STS", categories)
        self.assertIn("TLS-RPT", categories)

    def test_remediation_mta_sts_testing(self):
        """MTA-STS testing mode generates upgrade recommendation."""
        from modules.remediation import RemediationEngine
        result = {
            "DOMAIN": "test.com",
            "SPF": "v=spf1 -all", "SPF_MULTIPLE_ALLS": "-all",
            "DMARC": "v=DMARC1; p=reject", "DMARC_POLICY": "reject",
            "DMARC_AGGREGATE_REPORT": "mailto:d@t.com",
            "DKIM": "selector1", "BIMI_RECORD": None,
            "SPOOFING_POSSIBLE": False,
            "MTA_STS_TXT": "v=STSv1; id=1",
            "MTA_STS_MODE": "testing",
            "MTA_STS_MAX_AGE": 86400,
            "TLS_RPT_RECORD": "v=TLSRPTv1; rua=mailto:t@t.com",
        }
        engine = RemediationEngine(result)
        titles = [r.title for r in engine.recommendations]
        self.assertTrue(any("testing" in t.lower() for t in titles))


class TestMTASTSParsing(unittest.TestCase):
    """Tests for MTA-STS policy parsing logic."""

    @patch.object(MTASTS, '__init__', lambda self, *a, **kw: None)
    def test_parse_policy_text(self):
        """Test parsing of MTA-STS policy text."""
        obj = MTASTS.__new__(MTASTS)
        obj.domain = "example.com"
        obj.policy_mode = None
        obj.policy_max_age = None
        obj.policy_mx_patterns = []

        policy_text = """version: STSv1
mode: enforce
mx: *.mail.protection.outlook.com
mx: mail.example.com
max_age: 604800"""

        obj._parse_policy(policy_text)
        self.assertEqual(obj.policy_mode, "enforce")
        self.assertEqual(obj.policy_max_age, 604800)
        self.assertEqual(len(obj.policy_mx_patterns), 2)
        self.assertIn("*.mail.protection.outlook.com", obj.policy_mx_patterns)
        self.assertIn("mail.example.com", obj.policy_mx_patterns)


if __name__ == "__main__":
    unittest.main()
