# tests/test_mta_sts.py

"""Tests for MTA-STS and TLS-RPT module."""

import unittest
from unittest.mock import patch, MagicMock
from modules.mta_sts import MTASTS, _mx_matches_pattern


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
        obj.mta_sts_permerror = attrs.get("mta_sts_permerror", False)
        obj.policy_raw = attrs.get("policy_raw", None)
        obj.policy_version = attrs.get("policy_version", None)
        obj.policy_mode = attrs.get("policy_mode", None)
        obj.policy_max_age = attrs.get("policy_max_age", None)
        obj.policy_mx_patterns = attrs.get("policy_mx_patterns", [])
        obj.tls_rpt_record = attrs.get("tls_rpt_record", None)
        obj.tls_rpt_rua = attrs.get("tls_rpt_rua", None)
        obj.tls_rpt_permerror = attrs.get("tls_rpt_permerror", False)
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
        self.assertFalse(d["MTA_STS_PERMERROR"])
        self.assertFalse(d["TLS_RPT_PERMERROR"])

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

    def test_to_dict_permerror(self):
        """PermError should be exposed in to_dict without polluting TXT field."""
        obj = self._make_instance(mta_sts_permerror=True)
        d = obj.to_dict()
        self.assertTrue(d["MTA_STS_PERMERROR"])
        self.assertIsNone(d["MTA_STS_TXT"])  # NOT a string like "MULTIPLE_RECORDS_ERROR"

    # --- __str__ tests ---

    def test_str_permerror_mta_sts(self):
        """PermError should show CRITICAL in string output."""
        obj = self._make_instance(mta_sts_permerror=True)
        self.assertIn("CRITICAL", str(obj))
        self.assertIn("Multiple records", str(obj))

    def test_str_permerror_tls_rpt(self):
        """TLS-RPT permerror should show CRITICAL in string output."""
        obj = self._make_instance(tls_rpt_permerror=True)
        self.assertIn("CRITICAL", str(obj))

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
            "SPF_ALL": "-all",
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

    def test_scoring_mta_sts_permerror_with_valid_tls_rpt(self):
        """MTA-STS permerror must NOT steal TLS-RPT's 3 points."""
        from modules.scoring import SecurityScore
        result = {
            "SPF": None, "DMARC": None, "DKIM": None, "BIMI_RECORD": None,
            "SPOOFING_POSSIBLE": True,
            "MTA_STS_TXT": None, "MTA_STS_MODE": None,
            "MTA_STS_PERMERROR": True,
            "TLS_RPT_RECORD": "v=TLSRPTv1; rua=mailto:t@e.com",
            "MX_RECORDS": [], "MX_COUNT": 0,
        }
        score = SecurityScore(result)
        # MTA-STS zeroed (permerror), but TLS-RPT scores 3
        self.assertEqual(score.breakdown["mta_sts"]["score"], 3)

    def test_scoring_mta_sts_permerror_no_tls_rpt(self):
        """MTA-STS permerror without TLS-RPT must score 0."""
        from modules.scoring import SecurityScore
        result = {
            "SPF": None, "DMARC": None, "DKIM": None, "BIMI_RECORD": None,
            "SPOOFING_POSSIBLE": True,
            "MTA_STS_TXT": None, "MTA_STS_MODE": None,
            "MTA_STS_PERMERROR": True,
            "TLS_RPT_RECORD": None,
            "MX_RECORDS": [], "MX_COUNT": 0,
        }
        score = SecurityScore(result)
        self.assertEqual(score.breakdown["mta_sts"]["score"], 0)

    def test_scoring_tls_rpt_permerror_no_points(self):
        """TLS-RPT permerror must not award TLS-RPT points."""
        from modules.scoring import SecurityScore
        result = {
            "SPF": None, "DMARC": None, "DKIM": None, "BIMI_RECORD": None,
            "SPOOFING_POSSIBLE": True,
            "MTA_STS_TXT": "v=STSv1; id=1",
            "MTA_STS_MODE": "enforce",
            "TLS_RPT_RECORD": "v=TLSRPTv1; rua=mailto:t@e.com",
            "TLS_RPT_PERMERROR": True,
            "MX_RECORDS": [], "MX_COUNT": 0,
        }
        score = SecurityScore(result)
        # 2 (txt) + 5 (enforce) + 0 (TLS-RPT permerror) = 7
        self.assertEqual(score.breakdown["mta_sts"]["score"], 7)

    # --- Remediation integration tests ---

    def test_remediation_no_mta_sts(self):
        """Missing MTA-STS generates recommendation."""
        from modules.remediation import RemediationEngine
        result = {
            "DOMAIN": "test.com",
            "SPF": "v=spf1 -all", "SPF_ALL": "-all",
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
            "SPF": "v=spf1 -all", "SPF_ALL": "-all",
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

    def test_remediation_permerror(self):
        """PermError should generate priority-1 MTA-STS remediation."""
        from modules.remediation import RemediationEngine
        result = {
            "DOMAIN": "test.com",
            "SPF": "v=spf1 -all", "SPF_ALL": "-all",
            "DMARC": "v=DMARC1; p=reject", "DMARC_POLICY": "reject",
            "DMARC_AGGREGATE_REPORT": "mailto:d@t.com",
            "DKIM": "selector1", "BIMI_RECORD": None,
            "SPOOFING_POSSIBLE": False,
            "MTA_STS_TXT": None, "MTA_STS_MODE": None,
            "MTA_STS_PERMERROR": True,
            "TLS_RPT_RECORD": None,
        }
        engine = RemediationEngine(result)
        mta_recs = [r for r in engine.recommendations if r.category == "MTA-STS"]
        self.assertTrue(any("Multiple" in r.title for r in mta_recs))
        self.assertTrue(any(r.priority == 1 for r in mta_recs))

    def test_remediation_unreachable_policy(self):
        """TXT exists but HTTPS policy unreachable should generate priority-1 alert."""
        from modules.remediation import RemediationEngine
        result = {
            "DOMAIN": "test.com",
            "SPF": "v=spf1 -all", "SPF_ALL": "-all",
            "DMARC": "v=DMARC1; p=reject", "DMARC_POLICY": "reject",
            "DMARC_AGGREGATE_REPORT": "mailto:d@t.com",
            "DKIM": "selector1", "BIMI_RECORD": None,
            "SPOOFING_POSSIBLE": False,
            "MTA_STS_TXT": "v=STSv1; id=20240101",
            "MTA_STS_MODE": None,  # HTTPS fetch failed or policy invalid
            "TLS_RPT_RECORD": "v=TLSRPTv1; rua=mailto:t@t.com",
        }
        engine = RemediationEngine(result)
        mta_recs = [r for r in engine.recommendations if r.category == "MTA-STS"]
        self.assertTrue(any("unreachable" in r.title.lower() for r in mta_recs))
        self.assertTrue(any(r.priority == 1 for r in mta_recs))

    def test_remediation_tls_rpt_permerror_does_not_skip_mta_sts(self):
        """TLS-RPT permerror must NOT suppress MTA-STS testing-mode advice."""
        from modules.remediation import RemediationEngine
        result = {
            "DOMAIN": "test.com",
            "SPF": "v=spf1 -all", "SPF_ALL": "-all",
            "DMARC": "v=DMARC1; p=reject", "DMARC_POLICY": "reject",
            "DMARC_AGGREGATE_REPORT": "mailto:d@t.com",
            "DKIM": "selector1", "BIMI_RECORD": None,
            "SPOOFING_POSSIBLE": False,
            "MTA_STS_TXT": "v=STSv1; id=1",
            "MTA_STS_MODE": "testing",
            "MTA_STS_MAX_AGE": 86400,
            "TLS_RPT_RECORD": None,
            "TLS_RPT_PERMERROR": True,
        }
        engine = RemediationEngine(result)
        # MTA-STS testing advice should still appear
        mta_recs = [r for r in engine.recommendations if r.category == "MTA-STS"]
        self.assertTrue(any("testing" in r.title.lower() for r in mta_recs))
        # TLS-RPT permerror should also appear
        tls_recs = [r for r in engine.recommendations if r.category == "TLS-RPT"]
        self.assertTrue(any("Multiple" in r.title for r in tls_recs))


class TestMTASTSParsing(unittest.TestCase):
    """Tests for MTA-STS policy parsing logic."""

    @patch.object(MTASTS, '__init__', lambda self, *a, **kw: None)
    def _make_parser(self):
        """Create a bare MTASTS instance for parsing tests."""
        obj = MTASTS.__new__(MTASTS)
        obj.domain = "example.com"
        obj.policy_raw = None
        obj.policy_version = None
        obj.policy_mode = None
        obj.policy_max_age = None
        obj.policy_mx_patterns = []
        return obj

    def test_parse_valid_policy(self):
        """Test parsing of a valid MTA-STS policy."""
        obj = self._make_parser()
        policy_text = """version: STSv1
mode: enforce
mx: *.mail.protection.outlook.com
mx: mail.example.com
max_age: 604800"""

        obj._parse_policy(policy_text)
        self.assertEqual(obj.policy_version, "STSv1")
        self.assertEqual(obj.policy_mode, "enforce")
        self.assertEqual(obj.policy_max_age, 604800)
        self.assertEqual(len(obj.policy_mx_patterns), 2)
        self.assertIn("*.mail.protection.outlook.com", obj.policy_mx_patterns)
        self.assertIn("mail.example.com", obj.policy_mx_patterns)

    def test_parse_missing_version_resets(self):
        """Policy without 'version: STSv1' must be rejected (RFC 8461 §3.2)."""
        obj = self._make_parser()
        policy_text = """mode: enforce
mx: mail.example.com
max_age: 604800"""

        obj._parse_policy(policy_text)
        self.assertIsNone(obj.policy_mode)
        self.assertIsNone(obj.policy_max_age)

    def test_parse_wrong_version_resets(self):
        """Policy with wrong version string must be rejected."""
        obj = self._make_parser()
        policy_text = """version: STSv2
mode: enforce
mx: mail.example.com
max_age: 604800"""

        obj._parse_policy(policy_text)
        self.assertIsNone(obj.policy_mode)

    def test_parse_duplicate_mode_first_wins(self):
        """Duplicate 'mode' lines — first value wins (RFC 8461 §3.2)."""
        obj = self._make_parser()
        policy_text = """version: STSv1
mode: enforce
mode: none
mx: mail.example.com
max_age: 604800"""

        obj._parse_policy(policy_text)
        self.assertEqual(obj.policy_mode, "enforce")

    def test_parse_duplicate_max_age_first_wins(self):
        """Duplicate 'max_age' lines — first value wins (RFC 8461 §3.2)."""
        obj = self._make_parser()
        policy_text = """version: STSv1
mode: enforce
mx: mail.example.com
max_age: 604800
max_age: 100"""

        obj._parse_policy(policy_text)
        self.assertEqual(obj.policy_max_age, 604800)

    def test_parse_invalid_mode_resets(self):
        """Invalid mode value must reject the policy."""
        obj = self._make_parser()
        policy_text = """version: STSv1
mode: invalid
mx: mail.example.com
max_age: 604800"""

        obj._parse_policy(policy_text)
        self.assertIsNone(obj.policy_mode)

    def test_parse_uppercase_mode_rejected(self):
        """Uppercase mode 'ENFORCE' must be rejected (ABNF %s is case-sensitive)."""
        obj = self._make_parser()
        policy_text = """version: STSv1
mode: ENFORCE
mx: mail.example.com
max_age: 604800"""

        obj._parse_policy(policy_text)
        self.assertIsNone(obj.policy_mode)

    def test_parse_uppercase_key_rejected(self):
        """Uppercase key 'Mode' must be treated as unknown (case-sensitive ABNF)."""
        obj = self._make_parser()
        policy_text = """version: STSv1
Mode: enforce
mx: mail.example.com
max_age: 604800"""

        obj._parse_policy(policy_text)
        # 'Mode' != 'mode', so mode is never set → validation fails
        self.assertIsNone(obj.policy_mode)

    def test_parse_missing_mx_in_enforce_resets(self):
        """Enforce mode without any mx entries must reject the policy."""
        obj = self._make_parser()
        policy_text = """version: STSv1
mode: enforce
max_age: 604800"""

        obj._parse_policy(policy_text)
        self.assertIsNone(obj.policy_mode)

    def test_parse_none_mode_no_mx_ok(self):
        """Mode 'none' is valid without mx entries."""
        obj = self._make_parser()
        policy_text = """version: STSv1
mode: none
max_age: 604800"""

        obj._parse_policy(policy_text)
        self.assertEqual(obj.policy_mode, "none")

    def test_parse_max_age_out_of_range_resets(self):
        """max_age exceeding 31557600 must reject the policy."""
        obj = self._make_parser()
        policy_text = """version: STSv1
mode: enforce
mx: mail.example.com
max_age: 99999999"""

        obj._parse_policy(policy_text)
        self.assertIsNone(obj.policy_mode)

    def test_parse_max_age_invalid_string_resets(self):
        """Non-integer max_age must reject the policy."""
        obj = self._make_parser()
        policy_text = """version: STSv1
mode: enforce
mx: mail.example.com
max_age: forever"""

        obj._parse_policy(policy_text)
        self.assertIsNone(obj.policy_mode)


class TestWildcardMatching(unittest.TestCase):
    """Tests for RFC 8461 §4.1 wildcard matching."""

    def test_exact_match(self):
        self.assertTrue(_mx_matches_pattern("mail.example.com", "mail.example.com"))

    def test_wildcard_leftmost(self):
        self.assertTrue(_mx_matches_pattern("mx1.example.com", "*.example.com"))

    def test_wildcard_no_multi_label(self):
        """Wildcard must not match multiple labels."""
        self.assertFalse(_mx_matches_pattern("sub.mx1.example.com", "*.example.com"))

    def test_wildcard_mid_domain_rejected(self):
        """Wildcard in non-leftmost position must NOT match (RFC 8461 §4.1)."""
        self.assertFalse(_mx_matches_pattern("mx1.mail.example.com", "mx1.*.example.com"))

    def test_wildcard_mid_domain_pattern(self):
        """Another mid-domain wildcard that must be rejected."""
        self.assertFalse(_mx_matches_pattern("a.b.example.com", "a.*.example.com"))

    def test_case_insensitive(self):
        self.assertTrue(_mx_matches_pattern("MAIL.example.COM", "mail.EXAMPLE.com"))

    def test_trailing_dot_stripped(self):
        self.assertTrue(_mx_matches_pattern("mail.example.com.", "mail.example.com"))

    def test_length_mismatch(self):
        self.assertFalse(_mx_matches_pattern("example.com", "*.example.com"))


class TestTrailingDot(unittest.TestCase):
    """Test trailing dot stripping in MTASTS init."""

    @patch.object(MTASTS, '_check_mta_sts_txt', lambda self: None)
    @patch.object(MTASTS, '_fetch_mta_sts_policy', lambda self: None)
    @patch.object(MTASTS, '_check_tls_rpt', lambda self: None)
    def test_trailing_dot_stripped(self):
        """Trailing dot must be stripped to prevent SSL/SNI crashes."""
        obj = MTASTS("example.com.", dns_server="1.1.1.1")
        self.assertEqual(obj.domain, "example.com")

    @patch.object(MTASTS, '_check_mta_sts_txt', lambda self: None)
    @patch.object(MTASTS, '_fetch_mta_sts_policy', lambda self: None)
    @patch.object(MTASTS, '_check_tls_rpt', lambda self: None)
    def test_whitespace_stripped(self):
        """Leading/trailing whitespace must be stripped."""
        obj = MTASTS("  Example.COM  ", dns_server="1.1.1.1")
        self.assertEqual(obj.domain, "example.com")


if __name__ == "__main__":
    unittest.main()
