# tests/test_scoring.py

import unittest
from modules.scoring import SecurityScore


class TestSecurityScore(unittest.TestCase):
    """Tests for the SecurityScore engine."""

    def _make_result(self, **overrides):
        """Create a base result dict with sensible defaults, then apply overrides."""
        base = {
            "DOMAIN": "test.com",
            "DOMAIN_TYPE": "domain",
            "DNS_SERVER": "1.1.1.1",
            "SPF": None,
            "SPF_MULTIPLE_ALLS": None,
            "SPF_NUM_DNS_QUERIES": 0,
            "SPF_TOO_MANY_DNS_QUERIES": False,
            "DMARC": None,
            "DMARC_POLICY": None,
            "DMARC_PCT": None,
            "DMARC_ASPF": None,
            "DMARC_SP": None,
            "DMARC_FORENSIC_REPORT": None,
            "DMARC_AGGREGATE_REPORT": None,
            "DKIM": None,
            "DKIM_SELECTORS": [],
            "DKIM_HAS_WEAK_KEYS": False,
            "BIMI_RECORD": None,
            "BIMI_VERSION": None,
            "BIMI_LOCATION": None,
            "BIMI_AUTHORITY": None,
            "SPOOFING_POSSIBLE": True,
            "SPOOFING_TYPE": "Spoofing possible for test.com.",
            # Phase 2 defaults
            "MTA_STS_TXT": None,
            "MTA_STS_MODE": None,
            "MTA_STS_MAX_AGE": None,
            "TLS_RPT_RECORD": None,
            "TLS_RPT_RUA": None,
            "MX_RECORDS": [],
            "MX_COUNT": 0,
            "MX_ALL_STARTTLS": None,
            "MX_ALL_PTR": None,
            "MX_PROVIDERS": [],
            # DNSSEC defaults
            "DNSSEC_ENABLED": False,
            "DNSSEC_HAS_DS": False,
            "DNSSEC_KEY_COUNT": 0,
        }
        base.update(overrides)
        return base

    # --- Grade Tests ---

    def test_perfect_score_gets_a_plus(self):
        """A domain with all perfect settings should get A+."""
        result = self._make_result(
            SPF="v=spf1 include:_spf.google.com -all",
            SPF_MULTIPLE_ALLS="-all",
            SPF_NUM_DNS_QUERIES=3,
            SPF_TOO_MANY_DNS_QUERIES=False,
            DMARC="v=DMARC1; p=reject; rua=mailto:dmarc@test.com; pct=100; sp=reject",
            DMARC_POLICY="reject",
            DMARC_PCT="100",
            DMARC_AGGREGATE_REPORT="mailto:dmarc@test.com",
            DMARC_SP="reject",
            DKIM="[*] selector1._domainkey.test.com -> v=DKIM1\r\n[*] selector2._domainkey.test.com -> v=DKIM1",
            DKIM_SELECTORS=[
                {"selector": "selector1", "key_bits": 2048},
                {"selector": "selector2", "key_bits": 2048},
            ],
            DKIM_HAS_WEAK_KEYS=False,
            BIMI_RECORD="v=BIMI1; l=https://test.com/logo.svg; a=https://test.com/vmc.pem",
            BIMI_VERSION="BIMI1",
            BIMI_LOCATION="https://test.com/logo.svg",
            BIMI_AUTHORITY="https://test.com/vmc.pem",
            SPOOFING_POSSIBLE=False,
            SPOOFING_TYPE="Spoofing is not possible for test.com.",
            MTA_STS_TXT="v=STSv1; id=20240101",
            MTA_STS_MODE="enforce",
            TLS_RPT_RECORD="v=TLSRPTv1; rua=mailto:tls@test.com",
            MX_RECORDS=[
                {"host": "mx1.test.com", "starttls": True, "ptr": "mx1.test.com"},
                {"host": "mx2.test.com", "starttls": True, "ptr": "mx2.test.com"},
            ],
            MX_COUNT=2,
            MX_ALL_STARTTLS=True,
            MX_ALL_PTR=True,
            DNSSEC_ENABLED=True,
            DNSSEC_HAS_DS=True,
            DNSSEC_KEY_COUNT=3,
        )
        score = SecurityScore(result)
        self.assertEqual(score.score, 100)
        self.assertEqual(score.grade, "A+")

    def test_no_records_gets_f(self):
        """A domain with nothing configured should get F."""
        result = self._make_result()
        score = SecurityScore(result)
        self.assertEqual(score.score, 0)
        self.assertEqual(score.grade, "F")

    def test_spf_only_domain(self):
        """A domain with only SPF (hard fail) should get partial credit."""
        result = self._make_result(
            SPF="v=spf1 include:_spf.google.com -all",
            SPF_MULTIPLE_ALLS="-all",
            SPF_NUM_DNS_QUERIES=2,
            SPF_TOO_MANY_DNS_QUERIES=False,
        )
        score = SecurityScore(result)
        # SPF: 5+3+8+2 = 18, everything else 0
        self.assertEqual(score.breakdown["spf"]["score"], 18)
        self.assertEqual(score.breakdown["dmarc"]["score"], 0)
        self.assertEqual(score.score, 18)

    def test_softfail_spf_scores_lower(self):
        """~all should score less than -all."""
        result_hard = self._make_result(
            SPF="v=spf1 -all",
            SPF_MULTIPLE_ALLS="-all",
        )
        result_soft = self._make_result(
            SPF="v=spf1 ~all",
            SPF_MULTIPLE_ALLS="~all",
        )
        score_hard = SecurityScore(result_hard)
        score_soft = SecurityScore(result_soft)
        self.assertGreater(
            score_hard.breakdown["spf"]["score"],
            score_soft.breakdown["spf"]["score"],
        )

    def test_dmarc_reject_scores_higher_than_none(self):
        """p=reject should score more than p=none."""
        result_reject = self._make_result(
            DMARC="v=DMARC1; p=reject",
            DMARC_POLICY="reject",
        )
        result_none = self._make_result(
            DMARC="v=DMARC1; p=none",
            DMARC_POLICY="none",
        )
        score_reject = SecurityScore(result_reject)
        score_none = SecurityScore(result_none)
        self.assertGreater(
            score_reject.breakdown["dmarc"]["score"],
            score_none.breakdown["dmarc"]["score"],
        )

    def test_spoofable_domain_gets_zero_spoof_score(self):
        """A spoofable domain should get 0 points for spoofability."""
        result = self._make_result(SPOOFING_POSSIBLE=True)
        score = SecurityScore(result)
        self.assertEqual(score.breakdown["spoofability"]["score"], 0)

    def test_non_spoofable_domain_gets_full_spoof_score(self):
        """A non-spoofable domain should get full spoofability points (15)."""
        result = self._make_result(SPOOFING_POSSIBLE=False)
        score = SecurityScore(result)
        self.assertEqual(score.breakdown["spoofability"]["score"], 15)

    def test_maybe_spoofable_gets_partial_score(self):
        """A maybe-spoofable domain should get partial points (8)."""
        result = self._make_result(SPOOFING_POSSIBLE=None)
        score = SecurityScore(result)
        self.assertEqual(score.breakdown["spoofability"]["score"], 8)

    def test_too_many_dns_queries_loses_points(self):
        """Too many DNS queries should lose 4 SPF points."""
        result_ok = self._make_result(
            SPF="v=spf1 -all",
            SPF_MULTIPLE_ALLS="-all",
            SPF_NUM_DNS_QUERIES=5,
            SPF_TOO_MANY_DNS_QUERIES=False,
        )
        result_bad = self._make_result(
            SPF="v=spf1 -all",
            SPF_MULTIPLE_ALLS="-all",
            SPF_NUM_DNS_QUERIES=15,
            SPF_TOO_MANY_DNS_QUERIES=True,
        )
        score_ok = SecurityScore(result_ok)
        score_bad = SecurityScore(result_bad)
        self.assertEqual(
            score_ok.breakdown["spf"]["score"] - score_bad.breakdown["spf"]["score"], 2
        )

    def test_to_dict_returns_expected_keys(self):
        """to_dict() should return the expected keys."""
        result = self._make_result()
        score = SecurityScore(result)
        d = score.to_dict()
        self.assertIn("SECURITY_SCORE", d)
        self.assertIn("SECURITY_GRADE", d)
        self.assertIn("SCORE_BREAKDOWN", d)
        self.assertIn("SCORE_DETAILS", d)

    def test_grade_boundaries(self):
        """Test various score → grade mappings."""
        result = self._make_result()
        score = SecurityScore(result)
        # Manually test grade calculation
        score.score = 97
        self.assertEqual(score._calculate_grade(), "A+")
        score.score = 92
        self.assertEqual(score._calculate_grade(), "A")
        score.score = 82
        self.assertEqual(score._calculate_grade(), "B+")
        score.score = 72
        self.assertEqual(score._calculate_grade(), "B-")
        score.score = 55
        self.assertEqual(score._calculate_grade(), "C-")
        score.score = 30
        self.assertEqual(score._calculate_grade(), "F")

    def test_bimi_with_authority_scores_full(self):
        """BIMI with both location and authority should get full 5 points."""
        result = self._make_result(
            BIMI_RECORD="v=BIMI1; l=https://test.com/logo.svg; a=https://test.com/vmc.pem",
            BIMI_VERSION="BIMI1",
            BIMI_LOCATION="https://test.com/logo.svg",
            BIMI_AUTHORITY="https://test.com/vmc.pem",
        )
        score = SecurityScore(result)
        self.assertEqual(score.breakdown["bimi"]["score"], 5)

    def test_bimi_without_authority_gets_partial(self):
        """BIMI with location but no authority gets partial credit (4/5)."""
        result = self._make_result(
            BIMI_RECORD="v=BIMI1; l=https://test.com/logo.svg",
            BIMI_VERSION="BIMI1",
            BIMI_LOCATION="https://test.com/logo.svg",
        )
        score = SecurityScore(result)
        self.assertEqual(score.breakdown["bimi"]["score"], 4)

    def test_breakdown_has_all_categories(self):
        """Score breakdown includes all 8 categories."""
        result = self._make_result()
        score = SecurityScore(result)
        expected_cats = {"spf", "dmarc", "dkim", "bimi", "spoofability", "mta_sts", "mx", "dnssec"}
        self.assertEqual(set(score.breakdown.keys()), expected_cats)


class TestSecurityScoreStr(unittest.TestCase):
    """Test __str__ representation."""

    def test_str_contains_score(self):
        result = {
            "DOMAIN": "test.com",
            "SPF": None,
            "SPF_MULTIPLE_ALLS": None,
            "SPF_TOO_MANY_DNS_QUERIES": False,
            "DMARC": None,
            "DMARC_POLICY": None,
            "DMARC_PCT": None,
            "DMARC_AGGREGATE_REPORT": None,
            "DMARC_SP": None,
            "DKIM": None,
            "BIMI_RECORD": None,
            "BIMI_LOCATION": None,
            "BIMI_AUTHORITY": None,
            "SPOOFING_POSSIBLE": True,
            "SPOOFING_TYPE": "",
        }
        score = SecurityScore(result)
        output = str(score)
        self.assertIn("Security Score:", output)
        self.assertIn("/100", output)


if __name__ == "__main__":
    unittest.main()
