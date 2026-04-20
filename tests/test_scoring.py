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
            "CAA_RECORDS": [],
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
            CAA_RECORDS=[{"tag": "issue", "value": "letsencrypt.org"}],
            CAA_HAS_ISSUE=True,
            DNSSEC_ENABLED=True,
            DNSSEC_DNSKEY_PRESENT=True,
            DNSSEC_HAS_DS=True,
            DNSSEC_AD_FLAG=True,
            DNSSEC_KEY_COUNT=3,
            # DANE: secure TLSA with AD flag + origin DNSSEC
            DANE_HAS_TLSA=True,
            DANE_IS_SECURE=True,
            DANE_MX_COUNT=2,
            DANE_TOTAL_MX=2,
            DANE_HAS_BOGUS_RECORDS=False,
            DANE_HAS_UNSUPPORTED_RECORDS=False,
        )
        score = SecurityScore(result)
        self.assertEqual(score.score, 105)
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
        # SPF: 5+3+8+0 = 16, everything else 0
        self.assertEqual(score.breakdown["spf"]["score"], 16)
        self.assertEqual(score.breakdown["dmarc"]["score"], 0)
        self.assertEqual(score.score, 16)

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

    def test_too_many_dns_queries_hard_caps_score(self):
        """SPF with >10 DNS lookups causes RFC 7208 PermError — hard-cap at 5."""
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
        # Perfect SPF = 16, PermError = 5 (record exists only)
        self.assertEqual(score_ok.breakdown["spf"]["score"], 16)
        self.assertEqual(score_bad.breakdown["spf"]["score"], 5)

    def test_spf_permerror_multiple_records_caps_at_zero(self):
        """SPF with multiple records causes PermError — hard-cap at 0."""
        result = self._make_result(
            SPF="v=spf1 -all",
            SPF_MULTIPLE_ALLS="-all",
            SPF_PERMERROR=True,
        )
        score = SecurityScore(result)
        self.assertEqual(score.breakdown["spf"]["score"], 0)

    def test_spf_permerror_details_show_critical(self):
        """SPF PermError details should show critical finding."""
        result = self._make_result(
            SPF="v=spf1 -all",
            SPF_PERMERROR=True,
        )
        score = SecurityScore(result)
        details = score.breakdown["spf"]["details"]
        critical = [d for d in details if "CRITICAL" in d[1]]
        self.assertTrue(len(critical) > 0, "Should show CRITICAL PermError finding")

    def test_spf_single_record_no_permerror(self):
        """A normal single SPF record should not trigger PermError."""
        result = self._make_result(
            SPF="v=spf1 -all",
            SPF_MULTIPLE_ALLS="-all",
            SPF_PERMERROR=False,
        )
        score = SecurityScore(result)
        self.assertEqual(score.breakdown["spf"]["score"], 16)

    def test_to_dict_returns_expected_keys(self):
        """to_dict() should return the expected keys."""
        result = self._make_result()
        score = SecurityScore(result)
        d = score.to_dict()
        self.assertIn("SECURITY_SCORE", d)
        self.assertIn("SECURITY_SCORE_MAX", d)
        self.assertIn("SECURITY_SCORE_PCT", d)
        self.assertIn("SECURITY_GRADE", d)
        self.assertIn("SCORE_BREAKDOWN", d)
        self.assertIn("SCORE_DETAILS", d)

    def test_grade_boundaries(self):
        """Test various score → grade mappings."""
        result = self._make_result()
        score = SecurityScore(result)
        # Grade boundaries are percentage-based: score / max_score * 100
        # With max_score=105:
        score.score = 100  # 95.2% → A+
        self.assertEqual(score._calculate_grade(), "A+")
        score.score = 95   # 90.5% → A
        self.assertEqual(score._calculate_grade(), "A")
        score.score = 85   # 80.9% → B+
        self.assertEqual(score._calculate_grade(), "B+")
        score.score = 75   # 71.4% → B-
        self.assertEqual(score._calculate_grade(), "B-")
        score.score = 58   # 55.2% → C-
        self.assertEqual(score._calculate_grade(), "C-")
        score.score = 30   # 28.6% → F
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

    def test_null_mx_gets_full_mta_sts_score(self):
        """Null MX domains get full MTA-STS points — MTA-STS is inapplicable."""
        result = self._make_result(
            MX_COUNT=1,
            MX_HAS_NULL_MX=True,
        )
        score = SecurityScore(result)
        self.assertEqual(score.breakdown["mta_sts"]["score"], 10)

    def test_null_mx_mta_sts_details_short_circuit(self):
        """Null MX should short-circuit MTA-STS details."""
        result = self._make_result(
            MX_COUNT=1,
            MX_HAS_NULL_MX=True,
        )
        score = SecurityScore(result)
        details = score.breakdown["mta_sts"]["details"]
        self.assertEqual(len(details), 1)
        self.assertIn("Null MX", details[0][1])

    def test_bimi_pct_not_100_warning(self):
        """BIMI should warn when DMARC pct < 100."""
        result = self._make_result(
            BIMI_RECORD="v=BIMI1; l=https://test.com/logo.svg",
            BIMI_LOCATION="https://test.com/logo.svg",
            DMARC="v=DMARC1; p=reject; pct=50",
            DMARC_POLICY="reject",
            DMARC_PCT=50,
        )
        score = SecurityScore(result)
        details = score.breakdown["bimi"]["details"]
        pct_warnings = [d for d in details if "pct=100" in d[1]]
        self.assertTrue(len(pct_warnings) > 0, "Should warn about pct != 100")

    def test_bimi_pct_100_no_warning(self):
        """BIMI should not warn when DMARC pct=100."""
        result = self._make_result(
            BIMI_RECORD="v=BIMI1; l=https://test.com/logo.svg",
            BIMI_LOCATION="https://test.com/logo.svg",
            DMARC="v=DMARC1; p=reject; pct=100",
            DMARC_POLICY="reject",
            DMARC_PCT=100,
        )
        score = SecurityScore(result)
        details = score.breakdown["bimi"]["details"]
        pct_warnings = [d for d in details if "pct=100" in d[1]]
        self.assertEqual(len(pct_warnings), 0, "Should not warn when pct=100")

    def test_breakdown_has_all_categories(self):
        """Score breakdown includes all 10 categories."""
        result = self._make_result()
        score = SecurityScore(result)
        expected_cats = {"spf", "dmarc", "dkim", "bimi", "spoofability", "mta_sts", "mx", "dnssec", "dane", "caa"}
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
        self.assertIn("/105", output)


if __name__ == "__main__":
    unittest.main()
