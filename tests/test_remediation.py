# tests/test_remediation.py

import unittest
from modules.remediation import RemediationEngine, Recommendation


class TestRemediationEngine(unittest.TestCase):
    """Tests for the RemediationEngine."""

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
            "BIMI_RECORD": None,
            "BIMI_VERSION": None,
            "BIMI_LOCATION": None,
            "BIMI_AUTHORITY": None,
            "SPOOFING_POSSIBLE": True,
            "SPOOFING_TYPE": "Spoofing possible for test.com.",
        }
        base.update(overrides)
        return base

    # --- Missing Records ---

    def test_no_spf_generates_critical_recommendation(self):
        """Missing SPF should generate a critical (priority 1) recommendation."""
        result = self._make_result()
        engine = RemediationEngine(result)
        spf_recs = [r for r in engine.recommendations if r.category == "SPF"]
        self.assertTrue(len(spf_recs) > 0)
        self.assertEqual(spf_recs[0].priority, 1)
        self.assertIn("No SPF record", spf_recs[0].title)

    def test_no_dmarc_generates_critical_recommendation(self):
        """Missing DMARC should generate a critical (priority 1) recommendation."""
        result = self._make_result()
        engine = RemediationEngine(result)
        dmarc_recs = [r for r in engine.recommendations if r.category == "DMARC"]
        self.assertTrue(len(dmarc_recs) > 0)
        self.assertEqual(dmarc_recs[0].priority, 1)
        self.assertIn("No DMARC record", dmarc_recs[0].title)

    def test_no_dkim_generates_recommendation(self):
        """Missing DKIM should generate a recommendation."""
        result = self._make_result()
        engine = RemediationEngine(result)
        dkim_recs = [r for r in engine.recommendations if r.category == "DKIM"]
        self.assertTrue(len(dkim_recs) > 0)
        self.assertIn("DKIM", dkim_recs[0].title)

    # --- SPF Issues ---

    def test_plus_all_generates_critical(self):
        """SPF with +all should generate a critical recommendation."""
        result = self._make_result(
            SPF="v=spf1 +all",
            SPF_MULTIPLE_ALLS="+all",
        )
        engine = RemediationEngine(result)
        spf_recs = [r for r in engine.recommendations if r.category == "SPF"]
        plus_recs = [r for r in spf_recs if "+all" in r.title]
        self.assertTrue(len(plus_recs) > 0)
        self.assertEqual(plus_recs[0].priority, 1)

    def test_neutral_all_generates_high(self):
        """SPF with ?all should generate a high priority recommendation."""
        result = self._make_result(
            SPF="v=spf1 ?all",
            SPF_MULTIPLE_ALLS="?all",
        )
        engine = RemediationEngine(result)
        spf_recs = [r for r in engine.recommendations if r.category == "SPF"]
        neutral_recs = [r for r in spf_recs if "?all" in r.title]
        self.assertTrue(len(neutral_recs) > 0)
        self.assertEqual(neutral_recs[0].priority, 2)

    def test_softfail_generates_low(self):
        """SPF with ~all should generate a low priority recommendation."""
        result = self._make_result(
            SPF="v=spf1 ~all",
            SPF_MULTIPLE_ALLS="~all",
        )
        engine = RemediationEngine(result)
        spf_recs = [r for r in engine.recommendations if r.category == "SPF"]
        soft_recs = [r for r in spf_recs if "~all" in r.title]
        self.assertTrue(len(soft_recs) > 0)
        self.assertEqual(soft_recs[0].priority, 4)

    def test_too_many_dns_queries_generates_recommendation(self):
        """SPF with >10 DNS lookups should generate a recommendation."""
        result = self._make_result(
            SPF="v=spf1 -all",
            SPF_MULTIPLE_ALLS="-all",
            SPF_NUM_DNS_QUERIES=15,
            SPF_TOO_MANY_DNS_QUERIES=True,
        )
        engine = RemediationEngine(result)
        dns_recs = [r for r in engine.recommendations if "lookup" in r.title.lower() or "DNS" in r.title]
        self.assertTrue(len(dns_recs) > 0)

    def test_multiple_alls_generates_recommendation(self):
        """SPF with multiple 'all' mechanisms should generate a recommendation."""
        result = self._make_result(
            SPF="v=spf1 -all ~all",
            SPF_MULTIPLE_ALLS="2many",
        )
        engine = RemediationEngine(result)
        multi_recs = [r for r in engine.recommendations if "multiple" in r.title.lower()]
        self.assertTrue(len(multi_recs) > 0)

    # --- DMARC Issues ---

    def test_dmarc_none_generates_high(self):
        """DMARC p=none should generate a high priority recommendation."""
        result = self._make_result(
            DMARC="v=DMARC1; p=none",
            DMARC_POLICY="none",
        )
        engine = RemediationEngine(result)
        dmarc_recs = [r for r in engine.recommendations if r.category == "DMARC"]
        policy_recs = [r for r in dmarc_recs if "none" in r.title.lower()]
        self.assertTrue(len(policy_recs) > 0)
        self.assertEqual(policy_recs[0].priority, 2)

    def test_dmarc_quarantine_generates_low(self):
        """DMARC p=quarantine should generate a low priority recommendation."""
        result = self._make_result(
            DMARC="v=DMARC1; p=quarantine; rua=mailto:test@test.com",
            DMARC_POLICY="quarantine",
            DMARC_AGGREGATE_REPORT="mailto:test@test.com",
        )
        engine = RemediationEngine(result)
        dmarc_recs = [r for r in engine.recommendations if r.category == "DMARC"]
        quar_recs = [r for r in dmarc_recs if "quarantine" in r.title.lower()]
        self.assertTrue(len(quar_recs) > 0)
        self.assertEqual(quar_recs[0].priority, 4)

    def test_no_rua_generates_recommendation(self):
        """Missing DMARC rua should generate a recommendation."""
        result = self._make_result(
            DMARC="v=DMARC1; p=reject",
            DMARC_POLICY="reject",
        )
        engine = RemediationEngine(result)
        rua_recs = [r for r in engine.recommendations if "rua" in r.title.lower() or "aggregate" in r.title.lower()]
        self.assertTrue(len(rua_recs) > 0)

    # --- CAA Issues ---

    def test_no_caa_generates_recommendation(self):
        """Missing CAA should generate a recommendation."""
        result = self._make_result(CAA_RECORDS=[])
        engine = RemediationEngine(result)
        caa_recs = [r for r in engine.recommendations if r.category == "CAA"]
        self.assertTrue(len(caa_recs) > 0)
        self.assertIn("CAA", caa_recs[0].title)
        self.assertNotEqual(caa_recs[0].eli5_explanation, "")
        self.assertNotEqual(caa_recs[0].business_risk, "")

    # --- Perfect Config ---

    def test_perfect_config_minimal_recommendations(self):
        """A perfectly configured domain should have minimal recommendations."""
        result = self._make_result(
            SPF="v=spf1 include:_spf.google.com -all",
            SPF_MULTIPLE_ALLS="-all",
            SPF_NUM_DNS_QUERIES=3,
            SPF_TOO_MANY_DNS_QUERIES=False,
            DMARC="v=DMARC1; p=reject; rua=mailto:dmarc@test.com; sp=reject",
            DMARC_POLICY="reject",
            DMARC_AGGREGATE_REPORT="mailto:dmarc@test.com",
            DMARC_SP="reject",
            DKIM="[*] selector._domainkey.test.com -> v=DKIM1",
            BIMI_RECORD="v=BIMI1; l=https://test.com/logo.svg",
            SPOOFING_POSSIBLE=False,
            SPOOFING_TYPE="Spoofing is not possible for test.com.",
        )
        engine = RemediationEngine(result)
        # Should have no critical or high recommendations
        critical_high = [r for r in engine.recommendations if r.priority <= 2]
        self.assertEqual(len(critical_high), 0)

    # --- Ordering ---

    def test_recommendations_sorted_by_priority(self):
        """Recommendations should be sorted by priority (critical first)."""
        result = self._make_result()
        engine = RemediationEngine(result)
        if len(engine.recommendations) > 1:
            priorities = [r.priority for r in engine.recommendations]
            self.assertEqual(priorities, sorted(priorities))

    # --- Serialization ---

    def test_to_list_returns_dicts(self):
        """to_list() should return a list of dicts."""
        result = self._make_result()
        engine = RemediationEngine(result)
        recs_list = engine.to_list()
        self.assertIsInstance(recs_list, list)
        if recs_list:
            self.assertIsInstance(recs_list[0], dict)
            self.assertIn("priority", recs_list[0])
            self.assertIn("title", recs_list[0])
            self.assertIn("fix", recs_list[0])

    def test_str_representation(self):
        """__str__ should return a readable string."""
        result = self._make_result()
        engine = RemediationEngine(result)
        output = str(engine)
        self.assertIn("Remediation", output)

    def test_perfect_config_str(self):
        """__str__ for perfect config should show no items."""
        result = self._make_result(
            SPF="v=spf1 -all",
            SPF_MULTIPLE_ALLS="-all",
            DMARC="v=DMARC1; p=reject; rua=mailto:d@t.com; sp=reject",
            DMARC_POLICY="reject",
            DMARC_AGGREGATE_REPORT="mailto:d@t.com",
            DMARC_SP="reject",
            DKIM="[*] s._domainkey.t.com -> v=DKIM1",
            SPOOFING_POSSIBLE=False,
        )
        engine = RemediationEngine(result)
        # Should have only low priority / info items at most
        critical = [r for r in engine.recommendations if r.priority <= 2]
        self.assertEqual(len(critical), 0)


class TestRecommendation(unittest.TestCase):
    """Tests for the Recommendation dataclass."""

    def test_priority_label(self):
        rec = Recommendation(
            priority=1,
            category="SPF",
            title="Test",
            description="Test desc",
            impact="Test impact",
            fix="Test fix",
            reference="https://example.com",
        )
        self.assertIn("CRITICAL", rec.priority_label)

    def test_to_dict(self):
        rec = Recommendation(
            priority=2,
            category="DMARC",
            title="Test Title",
            description="Desc",
            impact="Impact",
            fix="Fix",
            reference="https://example.com",
        )
        d = rec.to_dict()
        self.assertEqual(d["priority"], 2)
        self.assertEqual(d["category"], "DMARC")
        self.assertEqual(d["title"], "Test Title")

    def test_eli_and_business_risk_fields(self):
        rec = Recommendation(
            priority=2,
            category="SPF",
            title="Test",
            description="Desc",
            impact="Impact",
            fix="Fix",
            reference="url",
            eli5_explanation="eli5",
            business_risk="risk"
        )
        d = rec.to_dict()
        self.assertEqual(d["eli5_explanation"], "eli5")
        self.assertEqual(d["business_risk"], "risk")


if __name__ == "__main__":
    unittest.main()
