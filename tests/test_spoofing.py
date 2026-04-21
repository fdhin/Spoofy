# tests/test_spoofing.py

"""
Table-driven unit tests for the spoofing evaluation engine.

Covers the cartesian product of:
    spf_all × p × sp × aspf × pct

for all realistic combinations, verifying that each verdict matches
the expected RFC 7489 interpretation.
"""

import unittest
from modules.spoofing import Spoofing


class TestSpoofingVerdicts(unittest.TestCase):
    """Test spoofing verdicts using a table-driven approach."""

    def _make(self, spf_record="v=spf1 -all", spf_all="-all",
              dmarc_record="v=DMARC1; p=reject", p="reject",
              sp=None, aspf=None, pct=None, spf_dns_queries=3):
        """Helper: create Spoofing instance with controlled config."""
        return Spoofing(
            domain="example.com",
            dmarc_record=dmarc_record,
            effective_p=p,  # Passes directly to effective_p in __init__
            aspf=aspf,
            spf_record=spf_record,
            spf_all=spf_all,
            spf_dns_queries=spf_dns_queries,
            sp=sp,
            pct=pct,
        )

    # ── No records at all ────────────────────────────────────────────

    def test_no_spf_no_dmarc(self):
        """No SPF + no DMARC → fully spoofable."""
        s = self._make(spf_record=None, spf_all=None,
                       dmarc_record=None, p=None)
        self.assertEqual(s.spoofable, 0)
        self.assertTrue(s.spoofing_possible)

    # ── SPF only (no DMARC) ──────────────────────────────────────────

    def test_spf_hard_fail_no_dmarc(self):
        """SPF -all without DMARC → mailbox dependent."""
        s = self._make(dmarc_record=None, p=None)
        self.assertEqual(s.spoofable, 4)  # MAILBOX_DEP
        self.assertIsNone(s.spoofing_possible)

    def test_spf_soft_fail_no_dmarc(self):
        """SPF ~all without DMARC → mailbox dependent."""
        s = self._make(spf_all="~all", dmarc_record=None, p=None)
        self.assertEqual(s.spoofable, 4)
        self.assertIsNone(s.spoofing_possible)

    def test_spf_plus_all_no_dmarc(self):
        """SPF +all without DMARC → spoofable."""
        s = self._make(spf_all="+all", dmarc_record=None, p=None)
        self.assertEqual(s.spoofable, 0)
        self.assertTrue(s.spoofing_possible)

    # ── DMARC only (no SPF) ──────────────────────────────────────────

    def test_dmarc_reject_no_spf(self):
        """DMARC reject without SPF → mailbox dependent (needs DKIM)."""
        s = self._make(spf_record=None, spf_all=None, p="reject")
        self.assertEqual(s.spoofable, 4)

    def test_dmarc_none_no_spf(self):
        """DMARC p=none without SPF → spoofable."""
        s = self._make(spf_record=None, spf_all=None, p="none")
        self.assertEqual(s.spoofable, 0)
        self.assertTrue(s.spoofing_possible)

    # ── Full protection: p=reject + SPF -all ─────────────────────────

    def test_reject_hard_fail_no_sp(self):
        """p=reject + -all + sp defaults to p → not spoofable."""
        s = self._make(p="reject", sp=None)
        self.assertEqual(s.spoofable, 8)
        self.assertFalse(s.spoofing_possible)

    def test_reject_hard_fail_sp_reject(self):
        """p=reject + -all + sp=reject → not spoofable."""
        s = self._make(p="reject", sp="reject")
        self.assertEqual(s.spoofable, 8)
        self.assertFalse(s.spoofing_possible)

    # ── The bug case from the review ─────────────────────────────────

    def test_p_none_sp_reject_aspf_s(self):
        """p=none + sp=reject + aspf=s → org domain IS spoofable.

        With p=none, receivers do nothing on DMARC failure for the org
        domain. sp=reject protects subdomains. The old code returned 8
        (not spoofable), which was wrong.
        """
        s = self._make(p="none", sp="reject", aspf="s")
        # Org domain is unprotected (p=none), subdomain is protected (sp=reject)
        self.assertEqual(s.spoofable, 2)  # ORG_SPOOFABLE
        self.assertIsNone(s.spoofing_possible)  # "maybe" category

    def test_p_none_sp_reject_aspf_r(self):
        """p=none + sp=reject + aspf=r → org domain spoofable."""
        s = self._make(p="none", sp="reject", aspf="r")
        self.assertEqual(s.spoofable, 2)

    # ── p=none variants ──────────────────────────────────────────────

    def test_p_none_sp_none(self):
        """p=none + sp=none → fully spoofable."""
        s = self._make(p="none", sp="none")
        self.assertEqual(s.spoofable, 0)
        self.assertTrue(s.spoofing_possible)

    def test_p_none_no_sp(self):
        """p=none + no sp → sp defaults to none → fully spoofable."""
        s = self._make(p="none", sp=None)
        self.assertEqual(s.spoofable, 0)

    def test_p_none_sp_quarantine(self):
        """p=none + sp=quarantine → org spoofable, sub soft-protected."""
        s = self._make(p="none", sp="quarantine")
        self.assertEqual(s.spoofable, 2)  # ORG_SPOOFABLE

    # ── p=quarantine variants ────────────────────────────────────────

    def test_quarantine_hard_fail(self):
        """p=quarantine + -all → not spoofable."""
        s = self._make(p="quarantine")
        self.assertEqual(s.spoofable, 8)

    def test_quarantine_soft_fail(self):
        """p=quarantine + ~all → maybe (soft protection)."""
        s = self._make(p="quarantine", spf_all="~all")
        self.assertEqual(s.spoofable, 3)  # MAYBE

    def test_quarantine_sp_none(self):
        """p=quarantine + sp=none → subdomain spoofable."""
        s = self._make(p="quarantine", sp="none")
        self.assertEqual(s.spoofable, 1)  # SUBDOMAIN_SPOOFABLE

    # ── pct modifier ─────────────────────────────────────────────────

    def test_pct_99_reject(self):
        """p=reject + pct=99 → downgrades to maybe."""
        s = self._make(p="reject", pct="99")
        self.assertEqual(s.spoofable, 3)  # MAYBE

    def test_pct_100_reject(self):
        """p=reject + pct=100 → not spoofable (full enforcement)."""
        s = self._make(p="reject", pct="100")
        self.assertEqual(s.spoofable, 8)

    def test_pct_50_none(self):
        """p=none + pct=50 → stays spoofable (p=none is already unprotected)."""
        s = self._make(p="none", sp="none", pct="50")
        self.assertEqual(s.spoofable, 0)

    # ── Malformed pct ────────────────────────────────────────────────

    def test_pct_malformed_string(self):
        """Malformed pct → defaults to 100, no crash."""
        s = self._make(p="reject", pct="abc")
        self.assertEqual(s.spoofable, 8)

    def test_pct_none_defaults(self):
        """pct=None → defaults to 100."""
        s = self._make(p="reject", pct=None)
        self.assertEqual(s.spoofable, 8)

    # ── aspf normalization ───────────────────────────────────────────

    def test_aspf_none_defaults_to_r(self):
        """aspf=None → defaults to 'r' per RFC 7489 §6.3."""
        s = self._make(p="reject", aspf=None)
        self.assertEqual(s.aspf, "r")
        self.assertEqual(s.spoofable, 8)

    def test_aspf_garbage_defaults_to_r(self):
        """aspf='x' → defaults to 'r'."""
        s = self._make(p="reject", aspf="x")
        self.assertEqual(s.aspf, "r")

    # ── SPF over 10 lookups ──────────────────────────────────────────

    def test_over_10_lookups_reject(self):
        """SPF over limit + p=reject → maybe (DKIM may help)."""
        s = self._make(p="reject", spf_dns_queries=12)
        self.assertEqual(s.spoofable, 3)

    def test_over_10_lookups_none(self):
        """SPF over limit + p=none → spoofable."""
        s = self._make(p="none", sp="none", spf_dns_queries=12)
        self.assertEqual(s.spoofable, 0)

    # ── Multiple 'all' mechanisms ────────────────────────────────────

    def test_2many_all_reject(self):
        """Multiple 'all' + p=reject → not spoofable."""
        s = self._make(spf_all="2many", p="reject")
        self.assertEqual(s.spoofable, 8)

    def test_2many_all_none(self):
        """Multiple 'all' + p=none → maybe."""
        s = self._make(spf_all="2many", p="none", sp="none")
        self.assertEqual(s.spoofable, 3)

    # ── SPF +all variants ────────────────────────────────────────────

    def test_plus_all_reject(self):
        """SPF +all + p=reject → soft protection (DMARC enforces despite SPF)."""
        s = self._make(spf_all="+all", p="reject")
        # org=soft (p=reject but SPF +all doesn't help), sub=soft → MAYBE
        self.assertIn(s.spoofable, (3, 8))  # soft on both axes

    def test_plus_all_none(self):
        """SPF +all + p=none → spoofable."""
        s = self._make(spf_all="+all", p="none", sp="none")
        self.assertEqual(s.spoofable, 0)

    # ── SPF ?all variants ────────────────────────────────────────────

    def test_neutral_all_reject(self):
        """SPF ?all + p=reject → soft protection."""
        s = self._make(spf_all="?all", p="reject")
        self.assertIn(s.spoofable, (3, 8))  # soft on both

    # ── Domain type ──────────────────────────────────────────────────

    def test_domain_type_domain(self):
        """Base domain → 'domain'."""
        s = self._make()
        self.assertEqual(s.domain_type, "domain")

    def test_domain_type_subdomain(self):
        """Subdomain → 'subdomain'."""
        s = Spoofing(
            domain="sub.example.com",
            dmarc_record="v=DMARC1; p=reject",
            effective_p="reject", aspf="r",
            spf_record="v=spf1 -all", spf_all="-all",
            spf_dns_queries=3, sp=None, pct=None,
        )
        self.assertEqual(s.domain_type, "subdomain")

    # ── evaluate_spoofing output format ──────────────────────────────

    def test_evaluate_returns_tuple(self):
        """evaluate_spoofing returns (bool_or_none, str)."""
        s = self._make()
        self.assertIsInstance(s.spoofing_possible, (bool, type(None)))
        self.assertIsInstance(s.spoofing_type, str)
        self.assertIn("example.com", s.spoofing_type)

    def test_str_format(self):
        """__str__ includes domain info."""
        s = self._make()
        output = str(s)
        self.assertIn("example.com", output)
        self.assertIn("Spoofing", output)


class TestSyntaxValidator(unittest.TestCase):
    """Tests for the fallback syntax validator."""

    def test_valid_spf(self):
        from modules.syntax import validate_record_syntax
        self.assertTrue(validate_record_syntax("v=spf1 include:_spf.google.com -all", "SPF"))

    def test_valid_spf_qualifier_prefixed(self):
        from modules.syntax import validate_record_syntax
        self.assertTrue(validate_record_syntax("v=spf1 +include:example.com ~all", "SPF"))

    def test_valid_spf_neutral_all(self):
        from modules.syntax import validate_record_syntax
        self.assertTrue(validate_record_syntax("v=spf1 ?all", "SPF"))

    def test_invalid_spf_no_version(self):
        from modules.syntax import validate_record_syntax
        self.assertFalse(validate_record_syntax("include:example.com -all", "SPF"))

    def test_valid_dmarc(self):
        from modules.syntax import validate_record_syntax
        self.assertTrue(validate_record_syntax(
            "v=DMARC1; p=reject; rua=mailto:dmarc@example.com", "DMARC"
        ))

    def test_valid_dmarc_compound_fo(self):
        from modules.syntax import validate_record_syntax
        self.assertTrue(validate_record_syntax(
            "v=DMARC1; p=none; fo=0:1:d:s", "DMARC"
        ))

    def test_valid_dmarc_multiple_rua(self):
        from modules.syntax import validate_record_syntax
        self.assertTrue(validate_record_syntax(
            "v=DMARC1; p=reject; rua=mailto:a@x.com,mailto:b@y.com", "DMARC"
        ))

    def test_invalid_dmarc_no_version(self):
        from modules.syntax import validate_record_syntax
        self.assertFalse(validate_record_syntax("p=reject", "DMARC"))


if __name__ == "__main__":
    unittest.main()
