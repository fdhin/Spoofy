# tests/test_dmarc.py

"""
Unit tests for the DMARC tag parser and policy discovery logic.

These tests cover the bugs identified in the external review:
  - split("p=") collision with sp= (Issue #2)
  - fo= detection too narrow (Issue #4)
  - Effective policy for org-domain fallback (Issue #1, logic only)
"""

import unittest
from unittest.mock import patch, MagicMock
from modules.dmarc import DMARC


class TestDmarcTagParser(unittest.TestCase):
    """Tests for the _parse_tags() method — Issue #2 fix validation."""

    def _make_dmarc_with_record(self, record):
        """Create a DMARC instance with a pre-set record, bypassing DNS."""
        with patch.object(DMARC, "get_dmarc_record", return_value=record), \
             patch.object(DMARC, "check_wildcard_dns", return_value=False):
            return DMARC("example.com")

    def test_p_tag_normal_order(self):
        """Standard ordering: p= before sp=."""
        d = self._make_dmarc_with_record("v=DMARC1; p=reject; sp=none;")
        self.assertEqual(d.policy, "reject")
        self.assertEqual(d.sp, "none")

    def test_p_tag_reversed_order(self):
        """BUG REGRESSION: sp= before p= must not confuse the parser.

        Old code: split("p=")[1] matched the 'p=' inside 'sp=reject',
        returning 'reject' instead of 'quarantine'.
        """
        d = self._make_dmarc_with_record("v=DMARC1; sp=reject; p=quarantine;")
        self.assertEqual(d.policy, "quarantine")
        self.assertEqual(d.sp, "reject")

    def test_aspf_does_not_collide_with_sp(self):
        """aspf= contains 'sp' as a substring — must not confuse sp= parser."""
        d = self._make_dmarc_with_record("v=DMARC1; p=reject; aspf=s;")
        self.assertEqual(d.aspf, "s")
        self.assertIsNone(d.sp)

    def test_all_tags_parsed(self):
        """Full record with all common tags."""
        record = (
            "v=DMARC1; p=reject; sp=quarantine; pct=50; aspf=s; "
            "rua=mailto:agg@example.com; ruf=mailto:for@example.com; fo=1"
        )
        d = self._make_dmarc_with_record(record)
        self.assertEqual(d.policy, "reject")
        self.assertEqual(d.sp, "quarantine")
        self.assertEqual(d.pct, "50")
        self.assertEqual(d.aspf, "s")
        self.assertEqual(d.rua, "mailto:agg@example.com")
        self.assertEqual(d.ruf, "mailto:for@example.com")
        self.assertEqual(d.fo, "1")

    def test_empty_record_returns_empty_tags(self):
        """None record should produce empty tags dict."""
        d = self._make_dmarc_with_record(None)
        self.assertEqual(d.tags, {})
        self.assertIsNone(d.policy)

    def test_whitespace_handling(self):
        """Tags with extra whitespace around = and ;."""
        d = self._make_dmarc_with_record("v=DMARC1 ;  p = reject ;  sp = none ;")
        self.assertEqual(d.policy, "reject")
        self.assertEqual(d.sp, "none")


class TestDmarcFoTag(unittest.TestCase):
    """Tests for fo= parsing — Issue #4 fix validation."""

    def _make_dmarc_with_record(self, record):
        with patch.object(DMARC, "get_dmarc_record", return_value=record), \
             patch.object(DMARC, "check_wildcard_dns", return_value=False):
            return DMARC("example.com")

    def test_fo_default_when_absent(self):
        """fo= defaults to '0' per RFC 7489 when not specified."""
        d = self._make_dmarc_with_record("v=DMARC1; p=reject;")
        self.assertEqual(d.fo, "0")

    def test_fo_simple_1(self):
        d = self._make_dmarc_with_record("v=DMARC1; p=reject; fo=1;")
        self.assertEqual(d.fo, "1")

    def test_fo_colon_separated(self):
        """fo=0:1:d:s — colon-separated combo must be preserved as-is."""
        d = self._make_dmarc_with_record("v=DMARC1; p=reject; fo=0:1:d:s;")
        self.assertEqual(d.fo, "0:1:d:s")

    def test_fo_d_only(self):
        d = self._make_dmarc_with_record("v=DMARC1; p=reject; fo=d;")
        self.assertEqual(d.fo, "d")

    def test_fo_s_only(self):
        d = self._make_dmarc_with_record("v=DMARC1; p=reject; fo=s;")
        self.assertEqual(d.fo, "s")

    def test_ruf_independent_of_fo(self):
        """ruf= and fo= are independent fields — ruf should exist even without fo=1."""
        d = self._make_dmarc_with_record(
            "v=DMARC1; p=reject; ruf=mailto:forensics@example.com;"
        )
        self.assertEqual(d.ruf, "mailto:forensics@example.com")
        self.assertEqual(d.fo, "0")  # default


class TestDmarcEffectivePolicy(unittest.TestCase):
    """Tests for effective_policy property — Issue #1 fix validation."""

    def _make_dmarc_with_record(self, record, is_fallback=False):
        with patch.object(DMARC, "get_dmarc_record", return_value=record), \
             patch.object(DMARC, "check_wildcard_dns", return_value=False):
            d = DMARC("mail.example.com")
            d.is_org_domain_fallback = is_fallback
            return d

    def test_direct_match_returns_p(self):
        """Direct DMARC match: effective_policy == p."""
        d = self._make_dmarc_with_record(
            "v=DMARC1; p=reject; sp=none;", is_fallback=False
        )
        self.assertEqual(d.effective_policy, "reject")

    def test_fallback_with_sp_returns_sp(self):
        """Org-domain fallback with sp=: effective_policy == sp."""
        d = self._make_dmarc_with_record(
            "v=DMARC1; p=reject; sp=none;", is_fallback=True
        )
        self.assertEqual(d.effective_policy, "none")

    def test_fallback_without_sp_returns_p(self):
        """Org-domain fallback without sp=: effective_policy falls back to p."""
        d = self._make_dmarc_with_record(
            "v=DMARC1; p=reject;", is_fallback=True
        )
        self.assertEqual(d.effective_policy, "reject")

    def test_fallback_sp_quarantine(self):
        d = self._make_dmarc_with_record(
            "v=DMARC1; p=reject; sp=quarantine;", is_fallback=True
        )
        self.assertEqual(d.effective_policy, "quarantine")


if __name__ == "__main__":
    unittest.main()
