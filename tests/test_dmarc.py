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

    def test_p_tag_reversed_order_aborts(self):
        """Strict ordering (RFC 7489 §6.3): 'p' MUST be the second tag.
        
        If 'sp' is before 'p', the record is functionally invalid and aborts.
        """
        d = self._make_dmarc_with_record("v=DMARC1; sp=reject; p=quarantine;")
        self.assertIsNone(d.policy)
        self.assertIsNone(d.sp)

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
        self.assertEqual(d.pct, 50)
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


class TestDmarcHardening(unittest.TestCase):
    """Tests RFC 7489 hard requirements."""
    
    def _make_dmarc_with_record(self, record):
        with patch.object(DMARC, "get_dmarc_record", return_value=record), \
             patch.object(DMARC, "check_wildcard_dns", return_value=False):
            return DMARC("example.com")

    def test_rua_fallback(self):
        """RFC §6.6.3 step 6: Invalid p with rua present falls back to p=none."""
        d = self._make_dmarc_with_record("v=DMARC1; p=typo; rua=mailto:a@b.c;")
        self.assertEqual(d.policy, "none")
        self.assertIsNone(d.sp)
        self.assertEqual(d.rua, "mailto:a@b.c")

    def test_invalid_p_no_rua_aborts(self):
        """RFC §6.6.3 step 6: Invalid p without rua aborts processing."""
        d = self._make_dmarc_with_record("v=DMARC1; p=typo;")
        self.assertIsNone(d.policy)
        self.assertIsNone(d.dmarc_record)
        self.assertEqual(d.tags, {})

    def test_strict_tag_ordering_invalid(self):
        """RFC §6.3: v and p must be in order."""
        # p is not second, no rua, so it aborts
        d = self._make_dmarc_with_record("v=DMARC1; rua=mailto:a@b.c; p=reject;")
        self.assertEqual(d.policy, "none") # Fallback to none because it's invalid but has rua
        self.assertFalse(d._is_ordering_valid)

    def test_tag_ordering_malformed_bypassing(self):
        """Test tag ordering handles tags lacking '=' properly (Bug 2)."""
        d = self._make_dmarc_with_record("v=DMARC1; malformed_tag; p=reject;")
        self.assertIsNone(d.policy)
        self.assertFalse(d._is_ordering_valid)

    def test_strict_tag_ordering_valid(self):
        """Valid tag ordering."""
        d = self._make_dmarc_with_record("v=DMARC1; p=reject; rua=mailto:a@b.c;")
        self.assertEqual(d.policy, "reject")
        self.assertTrue(d._is_ordering_valid)

    def test_case_insensitive_policy(self):
        """RFC 5234: literal text strings are case-insensitive (Bug 3)."""
        d = self._make_dmarc_with_record("v=DMARC1; p=REJECT; sp=QUARANTINE;")
        self.assertEqual(d.policy, "reject")
        self.assertEqual(d.sp, "quarantine")

    def test_pct_and_defaults(self):
        """Defaults and bad types should be handled safely."""
        d = self._make_dmarc_with_record("v=DMARC1; p=reject; pct=wat; adkim=wat;")
        self.assertEqual(d.pct, 100)
        self.assertEqual(d.adkim, "r")
        self.assertEqual(d.aspf, "r")

    @patch("dns.resolver.Resolver")
    def test_multiple_dmarc_records_aborts(self, mock_resolver_cls):
        """RFC §6.6.3 step 5: multiple records aborts without fallback (Bug 1)."""
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        
        # Create two valid DMARC1 answers
        mx1 = MagicMock()
        mx1.strings = [b"v=DMARC1; p=reject;"]
        mx2 = MagicMock()
        mx2.strings = [b"v=DMARC1; p=none;"]
        mock_resolver.resolve.return_value = [mx1, mx2]
        
        with patch.object(DMARC, "check_wildcard_dns", return_value=False):
            d = DMARC("sub.example.com")
            
        self.assertIsNone(d.dmarc_record)
        mock_resolver.resolve.assert_called_once_with("_dmarc.sub.example.com", "TXT")
        
    @patch("dns.resolver.Resolver")
    def test_idna_encoding(self, mock_resolver_cls):
        """RFC §6.6.1: IDNA encoding."""
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        
        mx1 = MagicMock()
        mx1.strings = [b"v=DMARC1; p=reject;"]
        mock_resolver.resolve.return_value = [mx1]
        
        with patch.object(DMARC, "check_wildcard_dns", return_value=False):
            d = DMARC("münchen.de")
            
        mock_resolver.resolve.assert_called_with("_dmarc.xn--mnchen-3ya.de", "TXT")
        self.assertEqual(d.policy, "reject")


class TestDmarcDuplicateTags(unittest.TestCase):
    """Tests for RFC 7489 §6.4: duplicate tag names invalidate the record.

    This was the core bug: a DMARC record with 'p=none; p=reject' was
    silently accepted as p=reject (last-wins), causing false 'protected'
    verdicts in the spoofing engine. With the txt_utils.parse_tag_value()
    integration, duplicate tags now invalidate the entire record.
    """

    def _make_dmarc_with_record(self, record):
        with patch.object(DMARC, "get_dmarc_record", return_value=record), \
             patch.object(DMARC, "check_wildcard_dns", return_value=False):
            return DMARC("example.com")

    def test_duplicate_p_tag_invalidates(self):
        """Duplicate p= tags must invalidate the entire record."""
        d = self._make_dmarc_with_record("v=DMARC1; p=none; p=reject;")
        self.assertEqual(d.tags, {})
        self.assertIsNone(d.dmarc_record)

    def test_duplicate_rua_invalidates(self):
        """Duplicate rua= tags must invalidate the entire record."""
        d = self._make_dmarc_with_record(
            "v=DMARC1; p=reject; rua=mailto:a@b.c; rua=mailto:x@y.z;"
        )
        self.assertEqual(d.tags, {})
        self.assertIsNone(d.dmarc_record)

    def test_duplicate_v_tag_invalidates(self):
        """Duplicate v= tags must invalidate the entire record."""
        d = self._make_dmarc_with_record("v=DMARC1; p=reject; v=DMARC1;")
        self.assertEqual(d.tags, {})
        self.assertIsNone(d.dmarc_record)

    def test_no_duplicates_is_valid(self):
        """Normal record with no duplicates must parse correctly."""
        d = self._make_dmarc_with_record("v=DMARC1; p=reject; rua=mailto:a@b.c;")
        self.assertEqual(d.policy, "reject")
        self.assertEqual(d.rua, "mailto:a@b.c")
        self.assertIsNotNone(d.dmarc_record)


class TestDmarcMultiStringTXT(unittest.TestCase):
    """Tests for multi-string TXT record handling via txt_utils.

    DMARC records exceeding 255 bytes are split into multiple TXT strings
    by DNS. The parse_txt_record() function must join them without
    injecting spaces at the boundary.
    """

    @patch("dns.resolver.Resolver")
    def test_multi_string_joined_correctly(self, mock_resolver_cls):
        """Multi-string TXT records must be joined without space injection."""
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        # Simulate a DMARC record split across two TXT strings
        rdata = MagicMock()
        rdata.strings = [
            b"v=DMARC1; p=reject; rua=mailto:agg@example.com; ruf=mailt",
            b"o:for@example.com; aspf=s; adkim=r; pct=100; fo=1",
        ]
        mock_resolver.resolve.return_value = [rdata]

        with patch.object(DMARC, "check_wildcard_dns", return_value=False):
            d = DMARC("example.com")

        self.assertEqual(d.policy, "reject")
        self.assertEqual(d.ruf, "mailto:for@example.com")
        self.assertEqual(d.aspf, "s")
        self.assertEqual(d.pct, 100)
        self.assertEqual(d.fo, "1")

    @patch("dns.resolver.Resolver")
    def test_multi_string_no_space_in_rua(self, mock_resolver_cls):
        """Boundary split inside a mailto: URI must not inject a space."""
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        # Split right in the middle of the rua mailto: URI
        rdata = MagicMock()
        rdata.strings = [
            b"v=DMARC1; p=reject; rua=mailto:very-long-address@exa",
            b"mple.com",
        ]
        mock_resolver.resolve.return_value = [rdata]

        with patch.object(DMARC, "check_wildcard_dns", return_value=False):
            d = DMARC("example.com")

        self.assertEqual(d.rua, "mailto:very-long-address@example.com")


class TestDmarcSubstringCollision(unittest.TestCase):
    """Tests verifying tag names don't collide with substrings.

    The old split("p=") approach would match "p=" inside "aspf=" or "sp=".
    With parse_tag_value() using partition("=") per-token, each tag is
    parsed independently.
    """

    def _make_dmarc_with_record(self, record):
        with patch.object(DMARC, "get_dmarc_record", return_value=record), \
             patch.object(DMARC, "check_wildcard_dns", return_value=False):
            return DMARC("example.com")

    def test_aspf_does_not_affect_p(self):
        """aspf=r must not interfere with p=reject parsing."""
        d = self._make_dmarc_with_record("v=DMARC1; p=reject; aspf=r;")
        self.assertEqual(d.policy, "reject")
        self.assertEqual(d.aspf, "r")

    def test_sp_does_not_affect_p(self):
        """sp=none must not interfere with p=reject parsing."""
        d = self._make_dmarc_with_record("v=DMARC1; p=reject; sp=none;")
        self.assertEqual(d.policy, "reject")
        self.assertEqual(d.sp, "none")

    def test_adkim_does_not_affect_other_tags(self):
        """adkim=s must not collide with any other tag."""
        d = self._make_dmarc_with_record("v=DMARC1; p=reject; adkim=s; aspf=s;")
        self.assertEqual(d.adkim, "s")
        self.assertEqual(d.aspf, "s")
        self.assertEqual(d.policy, "reject")


if __name__ == "__main__":
    unittest.main()
