# tests/test_dane.py

"""Tests for the DANE/TLSA detection module."""

import unittest
from unittest.mock import patch, MagicMock

import dns.resolver
import dns.flags

from modules.dane import DANE


class FakeTLSA:
    """Minimal fake TLSA rdata for testing."""
    def __init__(self, usage=3, selector=1, mtype=1, cert=None):
        self.usage = usage
        self.selector = selector
        self.mtype = mtype
        # Default: valid SHA-256 hash (32 bytes)
        self.cert = cert if cert is not None else (b'\xab' * 32)


def _make_ad_response():
    """Create a mock response with the AD flag set."""
    answer = MagicMock()
    answer.response = MagicMock()
    answer.response.flags = dns.flags.AD
    answer.__iter__ = lambda self: iter([FakeTLSA()])
    return answer


def _make_non_ad_response():
    """Create a mock response without the AD flag."""
    answer = MagicMock()
    answer.response = MagicMock()
    answer.response.flags = 0
    answer.__iter__ = lambda self: iter([FakeTLSA()])
    return answer


class TestDANEDetection(unittest.TestCase):
    """Test DANE/TLSA record detection."""

    @patch("modules.dane.dns.resolver.Resolver")
    def test_tlsa_found_with_ad(self, mock_resolver_cls):
        """TLSA records with AD flag should set has_dane to True."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        cd_answer = [FakeTLSA()]
        ad_answer = _make_ad_response()

        def resolve_side_effect(name, rdtype):
            return cd_answer

        resolver.resolve = MagicMock(side_effect=resolve_side_effect)
        # Override: second call (AD check) returns AD flag
        resolver.resolve.side_effect = [cd_answer, ad_answer]

        dane = DANE("example.com", ["mx1.example.com"])
        self.assertTrue(dane.has_dane)
        self.assertEqual(dane.dane_mx_count, 1)
        self.assertEqual(len(dane.tlsa_records), 1)
        self.assertTrue(dane.tlsa_records[0]["ad_flag"])
        self.assertFalse(dane.tlsa_records[0]["is_bogus"])

    @patch("modules.dane.dns.resolver.Resolver")
    def test_tlsa_found_without_ad(self, mock_resolver_cls):
        """TLSA records without AD flag should NOT count as secure DANE."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        cd_answer = [FakeTLSA()]
        non_ad_answer = _make_non_ad_response()

        resolver.resolve = MagicMock(side_effect=[cd_answer, non_ad_answer])

        dane = DANE("example.com", ["mx1.example.com"])
        # Records exist but not secure
        self.assertFalse(dane.has_dane)  # Not secure
        self.assertEqual(dane.dane_mx_count, 0)
        self.assertEqual(len(dane.tlsa_records), 1)
        self.assertFalse(dane.tlsa_records[0]["ad_flag"])

    @patch("modules.dane.dns.resolver.Resolver")
    def test_no_tlsa(self, mock_resolver_cls):
        """No TLSA records should leave has_dane as False."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.side_effect = dns.resolver.NoAnswer()
        dane = DANE("example.com", ["mx1.example.com"])
        self.assertFalse(dane.has_dane)
        self.assertEqual(dane.dane_mx_count, 0)
        self.assertEqual(len(dane.tlsa_records), 0)

    @patch("modules.dane.dns.resolver.Resolver")
    def test_nxdomain(self, mock_resolver_cls):
        """NXDOMAIN should not set has_dane."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        dane = DANE("example.com", ["mx1.example.com"])
        self.assertFalse(dane.has_dane)

    @patch("modules.dane.dns.resolver.Resolver")
    def test_timeout(self, mock_resolver_cls):
        """Timeout should not set has_dane."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.side_effect = dns.resolver.Timeout()
        dane = DANE("example.com", ["mx1.example.com"])
        self.assertFalse(dane.has_dane)

    @patch("modules.dane.dns.resolver.Resolver")
    def test_no_nameservers(self, mock_resolver_cls):
        """NoNameservers should not set has_dane."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.side_effect = dns.resolver.NoNameservers()
        dane = DANE("example.com", ["mx1.example.com"])
        self.assertFalse(dane.has_dane)


class TestDANEBogusDetection(unittest.TestCase):
    """Test SERVFAIL/bogus DNSSEC detection."""

    @patch("modules.dane.dns.resolver.Resolver")
    def test_bogus_dnssec_detected(self, mock_resolver_cls):
        """CD query succeeds but AD query SERVFAILs → bogus state detected."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        cd_answer = [FakeTLSA()]
        # AD query raises exception (SERVFAIL)
        resolver.resolve = MagicMock(
            side_effect=[cd_answer, dns.resolver.NoNameservers()]
        )

        dane = DANE("example.com", ["mx1.example.com"])
        self.assertFalse(dane.has_dane)  # Not secure
        self.assertEqual(len(dane.tlsa_records), 1)
        self.assertTrue(dane.tlsa_records[0]["is_bogus"])

    @patch("modules.dane.dns.resolver.Resolver")
    def test_bogus_in_str(self, mock_resolver_cls):
        """Bogus state should appear in string representation."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        cd_answer = [FakeTLSA()]
        resolver.resolve = MagicMock(
            side_effect=[cd_answer, dns.resolver.NoNameservers()]
        )

        dane = DANE("example.com", ["mx1.example.com"])
        self.assertIn("FATAL OUTAGE", str(dane))
        self.assertIn("BOGUS", str(dane))

    @patch("modules.dane.dns.resolver.Resolver")
    def test_empty_tlsa_but_servfail(self, mock_resolver_cls):
        """CD=1 returns NoAnswer but CD=0 SERVFAILs → bogus detected.

        This catches broken DNSSEC denial-of-existence (NSEC/NSEC3).
        """
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        # CD=1 succeeds with NoAnswer, CD=0 SERVFAILs
        resolver.resolve = MagicMock(
            side_effect=[dns.resolver.NoAnswer(), dns.resolver.NoNameservers()]
        )

        dane = DANE("example.com", ["mx1.example.com"])
        # No real TLSA records, but bogus state detected via dummy
        d = dane.to_dict()
        self.assertFalse(d["DANE_HAS_TLSA"])  # No real records
        self.assertTrue(d["DANE_HAS_BOGUS_RECORDS"])  # Bogus detected
        self.assertIn("FATAL OUTAGE", str(dane))

    @patch("modules.dane.dns.resolver.Resolver")
    def test_empty_tlsa_no_servfail_clean(self, mock_resolver_cls):
        """CD=1 NoAnswer + CD=0 NoAnswer → clean, no bogus."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        # Both queries return NoAnswer (no records, DNSSEC is fine)
        resolver.resolve = MagicMock(
            side_effect=[dns.resolver.NoAnswer(), dns.resolver.NoAnswer()]
        )

        dane = DANE("example.com", ["mx1.example.com"])
        d = dane.to_dict()
        self.assertFalse(d["DANE_HAS_TLSA"])
        self.assertFalse(d["DANE_HAS_BOGUS_RECORDS"])
        self.assertIn("No TLSA", str(dane))


class TestDANEValidation(unittest.TestCase):
    """Test TLSA record validation (hash lengths, unknown params)."""

    @patch("modules.dane.dns.resolver.Resolver")
    def test_valid_sha256_hash(self, mock_resolver_cls):
        """Valid SHA-256 hash (32 bytes) should be supported."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        cd_answer = [FakeTLSA(mtype=1, cert=b'\xab' * 32)]
        ad_answer = _make_ad_response()
        resolver.resolve = MagicMock(side_effect=[cd_answer, ad_answer])

        dane = DANE("example.com", ["mx1.example.com"])
        self.assertTrue(dane.tlsa_records[0]["is_supported"])
        self.assertEqual(dane.tlsa_records[0]["validation_errors"], [])

    @patch("modules.dane.dns.resolver.Resolver")
    def test_truncated_sha256_hash_flagged(self, mock_resolver_cls):
        """Truncated SHA-256 hash (31 bytes) should be flagged as unsupported."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        cd_answer = [FakeTLSA(mtype=1, cert=b'\xab' * 31)]
        ad_answer = _make_ad_response()
        resolver.resolve = MagicMock(side_effect=[cd_answer, ad_answer])

        dane = DANE("example.com", ["mx1.example.com"])
        self.assertFalse(dane.tlsa_records[0]["is_supported"])
        self.assertTrue(any("SHA-256" in e for e in dane.tlsa_records[0]["validation_errors"]))

    @patch("modules.dane.dns.resolver.Resolver")
    def test_unknown_usage_flagged(self, mock_resolver_cls):
        """Usage value outside 0-3 should be flagged as unsupported."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        cd_answer = [FakeTLSA(usage=99, cert=b'\xab' * 32)]
        ad_answer = _make_ad_response()
        resolver.resolve = MagicMock(side_effect=[cd_answer, ad_answer])

        dane = DANE("example.com", ["mx1.example.com"])
        self.assertFalse(dane.tlsa_records[0]["is_supported"])


class TestDANEMultipleMX(unittest.TestCase):
    """Test DANE with multiple MX hosts."""

    @patch("modules.dane.dns.resolver.Resolver")
    def test_all_mx_have_secure_tlsa(self, mock_resolver_cls):
        """All MX hosts with secure TLSA should report full coverage."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        cd_answer = [FakeTLSA()]
        ad_answer = _make_ad_response()
        # 2 MX hosts × 2 queries each (CD + AD)
        resolver.resolve = MagicMock(
            side_effect=[cd_answer, ad_answer, cd_answer, ad_answer]
        )

        dane = DANE("example.com", ["mx1.example.com", "mx2.example.com"])
        self.assertTrue(dane.has_dane)
        self.assertEqual(dane.dane_mx_count, 2)

    @patch("modules.dane.dns.resolver.Resolver")
    def test_partial_coverage(self, mock_resolver_cls):
        """Only some MX hosts with TLSA should show partial coverage."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        cd_answer = [FakeTLSA()]
        ad_answer = _make_ad_response()

        def side_effect(name, rdtype):
            if "mx1" in name:
                return cd_answer
            raise dns.resolver.NoAnswer()

        # First MX: CD + AD succeed; Second MX: CD NoAnswer + AD NoAnswer
        resolver.resolve = MagicMock(
            side_effect=[cd_answer, ad_answer, dns.resolver.NoAnswer(), dns.resolver.NoAnswer()]
        )

        dane = DANE("example.com", ["mx1.example.com", "mx2.example.com"])
        self.assertTrue(dane.has_dane)
        self.assertEqual(dane.dane_mx_count, 1)
        # Only mx1 has a real TLSA record
        real_records = [r for r in dane.tlsa_records if not r.get("is_dummy")]
        self.assertEqual(len(real_records), 1)


class TestDANEEdgeCases(unittest.TestCase):
    """Test edge cases."""

    def test_no_mx_hosts(self):
        """Empty MX list should not crash, has_dane should be False."""
        dane = DANE("example.com", [])
        self.assertFalse(dane.has_dane)
        self.assertEqual(dane.dane_mx_count, 0)

    def test_none_mx_hosts(self):
        """None MX list should be handled gracefully."""
        dane = DANE("example.com", None)
        self.assertFalse(dane.has_dane)

    def test_domain_normalization(self):
        """Domain should be normalized to lowercase."""
        dane = DANE("  Example.COM  ", [])
        self.assertEqual(dane.domain, "example.com")

    @patch("modules.dane.dns.resolver.Resolver")
    def test_trailing_dot_stripped(self, mock_resolver_cls):
        """Trailing dots on MX hosts should be stripped."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        cd_answer = [FakeTLSA()]
        ad_answer = _make_ad_response()
        resolver.resolve = MagicMock(side_effect=[cd_answer, ad_answer])

        dane = DANE("example.com", ["mx1.example.com."])
        self.assertEqual(dane.mx_hosts, ["mx1.example.com"])

    def test_null_mx_filtered(self):
        """Null MX ('.') should be filtered out to prevent root query leak."""
        dane = DANE("example.com", ["."])
        self.assertEqual(dane.mx_hosts, [])
        self.assertFalse(dane.has_dane)

    def test_empty_string_mx_filtered(self):
        """Empty string MX hosts should be filtered out."""
        dane = DANE("example.com", [""])
        self.assertEqual(dane.mx_hosts, [])

    def test_ip_address_mx_filtered(self):
        """IP address MX hosts should be filtered out (RFC 7672 §2.1.1)."""
        dane = DANE("example.com", ["192.168.1.1", "mx1.example.com"])
        self.assertEqual(dane.mx_hosts, ["mx1.example.com"])

    def test_ipv6_address_mx_filtered(self):
        """IPv6 address MX hosts should also be filtered out."""
        dane = DANE("example.com", ["2001:db8::1", "mx1.example.com"])
        self.assertEqual(dane.mx_hosts, ["mx1.example.com"])

    def test_duplicate_mx_hosts_deduplicated(self):
        """Duplicate MX hosts should be deduplicated to prevent inflated counts."""
        dane = DANE("example.com", ["mail.example.com", "mail.example.com", "mx2.example.com"])
        self.assertEqual(dane.mx_hosts, ["mail.example.com", "mx2.example.com"])
        self.assertEqual(len(dane.mx_hosts), 2)

    @patch("modules.dane.dns.resolver.Resolver")
    def test_timeout_on_ad_check_not_bogus(self, mock_resolver_cls):
        """Timeout on AD flag check should NOT be flagged as bogus."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        cd_answer = [FakeTLSA()]
        # AD query times out (network issue, not crypto failure)
        resolver.resolve = MagicMock(
            side_effect=[cd_answer, dns.resolver.Timeout()]
        )

        dane = DANE("example.com", ["mx1.example.com"])
        self.assertEqual(len(dane.tlsa_records), 1)
        # Timeout should NOT flag as bogus
        self.assertFalse(dane.tlsa_records[0]["is_bogus"])
        # But AD flag should still be False (we couldn't confirm it)
        self.assertFalse(dane.tlsa_records[0]["ad_flag"])


class TestDANEOutput(unittest.TestCase):
    """Test to_dict and __str__ output."""

    @patch("modules.dane.dns.resolver.Resolver")
    def test_to_dict_with_secure_tlsa(self, mock_resolver_cls):
        """to_dict should return expected keys when secure TLSA is found."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        cd_answer = [FakeTLSA()]
        ad_answer = _make_ad_response()
        resolver.resolve = MagicMock(side_effect=[cd_answer, ad_answer])

        dane = DANE("example.com", ["mx1.example.com"])
        d = dane.to_dict()
        self.assertTrue(d["DANE_HAS_TLSA"])
        self.assertTrue(d["DANE_IS_SECURE"])
        self.assertEqual(d["DANE_MX_COUNT"], 1)
        self.assertEqual(d["DANE_TOTAL_MX"], 1)
        self.assertIsInstance(d["DANE_TLSA_RECORDS"], list)
        self.assertFalse(d["DANE_HAS_BOGUS_RECORDS"])
        self.assertFalse(d["DANE_HAS_UNSUPPORTED_RECORDS"])

    def test_to_dict_no_tlsa(self):
        """to_dict should return expected keys when no MX hosts."""
        dane = DANE("example.com", [])
        d = dane.to_dict()
        self.assertFalse(d["DANE_HAS_TLSA"])
        self.assertFalse(d["DANE_IS_SECURE"])
        self.assertEqual(d["DANE_MX_COUNT"], 0)
        self.assertEqual(d["DANE_TOTAL_MX"], 0)

    @patch("modules.dane.dns.resolver.Resolver")
    def test_str_with_dane(self, mock_resolver_cls):
        """String representation should show secure DANE status."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        cd_answer = [FakeTLSA()]
        ad_answer = _make_ad_response()
        resolver.resolve = MagicMock(side_effect=[cd_answer, ad_answer])

        dane = DANE("example.com", ["mx1.example.com"])
        self.assertIn("1/1", str(dane))
        self.assertIn("secure TLSA", str(dane))

    def test_str_no_dane(self):
        """String with no DANE should indicate that."""
        dane = DANE("example.com", [])
        self.assertIn("No TLSA", str(dane))

    @patch("modules.dane.dns.resolver.Resolver")
    def test_str_ineffective_no_ad(self, mock_resolver_cls):
        """TLSA without AD should show ineffective message."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        cd_answer = [FakeTLSA()]
        non_ad_answer = _make_non_ad_response()
        resolver.resolve = MagicMock(side_effect=[cd_answer, non_ad_answer])

        dane = DANE("example.com", ["mx1.example.com"])
        self.assertIn("Ineffective", str(dane))

    @patch("modules.dane.dns.resolver.Resolver")
    def test_tlsa_record_fields(self, mock_resolver_cls):
        """TLSA record dict should have all expected fields."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        cd_answer = [FakeTLSA(usage=3, selector=1, mtype=1)]
        ad_answer = _make_ad_response()
        resolver.resolve = MagicMock(side_effect=[cd_answer, ad_answer])

        dane = DANE("example.com", ["mx1.example.com"])
        rec = dane.tlsa_records[0]
        self.assertEqual(rec["usage"], 3)
        self.assertEqual(rec["selector"], 1)
        self.assertEqual(rec["mtype"], 1)
        self.assertEqual(rec["usage_label"], "Domain-issued certificate (DANE-EE)")
        self.assertEqual(rec["selector_label"], "SubjectPublicKeyInfo")
        self.assertEqual(rec["mtype_label"], "SHA-256")
        self.assertIn("mx_host", rec)
        self.assertIn("cert_data", rec)
        self.assertIn("is_supported", rec)
        self.assertIn("ad_flag", rec)
        self.assertIn("is_bogus", rec)

    @patch("modules.dane.dns.resolver.Resolver")
    def test_generic_exception_sets_error(self, mock_resolver_cls):
        """Generic exceptions should set error attribute."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.side_effect = RuntimeError("test error")
        dane = DANE("example.com", ["mx1.example.com"])
        self.assertFalse(dane.has_dane)
        self.assertIsNotNone(dane.error)


if __name__ == "__main__":
    unittest.main()
