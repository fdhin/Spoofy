# tests/test_dane.py

"""Tests for the DANE/TLSA detection module."""

import unittest
from unittest.mock import patch, MagicMock

from modules.dane import DANE


class FakeTLSA:
    """Minimal fake TLSA rdata for testing."""
    def __init__(self, usage=3, selector=1, mtype=1, cert=b'\xab\xcd\xef' * 10):
        self.usage = usage
        self.selector = selector
        self.mtype = mtype
        self.cert = cert


class TestDANEDetection(unittest.TestCase):
    """Test DANE/TLSA record detection."""

    @patch("modules.dane.dns.resolver.Resolver")
    def test_tlsa_found(self, mock_resolver_cls):
        """TLSA records found should set has_dane to True."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.return_value = [FakeTLSA()]
        dane = DANE("example.com", ["mx1.example.com"])
        self.assertTrue(dane.has_dane)
        self.assertEqual(dane.dane_mx_count, 1)
        self.assertEqual(len(dane.tlsa_records), 1)

    @patch("modules.dane.dns.resolver.Resolver")
    def test_no_tlsa(self, mock_resolver_cls):
        """No TLSA records should leave has_dane as False."""
        import dns.resolver
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
        import dns.resolver
        import dns.name
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        dane = DANE("example.com", ["mx1.example.com"])
        self.assertFalse(dane.has_dane)

    @patch("modules.dane.dns.resolver.Resolver")
    def test_timeout(self, mock_resolver_cls):
        """Timeout should not set has_dane."""
        import dns.resolver
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.side_effect = dns.resolver.Timeout()
        dane = DANE("example.com", ["mx1.example.com"])
        self.assertFalse(dane.has_dane)

    @patch("modules.dane.dns.resolver.Resolver")
    def test_no_nameservers(self, mock_resolver_cls):
        """NoNameservers should not set has_dane."""
        import dns.resolver
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.side_effect = dns.resolver.NoNameservers()
        dane = DANE("example.com", ["mx1.example.com"])
        self.assertFalse(dane.has_dane)


class TestDANEMultipleMX(unittest.TestCase):
    """Test DANE with multiple MX hosts."""

    @patch("modules.dane.dns.resolver.Resolver")
    def test_all_mx_have_tlsa(self, mock_resolver_cls):
        """All MX hosts with TLSA should report full coverage."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.return_value = [FakeTLSA()]
        dane = DANE("example.com", ["mx1.example.com", "mx2.example.com"])
        self.assertTrue(dane.has_dane)
        self.assertEqual(dane.dane_mx_count, 2)
        self.assertEqual(len(dane.tlsa_records), 2)

    @patch("modules.dane.dns.resolver.Resolver")
    def test_partial_coverage(self, mock_resolver_cls):
        """Only some MX hosts with TLSA should show partial coverage."""
        import dns.resolver
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        def side_effect(name, rdtype):
            if "mx1" in name:
                return [FakeTLSA()]
            raise dns.resolver.NoAnswer()

        resolver.resolve.side_effect = side_effect
        dane = DANE("example.com", ["mx1.example.com", "mx2.example.com"])
        self.assertTrue(dane.has_dane)
        self.assertEqual(dane.dane_mx_count, 1)
        self.assertEqual(len(dane.tlsa_records), 1)

    @patch("modules.dane.dns.resolver.Resolver")
    def test_multiple_tlsa_per_host(self, mock_resolver_cls):
        """Multiple TLSA records per MX host should all be captured."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.return_value = [FakeTLSA(usage=2), FakeTLSA(usage=3)]
        dane = DANE("example.com", ["mx1.example.com"])
        self.assertTrue(dane.has_dane)
        self.assertEqual(dane.dane_mx_count, 1)
        self.assertEqual(len(dane.tlsa_records), 2)


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
        resolver.resolve.return_value = [FakeTLSA()]
        dane = DANE("example.com", ["mx1.example.com."])
        self.assertEqual(dane.mx_hosts, ["mx1.example.com"])
        self.assertTrue(dane.has_dane)


class TestDANEOutput(unittest.TestCase):
    """Test to_dict and __str__ output."""

    @patch("modules.dane.dns.resolver.Resolver")
    def test_to_dict_with_tlsa(self, mock_resolver_cls):
        """to_dict should return expected keys when TLSA is found."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.return_value = [FakeTLSA()]
        dane = DANE("example.com", ["mx1.example.com"])
        d = dane.to_dict()
        self.assertTrue(d["DANE_HAS_TLSA"])
        self.assertEqual(d["DANE_MX_COUNT"], 1)
        self.assertEqual(d["DANE_TOTAL_MX"], 1)
        self.assertIsInstance(d["DANE_TLSA_RECORDS"], list)

    def test_to_dict_no_tlsa(self):
        """to_dict should return expected keys when no MX hosts."""
        dane = DANE("example.com", [])
        d = dane.to_dict()
        self.assertFalse(d["DANE_HAS_TLSA"])
        self.assertEqual(d["DANE_MX_COUNT"], 0)
        self.assertEqual(d["DANE_TOTAL_MX"], 0)

    @patch("modules.dane.dns.resolver.Resolver")
    def test_str_with_dane(self, mock_resolver_cls):
        """String representation should show DANE status."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.return_value = [FakeTLSA()]
        dane = DANE("example.com", ["mx1.example.com"])
        self.assertIn("1/1", str(dane))
        self.assertIn("TLSA", str(dane))

    def test_str_no_dane(self):
        """String with no DANE should indicate that."""
        dane = DANE("example.com", [])
        self.assertIn("No TLSA", str(dane))

    @patch("modules.dane.dns.resolver.Resolver")
    def test_tlsa_record_fields(self, mock_resolver_cls):
        """TLSA record dict should have all expected fields."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.return_value = [FakeTLSA(usage=3, selector=1, mtype=1)]
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
