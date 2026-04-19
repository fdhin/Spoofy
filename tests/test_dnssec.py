# tests/test_dnssec.py

"""Tests for the DNSSEC detection module."""

import unittest
from unittest.mock import patch, MagicMock

import dns.resolver
import dns.rdatatype


class TestDNSSEC(unittest.TestCase):
    """Tests for DNSSEC class."""

    def _make_dnssec(self, dnskey_answer=None, ds_answer=None,
                     dnskey_exc=None, ds_exc=None):
        """Helper: create a DNSSEC instance with mocked DNS queries."""
        from modules.dnssec import DNSSEC

        def _resolve(domain, rdtype):
            if rdtype == "DNSKEY":
                if dnskey_exc:
                    raise dnskey_exc
                return dnskey_answer or []
            elif rdtype == "DS":
                if ds_exc:
                    raise ds_exc
                return ds_answer or []
            elif rdtype == "SOA":
                # AD flag check — return a mock response with no AD flag
                mock_answer = MagicMock()
                mock_answer.response = MagicMock()
                mock_answer.response.flags = 0  # No AD flag
                return mock_answer
            raise dns.resolver.NoAnswer()

        with patch("modules.dnssec.dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = MagicMock(side_effect=_resolve)
            return DNSSEC("example.com", "1.1.1.1")

    def _make_answer(self, count=1, algorithm=13):
        """Create a mock DNS answer with the given number of records."""
        records = []
        for _ in range(count):
            record = MagicMock()
            record.algorithm = algorithm
            records.append(record)
        answer = MagicMock()
        answer.__len__ = lambda self: len(records)
        answer.__iter__ = lambda self: iter(records)
        answer.__getitem__ = lambda self, i: records[i]
        return answer

    # --- DNSKEY tests ---

    def test_enabled_when_dnskey_and_ds_exist(self):
        """DNSSEC should be enabled only when BOTH DNSKEY and DS exist."""
        dnskey = self._make_answer(count=3)
        ds = self._make_answer(count=1, algorithm=13)
        dnssec = self._make_dnssec(dnskey_answer=dnskey, ds_answer=ds)
        self.assertTrue(dnssec.enabled)
        self.assertTrue(dnssec.dnskey_present)
        self.assertTrue(dnssec.has_ds)
        self.assertEqual(dnssec.dnskey_count, 3)

    def test_not_enabled_when_dnskey_only(self):
        """DNSKEY without DS is broken DNSSEC — enabled should be False."""
        dnskey = self._make_answer(count=3)
        dnssec = self._make_dnssec(dnskey_answer=dnskey,
                                    ds_exc=dns.resolver.NoAnswer())
        self.assertFalse(dnssec.enabled)
        self.assertTrue(dnssec.dnskey_present)
        self.assertFalse(dnssec.has_ds)

    def test_disabled_when_no_dnskey(self):
        """DNSSEC should be disabled when no DNSKEY records."""
        dnssec = self._make_dnssec(dnskey_exc=dns.resolver.NoAnswer())
        self.assertFalse(dnssec.enabled)
        self.assertFalse(dnssec.dnskey_present)
        self.assertEqual(dnssec.dnskey_count, 0)

    def test_disabled_on_nxdomain(self):
        """DNSSEC should be disabled for non-existent domains."""
        dnssec = self._make_dnssec(dnskey_exc=dns.resolver.NXDOMAIN())
        self.assertFalse(dnssec.enabled)

    def test_timeout_sets_error(self):
        """Timeout during DNSKEY query should set error message."""
        dnssec = self._make_dnssec(dnskey_exc=dns.resolver.Timeout())
        self.assertFalse(dnssec.enabled)
        self.assertIsNotNone(dnssec.error)
        self.assertIn("timed out", dnssec.error)

    def test_no_nameservers_sets_error(self):
        """NoNameservers during DNSKEY query should set error message."""
        dnssec = self._make_dnssec(dnskey_exc=dns.resolver.NoNameservers())
        self.assertFalse(dnssec.enabled)
        self.assertIsNotNone(dnssec.error)

    # --- DS tests ---

    def test_has_ds_when_ds_exists(self):
        """DS check should be True when DS record found."""
        dnskey = self._make_answer(count=2)
        ds = self._make_answer(count=1, algorithm=8)
        dnssec = self._make_dnssec(dnskey_answer=dnskey, ds_answer=ds)
        self.assertTrue(dnssec.enabled)
        self.assertTrue(dnssec.has_ds)
        self.assertEqual(dnssec.ds_algorithm, 8)

    def test_no_ds_when_missing(self):
        """DS should be False when no DS record found."""
        dnskey = self._make_answer(count=2)
        dnssec = self._make_dnssec(dnskey_answer=dnskey,
                                    ds_exc=dns.resolver.NoAnswer())
        self.assertFalse(dnssec.enabled)  # DNSKEY without DS = broken
        self.assertTrue(dnssec.dnskey_present)
        self.assertFalse(dnssec.has_ds)

    def test_ds_timeout_not_fatal(self):
        """DS query timeout should not crash. enabled=False since no DS confirmed."""
        dnskey = self._make_answer(count=2)
        dnssec = self._make_dnssec(dnskey_answer=dnskey,
                                    ds_exc=dns.resolver.Timeout())
        self.assertFalse(dnssec.enabled)  # Can't confirm chain of trust
        self.assertTrue(dnssec.dnskey_present)
        self.assertFalse(dnssec.has_ds)

    # --- to_dict ---

    def test_to_dict_enabled(self):
        """to_dict should return correct structure when DNSSEC enabled."""
        dnskey = self._make_answer(count=3)
        ds = self._make_answer(count=1, algorithm=13)
        dnssec = self._make_dnssec(dnskey_answer=dnskey, ds_answer=ds)
        d = dnssec.to_dict()
        self.assertEqual(d["DNSSEC_ENABLED"], True)
        self.assertEqual(d["DNSSEC_HAS_DS"], True)
        self.assertEqual(d["DNSSEC_KEY_COUNT"], 3)
        self.assertEqual(d["DNSSEC_DS_ALGORITHM"], 13)

    def test_to_dict_disabled(self):
        """to_dict should return correct structure when DNSSEC disabled."""
        dnssec = self._make_dnssec(dnskey_exc=dns.resolver.NoAnswer())
        d = dnssec.to_dict()
        self.assertEqual(d["DNSSEC_ENABLED"], False)
        self.assertEqual(d["DNSSEC_HAS_DS"], False)
        self.assertEqual(d["DNSSEC_KEY_COUNT"], 0)
        self.assertIsNone(d["DNSSEC_DS_ALGORITHM"])

    # --- __str__ ---

    def test_str_enabled(self):
        """String representation when enabled (DNSKEY + DS)."""
        dnskey = self._make_answer(count=2)
        ds = self._make_answer(count=1)
        dnssec = self._make_dnssec(dnskey_answer=dnskey, ds_answer=ds)
        s = str(dnssec)
        self.assertIn("Enabled", s)
        self.assertIn("DS verified", s)

    def test_str_broken(self):
        """String representation when DNSKEY exists but no DS (broken)."""
        dnskey = self._make_answer(count=1)
        dnssec = self._make_dnssec(dnskey_answer=dnskey,
                                    ds_exc=dns.resolver.NoAnswer())
        s = str(dnssec)
        self.assertIn("Broken", s)
        self.assertIn("no DS", s)

    def test_str_disabled(self):
        """String representation when disabled."""
        dnssec = self._make_dnssec(dnskey_exc=dns.resolver.NoAnswer())
        s = str(dnssec)
        self.assertIn("Not detected", s)

    # --- Domain normalization ---

    def test_domain_normalized(self):
        """Domain should be lowercased and stripped."""
        dnskey = self._make_answer(count=1)
        dnssec = self._make_dnssec(dnskey_answer=dnskey)
        self.assertEqual(dnssec.domain, "example.com")


if __name__ == "__main__":
    unittest.main()
