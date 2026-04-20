# tests/test_dnssec.py

"""Tests for the DNSSEC detection module."""

import unittest
from unittest.mock import patch, MagicMock, PropertyMock

import dns.resolver
import dns.rdatatype
import dns.flags


class TestDNSSEC(unittest.TestCase):
    """Tests for DNSSEC class."""

    def _make_dnssec(self, dnskey_answer=None, ds_answer=None,
                     dnskey_exc=None, ds_exc=None, domain="example.com"):
        """Helper: create a DNSSEC instance with mocked DNS queries."""
        from modules.dnssec import DNSSEC

        def _resolve(qname, rdtype):
            qname_str = str(qname)
            if rdtype == "DNSKEY":
                if dnskey_exc:
                    raise dnskey_exc
                return dnskey_answer or []
            elif rdtype == "DS":
                if ds_exc:
                    raise ds_exc
                return ds_answer or []
            elif rdtype in ("A", "AAAA", "SOA"):
                # AD flag check — return a mock response with no AD flag
                mock_answer = MagicMock()
                mock_answer.response = MagicMock()
                mock_answer.response.flags = 0  # No AD flag
                return mock_answer
            raise dns.resolver.NoAnswer()

        def _mock_zone_for_name(name, **kwargs):
            """Return the domain itself as the zone apex."""
            mock_name = MagicMock()
            mock_name.to_text.return_value = domain + "."
            return mock_name

        with patch("modules.dnssec.dns.resolver.Resolver") as MockResolver, \
             patch("modules.dnssec.dns.resolver.zone_for_name", side_effect=_mock_zone_for_name):
            instance = MockResolver.return_value
            instance.resolve = MagicMock(side_effect=_resolve)
            return DNSSEC(domain, "1.1.1.1")

    def _make_dnskey_answer(self, count=1, algorithm=13, flags=256, protocol=3):
        """Create a mock DNSKEY answer with Zone Key flag set by default."""
        records = []
        for _ in range(count):
            record = MagicMock()
            record.algorithm = algorithm
            record.flags = flags  # 256 = Zone Key flag
            record.protocol = protocol  # RFC 4034 §2.1.2: MUST be 3
            records.append(record)
        answer = MagicMock()
        answer.__len__ = lambda self: len(records)
        answer.__iter__ = lambda self: iter(records)
        answer.__getitem__ = lambda self, i: records[i]
        return answer

    def _make_ds_answer(self, count=1, algorithm=13, digest_type=2):
        """Create a mock DS answer with digest_type field."""
        records = []
        for _ in range(count):
            record = MagicMock()
            record.algorithm = algorithm
            record.digest_type = digest_type
            records.append(record)
        answer = MagicMock()
        answer.__len__ = lambda self: len(records)
        answer.__iter__ = lambda self: iter(records)
        answer.__getitem__ = lambda self, i: records[i]
        return answer

    # --- DNSKEY tests ---

    def test_enabled_when_dnskey_and_ds_exist(self):
        """DNSSEC should be enabled only when BOTH DNSKEY and DS exist."""
        dnskey = self._make_dnskey_answer(count=3)
        ds = self._make_ds_answer(count=1, algorithm=13, digest_type=2)
        dnssec = self._make_dnssec(dnskey_answer=dnskey, ds_answer=ds)
        self.assertTrue(dnssec.enabled)
        self.assertTrue(dnssec.dnskey_present)
        self.assertTrue(dnssec.has_ds)
        self.assertEqual(dnssec.dnskey_count, 3)

    def test_not_enabled_when_dnskey_only(self):
        """DNSKEY without DS is broken DNSSEC — enabled should be False."""
        dnskey = self._make_dnskey_answer(count=3)
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

    # --- Zone Key flag tests (RFC 4034 §2.1.1) ---

    def test_dnskey_without_zone_flag_ignored(self):
        """DNSKEY records without the Zone Key flag (256) should not count."""
        # flags=0 means no Zone Key flag
        dnskey = self._make_dnskey_answer(count=2, flags=0)
        ds = self._make_ds_answer(count=1)
        dnssec = self._make_dnssec(dnskey_answer=dnskey, ds_answer=ds)
        self.assertFalse(dnssec.dnskey_present)
        self.assertEqual(dnssec.dnskey_count, 0)
        self.assertFalse(dnssec.enabled)

    def test_dnskey_with_zone_flag_counted(self):
        """DNSKEY records WITH the Zone Key flag (257 = ZSK+SEP) should count."""
        dnskey = self._make_dnskey_answer(count=1, flags=257)
        ds = self._make_ds_answer(count=1)
        dnssec = self._make_dnssec(dnskey_answer=dnskey, ds_answer=ds)
        self.assertTrue(dnssec.dnskey_present)
        self.assertEqual(dnssec.dnskey_count, 1)

    def test_dnskey_with_wrong_protocol_ignored(self):
        """DNSKEY records with protocol != 3 should be ignored (RFC 4034 §2.1.2)."""
        dnskey = self._make_dnskey_answer(count=1, flags=256, protocol=0)
        ds = self._make_ds_answer(count=1)
        dnssec = self._make_dnssec(dnskey_answer=dnskey, ds_answer=ds)
        self.assertFalse(dnssec.dnskey_present)
        self.assertEqual(dnssec.dnskey_count, 0)

    # --- DS tests ---

    def test_has_ds_when_ds_exists(self):
        """DS check should be True when DS record found."""
        dnskey = self._make_dnskey_answer(count=2)
        ds = self._make_ds_answer(count=1, algorithm=8, digest_type=2)
        dnssec = self._make_dnssec(dnskey_answer=dnskey, ds_answer=ds)
        self.assertTrue(dnssec.enabled)
        self.assertTrue(dnssec.has_ds)
        # Verify digest_type is extracted, not just algorithm
        self.assertIn(2, dnssec.ds_digest_types)
        self.assertIn(8, dnssec.ds_algorithms)

    def test_no_ds_when_missing(self):
        """DS should be False when no DS record found."""
        dnskey = self._make_dnskey_answer(count=2)
        dnssec = self._make_dnssec(dnskey_answer=dnskey,
                                    ds_exc=dns.resolver.NoAnswer())
        self.assertFalse(dnssec.enabled)  # DNSKEY without DS = broken
        self.assertTrue(dnssec.dnskey_present)
        self.assertFalse(dnssec.has_ds)

    def test_ds_timeout_not_fatal(self):
        """DS query timeout should not crash. enabled=False since no DS confirmed."""
        dnskey = self._make_dnskey_answer(count=2)
        dnssec = self._make_dnssec(dnskey_answer=dnskey,
                                    ds_exc=dns.resolver.Timeout())
        self.assertFalse(dnssec.enabled)  # Can't confirm chain of trust
        self.assertTrue(dnssec.dnskey_present)
        self.assertFalse(dnssec.has_ds)

    # --- RFC 9904: Weak crypto detection ---

    def test_weak_dnskey_algorithm_flagged(self):
        """DNSKEY using RSASHA1 (algorithm 5) should be flagged as weak."""
        dnskey = self._make_dnskey_answer(count=1, algorithm=5)  # RSASHA1
        ds = self._make_ds_answer(count=1, digest_type=2)
        dnssec = self._make_dnssec(dnskey_answer=dnskey, ds_answer=ds)
        self.assertTrue(dnssec.has_weak_dnskey)
        self.assertFalse(dnssec.has_weak_ds)

    def test_weak_ds_digest_flagged(self):
        """DS using SHA-1 (digest_type 1) should be flagged as weak."""
        dnskey = self._make_dnskey_answer(count=1, algorithm=13)
        ds = self._make_ds_answer(count=1, algorithm=13, digest_type=1)  # SHA-1
        dnssec = self._make_dnssec(dnskey_answer=dnskey, ds_answer=ds)
        self.assertTrue(dnssec.has_weak_ds)
        self.assertFalse(dnssec.has_weak_dnskey)

    def test_strong_crypto_not_flagged(self):
        """ECDSA P-256 (algorithm 13) with SHA-256 (digest_type 2) should be clean."""
        dnskey = self._make_dnskey_answer(count=1, algorithm=13)
        ds = self._make_ds_answer(count=1, algorithm=13, digest_type=2)
        dnssec = self._make_dnssec(dnskey_answer=dnskey, ds_answer=ds)
        self.assertFalse(dnssec.has_weak_dnskey)
        self.assertFalse(dnssec.has_weak_ds)

    def test_rsasha512_not_flagged_as_weak(self):
        """RSASHA512 (algorithm 10) is operationally discouraged but cryptographically strong."""
        dnskey = self._make_dnskey_answer(count=1, algorithm=10)
        ds = self._make_ds_answer(count=1, digest_type=2)
        dnssec = self._make_dnssec(dnskey_answer=dnskey, ds_answer=ds)
        self.assertFalse(dnssec.has_weak_dnskey)

    # --- to_dict ---

    def test_to_dict_enabled(self):
        """to_dict should return correct structure when DNSSEC enabled."""
        dnskey = self._make_dnskey_answer(count=3, algorithm=13)
        ds = self._make_ds_answer(count=1, algorithm=13, digest_type=2)
        dnssec = self._make_dnssec(dnskey_answer=dnskey, ds_answer=ds)
        d = dnssec.to_dict()
        self.assertEqual(d["DNSSEC_ENABLED"], True)
        self.assertEqual(d["DNSSEC_HAS_DS"], True)
        self.assertEqual(d["DNSSEC_KEY_COUNT"], 3)
        self.assertIn(13, d["DNSSEC_DNSKEY_ALGORITHMS"])
        self.assertIn(2, d["DNSSEC_DS_DIGEST_TYPES"])
        self.assertFalse(d["DNSSEC_HAS_WEAK_DNSKEY"])
        self.assertFalse(d["DNSSEC_HAS_WEAK_DS"])

    def test_to_dict_disabled(self):
        """to_dict should return correct structure when DNSSEC disabled."""
        dnssec = self._make_dnssec(dnskey_exc=dns.resolver.NoAnswer())
        d = dnssec.to_dict()
        self.assertEqual(d["DNSSEC_ENABLED"], False)
        self.assertEqual(d["DNSSEC_HAS_DS"], False)
        self.assertEqual(d["DNSSEC_KEY_COUNT"], 0)
        self.assertEqual(d["DNSSEC_DNSKEY_ALGORITHMS"], [])
        self.assertEqual(d["DNSSEC_DS_DIGEST_TYPES"], [])

    # --- __str__ ---

    def test_str_enabled(self):
        """String representation when enabled (DNSKEY + DS)."""
        dnskey = self._make_dnskey_answer(count=2)
        ds = self._make_ds_answer(count=1)
        dnssec = self._make_dnssec(dnskey_answer=dnskey, ds_answer=ds)
        s = str(dnssec)
        self.assertIn("Enabled", s)
        self.assertIn("DS verified", s)

    def test_str_broken(self):
        """String representation when DNSKEY exists but no DS (broken)."""
        dnskey = self._make_dnskey_answer(count=1)
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

    def test_str_weak_crypto_warning(self):
        """String representation should flag deprecated crypto."""
        dnskey = self._make_dnskey_answer(count=1, algorithm=5)  # RSASHA1
        ds = self._make_ds_answer(count=1, digest_type=1)  # SHA-1
        dnssec = self._make_dnssec(dnskey_answer=dnskey, ds_answer=ds)
        s = str(dnssec)
        self.assertIn("DEPRECATED CRYPTO", s)

    def test_str_servfail_outage(self):
        """DS without DNSKEY should report FATAL OUTAGE."""
        ds = self._make_ds_answer(count=1)
        dnssec = self._make_dnssec(dnskey_exc=dns.resolver.NoAnswer(),
                                    ds_answer=ds)
        s = str(dnssec)
        self.assertIn("FATAL OUTAGE", s)
        self.assertIn("SERVFAIL", s)
        self.assertTrue(dnssec.has_ds)
        self.assertFalse(dnssec.dnskey_present)
        self.assertFalse(dnssec.enabled)

    # --- Domain normalization ---

    def test_domain_normalized(self):
        """Domain should be lowercased and stripped."""
        dnskey = self._make_dnskey_answer(count=1)
        dnssec = self._make_dnssec(dnskey_answer=dnskey)
        self.assertEqual(dnssec.domain, "example.com")

    # --- IDNA encoding ---

    def test_idna_encoding(self):
        """IDNA encoding function should convert Unicode domains."""
        from modules.dnssec import _encode_idna
        # Standard ASCII should pass through
        self.assertEqual(_encode_idna("example.com"), "example.com")

    def test_idna_ascii_passthrough(self):
        """Pure ASCII domains should pass through IDNA encoding unchanged."""
        from modules.dnssec import _encode_idna
        self.assertEqual(_encode_idna("mail.example.com"), "mail.example.com")


if __name__ == "__main__":
    unittest.main()
