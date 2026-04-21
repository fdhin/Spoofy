# tests/test_caa.py

"""Tests for CAA record analysis module (RFC 8659 / RFC 8657 / RFC 9495)."""

import unittest
from unittest.mock import patch, MagicMock
import dns.resolver
import dns.exception
from modules.caa import CAA, _encode_idna


def _mock_rdata(flags, tag, value):
    """Create a mock CAA rdata object with native dnspython attributes."""
    m = MagicMock()
    m.flags = flags
    m.tag = tag.encode("ascii") if isinstance(tag, str) else tag
    m.value = value.encode("utf-8") if isinstance(value, str) else value
    m.to_text.return_value = f'{flags} {tag} "{value}"'
    return m


class TestCAAFound(unittest.TestCase):
    """Tests for basic CAA record parsing."""

    @patch("dns.resolver.Resolver")
    def test_caa_found(self, mock_resolver_class):
        """Test parsing when CAA records are found."""
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue", "letsencrypt.org"),
            _mock_rdata(0, "issuewild", "letsencrypt.org"),
        ]

        caa = CAA("example.com")
        self.assertEqual(len(caa.caa_records), 2)
        self.assertTrue(caa.has_issue_record)
        self.assertTrue(caa.has_issuewild_record)

        d = caa.to_dict()
        self.assertTrue(d["CAA_HAS_ISSUE"])
        self.assertTrue(d["CAA_HAS_ISSUEWILD"])
        self.assertEqual(len(d["CAA_RECORDS"]), 2)

    @patch("dns.resolver.Resolver")
    def test_caa_no_records(self, mock_resolver_class):
        """Test behavior when no CAA records exist."""
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer

        caa = CAA("example.com")
        self.assertEqual(len(caa.caa_records), 0)
        self.assertFalse(caa.has_issue_record)
        self.assertFalse(caa.has_issuewild_record)

    @patch("dns.resolver.Resolver")
    def test_iodef_record(self, mock_resolver_class):
        """iodef tag should be tracked."""
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue", "letsencrypt.org"),
            _mock_rdata(0, "iodef", "mailto:security@example.com"),
        ]

        caa = CAA("example.com")
        self.assertTrue(caa.has_iodef_record)
        self.assertTrue(caa.to_dict()["CAA_HAS_IODEF"])

    @patch("dns.resolver.Resolver")
    def test_issuer_domain_extracted(self, mock_resolver_class):
        """issuer_domain should be extracted from issue value."""
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue", "ca1.example.net"),
        ]

        caa = CAA("example.com")
        self.assertEqual(caa.caa_records[0]["issuer_domain"], "ca1.example.net")

    @patch("dns.resolver.Resolver")
    def test_raw_uses_rdata_to_text(self, mock_resolver_class):
        """raw field should use rdata.to_text() not hand-rolled format."""
        mock_resolver = mock_resolver_class.return_value
        rdata = _mock_rdata(0, "issue", "letsencrypt.org")
        rdata.to_text.return_value = '0 issue "letsencrypt.org"'
        mock_resolver.resolve.return_value = [rdata]

        caa = CAA("example.com")
        self.assertEqual(caa.caa_records[0]["raw"], '0 issue "letsencrypt.org"')


class TestCAAContactSplit(unittest.TestCase):
    """Tests for split contactemail / contactphone fields."""

    @patch("dns.resolver.Resolver")
    def test_contactemail_tracked(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue", "letsencrypt.org"),
            _mock_rdata(0, "contactemail", "admin@example.com"),
        ]
        caa = CAA("example.com")
        self.assertTrue(caa.has_contactemail)
        self.assertFalse(caa.has_contactphone)

    @patch("dns.resolver.Resolver")
    def test_contactphone_tracked(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue", "letsencrypt.org"),
            _mock_rdata(0, "contactphone", "+1-555-0100"),
        ]
        caa = CAA("example.com")
        self.assertFalse(caa.has_contactemail)
        self.assertTrue(caa.has_contactphone)

    @patch("dns.resolver.Resolver")
    def test_both_contacts(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue", "letsencrypt.org"),
            _mock_rdata(0, "contactemail", "admin@example.com"),
            _mock_rdata(0, "contactphone", "+1-555-0100"),
        ]
        caa = CAA("example.com")
        self.assertTrue(caa.has_contactemail)
        self.assertTrue(caa.has_contactphone)
        d = caa.to_dict()
        self.assertTrue(d["CAA_HAS_CONTACTEMAIL"])
        self.assertTrue(d["CAA_HAS_CONTACTPHONE"])


class TestCAADenyAll(unittest.TestCase):
    """Tests for RFC 8659 §4.2/§4.3 additive deny-all with issue/issuewild split."""

    @patch("dns.resolver.Resolver")
    def test_issue_semicolon_alone_denies_both(self, mock_resolver_class):
        """issue ";" as the only record → deny_all_regular=True, deny_all_wildcard=True."""
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue", ";"),
        ]
        caa = CAA("nocerts.example.com")
        self.assertTrue(caa.deny_all_regular)
        self.assertTrue(caa.deny_all_wildcard)

    @patch("dns.resolver.Resolver")
    def test_issue_ca_plus_semicolon_NOT_deny_all(self, mock_resolver_class):
        """issue "digicert.com" + issue ";" → additive, NOT deny-all."""
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue", "digicert.com"),
            _mock_rdata(0, "issue", ";"),
        ]
        caa = CAA("example.com")
        self.assertFalse(caa.deny_all_regular)
        self.assertFalse(caa.deny_all_wildcard)

    @patch("dns.resolver.Resolver")
    def test_issue_deny_issuewild_allows(self, mock_resolver_class):
        """RFC 8659 §4.3: issue ";" + issuewild "digicert.com"
        → regular denied, wildcard allowed via DigiCert."""
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue", ";"),
            _mock_rdata(0, "issuewild", "digicert.com"),
        ]
        caa = CAA("example.com")
        self.assertTrue(caa.deny_all_regular)
        self.assertFalse(caa.deny_all_wildcard)

    @patch("dns.resolver.Resolver")
    def test_issue_allows_issuewild_denies(self, mock_resolver_class):
        """issue "ca.example" + issuewild ";" → regular allowed, wildcard denied."""
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue", "ca.example"),
            _mock_rdata(0, "issuewild", ";"),
        ]
        caa = CAA("example.com")
        self.assertFalse(caa.deny_all_regular)
        self.assertTrue(caa.deny_all_wildcard)

    @patch("dns.resolver.Resolver")
    def test_issuewild_fallback_to_issue(self, mock_resolver_class):
        """No issuewild records → wildcard evaluation falls back to issue (RFC 8659 §4.3)."""
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue", "letsencrypt.org"),
        ]
        caa = CAA("example.com")
        self.assertFalse(caa.deny_all_regular)
        self.assertFalse(caa.deny_all_wildcard)

    @patch("dns.resolver.Resolver")
    def test_issuewild_semicolon_alone(self, mock_resolver_class):
        """issuewild ";" only → deny_all_wildcard=True, deny_all_regular=False (no issue records)."""
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issuewild", ";"),
        ]
        caa = CAA("example.com")
        # No issue records → deny_all_regular stays False
        self.assertFalse(caa.deny_all_regular)
        self.assertTrue(caa.deny_all_wildcard)

    @patch("dns.resolver.Resolver")
    def test_deny_all_in_str_output(self, mock_resolver_class):
        """__str__ should mention deny-all when both blocked."""
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue", ";"),
        ]
        caa = CAA("example.com")
        self.assertIn("DENY-ALL", str(caa))

    @patch("dns.resolver.Resolver")
    def test_partial_deny_in_str(self, mock_resolver_class):
        """__str__ should distinguish regular-only deny."""
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue", ";"),
            _mock_rdata(0, "issuewild", "digicert.com"),
        ]
        caa = CAA("example.com")
        output = str(caa)
        self.assertIn("DENY-ALL", output)
        self.assertIn("regular", output)
        self.assertNotIn("wildcard", output)


class TestCAAServfail(unittest.TestCase):
    """Tests for RFC 8659 §6 fail-closed on SERVFAIL/Timeout."""

    @patch("dns.resolver.Resolver")
    def test_timeout_sets_error(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.side_effect = dns.resolver.Timeout
        caa = CAA("sub.example.com")
        self.assertIsNotNone(caa.error)
        self.assertIn("FATAL OUTAGE", caa.error)

    @patch("dns.resolver.Resolver")
    def test_no_nameservers_sets_error(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.side_effect = dns.resolver.NoNameservers
        caa = CAA("example.com")
        self.assertIsNotNone(caa.error)
        d = caa.to_dict()
        self.assertIsNotNone(d["CAA_ERROR"])

    @patch("dns.resolver.Resolver")
    def test_servfail_stops_tree_walk(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.side_effect = dns.resolver.Timeout
        caa = CAA("deep.sub.example.com")
        self.assertIsNotNone(caa.error)
        self.assertEqual(mock_resolver.resolve.call_count, 1)

    @patch("dns.resolver.Resolver")
    def test_error_domain_is_set(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.side_effect = dns.resolver.Timeout
        caa = CAA("example.com")
        self.assertIsNotNone(caa.error_domain)
        self.assertEqual(caa.error_domain, "example.com")
        d = caa.to_dict()
        self.assertEqual(d["CAA_ERROR_DOMAIN"], "example.com")

    @patch("dns.resolver.Resolver")
    def test_error_str_uses_error_domain_not_effective(self, mock_resolver_class):
        """__str__ should use error_domain, not effective_domain (which is None)."""
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.side_effect = dns.resolver.Timeout
        caa = CAA("example.com")
        output = str(caa)
        self.assertIn("FATAL OUTAGE", output)
        self.assertNotIn("None", output)
        self.assertIn("example.com", output)

    @patch("dns.resolver.Resolver")
    def test_formerror_does_NOT_abort_walk(self, mock_resolver_class):
        """FormError should NOT abort the tree walk."""
        mock_resolver = mock_resolver_class.return_value

        def resolve_side_effect(domain, rdtype):
            if domain == "sub.example.com":
                raise dns.exception.FormError("malformed")
            elif domain == "example.com":
                return [_mock_rdata(0, "issue", "letsencrypt.org")]
            else:
                raise dns.resolver.NoAnswer

        mock_resolver.resolve.side_effect = resolve_side_effect
        caa = CAA("sub.example.com")
        self.assertIsNone(caa.error)
        self.assertTrue(caa.has_issue_record)
        self.assertEqual(caa.effective_domain, "example.com")


class TestCAAUnknownCritical(unittest.TestCase):
    """Tests for RFC 8659 §4.5 unknown critical tags."""

    @patch("dns.resolver.Resolver")
    def test_unknown_critical_detected(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue", "ca1.example.net"),
            _mock_rdata(128, "tbs", "Unknown"),
        ]
        caa = CAA("new.example.com")
        self.assertTrue(caa.has_unknown_critical)
        self.assertTrue(caa.has_critical)

    @patch("dns.resolver.Resolver")
    def test_known_critical_not_flagged(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(128, "issue", "letsencrypt.org"),
        ]
        caa = CAA("example.com")
        self.assertTrue(caa.has_critical)
        self.assertFalse(caa.has_unknown_critical)

    @patch("dns.resolver.Resolver")
    def test_non_critical_unknown_tag_not_flagged(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "future_tag", "some_value"),
        ]
        caa = CAA("example.com")
        self.assertFalse(caa.has_unknown_critical)
        self.assertFalse(caa.has_critical)

    @patch("dns.resolver.Resolver")
    def test_issuemail_is_known(self, mock_resolver_class):
        """RFC 9495 issuemail should NOT trigger unknown critical."""
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(128, "issuemail", "ca.example"),
        ]
        caa = CAA("example.com")
        self.assertTrue(caa.has_critical)
        self.assertFalse(caa.has_unknown_critical)

    @patch("dns.resolver.Resolver")
    def test_unknown_critical_in_str(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(128, "tbs", "Unknown"),
        ]
        caa = CAA("example.com")
        self.assertIn("BLOCKED ISSUANCE", str(caa))


class TestCAATreeWalk(unittest.TestCase):
    """Tests for RFC 8659 §3 tree-climbing algorithm."""

    @patch("dns.resolver.Resolver")
    def test_inherits_from_parent(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value

        def resolve_side_effect(domain, rdtype):
            if domain == "sub.example.com":
                raise dns.resolver.NoAnswer
            elif domain == "example.com":
                return [_mock_rdata(0, "issue", "letsencrypt.org")]
            else:
                raise dns.resolver.NoAnswer

        mock_resolver.resolve.side_effect = resolve_side_effect
        caa = CAA("sub.example.com")
        self.assertTrue(caa.has_issue_record)
        self.assertEqual(caa.effective_domain, "example.com")

    @patch("dns.resolver.Resolver")
    def test_stops_at_first_rrset(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        call_count = {"n": 0}

        def resolve_side_effect(domain, rdtype):
            call_count["n"] += 1
            if domain == "sub.example.com":
                return [_mock_rdata(0, "issue", "ca1.example.net")]
            elif domain == "example.com":
                return [_mock_rdata(0, "issue", "ca2.example.org")]
            else:
                raise dns.resolver.NoAnswer

        mock_resolver.resolve.side_effect = resolve_side_effect
        caa = CAA("sub.example.com")
        self.assertEqual(caa.effective_domain, "sub.example.com")
        self.assertEqual(call_count["n"], 1)

    @patch("dns.resolver.Resolver")
    def test_climbs_to_tld(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        queried_domains = []

        def resolve_side_effect(domain, rdtype):
            queried_domains.append(domain)
            raise dns.resolver.NoAnswer

        mock_resolver.resolve.side_effect = resolve_side_effect
        caa = CAA("sub.example.com")
        self.assertIn("com", queried_domains)


class TestCAAParametersParsing(unittest.TestCase):
    """Tests for RFC 8657 parameter extensions."""

    @patch("dns.resolver.Resolver")
    def test_accounturi_detected(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue", "example.net; accounturi=https://example.net/account/1234"),
        ]
        caa = CAA("example.com")
        self.assertTrue(caa.has_rfc8657_extensions)
        self.assertEqual(caa.caa_records[0]["parameters"]["accounturi"],
                         "https://example.net/account/1234")

    @patch("dns.resolver.Resolver")
    def test_validationmethods_detected(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue", "example.net; validationmethods=dns-01,http-01"),
        ]
        caa = CAA("example.com")
        self.assertTrue(caa.has_rfc8657_extensions)

    @patch("dns.resolver.Resolver")
    def test_combined_accounturi_and_validationmethods(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue",
                        "example.net; accounturi=https://example.net/account/1234; validationmethods=dns-01"),
        ]
        caa = CAA("example.com")
        self.assertTrue(caa.has_rfc8657_extensions)
        params = caa.caa_records[0]["parameters"]
        self.assertIn("accounturi", params)
        self.assertIn("validationmethods", params)
        self.assertEqual(caa.caa_records[0]["issuer_domain"], "example.net")

    @patch("dns.resolver.Resolver")
    def test_no_parameters_no_extension_flag(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.return_value = [
            _mock_rdata(0, "issue", "letsencrypt.org"),
        ]
        caa = CAA("example.com")
        self.assertFalse(caa.has_rfc8657_extensions)


class TestIDNAEncoding(unittest.TestCase):
    """Tests for IDNA per-label encoding."""

    def test_ascii_domain_unchanged(self):
        self.assertEqual(_encode_idna("example.com"), "example.com")

    def test_unicode_label_encoded(self):
        result = _encode_idna("münchen.de")
        self.assertEqual(result, "xn--mnchen-3ya.de")

    def test_multi_label_unicode(self):
        result = _encode_idna("sub.münchen.de")
        self.assertEqual(result, "sub.xn--mnchen-3ya.de")

    def test_already_punycode_unchanged(self):
        result = _encode_idna("xn--mnchen-3ya.de")
        self.assertEqual(result, "xn--mnchen-3ya.de")


class TestCAAResolverOrder(unittest.TestCase):
    """Tests for resolver configuration (cross-zone safety)."""

    @patch("dns.resolver.Resolver")
    def test_recursive_resolvers_first_when_dns_server_set(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer
        caa = CAA("example.com", dns_server="10.0.0.1")
        resolver = caa._get_resolver()
        self.assertEqual(resolver.nameservers[0], "1.1.1.1")
        self.assertEqual(resolver.nameservers[1], "8.8.8.8")
        self.assertEqual(resolver.nameservers[2], "10.0.0.1")


class TestCAAToDict(unittest.TestCase):
    """Tests for to_dict() completeness."""

    @patch("dns.resolver.Resolver")
    def test_all_keys_present(self, mock_resolver_class):
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer
        caa = CAA("example.com")
        d = caa.to_dict()
        expected_keys = {
            "CAA_RECORDS", "CAA_HAS_ISSUE", "CAA_HAS_ISSUEWILD",
            "CAA_HAS_IODEF", "CAA_HAS_CONTACTEMAIL", "CAA_HAS_CONTACTPHONE",
            "CAA_HAS_CRITICAL", "CAA_HAS_UNKNOWN_CRITICAL",
            "CAA_HAS_RFC8657_EXT", "CAA_DENY_ALL_REGULAR", "CAA_DENY_ALL_WILDCARD",
            "CAA_EFFECTIVE_DOMAIN", "CAA_ERROR", "CAA_ERROR_DOMAIN",
        }
        self.assertEqual(set(d.keys()), expected_keys)


if __name__ == "__main__":
    unittest.main()
