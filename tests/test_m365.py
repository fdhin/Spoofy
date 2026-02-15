# tests/test_m365.py

"""Tests for the Microsoft 365 tenant discovery module."""

import unittest
from unittest.mock import patch, MagicMock

import dns.resolver


class TestM365Tenant(unittest.TestCase):
    """Tests for M365Tenant class."""

    def _make_m365(self, mx_records=None, resolve_domains=None):
        """Helper: create M365Tenant with mocked DNS.

        Args:
            mx_records: list of dicts with 'host' keys
            resolve_domains: set of FQDNs that should resolve successfully
        """
        from modules.m365 import M365Tenant

        resolve_domains = resolve_domains or set()

        def _resolve(domain, rdtype):
            if domain in resolve_domains:
                answer = MagicMock()
                answer.__len__ = lambda self: 1
                return answer
            raise dns.resolver.NXDOMAIN()

        with patch("modules.m365.dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = MagicMock(side_effect=_resolve)
            return M365Tenant("example.com", mx_records or [], "1.1.1.1")

    # --- M365 detection ---

    def test_m365_detected_from_mx(self):
        """Should detect M365 from outlook MX pattern."""
        mx = [{"host": "example-com.mail.protection.outlook.com"}]
        m365 = self._make_m365(mx_records=mx)
        self.assertTrue(m365.is_m365)

    def test_m365_detected_trailing_dot(self):
        """Should detect M365 from MX with trailing dot."""
        mx = [{"host": "example-com.mail.protection.outlook.com."}]
        m365 = self._make_m365(mx_records=mx)
        self.assertTrue(m365.is_m365)

    def test_m365_not_detected_google(self):
        """Should not detect M365 from Google MX."""
        mx = [{"host": "aspmx.l.google.com"}]
        m365 = self._make_m365(mx_records=mx)
        self.assertFalse(m365.is_m365)

    def test_m365_not_detected_empty(self):
        """Should not detect M365 with no MX records."""
        m365 = self._make_m365(mx_records=[])
        self.assertFalse(m365.is_m365)

    def test_m365_not_detected_proofpoint(self):
        """Should not detect M365 from Proofpoint MX."""
        mx = [{"host": "mx1.example.pphosted.com"}]
        m365 = self._make_m365(mx_records=mx)
        self.assertFalse(m365.is_m365)

    # --- Tenant name extraction ---

    def test_tenant_name_extracted(self):
        """Should extract tenant name from MX host."""
        mx = [{"host": "contoso-com.mail.protection.outlook.com"}]
        m365 = self._make_m365(mx_records=mx)
        self.assertEqual(m365.tenant_name, "contoso-com")

    def test_tenant_name_complex(self):
        """Should extract tenant name with hyphens."""
        mx = [{"host": "my-company-org.mail.protection.outlook.com"}]
        m365 = self._make_m365(mx_records=mx)
        self.assertEqual(m365.tenant_name, "my-company-org")

    # --- Tenant domain discovery ---

    def test_tenant_domains_discovered(self):
        """Should discover .onmicrosoft.com domains that resolve."""
        mx = [{"host": "contoso-com.mail.protection.outlook.com"}]
        resolving = {
            "contoso-com.onmicrosoft.com",
            "contoso-com.mail.onmicrosoft.com",
        }
        m365 = self._make_m365(mx_records=mx, resolve_domains=resolving)
        self.assertIn("contoso-com.onmicrosoft.com", m365.tenant_domains)
        self.assertIn("contoso-com.mail.onmicrosoft.com", m365.tenant_domains)

    def test_tenant_domains_none_resolve(self):
        """Should return empty list when no tenant domains resolve."""
        mx = [{"host": "contoso-com.mail.protection.outlook.com"}]
        m365 = self._make_m365(mx_records=mx, resolve_domains=set())
        self.assertEqual(m365.tenant_domains, [])

    def test_tenant_domains_partial(self):
        """Should only include domains that actually resolve."""
        mx = [{"host": "contoso-com.mail.protection.outlook.com"}]
        resolving = {"contoso-com.onmicrosoft.com"}
        m365 = self._make_m365(mx_records=mx, resolve_domains=resolving)
        self.assertIn("contoso-com.onmicrosoft.com", m365.tenant_domains)
        self.assertNotIn("contoso-com.mail.onmicrosoft.com", m365.tenant_domains)

    # --- to_dict ---

    def test_to_dict_detected(self):
        """to_dict should return correct structure when M365 detected."""
        mx = [{"host": "contoso-com.mail.protection.outlook.com"}]
        resolving = {"contoso-com.onmicrosoft.com"}
        m365 = self._make_m365(mx_records=mx, resolve_domains=resolving)
        d = m365.to_dict()
        self.assertTrue(d["M365_DETECTED"])
        self.assertEqual(d["M365_TENANT_NAME"], "contoso-com")
        self.assertIsInstance(d["M365_TENANT_DOMAINS"], list)

    def test_to_dict_not_detected(self):
        """to_dict should return correct structure when M365 not detected."""
        m365 = self._make_m365(mx_records=[])
        d = m365.to_dict()
        self.assertFalse(d["M365_DETECTED"])
        self.assertIsNone(d["M365_TENANT_NAME"])
        self.assertEqual(d["M365_TENANT_DOMAINS"], [])

    # --- __str__ ---

    def test_str_detected(self):
        """String representation when M365 detected."""
        mx = [{"host": "contoso-com.mail.protection.outlook.com"}]
        m365 = self._make_m365(mx_records=mx)
        s = str(m365)
        self.assertIn("Detected", s)

    def test_str_not_detected(self):
        """String representation when not M365."""
        m365 = self._make_m365(mx_records=[])
        s = str(m365)
        self.assertIn("Not detected", s)

    # --- MX as string input ---

    def test_mx_as_string(self):
        """Should handle MX records as plain strings."""
        mx = ["contoso-com.mail.protection.outlook.com"]
        m365 = self._make_m365(mx_records=mx)
        self.assertTrue(m365.is_m365)

    # --- Domain normalization ---

    def test_domain_normalized(self):
        """Domain should be lowercased and stripped."""
        mx = [{"host": "contoso-com.mail.protection.outlook.com"}]
        m365 = self._make_m365(mx_records=mx)
        self.assertEqual(m365.domain, "example.com")


if __name__ == "__main__":
    unittest.main()
