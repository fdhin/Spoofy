# tests/test_subdomain.py

"""Tests for the SubdomainFinder module."""

import unittest
from unittest.mock import patch, MagicMock
from modules.subdomain import SubdomainFinder


class TestSubdomainFinder(unittest.TestCase):
    """Tests for subdomain discovery via crt.sh."""

    def test_init(self):
        """Constructor should set domain and defaults."""
        finder = SubdomainFinder("example.com")
        self.assertEqual(finder.domain, "example.com")
        self.assertEqual(finder.subdomains, set())
        self.assertIsNone(finder.error)

    def test_init_strips_and_lowercases(self):
        """Domain should be normalized."""
        finder = SubdomainFinder("  EXAMPLE.COM  ")
        self.assertEqual(finder.domain, "example.com")

    # --- Validation Tests ---

    def test_valid_subdomain(self):
        """Valid subdomains should pass validation."""
        finder = SubdomainFinder("example.com")
        self.assertTrue(finder._is_valid_subdomain("mail.example.com"))
        self.assertTrue(finder._is_valid_subdomain("sub.sub.example.com"))
        self.assertTrue(finder._is_valid_subdomain("example.com"))

    def test_wildcard_rejected(self):
        """Wildcard entries should be rejected."""
        finder = SubdomainFinder("example.com")
        self.assertFalse(finder._is_valid_subdomain("*.example.com"))

    def test_wrong_domain_rejected(self):
        """Subdomains of other domains should be rejected."""
        finder = SubdomainFinder("example.com")
        self.assertFalse(finder._is_valid_subdomain("mail.other.com"))

    def test_empty_name_rejected(self):
        """Empty strings should be rejected."""
        finder = SubdomainFinder("example.com")
        self.assertFalse(finder._is_valid_subdomain(""))

    def test_invalid_chars_rejected(self):
        """Names with invalid characters should be rejected."""
        finder = SubdomainFinder("example.com")
        self.assertFalse(finder._is_valid_subdomain("sub domain.example.com"))
        self.assertFalse(finder._is_valid_subdomain("sub_domain.example.com"))

    # --- Discovery Tests ---

    @patch("modules.subdomain.requests.get")
    def test_discover_parses_crt_sh_response(self, mock_get):
        """discover() should parse crt.sh JSON and return unique subdomains."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"name_value": "mail.example.com"},
            {"name_value": "www.example.com\napi.example.com"},
            {"name_value": "mail.example.com"},  # duplicate
            {"name_value": "*.example.com"},  # wildcard
        ]
        mock_get.return_value = mock_resp

        finder = SubdomainFinder("example.com")
        result = finder.discover()

        self.assertIn("mail.example.com", result)
        self.assertIn("www.example.com", result)
        self.assertIn("api.example.com", result)
        self.assertIn("example.com", result)  # base domain always included
        # No wildcards
        self.assertNotIn("*.example.com", result)
        # Result should be sorted
        self.assertEqual(result, sorted(result))

    @patch("modules.subdomain.requests.get")
    def test_discover_deduplicates(self, mock_get):
        """Duplicate subdomains should be deduplicated."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"name_value": "mail.example.com"},
            {"name_value": "mail.example.com"},
            {"name_value": "mail.example.com"},
        ]
        mock_get.return_value = mock_resp

        finder = SubdomainFinder("example.com")
        result = finder.discover()
        mail_count = result.count("mail.example.com")
        self.assertEqual(mail_count, 1)

    @patch("modules.subdomain.requests.get")
    def test_discover_http_error(self, mock_get):
        """Non-200 response should return base domain and set error."""
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_get.return_value = mock_resp

        finder = SubdomainFinder("example.com")
        result = finder.discover()
        self.assertEqual(result, [])
        self.assertIsNotNone(finder.error)
        self.assertIn("429", finder.error)

    @patch("modules.subdomain.requests.get")
    def test_discover_timeout(self, mock_get):
        """Timeout should return base domain and set error."""
        import requests
        mock_get.side_effect = requests.exceptions.Timeout()

        finder = SubdomainFinder("example.com")
        result = finder.discover()
        self.assertIn("example.com", result)
        self.assertIsNotNone(finder.error)
        self.assertIn("timeout", finder.error.lower())

    @patch("modules.subdomain.requests.get")
    def test_discover_connection_error(self, mock_get):
        """Connection error should return base domain and set error."""
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError("DNS failure")

        finder = SubdomainFinder("example.com")
        result = finder.discover()
        self.assertIn("example.com", result)
        self.assertIsNotNone(finder.error)

    # --- to_dict Tests ---

    def test_to_dict_structure(self):
        """to_dict should return expected keys."""
        finder = SubdomainFinder("example.com")
        finder.subdomains = {"mail.example.com", "example.com"}
        d = finder.to_dict()
        self.assertEqual(d["domain"], "example.com")
        self.assertEqual(d["count"], 2)
        self.assertIsInstance(d["subdomains"], list)
        self.assertIsNone(d["error"])

    # --- __str__ Tests ---

    def test_str_no_results(self):
        """__str__ with no results should indicate that."""
        finder = SubdomainFinder("example.com")
        self.assertIn("No subdomains", str(finder))

    def test_str_with_results(self):
        """__str__ with results should list subdomains."""
        finder = SubdomainFinder("example.com")
        finder.subdomains = {"mail.example.com", "example.com"}
        output = str(finder)
        self.assertIn("mail.example.com", output)
        self.assertIn("2 found", output)


if __name__ == "__main__":
    unittest.main()
