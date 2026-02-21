# tests/test_caa.py

"""Tests for CAA record analysis module."""

import unittest
from unittest.mock import patch, MagicMock
from modules.caa import CAA

class TestCAA(unittest.TestCase):
    """Tests for the CAA class."""

    @patch("dns.resolver.Resolver")
    def test_caa_found(self, mock_resolver_class):
        """Test parsing when CAA records are found."""
        mock_resolver = mock_resolver_class.return_value
        
        # Mock DNS response
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = '0 issue "letsencrypt.org"'
        
        mock_answer2 = MagicMock()
        mock_answer2.to_text.return_value = '0 issuewild ";"'
        
        mock_resolver.resolve.return_value = [mock_answer, mock_answer2]

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
        import dns.resolver
        mock_resolver = mock_resolver_class.return_value
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer

        caa = CAA("example.com")
        self.assertEqual(len(caa.caa_records), 0)
        self.assertFalse(caa.has_issue_record)
        self.assertFalse(caa.has_issuewild_record)

        d = caa.to_dict()
        self.assertFalse(d["CAA_HAS_ISSUE"])
        self.assertEqual(len(d["CAA_RECORDS"]), 0)

if __name__ == "__main__":
    unittest.main()
