# tests/test_mx.py

"""Tests for MX record analysis module."""

import unittest
from unittest.mock import patch, MagicMock
from modules.mx import MX, MXRecord


class TestMX(unittest.TestCase):
    """Tests for MX class."""

    @patch.object(MX, '__init__', lambda self, *a, **kw: None)
    def _make_instance(self, records=None, providers=None):
        """Create a bare MX instance with specified attributes."""
        obj = MX.__new__(MX)
        obj.domain = "example.com"
        obj.dns_server = None
        obj.records = records or []
        obj.providers = providers or set()
        obj.all_starttls = None
        obj.has_ptr = None
        # Compute all_starttls and has_ptr from records
        if obj.records:
            tls_vals = [mx.starttls for mx in obj.records if mx.starttls is not None]
            if tls_vals:
                obj.all_starttls = all(tls_vals)
            ptr_vals = [mx.ptr_record for mx in obj.records]
            obj.has_ptr = all(p is not None for p in ptr_vals)
        return obj

    def _make_mx_record(self, priority, host, starttls=None, ptr=None, ip=None):
        """Create an MXRecord with given attributes."""
        rec = MXRecord(priority, host)
        rec.starttls = starttls
        rec.ptr_record = ptr
        rec.ip_address = ip
        return rec

    # --- to_dict tests ---

    def test_to_dict_empty(self):
        """No MX records returns empty lists."""
        obj = self._make_instance()
        d = obj.to_dict()
        self.assertEqual(d["MX_COUNT"], 0)
        self.assertEqual(d["MX_RECORDS"], [])
        self.assertEqual(d["MX_PROVIDERS"], [])
        self.assertIsNone(d["MX_ALL_STARTTLS"])
        self.assertIsNone(d["MX_ALL_PTR"])

    def test_to_dict_with_records(self):
        """MX records are included in output."""
        records = [
            self._make_mx_record(10, "mx1.example.com", starttls=True, ptr="mx1.example.com"),
            self._make_mx_record(20, "mx2.example.com", starttls=True, ptr="mx2.example.com"),
        ]
        obj = self._make_instance(records=records, providers={"Unknown"})
        d = obj.to_dict()
        self.assertEqual(d["MX_COUNT"], 2)
        self.assertTrue(d["MX_ALL_STARTTLS"])
        self.assertTrue(d["MX_ALL_PTR"])
        self.assertIn("Unknown", d["MX_PROVIDERS"])

    def test_to_dict_mixed_starttls(self):
        """Mixed STARTTLS results."""
        records = [
            self._make_mx_record(10, "mx1.example.com", starttls=True, ptr="mx1.example.com"),
            self._make_mx_record(20, "mx2.example.com", starttls=False, ptr="mx2.example.com"),
        ]
        obj = self._make_instance(records=records)
        d = obj.to_dict()
        self.assertFalse(d["MX_ALL_STARTTLS"])

    def test_to_dict_no_ptr(self):
        """Missing PTR records."""
        records = [
            self._make_mx_record(10, "mx1.example.com", starttls=True, ptr=None),
        ]
        obj = self._make_instance(records=records)
        d = obj.to_dict()
        self.assertFalse(d["MX_ALL_PTR"])

    # --- get_mx_hosts tests ---

    def test_get_mx_hosts(self):
        """get_mx_hosts returns list of hostnames."""
        records = [
            self._make_mx_record(10, "mx1.google.com"),
            self._make_mx_record(20, "mx2.google.com"),
        ]
        obj = self._make_instance(records=records)
        hosts = obj.get_mx_hosts()
        self.assertEqual(hosts, ["mx1.google.com", "mx2.google.com"])

    def test_get_mx_hosts_empty(self):
        """get_mx_hosts returns empty list when no records."""
        obj = self._make_instance()
        self.assertEqual(obj.get_mx_hosts(), [])

    # --- Provider identification tests ---

    def test_identify_google_provider(self):
        """Google Workspace MX hosts are identified."""
        obj = self._make_instance()
        obj.records = [MXRecord(10, "aspmx.l.google.com")]
        obj._identify_providers()
        self.assertEqual(obj.records[0].provider, "Google Workspace")
        self.assertIn("Google Workspace", obj.providers)

    def test_identify_microsoft_provider(self):
        """Microsoft 365 MX hosts are identified."""
        obj = self._make_instance()
        obj.records = [MXRecord(10, "example-com.mail.protection.outlook.com")]
        obj._identify_providers()
        self.assertEqual(obj.records[0].provider, "Microsoft 365")
        self.assertIn("Microsoft 365", obj.providers)

    def test_identify_proofpoint_provider(self):
        """Proofpoint MX hosts are identified."""
        obj = self._make_instance()
        obj.records = [MXRecord(10, "mx1.pphosted.com")]
        obj._identify_providers()
        self.assertEqual(obj.records[0].provider, "Proofpoint")
        self.assertIn("Proofpoint", obj.providers)

    def test_identify_unknown_provider(self):
        """Unknown providers get 'Unknown' label."""
        obj = self._make_instance()
        obj.records = [MXRecord(10, "mail.custommailserver.xyz")]
        obj._identify_providers()
        self.assertEqual(obj.records[0].provider, "Unknown")

    # --- Scoring integration tests ---

    def test_scoring_no_mx(self):
        """No MX records yields 0 MX score."""
        from modules.scoring import SecurityScore
        result = {
            "SPF": None, "DMARC": None, "DKIM": None, "BIMI_RECORD": None,
            "SPOOFING_POSSIBLE": True,
            "MTA_STS_TXT": None, "MTA_STS_MODE": None,
            "TLS_RPT_RECORD": None,
            "MX_RECORDS": [], "MX_COUNT": 0,
        }
        score = SecurityScore(result)
        self.assertEqual(score.breakdown["mx"]["score"], 0)

    def test_scoring_strong_mx(self):
        """Good MX setup gets high score."""
        from modules.scoring import SecurityScore
        result = {
            "SPF": None, "DMARC": None, "DKIM": None, "BIMI_RECORD": None,
            "SPOOFING_POSSIBLE": True,
            "MTA_STS_TXT": None, "MTA_STS_MODE": None,
            "TLS_RPT_RECORD": None,
            "MX_RECORDS": [
                {"host": "mx1.example.com", "starttls": True, "ptr": "mx1.example.com"},
                {"host": "mx2.example.com", "starttls": True, "ptr": "mx2.example.com"},
            ],
            "MX_COUNT": 2,
            "MX_ALL_STARTTLS": True,
            "MX_ALL_PTR": True,
            "MX_PROVIDERS": ["Unknown"],
        }
        score = SecurityScore(result)
        self.assertEqual(score.breakdown["mx"]["score"], 7)  # 2 + 2 + 3

    def test_scoring_single_mx_no_tls(self):
        """Single MX without STARTTLS gets minimal score."""
        from modules.scoring import SecurityScore
        result = {
            "SPF": None, "DMARC": None, "DKIM": None, "BIMI_RECORD": None,
            "SPOOFING_POSSIBLE": True,
            "MTA_STS_TXT": None, "MTA_STS_MODE": None,
            "TLS_RPT_RECORD": None,
            "MX_RECORDS": [{"host": "mx1.example.com", "starttls": False, "ptr": None}],
            "MX_COUNT": 1,
            "MX_ALL_STARTTLS": False,
            "MX_ALL_PTR": False,
        }
        score = SecurityScore(result)
        self.assertEqual(score.breakdown["mx"]["score"], 2)  # Just MX exists

    # --- Remediation integration tests ---

    def test_remediation_no_mx(self):
        """Missing MX records generates recommendation."""
        from modules.remediation import RemediationEngine
        result = {
            "DOMAIN": "test.com",
            "SPF": "v=spf1 -all", "SPF_MULTIPLE_ALLS": "-all",
            "DMARC": "v=DMARC1; p=reject", "DMARC_POLICY": "reject",
            "DMARC_AGGREGATE_REPORT": "mailto:d@t.com",
            "DKIM": "selector1", "BIMI_RECORD": None,
            "SPOOFING_POSSIBLE": False,
            "MTA_STS_TXT": "v=STSv1; id=1", "MTA_STS_MODE": "enforce",
            "TLS_RPT_RECORD": "v=TLSRPTv1; rua=mailto:t@t.com",
            "MX_RECORDS": [], "MX_COUNT": 0,
        }
        engine = RemediationEngine(result)
        categories = [r.category for r in engine.recommendations]
        self.assertIn("MX", categories)

    def test_remediation_no_starttls(self):
        """MX without STARTTLS generates recommendation."""
        from modules.remediation import RemediationEngine
        result = {
            "DOMAIN": "test.com",
            "SPF": "v=spf1 -all", "SPF_MULTIPLE_ALLS": "-all",
            "DMARC": "v=DMARC1; p=reject", "DMARC_POLICY": "reject",
            "DMARC_AGGREGATE_REPORT": "mailto:d@t.com",
            "DKIM": "selector1", "BIMI_RECORD": None,
            "SPOOFING_POSSIBLE": False,
            "MTA_STS_TXT": "v=STSv1; id=1", "MTA_STS_MODE": "enforce",
            "TLS_RPT_RECORD": "v=TLSRPTv1; rua=mailto:t@t.com",
            "MX_RECORDS": [{"host": "mx1.test.com", "starttls": False, "ptr": "mx1.test.com"}],
            "MX_COUNT": 1,
            "MX_ALL_STARTTLS": False,
            "MX_ALL_PTR": True,
        }
        engine = RemediationEngine(result)
        titles = [r.title for r in engine.recommendations]
        self.assertTrue(any("STARTTLS" in t for t in titles))

    def test_remediation_single_mx(self):
        """Single MX generates redundancy recommendation."""
        from modules.remediation import RemediationEngine
        result = {
            "DOMAIN": "test.com",
            "SPF": "v=spf1 -all", "SPF_MULTIPLE_ALLS": "-all",
            "DMARC": "v=DMARC1; p=reject", "DMARC_POLICY": "reject",
            "DMARC_AGGREGATE_REPORT": "mailto:d@t.com",
            "DKIM": "selector1", "BIMI_RECORD": None,
            "SPOOFING_POSSIBLE": False,
            "MTA_STS_TXT": "v=STSv1; id=1", "MTA_STS_MODE": "enforce",
            "TLS_RPT_RECORD": "v=TLSRPTv1; rua=mailto:t@t.com",
            "MX_RECORDS": [{"host": "mx1.test.com", "starttls": True, "ptr": "mx1.test.com"}],
            "MX_COUNT": 1,
            "MX_ALL_STARTTLS": True,
            "MX_ALL_PTR": True,
        }
        engine = RemediationEngine(result)
        titles = [r.title for r in engine.recommendations]
        self.assertTrue(any("redundancy" in t.lower() for t in titles))


if __name__ == "__main__":
    unittest.main()
