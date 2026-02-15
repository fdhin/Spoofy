# tests/test_history.py

"""Tests for the ScanHistory SQLite module."""

import json
import os
import sqlite3
import tempfile
import unittest

from modules.history import ScanHistory


class TestScanHistory(unittest.TestCase):
    """Tests for scan history storage and retrieval."""

    def setUp(self):
        """Create a temp database for each test."""
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_history.db")
        self.history = ScanHistory(db_path=self.db_path)

    def tearDown(self):
        """Clean up temp database."""
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        # Remove WAL/SHM files if present
        for ext in ["-wal", "-shm"]:
            p = self.db_path + ext
            if os.path.exists(p):
                os.remove(p)
        os.rmdir(self.tmpdir)

    def _make_result(self, domain="test.com", score=75, grade="B-", spoofable=False, **overrides):
        """Create a minimal scan result dict."""
        result = {
            "DOMAIN": domain,
            "SECURITY_SCORE": score,
            "SECURITY_GRADE": grade,
            "SPOOFING_POSSIBLE": spoofable,
            "SCORE_BREAKDOWN": {
                "spf": {"score": 20, "max": 20},
                "dmarc": {"score": 18, "max": 25},
                "dkim": {"score": 12, "max": 15},
                "bimi": {"score": 3, "max": 5},
                "spoofability": {"score": 15, "max": 15},
                "mta_sts": {"score": 5, "max": 10},
                "mx": {"score": 2, "max": 10},
            },
        }
        result.update(overrides)
        return result

    # --- Init Tests ---

    def test_db_created(self):
        """Database file should exist after init."""
        self.assertTrue(os.path.exists(self.db_path))

    def test_schema_tables_exist(self):
        """Schema should contain expected tables."""
        conn = sqlite3.connect(self.db_path)
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        conn.close()
        table_names = [t[0] for t in tables]
        self.assertIn("scans", table_names)
        self.assertIn("schema_info", table_names)

    # --- Save Tests ---

    def test_save_scan_returns_id(self):
        """save_scan should return a positive integer ID."""
        result = self._make_result()
        row_id = self.history.save_scan(result)
        self.assertIsInstance(row_id, int)
        self.assertGreater(row_id, 0)

    def test_save_scan_stores_data(self):
        """Saved scan should be retrievable."""
        result = self._make_result(domain="example.org", score=90, grade="A")
        row_id = self.history.save_scan(result)
        detail = self.history.get_scan_detail(row_id)
        self.assertIsNotNone(detail)
        self.assertEqual(detail["domain"], "example.org")
        self.assertEqual(detail["score"], 90)
        self.assertEqual(detail["grade"], "A")

    def test_save_spoofable_true(self):
        """Spoofable=True should be stored as 1."""
        result = self._make_result(spoofable=True)
        row_id = self.history.save_scan(result)
        detail = self.history.get_scan_detail(row_id)
        self.assertEqual(detail["spoofable"], 1)

    def test_save_spoofable_false(self):
        """Spoofable=False should be stored as 0."""
        result = self._make_result(spoofable=False)
        row_id = self.history.save_scan(result)
        detail = self.history.get_scan_detail(row_id)
        self.assertEqual(detail["spoofable"], 0)

    def test_save_spoofable_none(self):
        """Spoofable=None should be stored as -1."""
        result = self._make_result(spoofable=None)
        row_id = self.history.save_scan(result)
        detail = self.history.get_scan_detail(row_id)
        self.assertEqual(detail["spoofable"], -1)

    def test_save_bulk(self):
        """save_bulk should save multiple results in one transaction."""
        results = [
            self._make_result(domain="a.com", score=80),
            self._make_result(domain="b.com", score=60),
            self._make_result(domain="c.com", score=40),
        ]
        ids = self.history.save_bulk(results)
        self.assertEqual(len(ids), 3)
        scans = self.history.get_scans()
        self.assertEqual(len(scans), 3)

    # --- Retrieval Tests ---

    def test_get_scans_empty(self):
        """get_scans on empty DB returns empty list."""
        scans = self.history.get_scans()
        self.assertEqual(scans, [])

    def test_get_scans_ordered_by_timestamp(self):
        """Scans should be ordered newest first."""
        self.history.save_scan(self._make_result(domain="first.com"))
        self.history.save_scan(self._make_result(domain="second.com"))
        scans = self.history.get_scans()
        # second.com was saved last, should appear first
        self.assertEqual(scans[0]["domain"], "second.com")

    def test_get_scans_with_filter(self):
        """Domain filter should work with LIKE matching."""
        self.history.save_scan(self._make_result(domain="alpha.com"))
        self.history.save_scan(self._make_result(domain="beta.org"))
        scans = self.history.get_scans(domain_filter="alpha")
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["domain"], "alpha.com")

    def test_get_scans_pagination(self):
        """Limit and offset should work correctly."""
        for i in range(5):
            self.history.save_scan(self._make_result(domain=f"d{i}.com"))
        first_page = self.history.get_scans(limit=2, offset=0)
        second_page = self.history.get_scans(limit=2, offset=2)
        self.assertEqual(len(first_page), 2)
        self.assertEqual(len(second_page), 2)
        self.assertNotEqual(first_page[0]["domain"], second_page[0]["domain"])

    def test_get_scan_detail_not_found(self):
        """Non-existent scan ID should return None."""
        self.assertIsNone(self.history.get_scan_detail(99999))

    def test_get_scan_detail_includes_result_json(self):
        """Detail should include parsed result_json as 'result'."""
        result = self._make_result(domain="detail.com")
        row_id = self.history.save_scan(result)
        detail = self.history.get_scan_detail(row_id)
        self.assertIn("result", detail)
        self.assertIsInstance(detail["result"], dict)
        self.assertEqual(detail["result"]["DOMAIN"], "detail.com")

    def test_get_domain_history(self):
        """get_domain_history should filter by exact domain."""
        self.history.save_scan(self._make_result(domain="target.com", score=50))
        self.history.save_scan(self._make_result(domain="other.com", score=70))
        self.history.save_scan(self._make_result(domain="target.com", score=60))
        history = self.history.get_domain_history("target.com")
        self.assertEqual(len(history), 2)
        for s in history:
            self.assertEqual(s["domain"], "target.com")

    # --- Trend Tests ---

    def test_get_trend_ordered_oldest_first(self):
        """Trend data should be ordered oldest first for charting."""
        self.history.save_scan(self._make_result(domain="trend.com", score=40))
        self.history.save_scan(self._make_result(domain="trend.com", score=60))
        self.history.save_scan(self._make_result(domain="trend.com", score=80))
        trend = self.history.get_trend("trend.com")
        self.assertEqual(len(trend), 3)
        scores = [t["score"] for t in trend]
        self.assertEqual(scores, [40, 60, 80])

    def test_get_trend_empty(self):
        """Trend for non-existent domain returns empty list."""
        trend = self.history.get_trend("nonexistent.com")
        self.assertEqual(trend, [])

    # --- Stats Tests ---

    def test_get_stats(self):
        """get_stats should return aggregate data."""
        self.history.save_scan(self._make_result(domain="a.com", score=80, spoofable=False))
        self.history.save_scan(self._make_result(domain="b.com", score=40, spoofable=True))
        stats = self.history.get_stats()
        self.assertEqual(stats["total_scans"], 2)
        self.assertEqual(stats["unique_domains"], 2)
        self.assertEqual(stats["avg_score"], 60.0)
        self.assertEqual(stats["spoofable_count"], 1)
        self.assertEqual(stats["safe_count"], 1)

    def test_get_unique_domains(self):
        """Should return sorted list of unique domains."""
        self.history.save_scan(self._make_result(domain="b.com"))
        self.history.save_scan(self._make_result(domain="a.com"))
        self.history.save_scan(self._make_result(domain="b.com"))
        domains = self.history.get_unique_domains()
        self.assertEqual(domains, ["a.com", "b.com"])

    # --- Delete Tests ---

    def test_delete_domain(self):
        """delete_domain should remove all history for that domain."""
        self.history.save_scan(self._make_result(domain="delete.com"))
        self.history.save_scan(self._make_result(domain="keep.com"))
        self.history.delete_domain("delete.com")
        scans = self.history.get_scans()
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["domain"], "keep.com")

    # --- Category Scores ---

    def test_category_scores_stored(self):
        """Individual category scores should be stored in columns."""
        result = self._make_result()
        row_id = self.history.save_scan(result)
        detail = self.history.get_scan_detail(row_id)
        self.assertEqual(detail["spf_score"], 20)
        self.assertEqual(detail["dmarc_score"], 18)
        self.assertEqual(detail["dkim_score"], 12)
        self.assertEqual(detail["bimi_score"], 3)
        self.assertEqual(detail["spoof_score"], 15)
        self.assertEqual(detail["mta_sts_score"], 5)
        self.assertEqual(detail["mx_score"], 2)


if __name__ == "__main__":
    unittest.main()
