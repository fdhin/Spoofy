# modules/history.py

"""
SQLite-backed scan history for SpoofyVibe.

Stores scan results in a local database for trend tracking and comparison.
Default location: ~/.spoofyvibe/history.db
"""

import json
import logging
import os
import sqlite3
from datetime import datetime

logger = logging.getLogger("spoofyvibe.history")

DEFAULT_DB_DIR = os.path.expanduser("~/.spoofyvibe")
DEFAULT_DB_PATH = os.path.join(DEFAULT_DB_DIR, "history.db")

# Schema version for future migrations
SCHEMA_VERSION = 1


class ScanHistory:
    """Manages scan history storage and retrieval."""

    def __init__(self, db_path=None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self._ensure_dir()
        self._init_db()

    def _ensure_dir(self):
        """Create the database directory if it doesn't exist."""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            logger.debug("Created history directory: %s", db_dir)

    def _get_conn(self):
        """Get a new database connection (thread-safe pattern)."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        """Initialize the database schema."""
        conn = self._get_conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS schema_info (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );

                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    grade TEXT NOT NULL,
                    spoofable INTEGER,
                    spf_score INTEGER,
                    dmarc_score INTEGER,
                    dkim_score INTEGER,
                    bimi_score INTEGER,
                    spoof_score INTEGER,
                    mta_sts_score INTEGER,
                    mx_score INTEGER,
                    result_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_scans_domain
                    ON scans(domain);
                CREATE INDEX IF NOT EXISTS idx_scans_timestamp
                    ON scans(timestamp);
                CREATE INDEX IF NOT EXISTS idx_scans_domain_ts
                    ON scans(domain, timestamp);
            """)

            # Set schema version
            conn.execute(
                "INSERT OR REPLACE INTO schema_info (key, value) VALUES (?, ?)",
                ("schema_version", str(SCHEMA_VERSION)),
            )
            conn.commit()
            logger.debug("Database initialized at %s", self.db_path)
        finally:
            conn.close()

    def save_scan(self, result):
        """
        Save a scan result to the database.

        Args:
            result: dict from process_domain() with SECURITY_SCORE, SECURITY_GRADE, etc.

        Returns:
            int: the row ID of the inserted scan
        """
        domain = result.get("DOMAIN", "unknown")
        score = result.get("SECURITY_SCORE", 0)
        grade = result.get("SECURITY_GRADE", "?")
        spoofable = result.get("SPOOFING_POSSIBLE")
        breakdown = result.get("SCORE_BREAKDOWN", {})

        # Convert spoofable to int for SQLite (True=1, False=0, None=-1)
        if spoofable is True:
            spoofable_int = 1
        elif spoofable is False:
            spoofable_int = 0
        else:
            spoofable_int = -1

        timestamp = datetime.utcnow().isoformat() + "Z"

        conn = self._get_conn()
        try:
            cursor = conn.execute(
                """INSERT INTO scans
                   (domain, timestamp, score, grade, spoofable,
                    spf_score, dmarc_score, dkim_score, bimi_score,
                    spoof_score, mta_sts_score, mx_score, result_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    domain,
                    timestamp,
                    score,
                    grade,
                    spoofable_int,
                    breakdown.get("spf", {}).get("score", 0),
                    breakdown.get("dmarc", {}).get("score", 0),
                    breakdown.get("dkim", {}).get("score", 0),
                    breakdown.get("bimi", {}).get("score", 0),
                    breakdown.get("spoofability", {}).get("score", 0),
                    breakdown.get("mta_sts", {}).get("score", 0),
                    breakdown.get("mx", {}).get("score", 0),
                    json.dumps(result, default=str),
                ),
            )
            conn.commit()
            row_id = cursor.lastrowid
            logger.debug("Saved scan for %s (id=%d, score=%d)", domain, row_id, score)
            return row_id
        finally:
            conn.close()

    def save_bulk(self, results):
        """Save multiple scan results in a single transaction."""
        conn = self._get_conn()
        ids = []
        try:
            for result in results:
                domain = result.get("DOMAIN", "unknown")
                score = result.get("SECURITY_SCORE", 0)
                grade = result.get("SECURITY_GRADE", "?")
                spoofable = result.get("SPOOFING_POSSIBLE")
                breakdown = result.get("SCORE_BREAKDOWN", {})
                spoofable_int = 1 if spoofable is True else (0 if spoofable is False else -1)
                timestamp = datetime.utcnow().isoformat() + "Z"

                cursor = conn.execute(
                    """INSERT INTO scans
                       (domain, timestamp, score, grade, spoofable,
                        spf_score, dmarc_score, dkim_score, bimi_score,
                        spoof_score, mta_sts_score, mx_score, result_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        domain, timestamp, score, grade, spoofable_int,
                        breakdown.get("spf", {}).get("score", 0),
                        breakdown.get("dmarc", {}).get("score", 0),
                        breakdown.get("dkim", {}).get("score", 0),
                        breakdown.get("bimi", {}).get("score", 0),
                        breakdown.get("spoofability", {}).get("score", 0),
                        breakdown.get("mta_sts", {}).get("score", 0),
                        breakdown.get("mx", {}).get("score", 0),
                        json.dumps(result, default=str),
                    ),
                )
                ids.append(cursor.lastrowid)
            conn.commit()
            logger.debug("Saved %d scans in bulk", len(ids))
            return ids
        finally:
            conn.close()

    def get_scans(self, limit=50, offset=0, domain_filter=None):
        """
        Get recent scans, optionally filtered by domain.

        Returns:
            list of dicts with scan metadata (not full result JSON)
        """
        conn = self._get_conn()
        try:
            if domain_filter:
                rows = conn.execute(
                    """SELECT id, domain, timestamp, score, grade, spoofable,
                              spf_score, dmarc_score, dkim_score, bimi_score,
                              spoof_score, mta_sts_score, mx_score
                       FROM scans WHERE domain LIKE ?
                       ORDER BY timestamp DESC LIMIT ? OFFSET ?""",
                    (f"%{domain_filter}%", limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT id, domain, timestamp, score, grade, spoofable,
                              spf_score, dmarc_score, dkim_score, bimi_score,
                              spoof_score, mta_sts_score, mx_score
                       FROM scans
                       ORDER BY timestamp DESC LIMIT ? OFFSET ?""",
                    (limit, offset),
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_scan_detail(self, scan_id):
        """Get full scan detail including result JSON."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            if row:
                d = dict(row)
                d["result"] = json.loads(d.pop("result_json"))
                return d
            return None
        finally:
            conn.close()

    def get_domain_history(self, domain, limit=20):
        """Get scan history for a specific domain (newest first)."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                """SELECT id, domain, timestamp, score, grade, spoofable,
                          spf_score, dmarc_score, dkim_score, bimi_score,
                          spoof_score, mta_sts_score, mx_score
                   FROM scans WHERE domain = ?
                   ORDER BY timestamp DESC LIMIT ?""",
                (domain, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_trend(self, domain, limit=10):
        """
        Get score trend data for a domain (oldest first, for charting).

        Returns:
            list of dicts with timestamp, score, grade
        """
        conn = self._get_conn()
        try:
            rows = conn.execute(
                """SELECT timestamp, score, grade,
                          spf_score, dmarc_score, dkim_score, bimi_score,
                          spoof_score, mta_sts_score, mx_score
                   FROM scans WHERE domain = ?
                   ORDER BY timestamp ASC LIMIT ?""",
                (domain, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_unique_domains(self):
        """Get list of unique domains that have been scanned."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT DISTINCT domain FROM scans ORDER BY domain"
            ).fetchall()
            return [r["domain"] for r in rows]
        finally:
            conn.close()

    def get_stats(self):
        """Get aggregate statistics across all scans."""
        conn = self._get_conn()
        try:
            row = conn.execute("""
                SELECT
                    COUNT(*) as total_scans,
                    COUNT(DISTINCT domain) as unique_domains,
                    ROUND(AVG(score), 1) as avg_score,
                    MIN(score) as min_score,
                    MAX(score) as max_score,
                    SUM(CASE WHEN spoofable = 1 THEN 1 ELSE 0 END) as spoofable_count,
                    SUM(CASE WHEN spoofable = 0 THEN 1 ELSE 0 END) as safe_count,
                    MIN(timestamp) as first_scan,
                    MAX(timestamp) as last_scan
                FROM scans
            """).fetchone()
            return dict(row) if row else {}
        finally:
            conn.close()

    def delete_domain(self, domain):
        """Delete all scan history for a domain."""
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM scans WHERE domain = ?", (domain,))
            conn.commit()
            logger.info("Deleted history for %s", domain)
        finally:
            conn.close()
