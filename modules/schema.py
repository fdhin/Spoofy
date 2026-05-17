# modules/schema.py

"""
Canonical result schema for SpoofyVibe domain scans.

This module defines:
  1. ScanStatus enum — standardized status values across all modules.
  2. Result dict key constants — the ONE canonical name for each field.
  3. CATEGORY_DISPLAY_NAMES — human-friendly labels for scoring categories.

Every module that produces or consumes result dict keys should import
constants from here instead of using hardcoded string literals.

See SCHEMA.md for the full human-readable reference.
"""

from enum import Enum


class ScanStatus(str, Enum):
    """Standardized status values for DNS record lookups.

    All modules should use these values to indicate the outcome of a
    record lookup, rather than overloading None, boolean flags, or
    sentinel strings like "MULTIPLE".
    """
    OK = "ok"                # Record found and valid
    NOT_FOUND = "not_found"  # No record published
    PERMERROR = "permerror"   # Record exists but is invalid (multiple records, bad syntax)
    TEMPERROR = "temperror"  # Transient DNS failure (timeout, SERVFAIL)
    ERROR = "error"          # Unexpected error


# ── Core ─────────────────────────────────────────────────────────────────────

DOMAIN = "DOMAIN"
DOMAIN_TYPE = "DOMAIN_TYPE"
DNS_SERVER = "DNS_SERVER"
SCAN_ERROR = "SCAN_ERROR"

# ── SPF ──────────────────────────────────────────────────────────────────────

SPF_RECORD = "SPF"
SPF_ALL = "SPF_ALL"
SPF_DNS_QUERY_COUNT = "SPF_DNS_QUERY_COUNT"
SPF_TOO_MANY_QUERIES = "SPF_TOO_MANY_DNS_QUERIES"
SPF_PERMERROR = "SPF_PERMERROR"
SPF_MACROS = "SPF_MACROS"

# ── DMARC ────────────────────────────────────────────────────────────────────

DMARC_RECORD = "DMARC"
DMARC_POLICY = "DMARC_POLICY"
DMARC_EFFECTIVE_POLICY = "DMARC_EFFECTIVE_POLICY"
DMARC_ORG_DOMAIN_FALLBACK = "DMARC_ORG_DOMAIN_FALLBACK"
DMARC_PCT = "DMARC_PCT"
DMARC_ASPF = "DMARC_ASPF"
DMARC_SP = "DMARC_SP"
DMARC_FO = "DMARC_FO"
DMARC_FORENSIC_REPORT = "DMARC_FORENSIC_REPORT"
DMARC_AGGREGATE_REPORT = "DMARC_AGGREGATE_REPORT"
DMARC_HAS_WILDCARD_DNS = "DMARC_HAS_WILDCARD_DNS"

# ── DKIM ─────────────────────────────────────────────────────────────────────

DKIM_RECORD = "DKIM"
DKIM_SELECTORS = "DKIM_SELECTORS"
DKIM_SELECTOR_COUNT = "DKIM_SELECTOR_COUNT"
DKIM_HAS_WEAK_KEYS = "DKIM_HAS_WEAK_KEYS"
DKIM_HAS_REVOKED_KEYS = "DKIM_HAS_REVOKED_KEYS"
DKIM_HAS_TESTING_KEYS = "DKIM_HAS_TESTING_KEYS"
DKIM_SCANNED = "DKIM_SCANNED"

# ── BIMI ─────────────────────────────────────────────────────────────────────

BIMI_RECORD = "BIMI_RECORD"
BIMI_VERSION = "BIMI_VERSION"
BIMI_LOCATION = "BIMI_LOCATION"
BIMI_AUTHORITY = "BIMI_AUTHORITY"

# ── MX ───────────────────────────────────────────────────────────────────────

MX_RECORDS = "MX_RECORDS"
MX_COUNT = "MX_COUNT"
MX_PROVIDERS = "MX_PROVIDERS"
MX_ALL_STARTTLS = "MX_ALL_STARTTLS"
MX_ALL_PTR = "MX_ALL_PTR"
MX_HAS_NULL_MX = "MX_HAS_NULL_MX"
STARTTLS_SCANNED = "STARTTLS_SCANNED"

# ── MTA-STS & TLS-RPT ───────────────────────────────────────────────────────

MTA_STS_TXT = "MTA_STS_TXT"
MTA_STS_ID = "MTA_STS_ID"
MTA_STS_MODE = "MTA_STS_MODE"
MTA_STS_MAX_AGE = "MTA_STS_MAX_AGE"
MTA_STS_MX_PATTERNS = "MTA_STS_MX_PATTERNS"
MTA_STS_POLICY_RAW = "MTA_STS_POLICY_RAW"
MTA_STS_PERMERROR = "MTA_STS_PERMERROR"
MTA_STS_MX_MISMATCH = "MTA_STS_MX_MISMATCH"
TLS_RPT_RECORD = "TLS_RPT_RECORD"
TLS_RPT_RUA = "TLS_RPT_RUA"
TLS_RPT_PERMERROR = "TLS_RPT_PERMERROR"

# ── DNSSEC ───────────────────────────────────────────────────────────────────

DNSSEC_ENABLED = "DNSSEC_ENABLED"
DNSSEC_DNSKEY_PRESENT = "DNSSEC_DNSKEY_PRESENT"
DNSSEC_HAS_DS = "DNSSEC_HAS_DS"
DNSSEC_AD_FLAG = "DNSSEC_AD_FLAG"
DNSSEC_KEY_COUNT = "DNSSEC_KEY_COUNT"
DNSSEC_HAS_WEAK_DNSKEY = "DNSSEC_HAS_WEAK_DNSKEY"
DNSSEC_HAS_WEAK_DS = "DNSSEC_HAS_WEAK_DS"

# ── DANE ─────────────────────────────────────────────────────────────────────

DANE_HAS_TLSA = "DANE_HAS_TLSA"
DANE_IS_SECURE = "DANE_IS_SECURE"
DANE_MX_COUNT = "DANE_MX_COUNT"
DANE_TOTAL_MX = "DANE_TOTAL_MX"
DANE_TLSA_RECORDS = "DANE_TLSA_RECORDS"
DANE_HAS_BOGUS_RECORDS = "DANE_HAS_BOGUS_RECORDS"
DANE_HAS_UNSUPPORTED_RECORDS = "DANE_HAS_UNSUPPORTED_RECORDS"

# ── CAA ──────────────────────────────────────────────────────────────────────

CAA_RECORDS = "CAA_RECORDS"
CAA_HAS_ISSUE = "CAA_HAS_ISSUE"
CAA_HAS_ISSUEWILD = "CAA_HAS_ISSUEWILD"
CAA_HAS_IODEF = "CAA_HAS_IODEF"
CAA_HAS_CONTACTEMAIL = "CAA_HAS_CONTACTEMAIL"
CAA_HAS_CONTACTPHONE = "CAA_HAS_CONTACTPHONE"
CAA_HAS_CRITICAL = "CAA_HAS_CRITICAL"
CAA_HAS_UNKNOWN_CRITICAL = "CAA_HAS_UNKNOWN_CRITICAL"
CAA_HAS_RFC8657_EXT = "CAA_HAS_RFC8657_EXT"
CAA_DENY_ALL_REGULAR = "CAA_DENY_ALL_REGULAR"
CAA_DENY_ALL_WILDCARD = "CAA_DENY_ALL_WILDCARD"
CAA_EFFECTIVE_DOMAIN = "CAA_EFFECTIVE_DOMAIN"
CAA_ERROR = "CAA_ERROR"

# ── Microsoft 365 ────────────────────────────────────────────────────────────

M365_DETECTED = "M365_DETECTED"
M365_MX_PREFIX = "M365_MX_PREFIX"
M365_TENANT_NAME = "M365_TENANT_NAME"
M365_TENANT_DOMAINS = "M365_TENANT_DOMAINS"

# ── Spoofing ─────────────────────────────────────────────────────────────────

SPOOFING_POSSIBLE = "SPOOFING_POSSIBLE"
SPOOFING_TYPE = "SPOOFING_TYPE"

# ── Scoring ──────────────────────────────────────────────────────────────────

SECURITY_SCORE = "SECURITY_SCORE"
SECURITY_SCORE_MAX = "SECURITY_SCORE_MAX"
SECURITY_SCORE_PCT = "SECURITY_SCORE_PCT"
SECURITY_POSTURE = "SECURITY_POSTURE"
SCORE_BREAKDOWN = "SCORE_BREAKDOWN"
SCORE_DETAILS = "SCORE_DETAILS"

# ── Remediation ──────────────────────────────────────────────────────────────

RECOMMENDATIONS = "RECOMMENDATIONS"


# ── Scoring Category Display Names ──────────────────────────────────────────
# Used by report renderers to map scoring category keys to human-friendly labels.
# Renderers should iterate SCORE_BREAKDOWN and look up labels here, rather than
# maintaining their own hardcoded category lists.

CATEGORY_DISPLAY_NAMES = {
    "spf": "SPF",
    "dmarc": "DMARC",
    "dkim": "DKIM",
    "bimi": "BIMI",
    "caa": "CAA",
    "spoofability": "Spoof Resistance",
    "mta_sts": "MTA-STS & TLS-RPT",
    "mx": "MX Infrastructure",
    "dnssec": "DNSSEC",
    "dane": "DANE/TLSA",
}
