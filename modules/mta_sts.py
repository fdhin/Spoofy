# modules/mta_sts.py

"""
MTA-STS (SMTP MTA Strict Transport Security) and TLS-RPT detection.

Implements RFC 8461 §3.3 compliant policy fetching (no redirects) and
RFC 8461 §4.1 compliant wildcard matching (label-aware, not glob).
"""

import dns.resolver
import requests
import logging

from .txt_utils import parse_txt_record, parse_tag_value

logger = logging.getLogger("spoofyvibe.mta_sts")


def _mx_matches_pattern(host, pattern):
    """RFC 8461 §4.1 label-aware wildcard matching.

    The '*' wildcard matches exactly one DNS label (not multiple).
    Wildcards are only valid as the leftmost label.

    Examples:
        _mx_matches_pattern("mx1.example.com", "*.example.com")  → True
        _mx_matches_pattern("sub.mx1.example.com", "*.example.com")  → False
        _mx_matches_pattern("mx1.example.com", "mx1.example.com")  → True
    """
    host_labels = host.lower().rstrip(".").split(".")
    pattern_labels = pattern.lower().rstrip(".").split(".")
    if len(host_labels) != len(pattern_labels):
        return False
    for h, p in zip(host_labels, pattern_labels):
        if p == "*":
            continue  # wildcard matches exactly one label
        if h != p:
            return False
    return True


class MTASTS:
    """Check MTA-STS policy and TLS-RPT reporting for a domain."""

    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server

        # MTA-STS TXT record fields
        self.mta_sts_txt = None
        self.mta_sts_id = None

        # MTA-STS policy fields
        self.policy_raw = None
        self.policy_mode = None
        self.policy_max_age = None
        self.policy_mx_patterns = []

        # TLS-RPT fields
        self.tls_rpt_record = None
        self.tls_rpt_rua = None

        self._check_mta_sts_txt()
        if self.mta_sts_txt:
            self._fetch_mta_sts_policy()
        self._check_tls_rpt()

    def _check_mta_sts_txt(self):
        """Query _mta-sts.<domain> TXT record."""
        try:
            resolver = dns.resolver.Resolver()
            if self.dns_server:
                resolver.nameservers = [self.dns_server]
            logger.debug("Querying _mta-sts.%s TXT", self.domain)
            answers = resolver.resolve(f"_mta-sts.{self.domain}", "TXT")
            for rdata in answers:
                txt = parse_txt_record(rdata)
                # RFC 8461 §3.1: record must start with "v=STSv1"
                if txt.strip().startswith("v=STSv1"):
                    self.mta_sts_txt = txt
                    tags = parse_tag_value(txt)
                    self.mta_sts_id = tags.get("id")
                    logger.debug("Found MTA-STS TXT for %s: %s", self.domain, txt)
                    return
            logger.debug("No MTA-STS TXT record found for %s", self.domain)
        except dns.resolver.NXDOMAIN:
            logger.debug("No _mta-sts record (NXDOMAIN) for %s", self.domain)
        except dns.resolver.NoAnswer:
            logger.debug("No _mta-sts answer for %s", self.domain)
        except dns.resolver.Timeout:
            logger.warning("MTA-STS TXT query timeout for %s", self.domain)
        except dns.resolver.NoNameservers:
            logger.warning("No nameservers for MTA-STS query on %s", self.domain)
        except Exception as e:
            logger.error("Unexpected error querying MTA-STS for %s: %s", self.domain, e)

    def _fetch_mta_sts_policy(self):
        """Fetch MTA-STS policy from https://mta-sts.<domain>/.well-known/mta-sts.txt.

        RFC 8461 §3.3: MUST NOT follow redirects. A redirect to an
        attacker-controlled URL would defeat MTA-STS. Any non-200 response
        (including 3xx) is treated as "no policy".
        """
        url = f"https://mta-sts.{self.domain}/.well-known/mta-sts.txt"
        try:
            logger.debug("Fetching MTA-STS policy from %s", url)
            resp = requests.get(url, timeout=10, allow_redirects=False)
            if resp.status_code == 200:
                # Use explicit UTF-8 decode for predictable charset handling
                self.policy_raw = resp.content.decode("utf-8", errors="replace").strip()
                self._parse_policy(self.policy_raw)
                logger.debug("MTA-STS policy for %s: mode=%s, max_age=%s, mx=%s",
                             self.domain, self.policy_mode, self.policy_max_age,
                             self.policy_mx_patterns)
            elif 300 <= resp.status_code < 400:
                logger.warning(
                    "MTA-STS policy redirect (%d) for %s — RFC 8461 §3.3 violation",
                    resp.status_code, self.domain,
                )
            else:
                logger.warning("MTA-STS policy HTTP %d for %s", resp.status_code, self.domain)
        except requests.exceptions.SSLError as e:
            logger.warning("MTA-STS policy SSL error for %s: %s", self.domain, e)
        except requests.exceptions.ConnectionError as e:
            logger.debug("MTA-STS policy connection error for %s: %s", self.domain, e)
        except requests.exceptions.Timeout:
            logger.warning("MTA-STS policy fetch timeout for %s", self.domain)
        except Exception as e:
            logger.error("Unexpected error fetching MTA-STS policy for %s: %s", self.domain, e)

    def _parse_policy(self, raw):
        """Parse the MTA-STS policy file content."""
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()
                if key == "mode":
                    self.policy_mode = value.lower()
                elif key == "max_age":
                    try:
                        self.policy_max_age = int(value)
                    except ValueError:
                        self.policy_max_age = value
                elif key == "mx":
                    self.policy_mx_patterns.append(value)

    def _check_tls_rpt(self):
        """Query _smtp._tls.<domain> TXT record for TLS-RPT."""
        try:
            resolver = dns.resolver.Resolver()
            if self.dns_server:
                resolver.nameservers = [self.dns_server]
            logger.debug("Querying _smtp._tls.%s TXT", self.domain)
            answers = resolver.resolve(f"_smtp._tls.{self.domain}", "TXT")
            for rdata in answers:
                txt = parse_txt_record(rdata)
                # RFC 8460 §3: record must start with "v=TLSRPTv1"
                if txt.strip().startswith("v=TLSRPTv1"):
                    self.tls_rpt_record = txt
                    tags = parse_tag_value(txt)
                    self.tls_rpt_rua = tags.get("rua")
                    logger.debug("Found TLS-RPT for %s: %s", self.domain, txt)
                    return
            logger.debug("No TLS-RPT record found for %s", self.domain)
        except dns.resolver.NXDOMAIN:
            logger.debug("No TLS-RPT record (NXDOMAIN) for %s", self.domain)
        except dns.resolver.NoAnswer:
            logger.debug("No TLS-RPT answer for %s", self.domain)
        except dns.resolver.Timeout:
            logger.warning("TLS-RPT query timeout for %s", self.domain)
        except dns.resolver.NoNameservers:
            logger.warning("No nameservers for TLS-RPT query on %s", self.domain)
        except Exception as e:
            logger.error("Unexpected error querying TLS-RPT for %s: %s", self.domain, e)

    def validate_mx_against_policy(self, mx_hosts):
        """Check if MX hosts match the policy's mx patterns.

        Returns list of unmatched hosts. Uses RFC 8461 §4.1 label-aware
        wildcard matching instead of fnmatch (which treats * as multi-label).
        """
        if not self.policy_mx_patterns or not mx_hosts:
            return []

        unmatched = []
        for host in mx_hosts:
            matched = any(
                _mx_matches_pattern(host, pattern)
                for pattern in self.policy_mx_patterns
            )
            if not matched:
                unmatched.append(host)
        return unmatched

    def to_dict(self):
        """Return results as a flat dict for integration into the main result."""
        return {
            "MTA_STS_TXT": self.mta_sts_txt,
            "MTA_STS_ID": self.mta_sts_id,
            "MTA_STS_MODE": self.policy_mode,
            "MTA_STS_MAX_AGE": self.policy_max_age,
            "MTA_STS_MX_PATTERNS": self.policy_mx_patterns,
            "MTA_STS_POLICY_RAW": self.policy_raw,
            "TLS_RPT_RECORD": self.tls_rpt_record,
            "TLS_RPT_RUA": self.tls_rpt_rua,
        }

    def __str__(self):
        lines = [f"MTA-STS TXT: {self.mta_sts_txt or 'Not found'}"]
        if self.policy_mode:
            lines.append(f"MTA-STS Mode: {self.policy_mode}")
            lines.append(f"MTA-STS Max Age: {self.policy_max_age}")
            lines.append(f"MTA-STS MX Patterns: {', '.join(self.policy_mx_patterns)}")
        lines.append(f"TLS-RPT: {self.tls_rpt_record or 'Not found'}")
        if self.tls_rpt_rua:
            lines.append(f"TLS-RPT RUA: {self.tls_rpt_rua}")
        return "\n".join(lines)
