# modules/dnssec.py

"""
DNSSEC detection module.

Checks whether a domain has DNSSEC signing enabled by querying for DNSKEY
records and verifying chain of trust via DS records on the parent zone.

"Enabled" means the full chain of trust is valid: DNSKEY exists AND DS
record in the parent zone exists. DNSKEY without DS is a broken/incomplete
DNSSEC deployment that provides no real protection.

When querying a validating recursive resolver (1.1.1.1), we also check the
AD (Authenticated Data) flag to determine if the resolver actually validated
the DNSSEC chain.
"""

import logging

import dns.flags
import dns.name
import dns.resolver
import dns.rdatatype

logger = logging.getLogger("spoofyvibe.dnssec")


class DNSSEC:
    """Check DNSSEC status for a domain."""

    def __init__(self, domain, dns_server=None):
        """
        Initialize and check DNSSEC for the given domain.

        Args:
            domain: The domain name to check.
            dns_server: DNS server to use for DNSKEY query (IP string).
                        DS and AD-flag queries always use a recursive resolver.
        """
        self.domain = domain.strip().lower()
        self.dns_server = dns_server or "1.1.1.1"
        self.dnskey_present = False
        self.has_ds = False
        self.enabled = False  # True only when DNSKEY + DS both exist
        self.ad_flag = False  # True if validating resolver set AD bit
        self.dnskey_count = 0
        self.ds_algorithm = None
        self.error = None

        self._check()

    def _check(self):
        """Run DNSSEC detection."""
        self._check_dnskey()
        self._check_ds()
        self._check_ad_flag()
        # DNSSEC is only truly enabled when the full chain of trust exists
        self.enabled = self.dnskey_present and self.has_ds

    def _check_dnskey(self):
        """Query DNSKEY record for the domain."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.dns_server]
        try:
            logger.debug("Querying DNSKEY for %s", self.domain)
            answer = resolver.resolve(self.domain, "DNSKEY")
            self.dnskey_count = len(answer)
            if self.dnskey_count > 0:
                self.dnskey_present = True
                logger.debug(
                    "DNSKEY found for %s: %d records",
                    self.domain,
                    self.dnskey_count,
                )
        except dns.resolver.NoAnswer:
            logger.debug("No DNSKEY records for %s", self.domain)
        except dns.resolver.NXDOMAIN:
            logger.debug("Domain %s does not exist (NXDOMAIN)", self.domain)
        except dns.resolver.Timeout:
            logger.debug("DNSKEY query timeout for %s", self.domain)
            self.error = "DNSKEY query timed out"
        except dns.resolver.NoNameservers:
            logger.debug("No nameservers for DNSKEY query on %s", self.domain)
            self.error = "No nameservers available"
        except Exception as e:
            logger.error("DNSKEY query error for %s: %s", self.domain, e)
            self.error = str(e)

    def _check_ds(self):
        """Query DS record in the parent zone to verify chain of trust.

        DS records live in the parent zone (e.g. .com), not the domain's own
        zone. We must use a recursive resolver (not the domain's auth NS)
        because the auth NS can only serve records for its own zone.
        """
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.1"]  # Always use recursive resolver for DS
        try:
            logger.debug("Querying DS for %s via recursive resolver", self.domain)
            answer = resolver.resolve(self.domain, "DS")
            if len(answer) > 0:
                self.has_ds = True
                # Extract algorithm from first DS record
                ds_rdata = answer[0]
                self.ds_algorithm = ds_rdata.algorithm
                logger.debug(
                    "DS record found for %s (algorithm %s)",
                    self.domain,
                    self.ds_algorithm,
                )
        except dns.resolver.NoAnswer:
            logger.debug("No DS records for %s", self.domain)
        except dns.resolver.NXDOMAIN:
            logger.debug("Domain %s does not exist (NXDOMAIN)", self.domain)
        except dns.resolver.Timeout:
            logger.debug("DS query timeout for %s", self.domain)
        except dns.resolver.NoNameservers:
            logger.debug("No nameservers for DS query on %s", self.domain)
        except Exception as e:
            logger.error("DS query error for %s: %s", self.domain, e)

    def _check_ad_flag(self):
        """Check if a validating recursive resolver sets the AD flag.

        The AD (Authenticated Data) flag in the DNS response indicates that
        the resolver validated the DNSSEC chain for the answer. This is the
        ground-truth test: "would a validating resolver trust this zone?"

        We query with EDNS0 and the DO (DNSSEC OK) bit set to request
        DNSSEC-aware responses from the resolver.
        """
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.1"]  # Cloudflare validates DNSSEC
        resolver.use_edns(0, dns.flags.DO, 4096)
        try:
            answer = resolver.resolve(self.domain, "SOA")
            if answer.response.flags & dns.flags.AD:
                self.ad_flag = True
                logger.debug("AD flag set for %s — DNSSEC validated", self.domain)
            else:
                logger.debug("AD flag NOT set for %s", self.domain)
        except Exception as e:
            logger.debug("AD flag check failed for %s: %s", self.domain, e)

    def to_dict(self):
        """Return DNSSEC results as a dictionary."""
        return {
            "DNSSEC_ENABLED": self.enabled,
            "DNSSEC_DNSKEY_PRESENT": self.dnskey_present,
            "DNSSEC_HAS_DS": self.has_ds,
            "DNSSEC_AD_FLAG": self.ad_flag,
            "DNSSEC_KEY_COUNT": self.dnskey_count,
            "DNSSEC_DS_ALGORITHM": self.ds_algorithm,
        }

    def __str__(self):
        if self.enabled:
            ad_info = ", AD validated" if self.ad_flag else ", AD not set"
            return f"DNSSEC: Enabled ({self.dnskey_count} keys, DS verified{ad_info})"
        if self.dnskey_present and not self.has_ds:
            return f"DNSSEC: Broken — DNSKEY present but no DS in parent zone"
        return "DNSSEC: Not detected"
