# modules/dnssec.py

"""
DNSSEC detection module.

Checks whether a domain has DNSSEC signing enabled by querying for DNSKEY
records and verifying chain of trust via DS records on the parent zone.
"""

import logging

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
            dns_server: DNS server to use (IP string). Defaults to 1.1.1.1.
        """
        self.domain = domain.strip().lower()
        self.dns_server = dns_server or "1.1.1.1"
        self.enabled = False
        self.has_ds = False
        self.dnskey_count = 0
        self.ds_algorithm = None
        self.error = None

        self._check()

    def _check(self):
        """Run DNSSEC detection."""
        self._check_dnskey()
        self._check_ds()

    def _check_dnskey(self):
        """Query DNSKEY record for the domain."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.dns_server]
        try:
            logger.debug("Querying DNSKEY for %s", self.domain)
            answer = resolver.resolve(self.domain, "DNSKEY")
            self.dnskey_count = len(answer)
            if self.dnskey_count > 0:
                self.enabled = True
                logger.debug(
                    "DNSSEC enabled for %s: %d DNSKEY records",
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
        """Query DS record in the parent zone to verify chain of trust."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.dns_server]
        try:
            logger.debug("Querying DS for %s", self.domain)
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

    def to_dict(self):
        """Return DNSSEC results as a dictionary."""
        return {
            "DNSSEC_ENABLED": self.enabled,
            "DNSSEC_HAS_DS": self.has_ds,
            "DNSSEC_KEY_COUNT": self.dnskey_count,
            "DNSSEC_DS_ALGORITHM": self.ds_algorithm,
        }

    def __str__(self):
        if self.enabled:
            ds_info = "chain of trust verified" if self.has_ds else "no DS in parent zone"
            return f"DNSSEC: Enabled ({self.dnskey_count} keys, {ds_info})"
        return "DNSSEC: Not detected"
