# modules/dane.py

"""
DANE (DNS-based Authentication of Named Entities) detection module.

Checks TLSA records for MX hosts to determine if DANE is configured.
DANE binds TLS certificates to DNS via TLSA records, preventing MITM
attacks and certificate impersonation. Requires DNSSEC to be meaningful.

TLSA record format: _port._protocol.hostname
For SMTP: _25._tcp.mx.example.com
"""

import logging

import dns.resolver

logger = logging.getLogger("spoofyvibe.dane")

# TLSA Usage field values
USAGE_LABELS = {
    0: "CA constraint (PKIX-TA)",
    1: "Service certificate constraint (PKIX-EE)",
    2: "Trust anchor assertion (DANE-TA)",
    3: "Domain-issued certificate (DANE-EE)",
}

# TLSA Selector field values
SELECTOR_LABELS = {
    0: "Full certificate",
    1: "SubjectPublicKeyInfo",
}

# TLSA Matching Type field values
MATCHING_LABELS = {
    0: "Exact match",
    1: "SHA-256",
    2: "SHA-512",
}


class DANE:
    """Check DANE/TLSA records for a domain's MX hosts."""

    def __init__(self, domain, mx_hosts, dns_server=None):
        """
        Initialize and check DANE for the given domain's MX hosts.

        Args:
            domain: The domain name being checked.
            mx_hosts: List of MX hostnames (strings) to check TLSA records for.
            dns_server: DNS server to use (IP string). Defaults to 1.1.1.1.
        """
        self.domain = domain.strip().lower()
        self.dns_server = dns_server or "1.1.1.1"
        self.mx_hosts = [h.rstrip(".").lower() for h in (mx_hosts or [])]
        self.has_dane = False
        self.tlsa_records = []  # List of dicts with host + parsed TLSA data
        self.dane_mx_count = 0  # How many MX hosts have TLSA records
        self.error = None

        self._check()

    def _check(self):
        """Query TLSA records for each MX host."""
        if not self.mx_hosts:
            logger.debug("No MX hosts for %s — skipping DANE check", self.domain)
            return

        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.dns_server]

        for mx_host in self.mx_hosts:
            tlsa_name = f"_25._tcp.{mx_host}"
            try:
                logger.debug("Querying TLSA for %s", tlsa_name)
                answer = resolver.resolve(tlsa_name, "TLSA")
                for rdata in answer:
                    record = {
                        "mx_host": mx_host,
                        "usage": rdata.usage,
                        "usage_label": USAGE_LABELS.get(rdata.usage, f"Unknown ({rdata.usage})"),
                        "selector": rdata.selector,
                        "selector_label": SELECTOR_LABELS.get(rdata.selector, f"Unknown ({rdata.selector})"),
                        "mtype": rdata.mtype,
                        "mtype_label": MATCHING_LABELS.get(rdata.mtype, f"Unknown ({rdata.mtype})"),
                        "cert_data": rdata.cert.hex()[:32] + "...",  # Truncated for display
                    }
                    self.tlsa_records.append(record)
                    logger.debug(
                        "TLSA found for %s: usage=%d selector=%d mtype=%d",
                        mx_host, rdata.usage, rdata.selector, rdata.mtype,
                    )
            except dns.resolver.NoAnswer:
                logger.debug("No TLSA records for %s", tlsa_name)
            except dns.resolver.NXDOMAIN:
                logger.debug("NXDOMAIN for %s", tlsa_name)
            except dns.resolver.Timeout:
                logger.debug("TLSA query timeout for %s", tlsa_name)
            except dns.resolver.NoNameservers:
                logger.debug("No nameservers for TLSA query on %s", tlsa_name)
            except Exception as e:
                logger.error("TLSA query error for %s: %s", tlsa_name, e)
                if not self.error:
                    self.error = str(e)

        # Summarize
        dane_hosts = {r["mx_host"] for r in self.tlsa_records}
        self.dane_mx_count = len(dane_hosts)
        self.has_dane = self.dane_mx_count > 0

    def to_dict(self):
        """Return DANE results as a dictionary."""
        return {
            "DANE_HAS_TLSA": self.has_dane,
            "DANE_MX_COUNT": self.dane_mx_count,
            "DANE_TOTAL_MX": len(self.mx_hosts),
            "DANE_TLSA_RECORDS": self.tlsa_records,
        }

    def __str__(self):
        if self.has_dane:
            return (
                f"DANE: {self.dane_mx_count}/{len(self.mx_hosts)} MX hosts "
                f"have TLSA records ({len(self.tlsa_records)} total)"
            )
        return "DANE: No TLSA records found"
