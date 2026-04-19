# modules/dns.py

"""
DNS server discovery for a target domain.

Resolves the domain's SOA mname to find the authoritative nameserver,
validates it can answer queries, and falls back to a public recursive
resolver (1.1.1.1) if the authoritative NS is unreachable.

Important: the dns_server returned here is authoritative for the target
domain's zone ONLY. Cross-zone lookups (DANE TLSA on third-party MX hosts,
M365 tenant domains on onmicrosoft.com, DS records in the parent zone, etc.)
MUST use a recursive resolver instead. See spoofy.py for the wiring.
"""

import dns.resolver
import logging

logger = logging.getLogger("spoofyvibe.dns")

# Default recursive resolver used when authoritative NS is unavailable
DEFAULT_RECURSIVE = "1.1.1.1"


class DNS:
    def __init__(self, domain):
        self.domain = domain
        self.soa_record = None
        self.soa_mname = None
        self.dns_server = None
        self.errors = []

        self._discover()

    def _discover(self):
        """Discover a working DNS server for the target domain.

        Strategy:
          1. Resolve the SOA mname to get the authoritative NS IP.
          2. Validate the authoritative NS can answer queries for the domain.
          3. If either step fails, fall back to a public recursive resolver.
        """
        self._get_soa_record()

        if self.soa_record:
            if self._resolver_works(self.soa_record):
                self.dns_server = self.soa_record
                logger.debug(
                    "Using authoritative NS %s for %s", self.dns_server, self.domain
                )
                return

        # Authoritative NS unavailable — fall back to recursive resolver
        self.dns_server = DEFAULT_RECURSIVE
        logger.debug(
            "Using recursive resolver %s for %s", self.dns_server, self.domain
        )

    def _get_soa_record(self):
        """Resolve the SOA record and the mname IP for the domain."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [DEFAULT_RECURSIVE]
        resolver.lifetime = 10

        try:
            logger.debug("Querying SOA record for %s via %s", self.domain, DEFAULT_RECURSIVE)
            query = resolver.resolve(self.domain, "SOA")
        except dns.resolver.NXDOMAIN:
            logger.warning("Domain %s does not exist (NXDOMAIN)", self.domain)
            self.errors.append(("SOA", "NXDOMAIN"))
            return
        except dns.resolver.NoAnswer:
            logger.warning("No SOA answer for %s", self.domain)
            self.errors.append(("SOA", "NoAnswer"))
            return
        except dns.resolver.Timeout:
            logger.warning("SOA query timeout for %s", self.domain)
            self.errors.append(("SOA", "Timeout"))
            return
        except dns.resolver.NoNameservers:
            logger.warning("No nameservers available for %s", self.domain)
            self.errors.append(("SOA", "NoNameservers"))
            return
        except Exception as e:
            logger.error("Unexpected error querying SOA for %s: %s", self.domain, e)
            self.errors.append(("SOA", str(e)))
            return

        if not query:
            return

        for data in query:
            mname = str(data.mname)

        self.soa_mname = mname
        self.soa_record = self._resolve_nameserver_ip(mname)

    def _resolve_nameserver_ip(self, mname):
        """Resolve SOA mname hostname to an IP using dnspython.

        Tries A first, then AAAA. Uses a recursive resolver with a timeout
        instead of the blocking, IPv4-only socket.gethostbyname().
        """
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [DEFAULT_RECURSIVE]
        resolver.lifetime = 5

        for rdtype in ("A", "AAAA"):
            try:
                answer = resolver.resolve(mname, rdtype)
                ip = str(answer[0])
                logger.debug("SOA mname %s resolved to %s (%s)", mname, ip, rdtype)
                return ip
            except Exception:
                continue

        logger.warning("Failed to resolve SOA mname %s (A and AAAA)", mname)
        self.errors.append(("SOA_RESOLVE", f"Could not resolve {mname}"))
        return None

    def _resolver_works(self, nameserver):
        """Test if a resolver can answer queries for this domain.

        Uses a lightweight SOA query as a probe instead of constructing
        full SPF/DMARC/BIMI objects.
        """
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [nameserver]
        resolver.lifetime = 5
        try:
            resolver.resolve(self.domain, "SOA")
            return True
        except Exception as e:
            logger.debug(
                "Authoritative NS %s failed probe for %s: %s",
                nameserver, self.domain, e,
            )
            return False

    def __str__(self):
        return (
            f"Domain: {self.domain}\n"
            f"SOA Mname: {self.soa_mname}\n"
            f"SOA Record (NS IP): {self.soa_record}\n"
            f"DNS Server: {self.dns_server}"
        )
