# modules/dns.py

import dns.resolver
import socket
import logging
from .spf import SPF
from .dmarc import DMARC
from .bimi import BIMI

logger = logging.getLogger("spoofyvibe.dns")


class DNS:
    def __init__(self, domain):
        self.domain = domain
        self.soa_record = None
        self.dns_server = None
        self.spf_record = None
        self.dmarc_record = None
        self.bimi_record = None
        self.errors = []

        self.get_soa_record()
        self.get_dns_server()

    def get_soa_record(self):
        """Sets the SOA record and DNS server of a given domain."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.1"]
        try:
            logger.debug("Querying SOA record for %s via 1.1.1.1", self.domain)
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

        if query:
            for data in query:
                dns_server = str(data.mname)
            try:
                self.soa_record = socket.gethostbyname(dns_server)
                self.dns_server = self.soa_record
                logger.debug("SOA for %s resolved to %s", self.domain, self.dns_server)
            except socket.herror as e:
                logger.warning("Failed to resolve SOA nameserver %s: %s", dns_server, e)
                self.errors.append(("SOA_RESOLVE", str(e)))
                self.soa_record = None
            except socket.gaierror as e:
                logger.warning("DNS resolution failed for SOA nameserver %s: %s", dns_server, e)
                self.errors.append(("SOA_RESOLVE", str(e)))
                self.soa_record = None

    def get_dns_server(self):
        """Finds the DNS server that serves the domain and retrieves associated SPF, DMARC, and BIMI records."""
        if self.soa_record:
            logger.debug("Trying authoritative server %s for %s", self.soa_record, self.domain)
            self.spf_record = SPF(self.domain, self.soa_record)
            self.dmarc_record = DMARC(self.domain, self.soa_record)
            self.bimi_record = BIMI(self.domain, self.soa_record)
            if self.spf_record.spf_record and self.dmarc_record.dmarc_record:
                return

        for ip_address in ["1.1.1.1", "8.8.8.8", "9.9.9.9"]:
            logger.debug("Trying fallback DNS %s for %s", ip_address, self.domain)
            self.spf_record = SPF(self.domain, ip_address)
            self.dmarc_record = DMARC(self.domain, ip_address)
            self.bimi_record = BIMI(self.domain, ip_address)
            if self.spf_record.spf_record and self.dmarc_record.dmarc_record:
                self.dns_server = ip_address
                logger.debug("Using fallback DNS %s for %s", ip_address, self.domain)
                return

        self.dns_server = "1.1.1.1"
        logger.debug("Defaulting to 1.1.1.1 for %s", self.domain)

    def get_txt_record(self, record_type):
        """Returns the TXT record of a given type for the domain."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.dns_server]
        try:
            query = resolver.resolve(self.domain, record_type)
            return str(query[0])
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout) as e:
            logger.debug("TXT query (%s) for %s failed: %s", record_type, self.domain, e)
            return None
        except Exception as e:
            logger.error("Unexpected error in TXT query for %s: %s", self.domain, e)
            return None

    def __str__(self):
        return (
            f"Domain: {self.domain}\n"
            f"SOA Record: {self.soa_record}\n"
            f"DNS Server: {self.dns_server}\n"
            f"SPF Record: {self.spf_record.spf_record}\n"
            f"DMARC Record: {self.dmarc_record.dmarc_record}\n"
            f"BIMI Record: {self.bimi_record.bimi_record}"
        )
