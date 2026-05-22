# modules/bimi.py

import dns.resolver
import logging

from .dns_utils import encode_idna as _encode_idna, make_auth_resolver
from .txt_utils import parse_txt_record, parse_tag_value

logger = logging.getLogger("spoofyvibe.bimi")


class BIMI:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.bimi_record = self.get_bimi_record()
        self.version = None
        self.location = None
        self.authority = None

        if self.bimi_record:
            tags = parse_tag_value(self.bimi_record)
            self.version = tags.get("v")
            self.location = tags.get("l")
            self.authority = tags.get("a")

    def get_bimi_record(self):
        """Returns the BIMI record for the domain."""
        try:
            # RFC 5890: IDNA-encode domain before DNS query
            idna_domain = _encode_idna(self.domain)
            if not idna_domain:
                return None

            # BIMI is a same-zone query — use auth resolver per ARCHITECTURE.md §2
            resolver = make_auth_resolver(self.dns_server)

            logger.debug("Querying BIMI for %s", idna_domain)
            bimi = resolver.resolve(f"default._bimi.{idna_domain}", "TXT")
            for rdata in bimi:
                record = parse_txt_record(rdata)
                if record.startswith("v=BIMI"):
                    return record
            logger.debug("No BIMI record found in TXT records for %s", self.domain)
            return None
        except dns.resolver.NXDOMAIN:
            logger.debug("No BIMI record (NXDOMAIN) for %s", self.domain)
            return None
        except dns.resolver.NoAnswer:
            logger.debug("No BIMI answer for %s", self.domain)
            return None
        except dns.resolver.Timeout:
            logger.warning("BIMI query timeout for %s", self.domain)
            return None
        except dns.resolver.NoNameservers:
            logger.warning("No nameservers available for BIMI query on %s", self.domain)
            return None
        except Exception as e:
            logger.error("Unexpected error querying BIMI for %s: %s", self.domain, e)
            return None

    def get_bimi_details(self):
        """Returns a tuple containing version, location, and authority from a BIMI record."""
        return self.version, self.location, self.authority

    def __str__(self):
        return (
            f"BIMI Record: {self.bimi_record}\n"
            f"Version: {self.version}\n"
            f"Location: {self.location}\n"
            f"Authority: {self.authority}"
        )

