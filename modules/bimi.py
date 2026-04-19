# modules/bimi.py

import dns.resolver
import logging

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
            resolver = dns.resolver.Resolver()
            if self.dns_server:
                resolver.nameservers = [self.dns_server]
            bimi = resolver.resolve(f"default._bimi.{self.domain}", "TXT")
            for rdata in bimi:
                record = parse_txt_record(rdata)
                if record.startswith("v=BIMI"):
                    return record
            return None
        except Exception:
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
