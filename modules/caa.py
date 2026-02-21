# modules/caa.py

import dns.resolver
import logging

logger = logging.getLogger("spoofyvibe.caa")


class CAA:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.caa_records = []
        self.has_issue_record = False
        self.has_issuewild_record = False
        self.has_iodef_record = False
        
        self.get_caa_records()

    def get_caa_records(self):
        """Returns the CAA records for the domain."""
        try:
            resolver = dns.resolver.Resolver()
            if self.dns_server:
                resolver.nameservers = [self.dns_server]
            
            # CAA record type is queried
            caa = resolver.resolve(self.domain, "CAA")
            for record in caa:
                record_str = record.to_text()
                # A CAA record usually looks like:
                # 0 issue "letsencrypt.org"
                
                parts = record_str.split(" ", 2)
                if len(parts) >= 3:
                    flags = parts[0]
                    tag = parts[1].lower()
                    value = parts[2].strip('"')
                    
                    if tag == "issue":
                        self.has_issue_record = True
                    elif tag == "issuewild":
                        self.has_issuewild_record = True
                    elif tag == "iodef":
                        self.has_iodef_record = True
                        
                    self.caa_records.append({"flags": flags, "tag": tag, "value": value, "raw": record_str})
                    
        except dns.resolver.NoAnswer:
            logger.debug("No CAA records found for %s", self.domain)
        except dns.resolver.NXDOMAIN:
            logger.debug("Domain %s does not exist for CAA evaluation", self.domain)
        except dns.resolver.NoNameservers:
            logger.debug("No nameservers found for CAA lookup on %s", self.domain)
        except Exception as e:
            logger.debug("Error retrieving CAA records for %s: %s", self.domain, e)

    def to_dict(self):
        """Returns CAA details as a dictionary."""
        return {
            "CAA_RECORDS": self.caa_records,
            "CAA_HAS_ISSUE": self.has_issue_record,
            "CAA_HAS_ISSUEWILD": self.has_issuewild_record,
            "CAA_HAS_IODEF": self.has_iodef_record,
        }

    def __str__(self):
        records_str = ", ".join([r["raw"] for r in self.caa_records]) if self.caa_records else "None"
        return (
            f"CAA Records: {records_str}\n"
            f"Has Issue: {self.has_issue_record}\n"
            f"Has IssueWild: {self.has_issuewild_record}\n"
            f"Has Iodef: {self.has_iodef_record}"
        )
