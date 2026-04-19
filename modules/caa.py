# modules/caa.py

"""
CAA (Certification Authority Authorization) record discovery.

Implements RFC 8659 §4.1 tree-climbing: if the queried domain has no CAA
RRset, walk up one DNS label at a time until a record is found or the
registered domain (organizational domain) is exhausted.
"""

import dns.resolver
import tldextract
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
        self.has_contact_record = False
        self.has_critical = False
        self.effective_domain = None  # domain where CAA was actually found

        self._discover_caa()

    def _discover_caa(self):
        """RFC 8659 §4.1 tree walk: query domain, then walk up labels."""
        # Build the label walk: mail.sub.example.com → sub.example.com → example.com
        org_domain = tldextract.extract(self.domain).registered_domain
        candidates = self._build_walk(self.domain, org_domain)

        for candidate in candidates:
            if self._query_caa(candidate):
                self.effective_domain = candidate
                return

    def _build_walk(self, domain, org_domain):
        """Build ordered list of domains to check, from most to least specific."""
        candidates = [domain]
        current = domain
        while current and current != org_domain:
            parts = current.split(".", 1)
            if len(parts) < 2:
                break
            current = parts[1]
            if current:
                candidates.append(current)
        # Ensure org_domain is included if different from domain
        if org_domain and org_domain not in candidates:
            candidates.append(org_domain)
        return candidates

    def _query_caa(self, domain):
        """Query CAA records for a specific domain. Returns True if records found."""
        try:
            resolver = dns.resolver.Resolver()
            if self.dns_server:
                resolver.nameservers = [self.dns_server]

            caa = resolver.resolve(domain, "CAA")
            for record in caa:
                record_str = record.to_text()
                parts = record_str.split(" ", 2)
                if len(parts) >= 3:
                    flags = int(parts[0])
                    tag = parts[1].lower()
                    value = parts[2].strip('"')

                    # RFC 8659 §4.1: critical bit is bit 7 of flags byte
                    is_critical = bool(flags & 0x80)
                    if is_critical:
                        self.has_critical = True

                    if tag == "issue":
                        self.has_issue_record = True
                    elif tag == "issuewild":
                        self.has_issuewild_record = True
                    elif tag == "iodef":
                        self.has_iodef_record = True
                    elif tag in ("contactemail", "contactphone"):
                        self.has_contact_record = True

                    self.caa_records.append({
                        "flags": flags,
                        "is_critical": is_critical,
                        "tag": tag,
                        "value": value,
                        "raw": record_str,
                        "source_domain": domain,
                    })

            return len(self.caa_records) > 0

        except dns.resolver.NoAnswer:
            logger.debug("No CAA records found for %s (walking up)", domain)
            return False
        except dns.resolver.NXDOMAIN:
            logger.debug("Domain %s does not exist for CAA evaluation", domain)
            return False
        except dns.resolver.NoNameservers:
            logger.debug("No nameservers found for CAA lookup on %s", domain)
            return False
        except Exception as e:
            logger.debug("Error retrieving CAA records for %s: %s", domain, e)
            return False

    def to_dict(self):
        """Returns CAA details as a dictionary."""
        return {
            "CAA_RECORDS": self.caa_records,
            "CAA_HAS_ISSUE": self.has_issue_record,
            "CAA_HAS_ISSUEWILD": self.has_issuewild_record,
            "CAA_HAS_IODEF": self.has_iodef_record,
            "CAA_HAS_CONTACT": self.has_contact_record,
            "CAA_HAS_CRITICAL": self.has_critical,
            "CAA_EFFECTIVE_DOMAIN": self.effective_domain,
        }

    def __str__(self):
        records_str = ", ".join([r["raw"] for r in self.caa_records]) if self.caa_records else "None"
        source = f" (from {self.effective_domain})" if self.effective_domain and self.effective_domain != self.domain else ""
        return (
            f"CAA Records{source}: {records_str}\n"
            f"Has Issue: {self.has_issue_record}\n"
            f"Has IssueWild: {self.has_issuewild_record}\n"
            f"Has Iodef: {self.has_iodef_record}\n"
            f"Has Contact: {self.has_contact_record}\n"
            f"Has Critical: {self.has_critical}"
        )
