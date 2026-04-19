# modules/dmarc.py

import dns.resolver
import tldextract
import logging

logger = logging.getLogger("spoofyvibe.dmarc")


class DMARC:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.is_org_domain_fallback = False
        self.dmarc_record = self.get_dmarc_record()
        self.tags = self._parse_tags()
        self.policy = self.tags.get("p")
        self.pct = self.tags.get("pct")
        self.aspf = self.tags.get("aspf")
        self.sp = self.tags.get("sp")
        self.fo = self.tags.get("fo", "0")
        self.ruf = self.tags.get("ruf")
        self.rua = self.tags.get("rua")
        self.has_wildcard_dns = self.check_wildcard_dns()

    def _parse_tags(self):
        """Parse DMARC record into a dict of tag=value pairs per RFC 7489 §6.4.

        Splits on semicolons, then partitions each token on the first '=' to
        avoid substring collisions (e.g. 'sp=' matching inside 'aspf=').
        """
        tags = {}
        if not self.dmarc_record:
            return tags
        for part in self.dmarc_record.split(";"):
            part = part.strip()
            if "=" in part:
                key, _, value = part.partition("=")
                tags[key.strip().lower()] = value.strip()
        return tags

    @property
    def effective_policy(self):
        """Return the effective policy for this domain per RFC 7489 §6.6.3.

        When the DMARC record was retrieved via org-domain fallback (i.e. the
        queried domain is a subdomain that has no own _dmarc record), the
        effective policy is the 'sp' tag if present, otherwise the 'p' tag.
        For direct matches, the effective policy is simply 'p'.
        """
        if self.is_org_domain_fallback:
            return self.sp if self.sp else self.policy
        return self.policy

    def get_dmarc_record(self):
        """Discover the DMARC record per RFC 7489 §6.6.3.

        1. Query _dmarc.<full From domain> first.
        2. Only if that returns NXDOMAIN / NoAnswer, fall back to
           _dmarc.<organizational domain> and set is_org_domain_fallback.
        """
        # Step 1: query the full domain
        record = self.get_dmarc_record_for_domain(self.domain)
        if record:
            self.is_org_domain_fallback = False
            return record

        # Step 2: fall back to organizational domain (if different)
        org_domain = tldextract.extract(self.domain).registered_domain
        if org_domain and org_domain != self.domain:
            logger.debug(
                "No DMARC at %s, falling back to org domain %s",
                self.domain,
                org_domain,
            )
            record = self.get_dmarc_record_for_domain(org_domain)
            if record:
                self.is_org_domain_fallback = True
                return record

        self.is_org_domain_fallback = False
        return None

    def get_dmarc_record_for_domain(self, domain):
        try:
            resolver = dns.resolver.Resolver()
            if self.dns_server:
                resolver.nameservers = [self.dns_server]
            logger.debug("Querying _dmarc.%s TXT", domain)
            dmarc = resolver.resolve(f"_dmarc.{domain}", "TXT")
        except dns.resolver.NXDOMAIN:
            logger.debug("No DMARC record (NXDOMAIN) for %s", domain)
            return None
        except dns.resolver.NoAnswer:
            logger.debug("No DMARC answer for %s", domain)
            return None
        except dns.resolver.Timeout:
            logger.warning("DMARC query timeout for %s", domain)
            return None
        except dns.resolver.NoNameservers:
            logger.warning("No nameservers available for DMARC query on %s", domain)
            return None
        except Exception as e:
            logger.error("Unexpected error querying DMARC for %s: %s", domain, e)
            return None

        for dns_data in dmarc:
            # Join raw byte strings without separator to avoid space injection
            # at the 255-byte TXT boundary (fixes multi-string TXT mangling).
            record = b"".join(dns_data.strings).decode("utf-8", errors="replace").strip()
            # RFC 7489 §6.6.3 step 2: records must start with "v=DMARC1"
            if record.startswith("v=DMARC1"):
                logger.debug("Found DMARC for %s: %s", domain, record)
                return record
        return None

    def check_wildcard_dns(self):
        """Checks if wildcard DNS is enabled by querying a random subdomain."""
        import random
        import string
        rand_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        subdomain = f"spoofyvibe-wildcard-{rand_str}.{self.domain}"

        resolver = dns.resolver.Resolver()
        if self.dns_server:
            resolver.nameservers = [self.dns_server]

        try:
            resolver.resolve(subdomain, "A")
            return True
        except Exception:
            return False

    def __str__(self):
        return (
            f"DMARC Record: {self.dmarc_record}\n"
            f"Policy: {self.policy}\n"
            f"Effective Policy: {self.effective_policy}\n"
            f"Pct: {self.pct}\n"
            f"ASPF: {self.aspf}\n"
            f"Subdomain Policy: {self.sp}\n"
            f"Failure Reporting Options (fo): {self.fo}\n"
            f"Forensic Report URI (ruf): {self.ruf}\n"
            f"Aggregate Report URI (rua): {self.rua}\n"
            f"Org Domain Fallback: {self.is_org_domain_fallback}\n"
            f"Has Wildcard DNS: {self.has_wildcard_dns}"
        )
