# modules/dmarc.py

import dns.resolver
import tldextract
import logging
import re

from .txt_utils import parse_txt_record, parse_tag_value
from .dns_utils import encode_idna, make_auth_resolver

logger = logging.getLogger("spoofyvibe.dmarc")


class DMARC:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.is_org_domain_fallback = False
        
        self.policy = None
        self.pct = 100
        self.aspf = "r"
        self.adkim = "r"
        self.sp = None
        self.fo = "0"
        self.ruf = None
        self.rua = None
        self._is_ordering_valid = True
        
        self.dmarc_record = self.get_dmarc_record()
        self.tags = self._parse_tags()
        self._validate_and_apply_policy()
        
        self.has_wildcard_dns = self.check_wildcard_dns()

    def _parse_tags(self):
        """Parse DMARC record into a dict of tag=value pairs per RFC 7489 §6.4.

        Uses txt_utils.parse_tag_value() for the actual parsing, which:
          - Splits on semicolons, then partitions on the first '=' to avoid
            substring collisions (e.g. 'sp=' matching inside 'aspf=').
          - Detects duplicate tag names and returns {} (per RFC 7489 §6.4:
            "Tags with duplicate names MUST NOT occur within a single tag-list;
            if a tag name does occur more than once, the entire tag-list is invalid.")

        After parsing, validates DMARC-specific ordering constraints:
          - RFC 7489 §6.3: 'v' must be the first tag, 'p' must be the second.
        """
        if not self.dmarc_record:
            return {}

        tags = parse_tag_value(self.dmarc_record)

        # parse_tag_value returns {} for duplicate tags — this means the
        # entire DMARC record is invalid per RFC 7489 §6.4.
        if not tags and self.dmarc_record:
            logger.error(
                "DMARC record for %s has duplicate tags — entire record "
                "is invalid per RFC 7489 §6.4", self.domain
            )
            self._is_ordering_valid = False
            return {}

        # Enforce strict tag ordering (RFC 7489 §6.3: v first, p second)
        # We need to check the raw record since parse_tag_value returns a dict
        # which loses ordering information.
        is_ordering_valid = True
        parts = [p.strip() for p in self.dmarc_record.split(";") if p.strip()]
        extracted_keys = []
        for part in parts:
            if "=" in part:
                key, _, _ = part.partition("=")
                extracted_keys.append(key.strip().lower())
            else:
                extracted_keys.append("malformed")

        if extracted_keys:
            if extracted_keys[0] != "v":
                is_ordering_valid = False
            if len(extracted_keys) > 1 and extracted_keys[1] != "p":
                is_ordering_valid = False
                    
        self._is_ordering_valid = is_ordering_valid
        return tags

    def _validate_and_apply_policy(self):
        """Validates 'p' and 'sp', enforcing RFC 7489 §6.6.3 step 6 fallback."""
        if not self.dmarc_record:
            return
            
        p = self.tags.get("p")
        if p:
            p = p.lower()
        sp = self.tags.get("sp")
        if sp:
            sp = sp.lower()
        rua = self.tags.get("rua")
        
        valid_policies = {"none", "quarantine", "reject"}
        p_invalid = p not in valid_policies or not self._is_ordering_valid
        sp_invalid = sp is not None and sp not in valid_policies

        if p_invalid or sp_invalid:
            if rua:
                logger.error("DMARC record for %s has missing/invalid 'p'/'sp' or bad ordering, but 'rua' is present. Falling back to p=none.", self.domain)
                self.policy = "none"
                self.sp = None
            else:
                logger.error("DMARC record for %s is invalid (bad 'p'/'sp' or ordering) with no 'rua', aborting.", self.domain)
                self.dmarc_record = None
                self.tags = {}
                return
        else:
            self.policy = p
            self.sp = sp
            
        # Apply defaults for optional tags per RFC 7489 §6.3
        try:
            pct_val = int(self.tags.get("pct", 100))
            self.pct = pct_val if 0 <= pct_val <= 100 else 100
        except ValueError:
            self.pct = 100
            
        self.aspf = self.tags.get("aspf", "r").lower()
        if self.aspf not in {"r", "s"}:
            self.aspf = "r"
            
        self.adkim = self.tags.get("adkim", "r").lower()
        if self.adkim not in {"r", "s"}:
            self.adkim = "r"
            
        self.fo = self.tags.get("fo", "0")
        self.ruf = self.tags.get("ruf")
        self.rua = rua

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
        if record == "MULTIPLE":
            return None
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
            if record == "MULTIPLE":
                return None
            if record:
                self.is_org_domain_fallback = True
                return record

        self.is_org_domain_fallback = False
        return None

    def get_dmarc_record_for_domain(self, domain):
        try:
            # DMARC is a same-zone query — use auth resolver per ARCHITECTURE.md §2
            resolver = make_auth_resolver(self.dns_server)
                
            # IDNA encode domain per RFC 7489 §6.6.1
            idna_domain = encode_idna(domain)
                
            logger.debug("Querying _dmarc.%s TXT", idna_domain)
            dmarc = resolver.resolve(f"_dmarc.{idna_domain}", "TXT")
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

        # Multiple records check per RFC 7489 §6.6.3 step 5
        valid_records = []
        for dns_data in dmarc:
            # Use txt_utils.parse_txt_record() to safely join multi-string
            # TXT records without space injection at the 255-byte boundary.
            record = parse_txt_record(dns_data).strip()
            # RFC 7489 §6.4: v *WSP = *WSP DMARC1 precisely
            if re.match(r"^[vV][ \t]*=[ \t]*DMARC1([ \t]*;|$)", record):
                valid_records.append(record)
                
        if len(valid_records) == 1:
            logger.debug("Found DMARC for %s: %s", domain, valid_records[0])
            return valid_records[0]
        elif len(valid_records) > 1:
            logger.error("Multiple valid DMARC records found for %s, aborting", domain)
            return "MULTIPLE"
            
        return None

    def check_wildcard_dns(self):
        """Checks if wildcard DNS is enabled by querying a random subdomain."""
        import random
        import string
        rand_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        subdomain = f"spoofyvibe-wildcard-{rand_str}.{self.domain}"

        resolver = make_auth_resolver(self.dns_server)

        try:
            subdomain_encoded = encode_idna(subdomain)
        except Exception:
            subdomain_encoded = subdomain
            
        try:
            resolver.resolve(subdomain_encoded, "A")
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
            f"ADKIM: {self.adkim}\n"
            f"Subdomain Policy: {self.sp}\n"
            f"Failure Reporting Options (fo): {self.fo}\n"
            f"Forensic Report URI (ruf): {self.ruf}\n"
            f"Aggregate Report URI (rua): {self.rua}\n"
            f"Org Domain Fallback: {self.is_org_domain_fallback}\n"
            f"Has Wildcard DNS: {self.has_wildcard_dns}"
        )

