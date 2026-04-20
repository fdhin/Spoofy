# modules/dnssec.py

"""
DNSSEC detection and cryptographic posture module.

Checks whether a domain has DNSSEC signing enabled by querying for DNSKEY
records and verifying chain of trust via DS records on the parent zone.

RFC Compliance Notes:
  - Operational: Uses zone_for_name() to accurately resolve subdomains to their apex.
  - RFC 4035 §3.2.2: Queries use the CD (Checking Disabled) flag to bypass
    recursive validation, allowing us to inspect broken DNSSEC deployments.
  - RFC 4034 §2.1.1: Only evaluates DNSKEYs with the Zone Key flag (256) set.
  - RFC 4034 §5.1: Extracts DS digest_type to evaluate hash strength.
  - RFC 9904 / 8624: Evaluates DNSKEY and DS cryptographic algorithms against
    current IANA "MUST NOT" and "NOT RECOMMENDED" security requirement levels.
  - RFC 5890: IDNA encodes domains to A-labels before querying.
"""

import logging

import dns.flags
import dns.name
import dns.resolver
import dns.rdatatype
import tldextract

logger = logging.getLogger("spoofyvibe.dnssec")

# RFC 9904 Table 2: DNS Security Algorithm Numbers (Weak/Deprecated)
# 1: RSAMD5, 3: DSA, 5: RSASHA1, 6: DSA-NSEC3-SHA1, 7: RSASHA1-NSEC3-SHA1, 12: ECC-GOST
# Note: 10 (RSASHA512) is NOT RECOMMENDED operationally (UDP truncation from
# large keys), but is cryptographically strong — not included here.
_WEAK_DNSKEY_ALGS = frozenset({1, 3, 5, 6, 7, 12})

# RFC 9904 Table 3: Digest Algorithms (Weak/Deprecated)
# 1: SHA-1, 3: GOST R 34.11-94
# Note: 0 (NULL) is a CDS deletion signal per RFC 8078, not a weak hash.
_WEAK_DS_DIGESTS = frozenset({1, 3})


def _encode_idna(domain):
    """Encode a domain to IDNA A-label form per RFC 5890."""
    try:
        return domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        try:
            domain.encode("ascii")
            return domain
        except UnicodeEncodeError:
            logger.warning("Cannot IDNA-encode domain: %s", domain)
            return domain


class DNSSEC:
    """Check DNSSEC status and cryptographic strength for a domain."""

    def __init__(self, domain, dns_server=None):
        """
        Initialize and check DNSSEC for the given domain.

        Args:
            domain: The domain name to check.
            dns_server: DNS server to use for DNSKEY query (IP string).
                        DS and AD-flag queries always use a recursive resolver.
        """
        self.domain = domain.strip().lower()
        self.dns_server = dns_server or "1.1.1.1"

        self.dnskey_present = False
        self.has_ds = False
        self.enabled = False  # True only when DNSKEY + DS both exist
        self.ad_flag = False  # True if validating resolver set AD bit
        self.dnskey_count = 0

        # Cryptographic Posture
        self.dnskey_algorithms = set()
        self.ds_algorithms = set()
        self.ds_digest_types = set()
        self.has_weak_dnskey = False
        self.has_weak_ds = False

        self.error = None
        self._check()

    def _get_zone_apex(self, idna_domain):
        """
        Finds the zone apex (delegation point) for the requested domain.
        DNSKEY and DS records only exist at the zone apex. If the user
        scanned a subdomain (e.g., www.example.com), we must climb the
        tree to 'example.com' to perform DNSSEC queries.

        Uses the CD flag to avoid SERVFAIL when the domain has broken DNSSEC,
        and guards against climbing to the TLD for unregistered domains.
        """
        # Must use CD resolver: if DNSSEC is broken, SOA queries will
        # SERVFAIL on validating resolvers, preventing apex discovery.
        resolver = self._get_cd_resolver(["1.1.1.1", "8.8.8.8"])
        try:
            apex = dns.resolver.zone_for_name(idna_domain, resolver=resolver)
            apex_str = apex.to_text().rstrip('.')

            # Guard against TLD leak: if the domain is unregistered,
            # zone_for_name will climb all the way to the TLD (e.g. 'com').
            # We must not query DNSKEY/DS for the TLD itself.
            ext = tldextract.extract(idna_domain)
            if ext.suffix and apex_str == ext.suffix:
                logger.debug("zone_for_name climbed to TLD '%s' for %s — "
                             "domain likely unregistered", apex_str, idna_domain)
                return ext.registered_domain or idna_domain

            return apex_str
        except Exception as e:
            logger.debug("Could not determine zone apex for %s: %s", idna_domain, e)
            return idna_domain

    def _get_cd_resolver(self, nameservers):
        """Create a resolver with the CD (Checking Disabled) flag set.

        Prevents the recursive resolver from hiding the records via SERVFAIL
        if the DNSSEC chain is broken or expired.
        """
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ns for ns in nameservers if ns]
        # Set Checking Disabled (CD) and Recursion Desired (RD) flags
        resolver.flags = dns.flags.RD | dns.flags.CD
        return resolver

    def _check(self):
        """Run DNSSEC detection."""
        idna_domain = _encode_idna(self.domain)
        apex_domain = self._get_zone_apex(idna_domain)

        self._check_dnskey(apex_domain)
        self._check_ds(apex_domain)
        self._check_ad_flag(idna_domain)

        # DNSSEC is only truly enabled when the full chain of trust exists
        self.enabled = self.dnskey_present and self.has_ds

    def _check_dnskey(self, apex_domain):
        """Query DNSKEY record for the zone apex and extract key algorithms."""
        resolver = self._get_cd_resolver([self.dns_server, "1.1.1.1"])
        try:
            logger.debug("Querying DNSKEY for apex %s", apex_domain)
            answer = resolver.resolve(apex_domain, "DNSKEY")

            for rdata in answer:
                # RFC 4034 §2.1.2: Protocol Field MUST be 3.
                if rdata.protocol != 3:
                    continue

                # RFC 4034 §2.1.1: Bit 7 (value 256) is the Zone Key flag.
                # Only keys with this flag set are authorized to sign the zone.
                if rdata.flags & 256:
                    self.dnskey_count += 1
                    self.dnskey_algorithms.add(rdata.algorithm)

                    # RFC 9904: Check the security of deployed DNSKEY algorithms
                    if rdata.algorithm in _WEAK_DNSKEY_ALGS:
                        self.has_weak_dnskey = True

            if self.dnskey_count > 0:
                self.dnskey_present = True
                logger.debug("Valid Zone DNSKEY found for %s: %d records",
                             apex_domain, self.dnskey_count)
            elif len(answer) > 0:
                logger.warning("DNSKEY records found for %s, but none possess "
                               "the Zone Key flag (RFC 4034)", apex_domain)

        except dns.resolver.NoAnswer:
            logger.debug("No DNSKEY records for %s", apex_domain)
        except dns.resolver.NXDOMAIN:
            logger.debug("Domain %s does not exist (NXDOMAIN)", apex_domain)
        except dns.resolver.Timeout:
            logger.debug("DNSKEY query timeout for %s", apex_domain)
            self.error = "DNSKEY query timed out"
        except dns.resolver.NoNameservers:
            logger.debug("No nameservers for DNSKEY query on %s", apex_domain)
            self.error = "No nameservers available"
        except Exception as e:
            logger.error("DNSKEY query error for %s: %s", apex_domain, e)
            self.error = str(e)

    def _check_ds(self, apex_domain):
        """Query DS record via recursive resolver to verify chain of trust.

        DS records live in the parent zone (e.g. .com), not the domain's own
        zone. We must use a recursive resolver (not the domain's auth NS)
        because the auth NS can only serve records for its own zone.
        """
        resolver = self._get_cd_resolver(["1.1.1.1", "8.8.8.8"])
        try:
            logger.debug("Querying DS for %s via recursive resolver", apex_domain)
            answer = resolver.resolve(apex_domain, "DS")
            if len(answer) > 0:
                self.has_ds = True

                for rdata in answer:
                    self.ds_algorithms.add(rdata.algorithm)
                    # RFC 4034 §5.1.3: The hash securing the delegation is the
                    # digest_type, NOT the algorithm field (which refers to the
                    # DNSKEY algorithm). We must track both.
                    self.ds_digest_types.add(rdata.digest_type)

                    if rdata.digest_type in _WEAK_DS_DIGESTS:
                        self.has_weak_ds = True

                logger.debug(
                    "DS record found for %s (algorithms %s, digests %s)",
                    apex_domain,
                    self.ds_algorithms,
                    self.ds_digest_types,
                )
        except dns.resolver.NoAnswer:
            logger.debug("No DS records for %s", apex_domain)
        except dns.resolver.NXDOMAIN:
            logger.debug("Domain %s does not exist (NXDOMAIN)", apex_domain)
        except dns.resolver.Timeout:
            logger.debug("DS query timeout for %s", apex_domain)
        except dns.resolver.NoNameservers:
            logger.debug("No nameservers for DS query on %s", apex_domain)
        except Exception as e:
            logger.error("DS query error for %s: %s", apex_domain, e)

    def _check_ad_flag(self, idna_domain):
        """Check if a validating recursive resolver sets the AD flag.

        The AD (Authenticated Data) flag in the DNS response indicates that
        the resolver validated the DNSSEC chain for the answer. This is the
        ground-truth test: "would a validating resolver trust this zone?"

        We query the originally requested domain (not the apex) because we
        want to know if the specific host requested is actively validated.
        We do NOT use the CD flag here because we explicitly want the
        resolver to validate it.

        We query with EDNS0 and the DO (DNSSEC OK) bit set to request
        DNSSEC-aware responses from the resolver.
        """
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        # Use 0x8000 for the EDNS DO bit to avoid AttributeError crashes
        # on dnspython versions where dns.flags.DO may not exist.
        resolver.use_edns(0, 0x8000, 4096)

        # Try A, AAAA, then SOA to ensure we hit an existing record
        for qtype in ["A", "AAAA", "SOA"]:
            try:
                answer = resolver.resolve(idna_domain, qtype)
                if answer.response.flags & dns.flags.AD:
                    self.ad_flag = True
                    logger.debug("AD flag set for %s (%s) — DNSSEC validated",
                                 idna_domain, qtype)
                    return
            except Exception:
                continue

        logger.debug("AD flag NOT set or could not be verified for %s",
                     idna_domain)

    def to_dict(self):
        """Return DNSSEC results and cryptographic posture."""
        return {
            "DNSSEC_ENABLED": self.enabled,
            "DNSSEC_DNSKEY_PRESENT": self.dnskey_present,
            "DNSSEC_HAS_DS": self.has_ds,
            "DNSSEC_AD_FLAG": self.ad_flag,
            "DNSSEC_KEY_COUNT": self.dnskey_count,
            "DNSSEC_DNSKEY_ALGORITHMS": list(self.dnskey_algorithms),
            "DNSSEC_DS_ALGORITHMS": list(self.ds_algorithms),
            "DNSSEC_DS_DIGEST_TYPES": list(self.ds_digest_types),
            "DNSSEC_HAS_WEAK_DNSKEY": self.has_weak_dnskey,
            "DNSSEC_HAS_WEAK_DS": self.has_weak_ds,
        }

    def __str__(self):
        if self.enabled:
            ad_info = ", AD validated" if self.ad_flag else ", AD not set"
            crypto_warn = " [⚠️ DEPRECATED CRYPTO]" if (self.has_weak_dnskey or self.has_weak_ds) else ""
            return f"DNSSEC: Enabled ({self.dnskey_count} keys, DS verified{ad_info}){crypto_warn}"
        # Fatal: parent demands DNSSEC but host has no keys → resolvers SERVFAIL
        if self.has_ds and not self.dnskey_present:
            return "DNSSEC: FATAL OUTAGE — DS record present but no valid DNSKEY found (SERVFAIL)"
        if self.dnskey_present and not self.has_ds:
            return "DNSSEC: Broken — DNSKEY present but no DS in parent zone"
        return "DNSSEC: Not detected"
