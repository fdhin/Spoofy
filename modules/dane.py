# modules/dane.py

"""
DANE (DNS-based Authentication of Named Entities) detection module.

Checks TLSA records for MX hosts to determine if DANE is configured.
DANE binds TLS certificates to DNS via TLSA records, preventing MITM
attacks and certificate impersonation. Requires DNSSEC to be meaningful.

TLSA record format: _port._protocol.hostname
For SMTP: _25._tcp.mx.example.com

RFC Compliance Notes:
  - RFC 6698 §3: Queries use IDNA A-label encoded domains.
  - RFC 6698 §4.1: Validates the AD (Authenticated Data) flag. TLSA records
    without the AD flag MUST be considered unusable.
  - RFC 6698 §4.1: Detects BOGUS (SERVFAIL) validation states which MUST
    cause MTAs to abort the SMTP TLS connection.
  - RFC 6698 §4.1: Validates that usage, selector, and matching types
    are known, and strictly enforces expected hash lengths (SHA-256 = 32 bytes,
    SHA-512 = 64 bytes) to prevent malformed records from being trusted.
  - Operational: Uses a public recursive resolver with the CD (Checking Disabled)
    flag. This allows us to query external MX hosts (e.g. Google/Microsoft)
    without getting REFUSED from the domain's local Auth NS, and bypasses
    SERVFAIL if the external MX has a broken DNSSEC chain.
"""

import ipaddress
import logging

import dns.flags
import dns.resolver

logger = logging.getLogger("spoofyvibe.dane")

# TLSA Usage field values (RFC 6698 §2.1.1)
USAGE_LABELS = {
    0: "CA constraint (PKIX-TA)",
    1: "Service certificate constraint (PKIX-EE)",
    2: "Trust anchor assertion (DANE-TA)",
    3: "Domain-issued certificate (DANE-EE)",
}

# TLSA Selector field values (RFC 6698 §2.1.2)
SELECTOR_LABELS = {
    0: "Full certificate",
    1: "SubjectPublicKeyInfo",
}

# TLSA Matching Type field values (RFC 6698 §2.1.3)
MATCHING_LABELS = {
    0: "Exact match",
    1: "SHA-256",
    2: "SHA-512",
}

# Expected hash output lengths in bytes per matching type
_EXPECTED_HASH_LENGTHS = {
    1: 32,  # SHA-256
    2: 64,  # SHA-512
}


def _is_ip_address(host):
    """Check if a hostname is actually an IP address (RFC 7672 §2.1.1)."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _encode_idna(domain):
    """Encode a domain to IDNA A-label form per RFC 5890."""
    try:
        return domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        try:
            domain.encode("ascii")
            return domain
        except UnicodeEncodeError:
            logger.warning("Cannot IDNA-encode MX domain: %s", domain)
            return domain


class DANE:
    """Check DANE/TLSA records for a domain's MX hosts."""

    def __init__(self, domain, mx_hosts, dns_server=None):
        """
        Initialize and check DANE for the given domain's MX hosts.

        Args:
            domain: The domain name being checked.
            mx_hosts: List of MX hostnames (strings) to check TLSA records for.
            dns_server: Accepted for API compatibility but not used.
                        DANE strictly requires public recursive resolvers
                        because MX hosts are typically in external zones.
        """
        self.domain = domain.strip().lower()
        # Filter out Null MX records ('.'), empty strings, and explicit
        # IP addresses (RFC 7672 §2.1.1: DANE MUST NOT be performed on IPs).
        # Deduplicate to prevent skewed DANE_TOTAL_MX counts from redundant
        # MX records (e.g. 10 mail.example.com + 20 mail.example.com).
        raw_hosts = [
            h.rstrip(".").lower()
            for h in (mx_hosts or [])
            if h and h.rstrip(".") != "" and not _is_ip_address(h.rstrip("."))
        ]
        self.mx_hosts = list(dict.fromkeys(raw_hosts))
        self.has_dane = False
        self.tlsa_records = []  # List of dicts with host + parsed TLSA data
        self.dane_mx_count = 0  # How many MX hosts have USABLE TLSA records
        self.error = None

        self._check()

    def _get_resolver(self, check_disabled=False):
        """Create a resolver using public recursive resolvers.

        We MUST use recursive resolvers (1.1.1.1, 8.8.8.8) because TLSA
        records live in the MX host's zone, which is almost always external.
        Using the domain's local Auth NS would return REFUSED.
        """
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        flags = dns.flags.RD
        if check_disabled:
            flags |= dns.flags.CD  # Bypass validation to fetch broken records
        resolver.flags = flags
        # Request DNSSEC records (DO bit) using 0x8000 for portability
        resolver.use_edns(0, 0x8000, 4096)
        return resolver

    def _check(self):
        """Query TLSA records for each MX host and validate usability.

        Uses a CD-First Discriminator pattern:
        1. Query with CD=1 to fetch raw records (bypasses DNSSEC validation).
        2. If the nameserver is online (even if NoAnswer), query with CD=0
           to check the AD flag and detect SERVFAIL (broken DNSSEC).
        This catches the edge case where no TLSA records exist but the
        DNSSEC denial-of-existence proof (NSEC/NSEC3) is broken.
        """
        if not self.mx_hosts:
            logger.debug("No MX hosts for %s — skipping DANE check", self.domain)
            return

        cd_resolver = self._get_resolver(check_disabled=True)
        ad_resolver = self._get_resolver(check_disabled=False)

        for mx_host in self.mx_hosts:
            idna_mx = _encode_idna(mx_host)
            tlsa_name = f"_25._tcp.{idna_mx}"

            # 1. Fetch raw records (CD=1) to check if the nameserver is online
            cd_success = False
            raw_records = []
            try:
                logger.debug("Querying TLSA (CD=1) for %s", tlsa_name)
                cd_answer = cd_resolver.resolve(tlsa_name, "TLSA")
                cd_success = True
                raw_records = list(cd_answer)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                # Nameserver is online, just no TLSA records published.
                # We still need to check CD=0 for broken denial-of-existence.
                cd_success = True
            except dns.resolver.Timeout:
                logger.debug("TLSA CD=1 query timed out for %s", tlsa_name)
            except dns.resolver.NoNameservers:
                logger.debug("No nameservers for TLSA query on %s", tlsa_name)
            except Exception as e:
                logger.error("TLSA CD=1 query error for %s: %s", tlsa_name, e)
                if not self.error:
                    self.error = str(e)

            if not cd_success:
                continue  # Nameserver unreachable — skip this host entirely

            # 2. Check validation state (CD=0) — runs even if no records exist
            ad_flag = False
            is_bogus = False
            try:
                ad_answer = ad_resolver.resolve(tlsa_name, "TLSA")
                if ad_answer.response.flags & dns.flags.AD:
                    ad_flag = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except dns.resolver.Timeout:
                # Network timeout — NOT a cryptographic SERVFAIL
                logger.debug("TLSA AD flag check timed out for %s", tlsa_name)
            except Exception:
                # CD=1 succeeded but CD=0 threw a hard error (e.g. SERVFAIL).
                # This is proof of a broken DNSSEC chain.
                # RFC 7672 §3.1.3: MTAs MUST abort the TLS connection.
                is_bogus = True

            # 3. Process real TLSA records (if any)
            for rdata in raw_records:
                is_supported = True
                errors = []

                # RFC 6698 §4.1: Unrecognized values make the record unusable
                if rdata.usage not in USAGE_LABELS:
                    is_supported = False
                    errors.append(f"Invalid usage ({rdata.usage})")
                if rdata.selector not in SELECTOR_LABELS:
                    is_supported = False
                    errors.append(f"Invalid selector ({rdata.selector})")
                if rdata.mtype not in MATCHING_LABELS:
                    is_supported = False
                    errors.append(f"Invalid matching type ({rdata.mtype})")

                # RFC 6698 §2.1.4: Validate cryptographic hash lengths
                expected_len = _EXPECTED_HASH_LENGTHS.get(rdata.mtype)
                if expected_len is not None:
                    actual_len = len(rdata.cert)
                    if actual_len != expected_len:
                        is_supported = False
                        errors.append(
                            f"Malformed {MATCHING_LABELS.get(rdata.mtype)} hash "
                            f"(expected {expected_len} bytes, got {actual_len})"
                        )

                if not is_supported:
                    logger.warning("Malformed/Unusable TLSA record for %s: %s",
                                   mx_host, ", ".join(errors))

                # Format the certificate data for display
                cert_hex = rdata.cert.hex()
                if rdata.mtype == 0:
                    # Exact match can be very long — truncate for display
                    display_cert = cert_hex[:64] + "... (truncated)"
                else:
                    display_cert = cert_hex

                self.tlsa_records.append({
                    "mx_host": mx_host,
                    "usage": rdata.usage,
                    "usage_label": USAGE_LABELS.get(rdata.usage, f"Unknown/Unusable ({rdata.usage})"),
                    "selector": rdata.selector,
                    "selector_label": SELECTOR_LABELS.get(rdata.selector, f"Unknown/Unusable ({rdata.selector})"),
                    "mtype": rdata.mtype,
                    "mtype_label": MATCHING_LABELS.get(rdata.mtype, f"Unknown/Unusable ({rdata.mtype})"),
                    "cert_data": display_cert,
                    "is_supported": is_supported,
                    "validation_errors": errors,
                    "ad_flag": ad_flag,
                    "is_bogus": is_bogus,
                    "is_dummy": False,
                })
                logger.debug(
                    "TLSA found for %s: usage=%d selector=%d mtype=%d "
                    "[Supported: %s, AD: %s, Bogus: %s]",
                    mx_host, rdata.usage, rdata.selector, rdata.mtype,
                    is_supported, ad_flag, is_bogus,
                )

            # 4. If no TLSA records but SERVFAIL detected, emit a dummy record
            # to propagate the bogus state through the pipeline.
            if not raw_records and is_bogus:
                logger.warning(
                    "TLSA query for %s returned SERVFAIL (BOGUS) with no "
                    "records — DNSSEC denial-of-existence is broken", mx_host
                )
                self.tlsa_records.append({
                    "mx_host": mx_host,
                    "usage": None, "usage_label": "N/A",
                    "selector": None, "selector_label": "N/A",
                    "mtype": None, "mtype_label": "N/A",
                    "cert_data": "NO RECORDS (SERVFAIL)",
                    "is_supported": False,
                    "validation_errors": ["DNSSEC denial-of-existence is BOGUS (SERVFAIL)"],
                    "ad_flag": False,
                    "is_bogus": True,
                    "is_dummy": True,
                })

        # Summarize: only count MX hosts with at least one VALID + SECURE record
        secure_hosts = {
            r["mx_host"] for r in self.tlsa_records
            if r.get("is_supported") and r.get("ad_flag") and not r.get("is_bogus")
        }
        self.dane_mx_count = len(secure_hosts)
        self.has_dane = self.dane_mx_count > 0

    def to_dict(self):
        """Return DANE results as a dictionary."""
        has_bogus = any(r.get("is_bogus", False) for r in self.tlsa_records)
        has_unsupported = any(
            not r.get("is_supported", True)
            for r in self.tlsa_records
            if not r.get("is_dummy")
        )
        has_real_records = any(
            not r.get("is_dummy", False) for r in self.tlsa_records
        )

        return {
            "DANE_HAS_TLSA": has_real_records,
            "DANE_IS_SECURE": self.has_dane,
            "DANE_MX_COUNT": self.dane_mx_count,
            "DANE_TOTAL_MX": len(self.mx_hosts),
            "DANE_TLSA_RECORDS": [
                r for r in self.tlsa_records if not r.get("is_dummy")
            ],
            "DANE_HAS_BOGUS_RECORDS": has_bogus,
            "DANE_HAS_UNSUPPORTED_RECORDS": has_unsupported,
        }

    def __str__(self):
        # BOGUS check MUST be first — it takes priority even when no real
        # records exist (the "empty TLSA but SERVFAIL" scenario).
        has_bogus = any(r.get("is_bogus", False) for r in self.tlsa_records)
        if has_bogus:
            return ("DANE: FATAL OUTAGE — DNSSEC validation for TLSA queries "
                    "is BOGUS on one or more MX hosts (MTAs will drop mail)")

        if self.has_dane:
            real_records = [r for r in self.tlsa_records if not r.get("is_dummy")]
            warn = ""
            if any(not r["is_supported"] for r in real_records):
                warn = " [⚠️ CONTAINS UNUSABLE RECORDS]"
            return (
                f"DANE: {self.dane_mx_count}/{len(self.mx_hosts)} MX hosts "
                f"have secure TLSA records ({len(real_records)} total){warn}"
            )

        real_records = [r for r in self.tlsa_records if not r.get("is_dummy")]
        if real_records:
            return ("DANE: Ineffective — TLSA records found but no AD flag "
                    "(DNSSEC disabled/incomplete on MX host) or records are unusable")

        return "DANE: No TLSA records found"
