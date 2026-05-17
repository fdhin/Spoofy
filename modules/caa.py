# modules/caa.py

"""
CAA (Certification Authority Authorization) record discovery.

Implements RFC 8659 §3 tree-climbing: climbs the DNS name tree from the
specified label up to, but not including, the DNS root '.' until a CAA RRset
is found.  In practice this means we query the leaf FQDN, then each
successive parent label, including TLDs — the walk terminates only at
the root "." itself.

RFC Compliance Notes:
  - RFC 8659 §3: Full tree walk up to (not including) the DNS root ".".
  - RFC 8659 §4.2: Additive authorization — deny-all is true only when
    *every* issue/issuewild record has an empty issuer-domain-name.
  - RFC 8659 §6: Fail-closed on SERVFAIL / Timeout (not on FormError).
  - RFC 8659 §4.1: Bit 0 (value 128 / 0x80) = Issuer Critical Flag.
  - RFC 8659 §4.5: Unknown tags with Critical Flag MUST block issuance.
  - RFC 9495: issuemail tag recognized for S/MIME CAs.
  - RFC 8657: Detects Account URI and Validation Method Binding extensions.
  - IDNA: Per-label Punycode encoding via stdlib (IDNA 2003; see note below).

IDNA Note:
  Python's stdlib ``str.encode("idna")`` implements IDNA 2003 (RFC 3490).
  For full IDNA 2008 / UTS #46 support (German ß, Greek final sigma, etc.)
  the third-party ``idna`` package is recommended.  We use the stdlib here to
  avoid adding a dependency, but operators scanning internationalized domains
  with IDNA 2008-specific labels should be aware of this limitation.
"""

import dns.name
import dns.resolver
import logging

logger = logging.getLogger("spoofyvibe.caa")

from .dns_utils import encode_idna as _encode_idna




class CAA:
    """Check CAA records and evaluate issuance authorization for a domain."""

    def __init__(self, domain, dns_server=None):
        self.domain = domain.strip().lower().rstrip('.')
        self.dns_server = dns_server

        self.caa_records = []
        self.has_issue_record = False
        self.has_issuewild_record = False
        self.has_iodef_record = False
        self.has_contactemail = False
        self.has_contactphone = False
        self.has_critical = False
        self.has_unknown_critical = False
        self.has_rfc8657_extensions = False
        self.deny_all_regular = False   # True when every issue record has empty issuer-domain
        self.deny_all_wildcard = False  # True when every issuewild (or issue fallback) has empty issuer-domain

        self.effective_domain = None  # Domain where CAA was actually found
        self.error = None             # Track fatal DNS outages (SERVFAIL/Timeout)
        self.error_domain = None      # Domain where the fatal error occurred

        self._discover_caa()

    def _get_resolver(self):
        """Return a resolver configured for cross-zone tree-climbing.

        CAA tree-climbing crosses zone boundaries (e.g. example.com → com),
        so we MUST use recursive resolvers — an authoritative NS for
        example.com will REFUSED queries for 'com'.  The caller's dns_server
        is appended as a fallback, not placed first.
        """
        resolver = dns.resolver.Resolver()
        if self.dns_server:
            # Recursive resolvers first; authoritative NS last as fallback
            resolver.nameservers = ["1.1.1.1", "8.8.8.8", self.dns_server]
        return resolver

    def _build_walk(self, domain):
        """RFC 8659 §3 Tree Walk: Climb up to, but not including, the DNS root '.'

        Uses dns.name round-tripping to safely handle IDNA-encoded labels
        without manual byte decoding that can crash on non-ASCII fallback labels.
        """
        try:
            n = dns.name.from_text(domain)

            candidates = []
            # Walk from the full name up to the TLD (stop before root ".")
            while n != dns.name.root:
                # to_text(omit_final_dot=True) gives us "sub.example.com"
                candidates.append(n.to_text(omit_final_dot=True))
                n = n.parent()
            return candidates
        except Exception as e:
            logger.warning("Failed to build DNS label walk for %s: %s", domain, e)
            return [domain]

    def _discover_caa(self):
        """Climb the DNS tree until a CAA RRset is found or an error blocks it.

        After finding records, evaluates the additive deny-all predicate:
        deny-all is TRUE only when at least one issue/issuewild record exists
        AND every such record has an empty issuer-domain-name (RFC 8659 §4.2).
        """
        idna_domain = _encode_idna(self.domain)
        if not idna_domain:
            return

        candidates = self._build_walk(idna_domain)

        for candidate in candidates:
            status, found = self._query_caa(candidate)

            if status == "ERROR":
                # RFC 8659 §6: SERVFAIL/Timeouts prevent CAs from proving
                # non-existence.  Abort the walk — CAs will fail-closed.
                self.error = (
                    f"FATAL OUTAGE: DNS error querying CAA for {candidate}. "
                    "CAs will fail-closed and abort certificate issuance."
                )
                self.error_domain = candidate
                return

            if found:
                self.effective_domain = candidate
                # Evaluate additive deny-all AFTER the full RRset is collected
                self._evaluate_deny_all()
                return

    def _evaluate_deny_all(self):
        """RFC 8659 §4.2 + §4.3: Evaluate deny-all for regular and wildcard certs.

        Regular certs: evaluated over 'issue' records only.
        Wildcard certs: evaluated over 'issuewild' records if any exist;
          otherwise falls back to 'issue' records (RFC 8659 §4.3).

        Deny-all is TRUE for a category only when at least one record of
        that type exists AND every such record has an empty issuer-domain.

        Example:
            CAA 0 issue ";"                → deny_all_regular=True
            CAA 0 issuewild "digicert.com" → deny_all_wildcard=False
        """
        issue_recs = [r for r in self.caa_records if r["tag"] == "issue"]
        issuewild_recs = [r for r in self.caa_records if r["tag"] == "issuewild"]

        # Regular certs: only issue records apply
        if issue_recs:
            self.deny_all_regular = all(
                not r.get("issuer_domain") for r in issue_recs
            )

        # Wildcard certs: issuewild takes precedence; falls back to issue
        wild_pool = issuewild_recs if issuewild_recs else issue_recs
        if wild_pool:
            self.deny_all_wildcard = all(
                not r.get("issuer_domain") for r in wild_pool
            )

    def _query_caa(self, domain):
        """Query CAA records for a specific domain.
        Returns (status_string, bool_found).
        """
        try:
            resolver = self._get_resolver()
            logger.debug("Querying CAA for %s", domain)
            answers = resolver.resolve(domain, "CAA")

            for rdata in answers:
                # Use native dnspython attributes; fallback for ancient versions
                try:
                    flags = rdata.flags
                    # RFC 8659 §4.1: Tags are case-insensitive
                    tag = rdata.tag.decode("ascii").lower() if isinstance(rdata.tag, bytes) else rdata.tag.lower()
                    value = rdata.value.decode("utf-8") if isinstance(rdata.value, bytes) else rdata.value
                except AttributeError:
                    # Fallback for very old versions of dnspython
                    parts = rdata.to_text().split(" ", 2)
                    if len(parts) >= 3:
                        flags = int(parts[0])
                        tag = parts[1].lower()
                        value = parts[2].strip().strip('"')
                    else:
                        continue

                # RFC 8659 §4.1: critical bit is bit 0 (MSB → value 128 / 0x80)
                is_critical = bool(flags & 0x80)
                if is_critical:
                    self.has_critical = True

                # Known tags: RFC 8659 (issue, issuewild, iodef),
                # RFC 9495 (issuemail), and draft-ietf-lamps-caa-contact
                known_tags = {
                    "issue", "issuewild", "iodef", "issuemail",
                    "contactemail", "contactphone",
                }

                # RFC 8659 §4.5: Unknown tag with critical flag MUST block
                if is_critical and tag not in known_tags:
                    logger.warning(
                        "RFC 8659 §4.5 Warning: Unknown CAA tag '%s' "
                        "marked CRITICAL at %s", tag, domain,
                    )
                    self.has_unknown_critical = True

                if tag == "issue":
                    self.has_issue_record = True
                elif tag == "issuewild":
                    self.has_issuewild_record = True
                elif tag == "iodef":
                    self.has_iodef_record = True
                elif tag == "contactemail":
                    self.has_contactemail = True
                elif tag == "contactphone":
                    self.has_contactphone = True

                # Parse issuer-domain-name and RFC 8657 parameters
                parameters = {}
                issuer_domain = None
                if tag in ("issue", "issuewild"):
                    if ";" in value:
                        parts = value.split(";", 1)
                        issuer_domain = parts[0].strip()
                        param_str = parts[1].strip()

                        for param in param_str.split(";"):
                            if "=" in param:
                                k, v = param.split("=", 1)
                                parameters[k.strip().lower()] = v.strip()

                        if "accounturi" in parameters or "validationmethods" in parameters:
                            self.has_rfc8657_extensions = True
                    else:
                        issuer_domain = value.strip()

                # Use rdata.to_text() for faithful zone-file representation
                raw_str = rdata.to_text()

                self.caa_records.append({
                    "flags": flags,
                    "is_critical": is_critical,
                    "tag": tag,
                    "value": value,
                    "issuer_domain": issuer_domain if tag in ("issue", "issuewild") else None,
                    "parameters": parameters,
                    "raw": raw_str,
                    "source_domain": domain,
                })

            return "OK", len(self.caa_records) > 0

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            logger.debug("No CAA records found for %s (walking up)", domain)
            return "OK", False
        except (dns.resolver.Timeout, dns.resolver.NoNameservers) as e:
            # RFC 8659 §6: These are the conditions where CAs fail-closed.
            logger.error("SERVFAIL/Timeout querying CAA for %s: %s", domain, e)
            return "ERROR", False
        except dns.exception.DNSException as e:
            # Other DNS errors (FormError, etc.) — log but don't abort the
            # tree walk.  A malformed response from a single label shouldn't
            # be classified as a "FATAL OUTAGE" per §6.
            logger.warning(
                "Non-fatal DNS error querying CAA for %s: %s", domain, e
            )
            return "OK", False

    def to_dict(self):
        """Returns CAA details as a dictionary."""
        return {
            "CAA_RECORDS": self.caa_records,
            "CAA_HAS_ISSUE": self.has_issue_record,
            "CAA_HAS_ISSUEWILD": self.has_issuewild_record,
            "CAA_HAS_IODEF": self.has_iodef_record,
            "CAA_HAS_CONTACTEMAIL": self.has_contactemail,
            "CAA_HAS_CONTACTPHONE": self.has_contactphone,
            "CAA_HAS_CRITICAL": self.has_critical,
            "CAA_HAS_UNKNOWN_CRITICAL": self.has_unknown_critical,
            "CAA_HAS_RFC8657_EXT": self.has_rfc8657_extensions,
            "CAA_DENY_ALL_REGULAR": self.deny_all_regular,
            "CAA_DENY_ALL_WILDCARD": self.deny_all_wildcard,
            "CAA_EFFECTIVE_DOMAIN": self.effective_domain,
            "CAA_ERROR": self.error,
            "CAA_ERROR_DOMAIN": self.error_domain,
        }

    def __str__(self):
        if self.error:
            return (
                f"CAA: FATAL OUTAGE — DNS Resolution Error "
                f"(SERVFAIL/Timeout) at {self.error_domain} "
                f"blocked CAA tree walk!"
            )

        records_str = ", ".join(
            r["raw"] for r in self.caa_records
        ) if self.caa_records else "None"
        source = (
            f" (inherited from {self.effective_domain})"
            if self.effective_domain and self.effective_domain != self.domain
            else ""
        )

        warn = " [⚠️ BLOCKED ISSUANCE: Unknown Critical Tag]" if self.has_unknown_critical else ""
        deny_parts = []
        if self.deny_all_regular:
            deny_parts.append("regular")
        if self.deny_all_wildcard:
            deny_parts.append("wildcard")
        deny_str = f" [🔒 DENY-ALL: {'+'.join(deny_parts)} certs blocked]" if deny_parts else ""
        rfc8657_str = " (RFC 8657 Extensions Active)" if self.has_rfc8657_extensions else ""

        return (
            f"CAA Records{source}: {records_str}{warn}{deny_str}\n"
            f"Has Issue: {self.has_issue_record}\n"
            f"Has IssueWild: {self.has_issuewild_record}\n"
            f"Has Iodef: {self.has_iodef_record}\n"
            f"Has ContactEmail: {self.has_contactemail}\n"
            f"Has ContactPhone: {self.has_contactphone}\n"
            f"Has Critical: {self.has_critical}{rfc8657_str}"
        )
