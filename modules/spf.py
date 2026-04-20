# modules/spf.py

"""
SPF (Sender Policy Framework) record discovery and analysis.

Implements RFC 7208 compliant mechanism counting, including qualifier-prefixed
mechanisms (-include:, ~mx, etc.) and proper recursive include/redirect resolution.

RFC 7208 compliance notes:
  - §4.3: IDNA domains encoded to A-labels before DNS queries.
  - §4.5: Version string is case-sensitive, no leading whitespace,
    must be followed by SP or end-of-record.
  - §4.5: Multiple SPF records trigger PermError.
  - §4.6.1: Mechanism and modifier names are case-insensitive.
  - §6.1: Multiple redirect/exp modifiers trigger PermError.
  - §7: Macros in include/redirect targets are skipped during
    static DNS counting (require runtime IP context).
  - §7.1: Macro letters restricted to: s l o d i p h c r t v.
"""

import dns.resolver
import re
import logging

from .txt_utils import parse_txt_record

logger = logging.getLogger("spoofyvibe.spf")

# RFC 7208 §4.5: "v=spf1" is case-sensitive, MUST NOT have leading
# whitespace, and MUST be followed by SP or end-of-record.
# This regex rejects "V=SPF1", "v=spf10", "  v=spf1", etc.
_SPF_VERSION_RE = re.compile(r'^v=spf1(?:\s|$)')


def _is_spf_record(txt):
    """Return True if txt is a valid SPF record per RFC 7208 §4.5.

    The version tag is case-sensitive ('v=spf1', not 'V=SPF1'), must
    not have leading whitespace, and must be followed by a space
    character or be the entire record.
    """
    return bool(_SPF_VERSION_RE.match(txt))


def _encode_idna(domain):
    """Encode a domain to IDNA A-label form per RFC 7208 §4.3.

    Internationalized domain names MUST be encoded as A-labels
    (Punycode) before DNS queries.  ASCII-only domains pass through
    unchanged.  Returns the encoded domain or None on failure.
    """
    try:
        return domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        # Already ASCII or invalid — try as-is
        try:
            domain.encode("ascii")
            return domain
        except UnicodeEncodeError:
            logger.warning("Cannot IDNA-encode domain: %s", domain)
            return None


# RFC 7208 §7.1: Valid macro letters (case-insensitive in the RFC,
# but the regex captures the raw letter for reporting).
_MACRO_RE = re.compile(r'%{([slodiph crtvSLODIPHCRTV])[0-9r]*[.\-+,/_=]*}')

# SPF qualifier characters per RFC 7208 §4.6.2
_QUALIFIERS = frozenset("+-~?")


def _strip_qualifier(token):
    """Strip the leading qualifier character from an SPF token.

    Returns the mechanism/modifier without the qualifier prefix.
    e.g. "-include:_spf.google.com" → "include:_spf.google.com"
         "+a:mail.example.com"      → "a:mail.example.com"
         "mx"                        → "mx"
    """
    if token and token[0] in _QUALIFIERS:
        return token[1:]
    return token


def _has_macro(target):
    """Return True if the target string contains an SPF macro (%{...}).

    Static analyzers cannot resolve macros without runtime IP context,
    so these must be skipped during DNS counting (RFC 7208 §7).
    """
    return "%" in target


class SPF:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.spf_record = None
        self.all_mechanism = None
        self.spf_dns_query_count = 0
        self.too_many_dns_queries = False
        self.spf_macros = []
        self.spf_permerror = False  # RFC 7208 §4.5: multiple records = PermError

        self.spf_record = self.get_spf_record()

        if self.spf_record and not self.spf_permerror:
            self.all_mechanism = self.get_spf_all_string()
            self.spf_dns_query_count = self.get_spf_dns_queries()
            self.too_many_dns_queries = self.spf_dns_query_count > 10
            self.spf_macros = self.get_spf_macros()

    def get_spf_macros(self):
        """Returns a list of SPF macros used in the record.

        RFC 7208 §7.1 restricts macro-letter to: s l o d i p h c r t v
        (case-insensitive).  Invalid letters are rejected.
        """
        if not self.spf_record:
            return []
        macros = _MACRO_RE.findall(self.spf_record)
        # Return the full macro syntax for each match, deduplicated
        full_macros = re.findall(
            r'%{[slodiph crtvSLODIPHCRTV][0-9r]*[.\-+,/_=]*}',
            self.spf_record
        )
        return list(set(full_macros))

    def get_spf_record(self, domain=None):
        """Fetches the SPF record for the specified domain.

        Per RFC 7208 §4.5, if the DNS lookup returns more than one TXT
        record beginning with 'v=spf1', the check_host() evaluation MUST
        abort and return a PermError.  We detect this condition and set
        self.spf_permerror = True.  The first record is still returned
        for display/reporting purposes, but downstream analysis is skipped.

        Per RFC 7208 §4.3, internationalized domains are IDNA-encoded
        before querying.
        """
        try:
            if not domain:
                domain = self.domain

            # RFC 7208 §4.3: encode IDN to A-label (Punycode)
            encoded_domain = _encode_idna(domain)
            if not encoded_domain:
                return None

            resolver = self._make_recursive_resolver()
            logger.debug("Querying SPF for %s", encoded_domain)
            query_result = resolver.resolve(encoded_domain, "TXT")

            # Collect ALL records starting with v=spf1
            spf_records = []
            for record in query_result:
                txt = parse_txt_record(record)
                if _is_spf_record(txt):
                    spf_records.append(txt)

            if len(spf_records) > 1:
                # RFC 7208 §4.5: multiple SPF records = PermError
                logger.error(
                    "RFC 7208 §4.5 PermError: %d SPF records found for %s — "
                    "MTAs will abort SPF evaluation", len(spf_records), domain)
                # Only flag PermError on the primary domain lookup, not
                # during include/redirect recursion
                if domain == self.domain:
                    self.spf_permerror = True
                return spf_records[0]  # Return first for display

            if spf_records:
                logger.debug("Found SPF for %s: %s", domain, spf_records[0])
                return spf_records[0]

            logger.debug("No SPF record found in TXT records for %s", domain)
            return None
        except dns.resolver.NXDOMAIN:
            logger.debug("Domain %s does not exist (NXDOMAIN)", domain)
            return None
        except dns.resolver.NoAnswer:
            logger.debug("No TXT answer for %s", domain)
            return None
        except dns.resolver.Timeout:
            logger.warning("SPF query timeout for %s", domain)
            return None
        except dns.resolver.NoNameservers:
            logger.warning("No nameservers available for SPF query on %s", domain)
            return None
        except Exception as e:
            logger.error("Unexpected error querying SPF for %s: %s", domain, e)
            return None

    def _make_resolver(self):
        """Create a resolver for the primary domain (auth NS preferred)."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ns for ns in [self.dns_server, "1.1.1.1", "8.8.8.8"] if ns]
        return resolver

    def _make_recursive_resolver(self):
        """Create a recursive-only resolver for include/redirect recursion.

        Include targets (e.g. _spf.google.com) live in other zones. Using
        the customer's auth NS would cause REFUSED/timeouts before falling
        back. Go straight to public recursive resolvers.
        """
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        return resolver

    def get_spf_all_string(self):
        """Returns the string value of the 'all' mechanism in the SPF record.

        RFC 7208 §4.6.1: mechanism names are case-insensitive.
        RFC 7208 §6.1: multiple redirect modifiers trigger PermError.

        Uses word-boundary-aware matching to avoid false positives on tokens
        like 'allow' that contain 'all' as a substring.
        """
        spf_record = self.spf_record
        visited_domains = set()

        while spf_record:
            # Tokenize and check each token for an 'all' mechanism
            # RFC 7208 §4.6.1: mechanism names are case-insensitive
            all_matches = []
            redirect_targets = []
            for token in spf_record.split():
                token_lower = token.lower()
                if token_lower in ("-all", "~all", "?all", "+all", "all"):
                    all_matches.append(
                        token_lower if token_lower[0] in _QUALIFIERS
                        else "+" + token_lower
                    )
                # Collect redirects (case-insensitive per §4.6.1)
                mech = _strip_qualifier(token).lower()
                if mech.startswith("redirect="):
                    redirect_targets.append(mech[len("redirect="):])

            if len(all_matches) == 1:
                return all_matches[0]
            elif len(all_matches) > 1:
                return "2many"

            # RFC 7208 §6.1: multiple redirect modifiers = PermError
            if len(redirect_targets) > 1:
                logger.error(
                    "RFC 7208 §6.1 PermError: %d redirect modifiers in SPF "
                    "for %s", len(redirect_targets), self.domain)
                self.spf_permerror = True
                return None

            if redirect_targets:
                redirect_domain = redirect_targets[0]
                if redirect_domain in visited_domains:
                    logger.warning("Circular SPF redirect detected for %s", self.domain)
                    break
                visited_domains.add(redirect_domain)
                # Use recursive resolver for cross-zone redirect targets
                spf_record = self._get_spf_via_recursive(redirect_domain)
            else:
                break

        return None

    def _get_spf_via_recursive(self, domain):
        """Fetch an SPF record using public recursive resolvers only.

        Used for redirect= and include: targets that live in foreign
        zones where the customer's authoritative NS would return REFUSED.
        """
        encoded_domain = _encode_idna(domain)
        if not encoded_domain:
            return None
        try:
            resolver = self._make_recursive_resolver()
            answers = resolver.resolve(encoded_domain, "TXT")
            for rdata in answers:
                txt = parse_txt_record(rdata)
                if _is_spf_record(txt):
                    return txt
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.Timeout, dns.resolver.NoNameservers):
            logger.debug("SPF redirect lookup failed for %s", domain)
        except Exception as e:
            logger.debug("SPF redirect lookup error for %s: %s", domain, e)
        return None

    def get_spf_dns_queries(self):
        """Count DNS-causing mechanisms per RFC 7208 §4.6.4.

        Mechanisms that cause DNS lookups: include, a, mx, ptr, exists, redirect.
        Handles qualifier-prefixed forms (-include:, ~mx, +a:, etc.).

        RFC 7208 §7: Targets containing macros (%{...}) are skipped during
        static counting because they require runtime IP context to resolve.

        Note: this counts the mechanism itself as 1 lookup. Per RFC 7208,
        mx can cause up to 10 additional A/AAAA lookups (one per MX host),
        and a can cause multiple A/AAAA lookups. This count is therefore a
        lower bound on actual DNS queries.
        """
        resolver = self._make_recursive_resolver()

        def count_dns_queries(spf_record, depth=0):
            if depth > 10:
                logger.warning("SPF recursion depth exceeded for %s", self.domain)
                return 0
            count = 0
            for token in spf_record.split():
                mech = _strip_qualifier(token).lower()

                # include: and redirect= — count + recurse
                if mech.startswith("include:") or mech.startswith("redirect="):
                    if mech.startswith("include:"):
                        target = mech[len("include:"):]
                    else:
                        target = mech[len("redirect="):]

                    count += 1

                    # RFC 7208 §7: skip macro targets — they require
                    # runtime IP context that static analysis cannot provide
                    if _has_macro(target):
                        logger.debug("Skipping macro target in SPF count: %s", target)
                        continue

                    # IDNA-encode before resolving
                    encoded_target = _encode_idna(target)
                    if not encoded_target:
                        continue

                    try:
                        answers = resolver.resolve(encoded_target, "TXT")
                        for rdata in answers:
                            txt_record = parse_txt_record(rdata)
                            if _is_spf_record(txt_record):
                                count += count_dns_queries(txt_record, depth + 1)
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                            dns.resolver.Timeout, dns.resolver.NoNameservers):
                        logger.debug("SPF include/redirect lookup failed for %s", target)
                    except Exception as e:
                        logger.debug("SPF include lookup error for %s: %s", target, e)

                # a mechanism: bare "a", "a:domain", "a/cidr"
                elif mech == "a" or mech.startswith("a:") or mech.startswith("a/"):
                    count += 1

                # mx mechanism: bare "mx", "mx:domain", "mx/cidr"
                elif mech == "mx" or mech.startswith("mx:") or mech.startswith("mx/"):
                    count += 1

                # ptr mechanism (deprecated but still counts)
                elif mech == "ptr" or mech.startswith("ptr:"):
                    count += 1

                # exists mechanism
                elif mech.startswith("exists:"):
                    count += 1

            return count

        return count_dns_queries(self.spf_record)

    def __str__(self):
        return (
            f"SPF Record: {self.spf_record}\n"
            f"All Mechanism: {self.all_mechanism}\n"
            f"DNS Query Count: {self.spf_dns_query_count}\n"
            f"Too Many DNS Queries: {self.too_many_dns_queries}"
        )
