# modules/spf.py

"""
SPF (Sender Policy Framework) record discovery and analysis.

Implements RFC 7208 compliant mechanism counting, including qualifier-prefixed
mechanisms (-include:, ~mx, etc.) and proper recursive include/redirect resolution.
"""

import dns.resolver
import re
import logging

from .txt_utils import parse_txt_record

logger = logging.getLogger("spoofyvibe.spf")

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


class SPF:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.spf_record = self.get_spf_record()
        self.all_mechanism = None
        self.spf_dns_query_count = 0
        self.too_many_dns_queries = False
        self.spf_macros = []

        if self.spf_record:
            self.all_mechanism = self.get_spf_all_string()
            self.spf_dns_query_count = self.get_spf_dns_queries()
            self.too_many_dns_queries = self.spf_dns_query_count > 10
            self.spf_macros = self.get_spf_macros()

    def get_spf_macros(self):
        """Returns a list of SPF macros used in the record.

        RFC 7208 §7.1 allows macro delimiters: . - + , / _ =
        """
        if not self.spf_record:
            return []
        macros = re.findall(r"%{[a-zA-Z][0-9r]*[.\-+,/_=]*}", self.spf_record)
        return list(set(macros))

    def get_spf_record(self, domain=None):
        """Fetches the SPF record for the specified domain."""
        try:
            if not domain:
                domain = self.domain
            resolver = dns.resolver.Resolver()
            # Filter out None to avoid dnspython error when dns_server is unset
            resolver.nameservers = [ns for ns in [self.dns_server, "1.1.1.1", "8.8.8.8"] if ns]
            logger.debug("Querying SPF for %s", domain)
            query_result = resolver.resolve(domain, "TXT")
            for record in query_result:
                txt = parse_txt_record(record)
                # RFC 7208 §4.5: SPF record begins with "v=spf1"
                if txt.strip().lower().startswith("v=spf1"):
                    logger.debug("Found SPF for %s: %s", domain, txt)
                    return txt
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

        Uses word-boundary-aware matching to avoid false positives on tokens
        like 'allow' that contain 'all' as a substring.
        """
        spf_record = self.spf_record
        visited_domains = set()

        while spf_record:
            # Tokenize and check each token for an 'all' mechanism
            all_matches = []
            for token in spf_record.split():
                if token in ("-all", "~all", "?all", "+all", "all"):
                    all_matches.append(token if token[0] in _QUALIFIERS else "+" + token)

            if len(all_matches) == 1:
                return all_matches[0]
            elif len(all_matches) > 1:
                return "2many"

            redirect_match = re.search(r"redirect=([\w.-]+)", spf_record)
            if redirect_match:
                redirect_domain = redirect_match.group(1)
                if redirect_domain in visited_domains:
                    logger.warning("Circular SPF redirect detected for %s", self.domain)
                    break
                visited_domains.add(redirect_domain)
                spf_record = self.get_spf_record(redirect_domain)
            else:
                break

        return None

    def get_spf_dns_queries(self):
        """Count DNS-causing mechanisms per RFC 7208 §4.6.4.

        Mechanisms that cause DNS lookups: include, a, mx, ptr, exists, redirect.
        Handles qualifier-prefixed forms (-include:, ~mx, +a:, etc.).

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
                        url = mech[len("include:"):]
                    else:
                        url = mech[len("redirect="):]

                    count += 1
                    try:
                        answers = resolver.resolve(url, "TXT")
                        for rdata in answers:
                            txt_record = parse_txt_record(rdata)
                            if txt_record.strip().lower().startswith("v=spf1"):
                                count += count_dns_queries(txt_record, depth + 1)
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                            dns.resolver.Timeout, dns.resolver.NoNameservers):
                        logger.debug("SPF include/redirect lookup failed for %s", url)
                    except Exception as e:
                        logger.debug("SPF include lookup error for %s: %s", url, e)

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
