# modules/mta_sts.py

from .dns_utils import encode_idna as _encode_idna

"""
MTA-STS (SMTP MTA Strict Transport Security) and TLS-RPT detection.

Implements RFC 8461 §3.3 compliant policy fetching (no redirects, 64KB limit),
RFC 8461 §4.1 compliant wildcard matching (leftmost label only), and proper
IDNA handling for internationalized domains.

RFC Compliance Notes:
  - RFC 8461 §3.1 / RFC 8460 §3: Multiple valid TXT records MUST be discarded.
    Tracked via `mta_sts_permerror`/`tls_rpt_permerror` flags (not by overloading
    the TXT string field, which would bypass truthy checks in scoring).
  - RFC 8461 §3.1: The 'id' tag is required by ABNF. Records without a valid
    'id' are syntactically invalid and MUST be discarded.
  - RFC 8460 §3: The 'rua' tag is required by ABNF. Records without it
    are syntactically invalid.
  - RFC 8461 §3.2: In the policy file, duplicate non-repeating fields MUST
    be ignored (only the first occurrence is honored).
  - RFC 8461 §3.2: The policy file MUST contain exactly 'version: STSv1'.
  - RFC 8461 §3.2: All key and value matching is case-sensitive per ABNF
    (RFC 7405 %s modifier).
  - RFC 8461 §4.1: Wildcard '*' is strictly limited to the left-most label.
  - RFC 5890: Domains are IDNA-encoded to A-labels for DNS queries.
  - RFC 8461 §3.3: HTTP redirects MUST NOT be followed, and payload size
    is limited to 64KB.
"""

import dns.resolver
import logging
import re
import requests

from .txt_utils import parse_txt_record, parse_tag_value

logger = logging.getLogger("spoofyvibe.mta_sts")

# Maximum policy size (RFC 8461 §3.3 suggested limit)
_MAX_POLICY_SIZE = 65536  # 64 KB

# Strict version matching per ABNF.  Uses regex instead of startswith()
# to prevent substring attacks (e.g. "v=STSv10" matching "v=STSv1").
_MTA_STS_TXT_RE = re.compile(r'^v=STSv1(?:[ \t;]|$)', re.ASCII)
_TLS_RPT_TXT_RE = re.compile(r'^v=TLSRPTv1(?:[ \t;]|$)', re.ASCII)

# RFC 8461 §3.1 ABNF: sts-id = %s"id=" 1*32(ALPHA / DIGIT)
_STS_ID_RE = re.compile(r'^[a-zA-Z0-9]{1,32}$')




def _mx_matches_pattern(host, pattern):
    """RFC 8461 §4.1 label-aware wildcard matching.

    The '*' wildcard matches exactly one DNS label, and MUST ONLY
    be the complete left-most label.

    Examples:
        _mx_matches_pattern("mx1.example.com", "*.example.com")  → True
        _mx_matches_pattern("sub.mx1.example.com", "*.example.com")  → False
        _mx_matches_pattern("mx1.example.com", "mx1.example.com")  → True
        _mx_matches_pattern("mx1.example.com", "mail.*.example.com")  → False
    """
    host_labels = host.lower().rstrip(".").split(".")
    pattern_labels = pattern.lower().rstrip(".").split(".")

    if len(host_labels) != len(pattern_labels):
        return False

    for i, (h, p) in enumerate(zip(host_labels, pattern_labels)):
        if p == "*":
            # RFC 8461 §4.1: Wildcard may ONLY be the left-most label
            if i != 0:
                return False
            continue
        if h != p:
            return False

    return True


class MTASTS:
    """Check MTA-STS policy and TLS-RPT reporting for a domain."""

    def __init__(self, domain, dns_server=None):
        # Strip trailing dots to prevent SSL/SNI mismatches in HTTPS requests.
        # DNS uses FQDNs with trailing dots, but SSL certificates do not.
        self.domain = domain.strip().rstrip(".").lower()
        self.dns_server = dns_server

        # MTA-STS TXT record fields
        self.mta_sts_txt = None
        self.mta_sts_id = None
        self.mta_sts_permerror = False  # Multiple records or syntactically invalid

        # MTA-STS policy fields
        self.policy_raw = None
        self.policy_version = None
        self.policy_mode = None
        self.policy_max_age = None
        self.policy_mx_patterns = []

        # TLS-RPT fields
        self.tls_rpt_record = None
        self.tls_rpt_rua = None
        self.tls_rpt_permerror = False  # Multiple records or syntactically invalid

        self._check_mta_sts_txt()
        if self.mta_sts_txt and not self.mta_sts_permerror:
            self._fetch_mta_sts_policy()
        self._check_tls_rpt()

    def _get_resolver(self):
        """Create a resolver preferring the provided DNS server."""
        resolver = dns.resolver.Resolver()
        if self.dns_server:
            resolver.nameservers = [self.dns_server]
        return resolver

    def _reset_policy(self):
        """Wipe policy fields if validation fails.

        Preserves policy_raw for debugging/display in reports.
        """
        self.policy_version = None
        self.policy_mode = None
        self.policy_max_age = None
        self.policy_mx_patterns = []

    def _check_mta_sts_txt(self):
        """Query _mta-sts.<domain> TXT record.

        RFC 8461 §3.1: If the number of resulting records is not one,
        senders MUST assume the domain does not have an available policy.
        The 'id' tag is required; missing or invalid 'id' makes the record
        syntactically invalid.
        """
        idna_domain = _encode_idna(self.domain)
        if not idna_domain:
            return

        qname = f"_mta-sts.{idna_domain}"

        try:
            resolver = self._get_resolver()
            logger.debug("Querying %s TXT", qname)
            answers = resolver.resolve(qname, "TXT")

            valid_records = []
            for rdata in answers:
                txt = parse_txt_record(rdata).strip()
                # Strict regex instead of startswith() to reject "v=STSv10"
                if _MTA_STS_TXT_RE.match(txt):
                    valid_records.append(txt)

            # RFC 8461 §3.1: Exactly one valid record required.
            if len(valid_records) == 1:
                self.mta_sts_txt = valid_records[0]
                tags = parse_tag_value(self.mta_sts_txt)
                self.mta_sts_id = tags.get("id")

                # RFC 8461 §3.1 ABNF: 'id' is required, 1-32 alphanumeric.
                # Missing/invalid 'id' → syntactically invalid → no policy.
                if not self.mta_sts_id or not _STS_ID_RE.match(self.mta_sts_id):
                    logger.error(
                        "RFC 8461 §3.1: MTA-STS TXT record for %s has "
                        "missing or invalid 'id' tag — record is invalid",
                        self.domain,
                    )
                    self.mta_sts_txt = None
                    self.mta_sts_id = None
                    return

                logger.debug("Found MTA-STS TXT for %s: %s", self.domain, self.mta_sts_txt)
            elif len(valid_records) > 1:
                # Use a boolean flag instead of overloading mta_sts_txt
                # to prevent truthy string from bypassing scoring checks.
                logger.error(
                    "RFC 8461 §3.1 Violation: Multiple MTA-STS TXT records "
                    "found for %s — treating as no policy", self.domain
                )
                self.mta_sts_permerror = True

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            logger.debug("No MTA-STS records for %s", self.domain)
        except dns.resolver.Timeout:
            logger.warning("MTA-STS TXT query timeout for %s", self.domain)
        except dns.resolver.NoNameservers:
            logger.warning("No nameservers for MTA-STS query on %s", self.domain)
        except Exception as e:
            logger.error("Unexpected error querying MTA-STS for %s: %s", self.domain, e)

    def _fetch_mta_sts_policy(self):
        """Fetch MTA-STS policy from https://mta-sts.<domain>/.well-known/mta-sts.txt.

        RFC 8461 §3.3: MUST NOT follow redirects. A redirect to an
        attacker-controlled URL would defeat MTA-STS. Any non-200 response
        (including 3xx) is treated as "no policy".

        RFC 8461 §3.3: Payload is limited to 64KB to prevent DoS.
        """
        idna_domain = _encode_idna(self.domain)
        if not idna_domain:
            return

        url = f"https://mta-sts.{idna_domain}/.well-known/mta-sts.txt"

        try:
            logger.debug("Fetching MTA-STS policy from %s", url)
            # stream=True to enforce the 64KB limit without loading everything
            with requests.get(url, timeout=10, allow_redirects=False, stream=True) as resp:
                if resp.status_code == 200:
                    # RFC 8461 §3.2: SHOULD validate media type is text/plain
                    content_type = resp.headers.get("Content-Type", "")
                    if not content_type.lower().startswith("text/plain"):
                        logger.warning(
                            "RFC 8461 §3.2: MTA-STS policy Content-Type is "
                            "not text/plain for %s", self.domain
                        )

                    # RFC 8461 §3.3: Limit to 64KB
                    raw_bytes = b""
                    for chunk in resp.iter_content(chunk_size=8192):
                        raw_bytes += chunk
                        if len(raw_bytes) > _MAX_POLICY_SIZE:
                            logger.error(
                                "MTA-STS policy for %s exceeds 64KB limit — "
                                "aborting fetch", self.domain
                            )
                            return

                    self.policy_raw = raw_bytes.decode("utf-8", errors="replace").strip()
                    self._parse_policy(self.policy_raw)
                    logger.debug(
                        "MTA-STS policy for %s: mode=%s, max_age=%s, mx=%s",
                        self.domain, self.policy_mode, self.policy_max_age,
                        self.policy_mx_patterns,
                    )
                elif 300 <= resp.status_code < 400:
                    logger.warning(
                        "RFC 8461 §3.3 Violation: MTA-STS policy redirect (%d) "
                        "for %s — redirects MUST NOT be followed",
                        resp.status_code, self.domain,
                    )
                else:
                    logger.warning("MTA-STS policy HTTP %d for %s", resp.status_code, self.domain)

        except requests.exceptions.SSLError as e:
            logger.warning("MTA-STS policy SSL error for %s: %s", self.domain, e)
        except requests.exceptions.ConnectionError as e:
            logger.debug("MTA-STS policy connection error for %s: %s", self.domain, e)
        except requests.exceptions.Timeout:
            logger.warning("MTA-STS policy fetch timeout for %s", self.domain)
        except Exception as e:
            logger.error("Unexpected error fetching MTA-STS policy for %s: %s", self.domain, e)

    def _parse_policy(self, raw):
        """Parse the MTA-STS policy file content.

        RFC 8461 §3.2:
          - 'version: STSv1' is required exactly once (case-sensitive).
          - Duplicate non-repeating fields: only the first is honored.
          - 'mx' can be repeated.
          - 'mode' must be exactly one of 'enforce', 'testing', 'none'
            (case-sensitive per ABNF %s modifier).
          - 'max_age' must be a non-negative integer (max 31557600).

        Keys are case-sensitive per RFC 7405 %s notation:
          - %s"version", %s"mode", %s"mx", %s"max_age"
        """
        seen_keys = set()
        has_valid_version = False

        for line in raw.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue

            key, _, value = line.partition(":")
            # Keys are case-sensitive per ABNF %s notation — do NOT lowercase.
            key = key.strip()
            value = value.strip()

            # 'mx' can be repeated indefinitely
            if key == "mx":
                self.policy_mx_patterns.append(value)
                continue

            # RFC 8461 §3.2: "If any non-repeated field... is duplicated,
            # all entries except for the first SHALL be ignored."
            if key in seen_keys:
                logger.warning(
                    "RFC 8461 §3.2: Duplicate key '%s' in MTA-STS policy "
                    "for %s — ignoring", key, self.domain
                )
                continue

            seen_keys.add(key)

            if key == "version":
                self.policy_version = value
                if value == "STSv1":
                    has_valid_version = True
            elif key == "mode":
                # Store as-is; validate case-sensitivity below
                self.policy_mode = value
            elif key == "max_age":
                try:
                    self.policy_max_age = int(value)
                except ValueError:
                    self.policy_max_age = -1  # Mark as invalid

        # ---- RFC 8461 §3.2 Structural Validation ----

        # ABNF: sts-policy-version-value = %s"STSv1" (case-sensitive)
        if not has_valid_version:
            logger.error(
                "RFC 8461 §3.2 Violation: Policy for %s missing or invalid "
                "'version: STSv1'", self.domain
            )
            self._reset_policy()
            return

        # ABNF: %s"enforce" / %s"testing" / %s"none" (case-sensitive)
        if self.policy_mode not in ("enforce", "testing", "none"):
            logger.error(
                "RFC 8461 §3.2 Violation: Policy for %s has missing or "
                "invalid 'mode' (got '%s')", self.domain, self.policy_mode
            )
            self._reset_policy()
            return

        if self.policy_max_age is None or not (0 <= self.policy_max_age <= 31557600):
            logger.error(
                "RFC 8461 §3.2 Violation: Policy for %s has missing or "
                "out-of-range 'max_age'", self.domain
            )
            self._reset_policy()
            return

        # Must have at least one MX unless mode is 'none'
        if self.policy_mode in ("enforce", "testing") and not self.policy_mx_patterns:
            logger.error(
                "RFC 8461 §3.2 Violation: Policy mode '%s' for %s requires "
                "at least one 'mx' entry", self.policy_mode, self.domain
            )
            self._reset_policy()
            return

    def _check_tls_rpt(self):
        """Query _smtp._tls.<domain> TXT record for TLS-RPT.

        RFC 8460 §3: If multiple valid records exist, assume NO POLICY.
        The 'rua' tag is required; missing 'rua' makes the record invalid.
        """
        idna_domain = _encode_idna(self.domain)
        if not idna_domain:
            return

        qname = f"_smtp._tls.{idna_domain}"

        try:
            resolver = self._get_resolver()
            logger.debug("Querying %s TXT", qname)
            answers = resolver.resolve(qname, "TXT")

            valid_records = []
            for rdata in answers:
                txt = parse_txt_record(rdata).strip()
                # Strict regex instead of startswith()
                if _TLS_RPT_TXT_RE.match(txt):
                    valid_records.append(txt)

            # RFC 8460 §3: Multiple valid records → no policy
            if len(valid_records) == 1:
                self.tls_rpt_record = valid_records[0]
                tags = parse_tag_value(self.tls_rpt_record)
                self.tls_rpt_rua = tags.get("rua")

                # RFC 8460 §3: 'rua' is required by ABNF
                if not self.tls_rpt_rua:
                    logger.error(
                        "RFC 8460 §3: TLS-RPT record for %s missing "
                        "required 'rua' tag — record is invalid", self.domain
                    )
                    self.tls_rpt_record = None
                    self.tls_rpt_rua = None
                    return

                logger.debug("Found TLS-RPT for %s: %s", self.domain, self.tls_rpt_record)
            elif len(valid_records) > 1:
                logger.error(
                    "RFC 8460 §3 Violation: Multiple TLS-RPT TXT records "
                    "found for %s — treating as no policy", self.domain
                )
                self.tls_rpt_permerror = True

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            logger.debug("No TLS-RPT record found for %s", self.domain)
        except dns.resolver.Timeout:
            logger.warning("TLS-RPT query timeout for %s", self.domain)
        except dns.resolver.NoNameservers:
            logger.warning("No nameservers for TLS-RPT query on %s", self.domain)
        except Exception as e:
            logger.error("Unexpected error querying TLS-RPT for %s: %s", self.domain, e)

    def validate_mx_against_policy(self, mx_hosts):
        """Check if MX hosts match the policy's mx patterns.

        Returns list of unmatched hosts. Uses RFC 8461 §4.1 strict left-most
        label wildcard matching. Both hosts and patterns are IDNA-encoded
        before comparison.
        """
        if not self.policy_mx_patterns or not mx_hosts:
            return []

        unmatched = []
        for host in mx_hosts:
            # IDNA-encode the host before comparison (RFC 8461 §3.2)
            idna_host = _encode_idna(host) or host

            matched = any(
                _mx_matches_pattern(idna_host, _encode_idna(pattern) or pattern)
                for pattern in self.policy_mx_patterns
            )
            if not matched:
                unmatched.append(host)
        return unmatched

    def to_dict(self):
        """Return results as a flat dict for integration into the main result."""
        return {
            "MTA_STS_TXT": self.mta_sts_txt,
            "MTA_STS_ID": self.mta_sts_id,
            "MTA_STS_MODE": self.policy_mode,
            "MTA_STS_MAX_AGE": self.policy_max_age,
            "MTA_STS_MX_PATTERNS": self.policy_mx_patterns,
            "MTA_STS_POLICY_RAW": self.policy_raw,
            "MTA_STS_PERMERROR": self.mta_sts_permerror,
            "TLS_RPT_RECORD": self.tls_rpt_record,
            "TLS_RPT_RUA": self.tls_rpt_rua,
            "TLS_RPT_PERMERROR": self.tls_rpt_permerror,
        }

    def __str__(self):
        lines = []
        if self.mta_sts_permerror:
            lines.append("MTA-STS TXT: CRITICAL (Multiple records found)")
        else:
            lines.append(f"MTA-STS TXT: {self.mta_sts_txt or 'Not found'}")

        if self.policy_mode:
            lines.append(f"MTA-STS Mode: {self.policy_mode}")
            lines.append(f"MTA-STS Max Age: {self.policy_max_age}")
            lines.append(f"MTA-STS MX Patterns: {', '.join(self.policy_mx_patterns)}")

        if self.tls_rpt_permerror:
            lines.append("TLS-RPT: CRITICAL (Multiple records found)")
        else:
            lines.append(f"TLS-RPT: {self.tls_rpt_record or 'Not found'}")
            if self.tls_rpt_rua:
                lines.append(f"TLS-RPT RUA: {self.tls_rpt_rua}")

        return "\n".join(lines)
