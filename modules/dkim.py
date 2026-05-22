# modules/dkim.py

import dns.resolver
import base64
import binascii
import logging
import re
import requests
from datetime import datetime

from .txt_utils import parse_txt_record
from .dns_utils import encode_idna

logger = logging.getLogger("spoofyvibe.dkim")

# ---------------------------------------------------------------------------
# Curated DKIM selector dictionary.
#
# ONLY contains selectors that are universally deployed vendor defaults or
# widely documented constants. Entries that depend on tenant-specific IDs,
# customer-chosen names, or randomized tokens are intentionally excluded
# (e.g. Amazon SES, HubSpot, Proofpoint, Mimecast) because they cannot be
# discovered by static brute-forcing.  See _generate_dynamic_selectors()
# for algorithmic pattern generation.
# ---------------------------------------------------------------------------
STATIC_SELECTORS = [
    # ── Generic / self-hosted ──────────────────────────────────────────
    "default", "dkim", "mail", "email",
    "k1", "k2", "k3",
    "s1", "s2",
    "key1", "key2",

    # ── Microsoft 365 (rigid CNAME delegation, highly predictable) ────
    "selector1", "selector2",

    # ── Google Workspace (brand default + date-based rotation) ────────
    "google",

    # ── Mailgun ────────────────────────────────────────────────────────
    "mailo", "mg", "smtp",

    # ── Zendesk (numerically iterated corporate prefix) ───────────────
    "zendesk1", "zendesk2",

    # ── Postmark ───────────────────────────────────────────────────────
    "pm",

    # ── Fastmail (mandatory three-record CNAME framework) ─────────────
    "fm1", "fm2", "fm3",

    # ── Mailchimp / Mandrill (legacy but widely active) ───────────────
    "mandrill",

    # ── Salesforce Core CRM ───────────────────────────────────────────
    "sf1", "sf2", "salesforce", "salesforce1",

    # ── Salesforce Marketing Cloud (independent numeric taxonomy) ─────
    "200608", "10dkim1", "11dkim1", "12dkim1", "13dkim1",
    "50dkim1", "51dkim1",

    # ── Klaviyo ────────────────────────────────────────────────────────
    "kl", "kl2",

    # ── ActiveCampaign ─────────────────────────────────────────────────
    "dk", "acmail", "activecampaign",

    # ── Adobe Marketo Engage ──────────────────────────────────────────
    "m1", "m2", "a1", "mkto",

    # ── Campaign Monitor ──────────────────────────────────────────────
    "cm", "cm1", "cm2",

    # ── Constant Contact ──────────────────────────────────────────────
    "ctct1", "ctct2",

    # ── Brevo (formerly Sendinblue) ───────────────────────────────────
    "sib2k",

    # ── SparkPost (semi-algorithmic scph prefix) ──────────────────────
    "scph0421", "scph0850a",

    # ── Apple iCloud Custom Domains ───────────────────────────────────
    "sig1", "apple",

    # ── Yahoo Mail ────────────────────────────────────────────────────
    "yahoo",

    # ── Zoho Mail (rigid standardization for all tenants) ─────────────
    "zoho",

    # ── ProtonMail ────────────────────────────────────────────────────
    "protonmail",

    # ── Acoustic / IBM Watson ─────────────────────────────────────────
    "spop1024",

    # ── AWeber (three-tier rotational delegation) ─────────────────────
    "aweber_key_a", "aweber_key_b", "aweber_key_c",

    # ── Everylytic (legacy; eversrv deprecated but retained for audit) ─
    "everlytickey1", "everlytickey2", "eversrv",
]

# Prefixes used by the dynamic generator for temporal and numeric patterns.
_DYNAMIC_PREFIXES = ["", "s", "k", "key", "dkim", "selector", "mail"]
_DYNAMIC_YEAR_RANGE_START = 2015


def _get_exact_key_size(der_bytes):
    """Try to get the exact RSA key size using the cryptography library.

    Returns the key size in bits, or None if the library is unavailable
    or the key can't be parsed.
    """
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        pubkey = load_der_public_key(der_bytes)
        return pubkey.key_size
    except Exception:
        return None


def _estimate_key_size(der_bytes):
    """Estimate RSA key size from DER-encoded SubjectPublicKeyInfo byte length.

    Falls back to this when the cryptography library is not available.
    This is approximate — non-standard sizes (1536, 3072) may be misclassified.
    """
    key_len = len(der_bytes)
    if key_len <= 0:
        return 0
    elif key_len <= 100:
        return 512
    elif key_len <= 170:
        return 1024
    elif key_len <= 300:
        return 2048
    elif key_len <= 550:
        return 4096
    else:
        return key_len * 8


class DKIMSelector:
    """Represents a single discovered DKIM selector with analysis."""

    def __init__(self, selector, domain, raw_value, source="dns"):
        self.selector = selector
        self.domain = domain
        self.raw_value = raw_value
        self.source = source  # "dns" or "api"
        self.key_type = None
        self.key_bits = None
        self.hash_algorithms = None  # list of supported hash algorithms
        self.is_revoked = False
        self.is_testing = False
        self.is_strict = False  # t=s flag: strict subdomain mode (RFC 6376 §3.6.1)
        self.is_valid_version = True  # True if v= absent or v=DKIM1
        self.is_email_applicable = True  # True if s= absent, s=*, or s=email
        self._analyze_key()

    def _analyze_key(self):
        """Parse DKIM TXT record to extract key metadata per RFC 6376 §3.6.1.

        Uses a local tag parser instead of the shared parse_tag_value() because
        RFC 6376 §3.2 requires:
          - Tag names are CASE-SENSITIVE ("k" is valid, "K" is not)
          - v= tag MUST be the FIRST tag if present (positional constraint)
          - Duplicate tag names invalidate the entire record
        The shared parser lowercases keys and loses positional info.
        """
        if not self.raw_value:
            return

        parts = [p.strip() for p in self.raw_value.split(";") if p.strip()]
        if not parts:
            return

        tags = {}
        first_tag_key = None

        # Parse tags locally to enforce RFC 6376 §3.2 constraints
        for i, part in enumerate(parts):
            if "=" in part:
                key, _, value = part.partition("=")
                key = key.strip()  # Case-sensitive per RFC — do NOT lowercase

                if i == 0:
                    first_tag_key = key

                if key in tags:
                    # Duplicate tag name — entire record is invalid (RFC §3.2)
                    logger.error("DKIM key %s._domainkey.%s has duplicate tag '%s'. "
                                 "Record invalid per RFC 6376 §3.2.",
                                 self.selector, self.domain, key)
                    self.is_valid_version = False
                    return
                tags[key] = value.strip()
            else:
                # Malformed token without "=" — track for v= ordering check
                if i == 0:
                    first_tag_key = "malformed"

        # Version: v= (RFC §3.6.1 — RECOMMENDED, default "DKIM1")
        # "If specified, this tag MUST be set to DKIM1. This tag MUST be
        #  the first tag in the record."
        if "v" in tags:
            if first_tag_key != "v":
                logger.error("RFC 6376 §3.6.1 violation: 'v' MUST be the first tag in "
                             "%s._domainkey.%s (found at non-first position)",
                             self.selector, self.domain)
                self.is_valid_version = False
                return
            if tags["v"] != "DKIM1":
                logger.error("DKIM key record has invalid version '%s' for %s._domainkey.%s "
                             "(expected 'DKIM1'), discarding per RFC 6376 §3.6.1",
                             tags["v"], self.selector, self.domain)
                self.is_valid_version = False
                return

        # Key type: k= (default "rsa" per RFC 6376, "ed25519" added in RFC 8463)
        self.key_type = tags.get("k", "rsa").lower()

        # Hash algorithms: h= (default: all algorithms allowed)
        # Stored as a list for downstream analysis (e.g. sha1-only detection)
        h_tag = tags.get("h")
        if h_tag:
            self.hash_algorithms = [a.strip().lower() for a in h_tag.split(":") if a.strip()]
        else:
            self.hash_algorithms = None  # None means all algorithms accepted

        # Service type: s= (default "*" — matches all)
        # "Verifiers for a given service type MUST ignore this record
        #  if the appropriate type is not listed."
        s_tag = tags.get("s")
        if s_tag:
            service_types = [s.strip().lower() for s in s_tag.split(":") if s.strip()]
            self.is_email_applicable = "*" in service_types or "email" in service_types
            if not self.is_email_applicable:
                logger.warning("DKIM key %s._domainkey.%s has s=%s — not applicable for email",
                               self.selector, self.domain, s_tag)

        # Flags: t= (default: no flags)
        # "y" = testing mode — verifiers MUST treat as unsigned
        # "s" = strict — i= domain MUST exactly match d= (no subdomains)
        t_tag = tags.get("t")
        if t_tag:
            flags = [f.strip().lower() for f in t_tag.split(":") if f.strip()]
            self.is_testing = "y" in flags
            self.is_strict = "s" in flags

        # Public key: p= (REQUIRED)
        # "An empty value means that this public key has been revoked."
        p_value = tags.get("p")
        if p_value is None:
            # No p= tag at all — malformed record, mark as invalid
            logger.error("DKIM key record missing required p= tag for %s._domainkey.%s",
                         self.selector, self.domain)
            self.is_valid_version = False
            return

        # Strip ALL whitespace (spaces, tabs, newlines, carriage returns)
        # per RFC 6376 §2.8: FWS includes WSP (SP/HTAB) and CRLF
        p_value = re.sub(r'\s+', '', p_value)
        if not p_value:
            # Empty p= means key is revoked per RFC 6376 §3.6.1
            self.is_revoked = True
            logger.info("DKIM key %s._domainkey.%s is revoked (empty p= tag)",
                        self.selector, self.domain)
            return

        # Fix missing base64 padding — DNS admins frequently truncate trailing "="
        p_value += "=" * ((4 - len(p_value) % 4) % 4)

        try:
            # validate=True rejects stray non-base64 characters
            key_bytes = base64.b64decode(p_value, validate=True)
        except (binascii.Error, ValueError):
            logger.error("DKIM public key contains invalid base64 for %s._domainkey.%s",
                         self.selector, self.domain)
            self.is_valid_version = False
            return

        # Ed25519 keys (RFC 8463 §3.1.1) are raw 32-byte public keys
        if self.key_type == "ed25519":
            if len(key_bytes) == 32:
                self.key_bits = 256
            else:
                logger.error("Ed25519 DKIM key must be exactly 32 bytes, got %d for "
                             "%s._domainkey.%s", len(key_bytes), self.selector, self.domain)
                self.is_valid_version = False
            return

        # RSA key — DER-encoded SubjectPublicKeyInfo
        # Try exact key size via cryptography library first
        exact = _get_exact_key_size(key_bytes)
        if exact is not None:
            self.key_bits = exact
        else:
            self.key_bits = _estimate_key_size(key_bytes)

    @property
    def is_weak(self):
        """Key is weak if below the minimum for its algorithm.

        RSA keys < 2048 bits are weak per RFC 6376 §3.3.3.
        Ed25519 keys are always 256-bit but are NOT weak (RFC 8463).
        """
        if self.key_bits is None:
            return None
        if self.key_type == "ed25519":
            return False
        return self.key_bits < 2048

    @property
    def is_sha1_only(self):
        """Returns True if the key record restricts to SHA-1 only (no SHA-256).

        Per RFC 6376 §3.3, signers SHOULD sign using rsa-sha256.
        A key restricted to sha1-only is a weaker configuration.
        """
        if self.hash_algorithms is None:
            return False  # None means all algorithms accepted
        return "sha1" in self.hash_algorithms and "sha256" not in self.hash_algorithms

    @property
    def is_usable(self):
        """A selector is usable for email DKIM if it passes all RFC checks."""
        return (self.is_valid_version
                and not self.is_revoked
                and self.is_email_applicable)

    def to_dict(self):
        return {
            "selector": self.selector,
            "domain": self.domain,
            "source": self.source,
            "key_type": self.key_type,
            "key_bits": self.key_bits,
            "hash_algorithms": self.hash_algorithms,
            "is_weak": self.is_weak,
            "is_revoked": self.is_revoked,
            "is_testing": self.is_testing,
            "is_strict": self.is_strict,
            "is_valid_version": self.is_valid_version,
            "is_email_applicable": self.is_email_applicable,
            "is_sha1_only": self.is_sha1_only,
            "is_usable": self.is_usable,
            "raw": self.raw_value[:200] + "..." if len(self.raw_value) > 200 else self.raw_value,
        }

    def __str__(self):
        strength = ""
        if self.is_revoked:
            strength = " (REVOKED)"
        elif not self.is_valid_version:
            strength = " (INVALID VERSION)"
        elif not self.is_email_applicable:
            strength = " (NOT FOR EMAIL)"
        elif self.is_testing:
            strength = " (TESTING MODE)"
        elif self.key_bits:
            weak_marker = " ⚠️ WEAK" if self.is_weak else ""
            sha1_marker = " ⚠️ SHA1-ONLY" if self.is_sha1_only else ""
            strict_marker = " [STRICT]" if self.is_strict else ""
            strength = f" ({self.key_bits}-bit {self.key_type}{weak_marker}{sha1_marker}{strict_marker})"
        return f"{self.selector}._domainkey.{self.domain}{strength}"


class DKIM:
    def __init__(self, domain, dns_server=None, api_base_url=None):
        self.domain = domain
        self.dns_server = dns_server
        self.api_base_url = api_base_url or "https://archive.prove.email/api"
        self.selectors = []
        self.dkim_record = None
        self.has_weak_keys = False
        self.has_revoked_keys = False
        self.has_testing_keys = False

        # Try API first, then fall back to DNS brute-force
        self._query_api()
        self._brute_force_dns()
        self._compile_results()

    def _query_api(self):
        """Query the archive.prove.email API for known selectors."""
        try:
            base_url = self.api_base_url.rstrip("/")
            url = f"{base_url}/key"
            params = {"domain": self.domain}
            headers = {"accept": "application/json"}

            logger.debug("Querying DKIM API for %s", self.domain)
            response = requests.get(url, params=params, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    seen = set()
                    for record in data:
                        if not isinstance(record, dict):
                            continue
                        selector = record.get("selector", "unknown")
                        value = record.get("value", "")
                        if selector in seen:
                            continue
                        seen.add(selector)
                        if value:
                            sel = DKIMSelector(selector, self.domain, value, source="api")
                            self.selectors.append(sel)
                    logger.debug("API returned %d DKIM selectors for %s",
                                 len(self.selectors), self.domain)
            else:
                logger.debug("DKIM API returned %d for %s", response.status_code, self.domain)
        except requests.exceptions.RequestException as e:
            logger.debug("DKIM API request failed for %s: %s", self.domain, e)
        except (KeyError, ValueError, TypeError) as e:
            logger.debug("DKIM API response parse error for %s: %s", self.domain, e)

    @staticmethod
    def _generate_dynamic_selectors():
        """Algorithmically generate high-probability DKIM selectors.

        Targets two prevalent naming patterns that bypass static dictionaries:

        1. **Temporal (year-based):**  Administrators and platforms frequently
           embed the key's creation year into the selector for lifecycle
           tracking. Generates combinations of common prefixes with years
           from 2015 through the current year.  (e.g. s2023, dkim2024, 20230601)

        2. **Numeric iteration:**  Manual key rotation schemes commonly
           append sequential numbers to a base prefix.
           (e.g. s3, s4, key1, key2, selector3, selector4, selector5)

        Returns a list of generated selector strings (deduplicated against
        STATIC_SELECTORS at the call site).
        """
        generated = []
        current_year = datetime.now().year

        # Temporal combinations: prefix + year
        for year in range(_DYNAMIC_YEAR_RANGE_START, current_year + 1):
            for prefix in _DYNAMIC_PREFIXES:
                generated.append(f"{prefix}{year}")

        # Numeric iterations: prefix + 1..5
        for n in range(1, 6):
            for prefix in _DYNAMIC_PREFIXES:
                if prefix:  # skip bare numbers — they overlap with years
                    generated.append(f"{prefix}{n}")

        return generated

    def _brute_force_dns(self):
        """Try DKIM selectors via direct DNS lookups.

        Combines the curated STATIC_SELECTORS dictionary with dynamically
        generated temporal and numeric patterns.  All candidates are
        deduplicated before querying to avoid redundant DNS traffic.

        Handles both direct TXT records and CNAME-based selectors (e.g. M365
        uses CNAME records like selector1._domainkey.example.com pointing to
        selector1-example-com._domainkey.example.onmicrosoft.com).
        """
        known_selectors = {s.selector for s in self.selectors}

        # Build deduplicated candidate set: static + dynamic
        candidates = list(dict.fromkeys(
            STATIC_SELECTORS + self._generate_dynamic_selectors()
        ))

        resolver = dns.resolver.Resolver()
        if self.dns_server:
            resolver.nameservers = [self.dns_server]

        for selector in candidates:
            if selector in known_selectors:
                continue
            qname = f"{selector}._domainkey.{encode_idna(self.domain)}"

            # Try direct TXT lookup first
            txt_value = self._resolve_dkim_txt(resolver, qname)

            # If no direct TXT, check for CNAME and follow it
            if not txt_value:
                txt_value = self._resolve_dkim_via_cname(resolver, qname)

            if txt_value:
                sel = DKIMSelector(selector, self.domain, txt_value, source="dns")
                self.selectors.append(sel)
                known_selectors.add(selector)
                logger.debug("DNS brute-force found DKIM selector: %s for %s",
                             selector, self.domain)

        logger.debug("Total DKIM selectors for %s after brute-force: %d "
                     "(from %d candidates)",
                     self.domain, len(self.selectors), len(candidates))

    # Regex pre-filter for DKIM TXT record detection.
    # Matches either "v=DKIM1" at the start (with optional FWS around "=")
    # or a standalone "p=" tag (preceded by start-of-string or semicolon).
    # This avoids substring collisions like "ip4=..." or notes containing "p=".
    _DKIM_TXT_RE = re.compile(
        r'^[ \t]*v[ \t]*=[ \t]*DKIM1'
        r'|(?:^|;)\s*p\s*=',
    )

    def _resolve_dkim_txt(self, resolver, qname):
        """Resolve a DKIM TXT record directly. Returns the TXT value or None.

        Uses a regex pre-filter to validate the record looks like a DKIM key
        record, avoiding substring collisions (e.g. SPF "ip4=" or notes
        containing "p="). Per RFC 6376 §3.6.1, the p= tag is REQUIRED.

        Per RFC 6376 §3.6.2.2, if multiple valid DKIM TXT records are found
        in the same RRset, "the results are undefined". We log a warning and
        return the first match.
        """
        try:
            answers = resolver.resolve(qname, "TXT")
            matches = []
            for rdata in answers:
                txt = parse_txt_record(rdata)
                if self._DKIM_TXT_RE.search(txt):
                    matches.append(txt)
            if len(matches) > 1:
                logger.warning("Multiple DKIM TXT records found for %s — "
                               "results are undefined per RFC 6376 §3.6.2.2", qname)
            if matches:
                return matches[0]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.resolver.Timeout):
            pass
        except Exception:
            pass
        return None

    def _resolve_dkim_via_cname(self, resolver, qname):
        """Check if qname has a CNAME, follow it, and resolve TXT there.

        Defense-in-depth for CNAME-based DKIM setups (e.g. M365). A recursive
        resolver normally chases CNAMEs automatically, but this explicit
        fallback handles edge cases where the primary resolver can't follow
        the chain across zones.
        """
        try:
            cname_answers = resolver.resolve(qname, "CNAME")
            for rdata in cname_answers:
                target = str(rdata).rstrip(".")
                logger.debug("DKIM CNAME found: %s -> %s", qname, target)

                # Try with current resolver first
                txt_value = self._resolve_dkim_txt(resolver, target)
                if txt_value:
                    return txt_value

                # Fall back to public recursive resolver for cross-zone CNAMEs
                fallback = dns.resolver.Resolver()
                fallback.nameservers = ["1.1.1.1"]
                txt_value = self._resolve_dkim_txt(fallback, target)
                if txt_value:
                    logger.debug("Resolved DKIM TXT via fallback resolver for %s", target)
                    return txt_value
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.resolver.Timeout):
            pass
        except Exception:
            pass

        # Last resort: try the whole original qname via public resolver
        # This handles cases where the auth NS returns NoAnswer for TXT
        # but a recursive resolver can follow the CNAME chain automatically
        try:
            fallback = dns.resolver.Resolver()
            fallback.nameservers = ["1.1.1.1"]
            txt_value = self._resolve_dkim_txt(fallback, qname)
            if txt_value:
                logger.debug("Resolved DKIM TXT via fallback resolver for %s", qname)
                return txt_value
        except Exception:
            pass
        return None

    def _compile_results(self):
        """Build the legacy dkim_record string and check for weak/revoked/testing keys."""
        if not self.selectors:
            self.dkim_record = None
            return

        lines = []
        for sel in self.selectors:
            trimmed = sel.raw_value[:128] + "...(trimmed)" if len(sel.raw_value) > 128 else sel.raw_value
            strength = ""
            if sel.is_revoked:
                strength = " [REVOKED]"
            elif not sel.is_valid_version:
                strength = " [INVALID]"
            elif not sel.is_email_applicable:
                strength = " [NOT-EMAIL]"
            elif sel.is_testing:
                strength = " [TESTING]"
            elif sel.key_bits:
                strength = f" [{sel.key_bits}-bit]"
            lines.append(f"[*]    {sel.selector}._domainkey.{sel.domain}{strength} -> {trimmed}")

        self.dkim_record = "\r\n".join(lines)

        # Only count usable selectors for weak-key assessment
        usable = [s for s in self.selectors if s.is_usable]
        self.has_weak_keys = any(s.is_weak for s in usable if s.is_weak is not None)
        self.has_revoked_keys = any(s.is_revoked for s in self.selectors)
        self.has_testing_keys = any(s.is_testing for s in self.selectors if s.is_usable)

    def to_dict(self):
        """Return structured results for integration."""
        usable = [s for s in self.selectors if s.is_usable]
        return {
            "DKIM": self.dkim_record,
            "DKIM_SELECTORS": [s.to_dict() for s in self.selectors],
            "DKIM_SELECTOR_COUNT": len(usable),
            "DKIM_HAS_WEAK_KEYS": self.has_weak_keys,
            "DKIM_HAS_REVOKED_KEYS": self.has_revoked_keys,
            "DKIM_HAS_TESTING_KEYS": self.has_testing_keys,
        }

    def __str__(self):
        if not self.selectors:
            return f"No DKIM selectors found for {self.domain}"
        lines = [f"DKIM Selectors for {self.domain} ({len(self.selectors)} found):"]
        for sel in self.selectors:
            lines.append(f"  [{sel.source}] {sel}")
        return "\n".join(lines)
