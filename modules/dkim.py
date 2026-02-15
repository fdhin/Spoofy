# modules/dkim.py

import dns.resolver
import base64
import logging
import requests

logger = logging.getLogger("spoofyvibe.dkim")

# Common DKIM selectors to brute-force via DNS
COMMON_SELECTORS = [
    # Generic
    "default", "dkim", "mail", "email", "k1", "k2", "k3", "s1", "s2",
    # Microsoft 365
    "selector1", "selector2",
    # Google Workspace
    "google", "20161025", "20230601",
    # Proofpoint
    "proofpoint", "ppk1", "ppk2",
    # Mimecast
    "mimecast", "mimecast20190104",
    # Mailchimp / Mandrill
    "mandrill", "k2._domainkey", "k3._domainkey",
    # Amazon SES
    "amazonses", "ug7nbt3p4vbsqexampleqaus2lqsflk",
    # SendGrid
    "s1", "s2", "smtpapi",
    # Mailgun
    "mailo", "mg", "smtp",
    # Zendesk
    "zendesk1", "zendesk2",
    # Postmark
    "pm",
    # Everylytic
    "everlytickey1", "everlytickey2", "eversrv",
    # Salesforce
    "sf1", "sf2", "salesforce", "salesforce1",
    # HubSpot
    "hs1", "hs2", "hubspot",
    # Fastmail
    "fm1", "fm2", "fm3",
]


class DKIMSelector:
    """Represents a single discovered DKIM selector with analysis."""

    def __init__(self, selector, domain, raw_value, source="dns"):
        self.selector = selector
        self.domain = domain
        self.raw_value = raw_value
        self.source = source  # "dns" or "api"
        self.key_type = None
        self.key_bits = None
        self.hash_algorithm = None
        self._analyze_key()

    def _analyze_key(self):
        """Parse DKIM TXT record to extract key type and estimate key size."""
        if not self.raw_value:
            return

        txt = self.raw_value

        # Extract key type (k=)
        if "k=" in txt:
            self.key_type = txt.split("k=")[1].split(";")[0].strip()
        else:
            self.key_type = "rsa"  # Default per RFC 6376

        # Extract hash algorithm (h=)
        if "h=" in txt:
            self.hash_algorithm = txt.split("h=")[1].split(";")[0].strip()

        # Extract and measure public key (p=)
        if "p=" in txt:
            p_value = txt.split("p=")[1].split(";")[0].strip()
            p_value = p_value.replace(" ", "")
            if p_value:
                try:
                    key_bytes = base64.b64decode(p_value)
                    # RSA key size estimation: DER-encoded SubjectPublicKeyInfo
                    # The key length in bits ≈ len(key_bytes) * 8 - overhead
                    # For RSA, a rough but practical estimation:
                    key_len = len(key_bytes)
                    if key_len <= 0:
                        self.key_bits = 0
                    elif key_len <= 100:
                        self.key_bits = 512
                    elif key_len <= 170:
                        self.key_bits = 1024
                    elif key_len <= 300:
                        self.key_bits = 2048
                    elif key_len <= 550:
                        self.key_bits = 4096
                    else:
                        self.key_bits = key_len * 8
                except Exception:
                    logger.debug("Could not decode DKIM public key for %s._domainkey.%s",
                                 self.selector, self.domain)

    @property
    def is_weak(self):
        """Key is weak if < 2048 bits."""
        if self.key_bits is None:
            return None
        return self.key_bits < 2048

    def to_dict(self):
        return {
            "selector": self.selector,
            "domain": self.domain,
            "source": self.source,
            "key_type": self.key_type,
            "key_bits": self.key_bits,
            "hash_algorithm": self.hash_algorithm,
            "is_weak": self.is_weak,
            "raw": self.raw_value[:200] + "..." if len(self.raw_value) > 200 else self.raw_value,
        }

    def __str__(self):
        strength = ""
        if self.key_bits:
            weak_marker = " ⚠️ WEAK" if self.is_weak else ""
            strength = f" ({self.key_bits}-bit {self.key_type or 'rsa'}{weak_marker})"
        return f"{self.selector}._domainkey.{self.domain}{strength}"


class DKIM:
    def __init__(self, domain, dns_server=None, api_base_url=None):
        self.domain = domain
        self.dns_server = dns_server
        self.api_base_url = api_base_url or "https://archive.prove.email/api"
        self.selectors = []
        self.dkim_record = None
        self.has_weak_keys = False

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

    def _brute_force_dns(self):
        """Try common DKIM selectors via direct DNS lookups.

        Handles both direct TXT records and CNAME-based selectors (e.g. M365
        uses CNAME records like selector1._domainkey.example.com pointing to
        selector1-example-com._domainkey.example.onmicrosoft.com).
        """
        known_selectors = {s.selector for s in self.selectors}
        resolver = dns.resolver.Resolver()
        if self.dns_server:
            resolver.nameservers = [self.dns_server]

        for selector in COMMON_SELECTORS:
            if selector in known_selectors:
                continue
            qname = f"{selector}._domainkey.{self.domain}"

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

        logger.debug("Total DKIM selectors for %s after brute-force: %d",
                     self.domain, len(self.selectors))

    def _resolve_dkim_txt(self, resolver, qname):
        """Resolve a DKIM TXT record directly. Returns the TXT value or None."""
        try:
            answers = resolver.resolve(qname, "TXT")
            for rdata in answers:
                txt = str(rdata).replace('"', "")
                if "p=" in txt:
                    return txt
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.resolver.Timeout):
            pass
        except Exception:
            pass
        return None

    def _resolve_dkim_via_cname(self, resolver, qname):
        """Check if qname has a CNAME, follow it, and resolve TXT there."""
        try:
            cname_answers = resolver.resolve(qname, "CNAME")
            for rdata in cname_answers:
                target = str(rdata).rstrip(".")
                logger.debug("DKIM CNAME found: %s -> %s", qname, target)
                txt_value = self._resolve_dkim_txt(resolver, target)
                if txt_value:
                    return txt_value
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.resolver.Timeout):
            pass
        except Exception:
            pass
        return None

    def _compile_results(self):
        """Build the legacy dkim_record string and check for weak keys."""
        if not self.selectors:
            self.dkim_record = None
            return

        lines = []
        for sel in self.selectors:
            trimmed = sel.raw_value[:128] + "...(trimmed)" if len(sel.raw_value) > 128 else sel.raw_value
            strength = ""
            if sel.key_bits:
                strength = f" [{sel.key_bits}-bit]"
            lines.append(f"[*]    {sel.selector}._domainkey.{sel.domain}{strength} -> {trimmed}")

        self.dkim_record = "\r\n".join(lines)
        self.has_weak_keys = any(s.is_weak for s in self.selectors if s.is_weak is not None)

    def to_dict(self):
        """Return structured results for integration."""
        return {
            "DKIM": self.dkim_record,
            "DKIM_SELECTORS": [s.to_dict() for s in self.selectors],
            "DKIM_SELECTOR_COUNT": len(self.selectors),
            "DKIM_HAS_WEAK_KEYS": self.has_weak_keys,
        }

    def __str__(self):
        if not self.selectors:
            return f"No DKIM selectors found for {self.domain}"
        lines = [f"DKIM Selectors for {self.domain} ({len(self.selectors)} found):"]
        for sel in self.selectors:
            lines.append(f"  [{sel.source}] {sel}")
        return "\n".join(lines)
