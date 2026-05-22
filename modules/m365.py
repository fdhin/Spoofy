# modules/m365.py

"""
Microsoft 365 tenant discovery module.

Detects if a domain uses Microsoft 365 for email by examining MX records,
then discovers the actual tenant name via DKIM CNAME resolution rather
than relying on the MX hostname prefix (which is just the primary SMTP
domain with dots replaced by dashes, not the actual tenant name).

Tenant discovery methods (in order of reliability):
  1. DKIM CNAME: selector1._domainkey.<domain> → selector1-<dashed>._domainkey.<TENANT>.onmicrosoft.com
  2. MX hostname prefix (fallback): <token>.mail.protection.outlook.com
  3. DNS probing of .onmicrosoft.com candidates
"""

import logging
import re

import dns.resolver

from .dns_utils import encode_idna

logger = logging.getLogger("spoofyvibe.m365")


class M365Tenant:
    """Discover Microsoft 365 tenant information for a domain."""

    # MX patterns indicating Microsoft 365 (includes GCC High)
    M365_MX_PATTERN = re.compile(
        r"\.mail\.protection\.(outlook\.com|office365\.us)\.?$", re.IGNORECASE
    )

    # DKIM CNAME target pattern for extracting tenant name
    # Format: selector1-<dashed-domain>._domainkey.<TENANT>.onmicrosoft.com
    _DKIM_CNAME_PATTERN = re.compile(
        r"\._domainkey\.([^.]+)\.onmicrosoft\.com\.?$", re.IGNORECASE
    )

    def __init__(self, domain, mx_records=None, dns_server=None):
        """
        Initialize and detect M365 tenant info.

        Args:
            domain: The domain name being analyzed.
            mx_records: Optional list of MX record dicts (from mx.py).
                        Each should have a 'host' key.
            dns_server: DNS server to use for same-zone queries.
                        Cross-zone queries always use recursive resolvers.
        """
        self.domain = domain.strip().lower()
        self.dns_server = dns_server
        self.is_m365 = False
        self.mx_prefix = None  # The MX hostname prefix (NOT the tenant name)
        self.tenant_name = None  # Actual tenant from DKIM CNAME (if discovered)
        self.tenant_domains = []
        self.error = None

        self._detect(mx_records or [])

    def _make_resolver(self, timeout=5):
        """Create a recursive resolver for cross-zone queries.

        .onmicrosoft.com and _domainkey lookups are always cross-zone,
        so we use public recursive resolvers instead of the customer's
        authoritative NS (which can't answer for these zones).
        """
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        resolver.timeout = timeout
        resolver.lifetime = timeout
        return resolver

    def _detect(self, mx_records):
        """Run M365 detection pipeline."""
        # Step 1: Check MX records for M365 pattern
        for mx in mx_records:
            host = mx.get("host", "") if isinstance(mx, dict) else str(mx)
            if self.M365_MX_PATTERN.search(host):
                self.is_m365 = True
                # Extract MX hostname prefix (NOT the tenant name)
                self.mx_prefix = self._extract_mx_prefix(host)
                logger.debug(
                    "M365 detected for %s (mx_prefix: %s)", self.domain, self.mx_prefix
                )
                break

        if not self.is_m365:
            return

        # Step 2: Try to discover actual tenant name via DKIM CNAME
        self._discover_via_dkim_cname()

        # Step 3: Discover tenant domains via DNS probing
        self._discover_tenant_domains()

    def _extract_mx_prefix(self, mx_host):
        """Extract MX hostname prefix.

        Pattern: <prefix>.mail.protection.outlook.com (or office365.us)
        Note: this is the primary SMTP domain encoded as one label
        (dots→dashes), NOT the actual M365 tenant name.
        """
        mx_host = mx_host.rstrip(".")
        parts = mx_host.split(".")
        if len(parts) >= 5 and parts[-4] == "mail":
            return parts[0]
        return None

    def _discover_via_dkim_cname(self):
        """Discover actual tenant name via DKIM CNAME resolution.

        For M365 tenants with DKIM enabled:
            selector1._domainkey.<domain> CNAME selector1-<dashed>._domainkey.<TENANT>.onmicrosoft.com

        The <TENANT> portion is the actual M365 tenant prefix.
        This is the standard OSINT technique used by AADInternals, ROADtools, etc.
        """
        resolver = self._make_resolver()
        selectors = ["selector1", "selector2"]
        idna_domain = encode_idna(self.domain)

        for selector in selectors:
            fqdn = f"{selector}._domainkey.{idna_domain}"
            try:
                answers = resolver.resolve(fqdn, "CNAME")
                for rdata in answers:
                    target = str(rdata).lower()
                    match = self._DKIM_CNAME_PATTERN.search(target)
                    if match:
                        self.tenant_name = match.group(1)
                        logger.debug(
                            "Tenant name discovered via DKIM CNAME for %s: %s",
                            self.domain, self.tenant_name,
                        )
                        return
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                logger.debug("No DKIM CNAME for %s at %s", self.domain, fqdn)
            except dns.resolver.Timeout:
                logger.debug("DKIM CNAME timeout for %s at %s", self.domain, fqdn)
            except dns.resolver.NoNameservers:
                logger.debug("No nameservers for DKIM CNAME query on %s", fqdn)
            except Exception as e:
                logger.debug("DKIM CNAME lookup error for %s: %s", fqdn, e)

    def _discover_tenant_domains(self):
        """Try to resolve .onmicrosoft.com and .mail.onmicrosoft.com domains."""
        candidates = set()

        # Best candidate: actual tenant name from DKIM CNAME
        if self.tenant_name:
            candidates.add(self.tenant_name)

        # Fallback candidates
        if self.mx_prefix:
            candidates.add(self.mx_prefix)

        # Also try the domain name without TLD
        domain_parts = self.domain.split(".")
        if len(domain_parts) >= 2:
            candidates.add(domain_parts[0])

        suffixes = [".onmicrosoft.com", ".mail.onmicrosoft.com"]
        resolver = self._make_resolver()

        for candidate in candidates:
            for suffix in suffixes:
                fqdn = candidate + suffix
                try:
                    resolver.resolve(fqdn, "A")
                    if fqdn not in self.tenant_domains:
                        self.tenant_domains.append(fqdn)
                        logger.debug("Tenant domain found: %s", fqdn)
                except (
                    dns.resolver.NXDOMAIN,
                    dns.resolver.NoAnswer,
                    dns.resolver.Timeout,
                    dns.resolver.NoNameservers,
                ):
                    logger.debug("Tenant domain not found: %s", fqdn)
                except Exception as e:
                    logger.debug("Error resolving tenant domain %s: %s", fqdn, e)

        # Also try MX lookup for the onmicrosoft.com domain
        for candidate in candidates:
            fqdn = candidate + ".onmicrosoft.com"
            if fqdn in self.tenant_domains:
                continue
            try:
                resolver.resolve(fqdn, "MX")
                if fqdn not in self.tenant_domains:
                    self.tenant_domains.append(fqdn)
                    logger.debug("Tenant domain found via MX: %s", fqdn)
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.Timeout,
                dns.resolver.NoNameservers,
            ):
                logger.debug("Tenant domain not found via MX: %s", fqdn)
            except Exception as e:
                logger.debug("Error resolving tenant MX %s: %s", fqdn, e)

        self.tenant_domains.sort()

    def to_dict(self):
        """Return M365 tenant data as a dictionary."""
        return {
            "M365_DETECTED": self.is_m365,
            "M365_MX_PREFIX": self.mx_prefix,
            "M365_TENANT_NAME": self.tenant_name,
            "M365_TENANT_DOMAINS": self.tenant_domains,
        }

    def __str__(self):
        if not self.is_m365:
            return "Microsoft 365: Not detected"
        parts = []
        if self.tenant_name:
            parts.append(f"Microsoft 365: Detected (tenant: {self.tenant_name})")
        else:
            parts.append(f"Microsoft 365: Detected (MX prefix: {self.mx_prefix})")
        if self.tenant_domains:
            parts.append(f"  Tenant domains: {', '.join(self.tenant_domains)}")
        return "\n".join(parts)
