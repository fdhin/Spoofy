# modules/m365.py

"""
Microsoft 365 tenant discovery module.

Detects if a domain uses Microsoft 365 for email by examining MX records,
then discovers associated .onmicrosoft.com tenant domains.
"""

import logging
import re

import dns.resolver

logger = logging.getLogger("spoofyvibe.m365")


class M365Tenant:
    """Discover Microsoft 365 tenant information for a domain."""

    # MX patterns indicating Microsoft 365
    M365_MX_PATTERN = re.compile(
        r"\.mail\.protection\.outlook\.com\.?$", re.IGNORECASE
    )

    def __init__(self, domain, mx_records=None, dns_server=None):
        """
        Initialize and detect M365 tenant info.

        Args:
            domain: The domain name being analyzed.
            mx_records: Optional list of MX record dicts (from mx.py).
                        Each should have a 'host' key.
            dns_server: DNS server to use. Defaults to 1.1.1.1.
        """
        self.domain = domain.strip().lower()
        self.dns_server = dns_server or "1.1.1.1"
        self.is_m365 = False
        self.tenant_name = None
        self.tenant_domains = []
        self.error = None

        self._detect(mx_records or [])

    def _detect(self, mx_records):
        """Run M365 detection pipeline."""
        # Step 1: Check MX records for M365 pattern
        for mx in mx_records:
            host = mx.get("host", "") if isinstance(mx, dict) else str(mx)
            if self.M365_MX_PATTERN.search(host):
                self.is_m365 = True
                # Extract tenant name from MX host
                # e.g. "contoso-com.mail.protection.outlook.com" → "contoso-com"
                self.tenant_name = self._extract_tenant_name(host)
                logger.debug(
                    "M365 detected for %s (tenant: %s)", self.domain, self.tenant_name
                )
                break

        if not self.is_m365:
            return

        # Step 2: Discover tenant domains
        self._discover_tenant_domains()

    def _extract_tenant_name(self, mx_host):
        """Extract tenant name from MX hostname.

        Pattern: <tenant>.mail.protection.outlook.com
        """
        mx_host = mx_host.rstrip(".")
        parts = mx_host.split(".")
        if len(parts) >= 5 and parts[-4] == "mail":
            return parts[0]
        return None

    def _discover_tenant_domains(self):
        """Try to resolve .onmicrosoft.com and .mail.onmicrosoft.com domains."""
        if not self.tenant_name:
            return

        # The tenant name in MX is typically "domain-tld" (e.g. contoso-com)
        # but the onmicrosoft domain uses the actual tenant prefix
        # Try both the MX-derived name and a cleaned version
        candidates = set()
        candidates.add(self.tenant_name)

        # Also try the domain name without TLD, replacing dots/hyphens
        domain_parts = self.domain.split(".")
        if len(domain_parts) >= 2:
            candidates.add(domain_parts[0])

        suffixes = [".onmicrosoft.com", ".mail.onmicrosoft.com"]

        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.dns_server]

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
                    logger.error("Error resolving %s: %s", fqdn, e)

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
                pass
            except Exception:
                pass

        self.tenant_domains.sort()

    def to_dict(self):
        """Return M365 tenant data as a dictionary."""
        return {
            "M365_DETECTED": self.is_m365,
            "M365_TENANT_NAME": self.tenant_name,
            "M365_TENANT_DOMAINS": self.tenant_domains,
        }

    def __str__(self):
        if not self.is_m365:
            return "Microsoft 365: Not detected"
        parts = [f"Microsoft 365: Detected (tenant: {self.tenant_name})"]
        if self.tenant_domains:
            parts.append(f"  Tenant domains: {', '.join(self.tenant_domains)}")
        return "\n".join(parts)
