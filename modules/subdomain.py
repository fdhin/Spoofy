# modules/subdomain.py

"""
Subdomain discovery via Certificate Transparency logs.

Uses crt.sh to passively enumerate subdomains without active scanning.
"""

import logging
import re
import requests

logger = logging.getLogger("spoofyvibe.subdomain")

CRT_SH_URL = "https://crt.sh/"


class SubdomainFinder:
    """Discover subdomains using Certificate Transparency logs."""

    def __init__(self, domain, timeout=15):
        """
        Args:
            domain: base domain to enumerate subdomains for
            timeout: HTTP request timeout in seconds
        """
        self.domain = domain.lower().strip()
        self.timeout = timeout
        self.subdomains = set()
        self.raw_entries = []
        self.error = None

    def discover(self):
        """
        Query crt.sh for subdomains.

        Returns:
            list: sorted list of unique subdomains
        """
        try:
            logger.debug("Querying crt.sh for %s", self.domain)
            resp = requests.get(
                CRT_SH_URL,
                params={"q": f"%.{self.domain}", "output": "json"},
                timeout=self.timeout,
                headers={"User-Agent": "SpoofyVibe/2.0"},
            )

            if resp.status_code != 200:
                logger.warning("crt.sh returned HTTP %d for %s", resp.status_code, self.domain)
                self.error = f"crt.sh HTTP {resp.status_code}"
                return []

            entries = resp.json()
            self.raw_entries = entries
            logger.debug("crt.sh returned %d certificate entries for %s", len(entries), self.domain)

            for entry in entries:
                name_value = entry.get("name_value", "")
                # name_value can contain multiple names separated by newlines
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if self._is_valid_subdomain(name):
                        self.subdomains.add(name)

            # Always include the base domain
            self.subdomains.add(self.domain)

            result = sorted(self.subdomains)
            logger.debug("Found %d unique subdomains for %s", len(result), self.domain)
            return result

        except requests.exceptions.Timeout:
            logger.warning("crt.sh timeout for %s", self.domain)
            self.error = "crt.sh request timeout"
            return [self.domain]
        except requests.exceptions.ConnectionError as e:
            logger.warning("crt.sh connection error for %s: %s", self.domain, e)
            self.error = f"Connection error: {e}"
            return [self.domain]
        except ValueError as e:
            logger.warning("crt.sh JSON parse error for %s: %s", self.domain, e)
            self.error = f"JSON parse error: {e}"
            return [self.domain]
        except Exception as e:
            logger.error("Unexpected error querying crt.sh for %s: %s", self.domain, e)
            self.error = str(e)
            return [self.domain]

    def _is_valid_subdomain(self, name):
        """Check if a name is a valid subdomain of our target domain."""
        if not name:
            return False

        # Must end with our domain
        if not name.endswith(f".{self.domain}") and name != self.domain:
            return False

        # Skip wildcard entries
        if "*" in name:
            return False

        # Basic DNS name validation
        if not re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', name):
            return False

        # Skip excessively long names
        if len(name) > 253:
            return False

        return True

    def to_dict(self):
        """Return discovery results as a dict."""
        return {
            "domain": self.domain,
            "subdomains": sorted(self.subdomains),
            "count": len(self.subdomains),
            "error": self.error,
        }

    def __str__(self):
        if not self.subdomains:
            return f"No subdomains found for {self.domain}"
        lines = [f"Subdomains for {self.domain} ({len(self.subdomains)} found):"]
        for sub in sorted(self.subdomains):
            marker = "  " if sub != self.domain else "→ "
            lines.append(f"  {marker}{sub}")
        return "\n".join(lines)
