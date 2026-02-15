# modules/mta_sts.py

import dns.resolver
import requests
import logging

logger = logging.getLogger("spoofyvibe.mta_sts")


class MTASTS:
    """Check MTA-STS policy and TLS-RPT reporting for a domain."""

    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server

        # MTA-STS TXT record fields
        self.mta_sts_txt = None
        self.mta_sts_id = None

        # MTA-STS policy fields
        self.policy_raw = None
        self.policy_mode = None
        self.policy_max_age = None
        self.policy_mx_patterns = []

        # TLS-RPT fields
        self.tls_rpt_record = None
        self.tls_rpt_rua = None

        self._check_mta_sts_txt()
        if self.mta_sts_txt:
            self._fetch_mta_sts_policy()
        self._check_tls_rpt()

    def _check_mta_sts_txt(self):
        """Query _mta-sts.<domain> TXT record."""
        try:
            resolver = dns.resolver.Resolver()
            if self.dns_server:
                resolver.nameservers = [self.dns_server]
            logger.debug("Querying _mta-sts.%s TXT", self.domain)
            answers = resolver.resolve(f"_mta-sts.{self.domain}", "TXT")
            for rdata in answers:
                txt = str(rdata).replace('"', "")
                if "STSv1" in txt or "v=STSv1" in txt:
                    self.mta_sts_txt = txt
                    # Extract id
                    if "id=" in txt:
                        self.mta_sts_id = txt.split("id=")[1].split(";")[0].strip()
                    logger.debug("Found MTA-STS TXT for %s: %s", self.domain, txt)
                    return
            logger.debug("No MTA-STS TXT record found for %s", self.domain)
        except dns.resolver.NXDOMAIN:
            logger.debug("No _mta-sts record (NXDOMAIN) for %s", self.domain)
        except dns.resolver.NoAnswer:
            logger.debug("No _mta-sts answer for %s", self.domain)
        except dns.resolver.Timeout:
            logger.warning("MTA-STS TXT query timeout for %s", self.domain)
        except dns.resolver.NoNameservers:
            logger.warning("No nameservers for MTA-STS query on %s", self.domain)
        except Exception as e:
            logger.error("Unexpected error querying MTA-STS for %s: %s", self.domain, e)

    def _fetch_mta_sts_policy(self):
        """Fetch MTA-STS policy from https://mta-sts.<domain>/.well-known/mta-sts.txt."""
        url = f"https://mta-sts.{self.domain}/.well-known/mta-sts.txt"
        try:
            logger.debug("Fetching MTA-STS policy from %s", url)
            resp = requests.get(url, timeout=10, allow_redirects=True)
            if resp.status_code == 200:
                self.policy_raw = resp.text.strip()
                self._parse_policy(self.policy_raw)
                logger.debug("MTA-STS policy for %s: mode=%s, max_age=%s, mx=%s",
                             self.domain, self.policy_mode, self.policy_max_age,
                             self.policy_mx_patterns)
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
        """Parse the MTA-STS policy file content."""
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()
                if key == "mode":
                    self.policy_mode = value.lower()
                elif key == "max_age":
                    try:
                        self.policy_max_age = int(value)
                    except ValueError:
                        self.policy_max_age = value
                elif key == "mx":
                    self.policy_mx_patterns.append(value)

    def _check_tls_rpt(self):
        """Query _smtp._tls.<domain> TXT record for TLS-RPT."""
        try:
            resolver = dns.resolver.Resolver()
            if self.dns_server:
                resolver.nameservers = [self.dns_server]
            logger.debug("Querying _smtp._tls.%s TXT", self.domain)
            answers = resolver.resolve(f"_smtp._tls.{self.domain}", "TXT")
            for rdata in answers:
                txt = str(rdata).replace('"', "")
                if "TLSRPTv1" in txt or "v=TLSRPTv1" in txt:
                    self.tls_rpt_record = txt
                    if "rua=" in txt:
                        self.tls_rpt_rua = txt.split("rua=")[1].split(";")[0].strip()
                    logger.debug("Found TLS-RPT for %s: %s", self.domain, txt)
                    return
            logger.debug("No TLS-RPT record found for %s", self.domain)
        except dns.resolver.NXDOMAIN:
            logger.debug("No TLS-RPT record (NXDOMAIN) for %s", self.domain)
        except dns.resolver.NoAnswer:
            logger.debug("No TLS-RPT answer for %s", self.domain)
        except dns.resolver.Timeout:
            logger.warning("TLS-RPT query timeout for %s", self.domain)
        except dns.resolver.NoNameservers:
            logger.warning("No nameservers for TLS-RPT query on %s", self.domain)
        except Exception as e:
            logger.error("Unexpected error querying TLS-RPT for %s: %s", self.domain, e)

    def validate_mx_against_policy(self, mx_hosts):
        """Check if MX hosts match the policy's mx patterns. Returns list of unmatched hosts."""
        if not self.policy_mx_patterns or not mx_hosts:
            return []

        import fnmatch
        unmatched = []
        for host in mx_hosts:
            host_lower = host.lower().rstrip(".")
            matched = False
            for pattern in self.policy_mx_patterns:
                pattern_lower = pattern.lower().rstrip(".")
                if fnmatch.fnmatch(host_lower, pattern_lower):
                    matched = True
                    break
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
            "TLS_RPT_RECORD": self.tls_rpt_record,
            "TLS_RPT_RUA": self.tls_rpt_rua,
        }

    def __str__(self):
        lines = [f"MTA-STS TXT: {self.mta_sts_txt or 'Not found'}"]
        if self.policy_mode:
            lines.append(f"MTA-STS Mode: {self.policy_mode}")
            lines.append(f"MTA-STS Max Age: {self.policy_max_age}")
            lines.append(f"MTA-STS MX Patterns: {', '.join(self.policy_mx_patterns)}")
        lines.append(f"TLS-RPT: {self.tls_rpt_record or 'Not found'}")
        if self.tls_rpt_rua:
            lines.append(f"TLS-RPT RUA: {self.tls_rpt_rua}")
        return "\n".join(lines)
