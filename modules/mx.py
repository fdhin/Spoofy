# modules/mx.py

import dns.resolver
import socket
import ssl
import logging

logger = logging.getLogger("spoofyvibe.mx")

# Known mail provider patterns → display name
KNOWN_PROVIDERS = {
    # Microsoft 365
    "mail.protection.outlook.com": "Microsoft 365",
    "olc.protection.outlook.com": "Microsoft 365 (GCC)",
    # Google Workspace
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "aspmx.l.google.com": "Google Workspace",
    # Proofpoint
    "pphosted.com": "Proofpoint",
    "ppe-hosted.com": "Proofpoint Essentials",
    # Mimecast
    "mimecast.com": "Mimecast",
    # Barracuda
    "barracudanetworks.com": "Barracuda",
    # Cisco Secure Email (IronPort)
    "iphmx.com": "Cisco Secure Email",
    # Sophos
    "sophos.com": "Sophos",
    # Trend Micro
    "in.hes.trendmicro.com": "Trend Micro",
    "in.hes.trendmicro.eu": "Trend Micro",
    # Zoho
    "zoho.com": "Zoho Mail",
    "zoho.eu": "Zoho Mail",
    # Fastmail
    "fastmail.com": "Fastmail",
    # ProtonMail
    "protonmail.ch": "ProtonMail",
    # Amazon SES / WorkMail
    "amazonaws.com": "Amazon SES",
    "awsapps.com": "Amazon WorkMail",
    # Rackspace
    "emailsrvr.com": "Rackspace",
    # GoDaddy
    "secureserver.net": "GoDaddy",
    # OVH
    "ovh.net": "OVH",
    # Mailgun
    "mailgun.org": "Mailgun",
    # SendGrid
    "sendgrid.net": "Twilio SendGrid",
    # Postmark
    "mtasv.net": "Postmark",
    # Fortinet / FortiMail
    "fortimail.com": "FortiMail",
}


class MXRecord:
    """Represents a single MX record with analysis results."""

    def __init__(self, priority, host):
        self.priority = priority
        self.host = host.rstrip(".")
        self.provider = None
        self.starttls = None
        self.ptr_record = None
        self.ip_address = None

    def to_dict(self):
        return {
            "priority": self.priority,
            "host": self.host,
            "provider": self.provider,
            "starttls": self.starttls,
            "ptr": self.ptr_record,
            "ip": self.ip_address,
        }


class MX:
    """Analyze MX records for a domain."""

    def __init__(self, domain, dns_server=None, check_starttls=True):
        self.domain = domain
        self.dns_server = dns_server
        self.records = []
        self.providers = set()
        self.all_starttls = None
        self.has_ptr = None

        self._query_mx()
        self._identify_providers()
        if check_starttls and self.records:
            self._check_starttls()
            self._check_ptr()

    def _query_mx(self):
        """Query MX records for the domain."""
        try:
            resolver = dns.resolver.Resolver()
            if self.dns_server:
                resolver.nameservers = [self.dns_server]
            logger.debug("Querying MX for %s", self.domain)
            answers = resolver.resolve(self.domain, "MX")
            for rdata in answers:
                mx = MXRecord(rdata.preference, str(rdata.exchange))
                self.records.append(mx)
            # Sort by priority (lowest first)
            self.records.sort(key=lambda r: r.priority)
            logger.debug("Found %d MX records for %s", len(self.records), self.domain)
        except dns.resolver.NXDOMAIN:
            logger.debug("No MX records (NXDOMAIN) for %s", self.domain)
        except dns.resolver.NoAnswer:
            logger.debug("No MX answer for %s", self.domain)
        except dns.resolver.Timeout:
            logger.warning("MX query timeout for %s", self.domain)
        except dns.resolver.NoNameservers:
            logger.warning("No nameservers for MX query on %s", self.domain)
        except Exception as e:
            logger.error("Unexpected error querying MX for %s: %s", self.domain, e)

    def _identify_providers(self):
        """Match MX hostnames to known providers."""
        for mx in self.records:
            host_lower = mx.host.lower()
            for pattern, provider in KNOWN_PROVIDERS.items():
                if host_lower.endswith(pattern) or pattern in host_lower:
                    mx.provider = provider
                    self.providers.add(provider)
                    break
            if not mx.provider:
                mx.provider = "Unknown"

    def _check_starttls(self):
        """Test STARTTLS support on each MX host (port 25)."""
        all_ok = True
        for mx in self.records:
            try:
                # Resolve the MX hostname
                mx.ip_address = socket.gethostbyname(mx.host)
                logger.debug("Testing STARTTLS on %s (%s):25", mx.host, mx.ip_address)
                sock = socket.create_connection((mx.ip_address, 25), timeout=10)
                banner = sock.recv(1024).decode("utf-8", errors="replace")
                logger.debug("SMTP banner from %s: %s", mx.host, banner.strip())

                sock.sendall(b"EHLO spoofyvibe.local\r\n")
                ehlo_resp = sock.recv(4096).decode("utf-8", errors="replace")

                if "STARTTLS" in ehlo_resp.upper():
                    mx.starttls = True
                    logger.debug("STARTTLS supported on %s", mx.host)
                else:
                    mx.starttls = False
                    all_ok = False
                    logger.warning("STARTTLS NOT supported on %s", mx.host)

                sock.sendall(b"QUIT\r\n")
                sock.close()
            except socket.timeout:
                logger.warning("STARTTLS check timeout for %s", mx.host)
                mx.starttls = None
                all_ok = False
            except ConnectionRefusedError:
                logger.warning("Port 25 connection refused on %s", mx.host)
                mx.starttls = None
                all_ok = False
            except OSError as e:
                logger.warning("STARTTLS check error for %s: %s", mx.host, e)
                mx.starttls = None
                all_ok = False
            except Exception as e:
                logger.error("Unexpected STARTTLS error for %s: %s", mx.host, e)
                mx.starttls = None
                all_ok = False

        self.all_starttls = all_ok if self.records else None

    def _check_ptr(self):
        """Check reverse DNS (PTR) for each MX host."""
        all_ptr = True
        for mx in self.records:
            if not mx.ip_address:
                try:
                    mx.ip_address = socket.gethostbyname(mx.host)
                except (socket.herror, socket.gaierror):
                    mx.ptr_record = None
                    all_ptr = False
                    continue

            try:
                result = socket.gethostbyaddr(mx.ip_address)
                mx.ptr_record = result[0]
                logger.debug("PTR for %s (%s): %s", mx.host, mx.ip_address, mx.ptr_record)
            except (socket.herror, socket.gaierror):
                logger.debug("No PTR for %s (%s)", mx.host, mx.ip_address)
                mx.ptr_record = None
                all_ptr = False
            except Exception as e:
                logger.error("PTR check error for %s: %s", mx.host, e)
                mx.ptr_record = None
                all_ptr = False

        self.has_ptr = all_ptr if self.records else None

    def get_mx_hosts(self):
        """Return list of MX hostnames (for MTA-STS validation)."""
        return [mx.host for mx in self.records]

    def to_dict(self):
        """Return results as a flat dict for integration."""
        return {
            "MX_RECORDS": [mx.to_dict() for mx in self.records],
            "MX_COUNT": len(self.records),
            "MX_PROVIDERS": list(self.providers),
            "MX_ALL_STARTTLS": self.all_starttls,
            "MX_ALL_PTR": self.has_ptr,
        }

    def provider_summary(self):
        """Return a human-readable provider summary string."""
        if not self.providers:
            return "No MX records"
        return ", ".join(sorted(self.providers))

    def __str__(self):
        if not self.records:
            return "No MX records found"
        lines = [f"MX Records for {self.domain} ({len(self.records)} total):"]
        for mx in self.records:
            tls_str = "✅" if mx.starttls else "❌" if mx.starttls is False else "?"
            ptr_str = mx.ptr_record or "None"
            lines.append(
                f"  [{mx.priority}] {mx.host} — {mx.provider} — "
                f"STARTTLS: {tls_str} — PTR: {ptr_str}"
            )
        return "\n".join(lines)
