# modules/mx.py

"""
MX record analysis module.

Discovers MX records, identifies mail providers, tests STARTTLS support,
and validates reverse DNS (PTR) and Forward-Confirmed reverse DNS (FCrDNS).

Uses dns.resolver for all DNS operations (replaces socket.gethostbyname/
gethostbyaddr which were IPv4-only, blocking, and had no timeout control).
"""

import dns.resolver
import dns.reversename
import socket
import logging

logger = logging.getLogger("spoofyvibe.mx")

# Known mail provider patterns → display name
# Sorted longest-first for deterministic matching when multiple could match.
KNOWN_PROVIDERS = {
    # Microsoft 365
    "mail.protection.office365.us": "Microsoft 365 (GCC High)",
    "mail.protection.outlook.com": "Microsoft 365",
    "olc.protection.outlook.com": "Microsoft 365 (GCC)",
    # Google Workspace
    "aspmx.l.google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "google.com": "Google Workspace",
    # Proofpoint
    "ppe-hosted.com": "Proofpoint Essentials",
    "pphosted.com": "Proofpoint",
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

# Pre-sort patterns longest-first for deterministic matching
_SORTED_PROVIDERS = sorted(KNOWN_PROVIDERS.items(), key=lambda x: -len(x[0]))


def _resolve_host_ip(host, resolver):
    """Resolve a hostname to an IP address using dns.resolver.

    Tries A record first, falls back to AAAA for IPv6-only hosts.
    Returns (ip_address, is_ipv6) or (None, False) on failure.
    """
    # Try A record first
    try:
        answers = resolver.resolve(host, "A")
        for rdata in answers:
            return str(rdata), False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.Timeout, dns.resolver.NoNameservers):
        pass

    # Try AAAA for IPv6-only hosts
    try:
        answers = resolver.resolve(host, "AAAA")
        for rdata in answers:
            return str(rdata), True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.Timeout, dns.resolver.NoNameservers):
        pass

    return None, False


def _resolve_ptr(ip_address, resolver):
    """Resolve PTR record for an IP address using dns.reversename.

    Works for both IPv4 and IPv6 addresses.
    Returns the PTR hostname or None.
    """
    try:
        rev_name = dns.reversename.from_address(ip_address)
        answers = resolver.resolve(rev_name, "PTR")
        for rdata in answers:
            return str(rdata).rstrip(".")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.Timeout, dns.resolver.NoNameservers):
        pass
    except Exception as e:
        logger.debug("PTR resolution error for %s: %s", ip_address, e)
    return None


def _read_smtp_response(sock, timeout=10):
    """Read a complete SMTP response, handling multi-line replies.

    SMTP multi-line responses use '250-' for continuation lines and
    '250 ' (space) for the final line. A single recv() may miss lines
    on slower servers. This function reads until the final line.

    Returns the complete response as a string.
    """
    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            # Check if we've received the final line
            # Final line format: "NNN text\r\n" (space after code, not hyphen)
            lines = data.decode("utf-8", errors="replace").split("\r\n")
            for line in lines:
                if len(line) >= 4 and line[3:4] == " ":
                    return data.decode("utf-8", errors="replace")
        except socket.timeout:
            break
    return data.decode("utf-8", errors="replace")


class MXRecord:
    """Represents a single MX record with analysis results."""

    def __init__(self, priority, host):
        self.priority = priority
        # Detect null MX before stripping trailing dot
        raw_host = str(host)
        self.is_null_mx = (priority == 0 and raw_host in ("", ".", "\x00"))
        self.host = raw_host.rstrip(".")
        self.provider = None
        self.starttls = None
        self.starttls_note = None  # Documents limitations
        self.ptr_record = None
        self.ip_address = None
        self.fcrdns = None

    def to_dict(self):
        return {
            "priority": self.priority,
            "host": self.host,
            "provider": self.provider,
            "starttls": self.starttls,
            "starttls_note": self.starttls_note,
            "ptr": self.ptr_record,
            "ip": self.ip_address,
            "fcrdns": self.fcrdns,
            "is_null_mx": self.is_null_mx,
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
        self.has_null_mx = False

        self._query_mx()
        self._identify_providers()
        if check_starttls and self.records:
            self._check_starttls()
            self._check_ptr()

    def _make_resolver(self, timeout=5):
        """Create a resolver for cross-zone lookups (MX host IPs, PTR)."""
        resolver = dns.resolver.Resolver()
        # MX host IPs and PTR records are cross-zone — use recursive resolvers
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        resolver.timeout = timeout
        resolver.lifetime = timeout
        return resolver

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
                if mx.is_null_mx:
                    self.has_null_mx = True
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
        """Match MX hostnames to known providers.

        Uses label-boundary-aware endswith only (no substring matching)
        to avoid false positives like 'fake-google.com-mx.attacker.org'.
        Patterns are sorted longest-first for deterministic matching.
        """
        for mx in self.records:
            host_lower = mx.host.lower()
            for pattern, provider in _SORTED_PROVIDERS:
                # endswith with label boundary: must match at a dot boundary
                if host_lower.endswith("." + pattern) or host_lower == pattern:
                    mx.provider = provider
                    self.providers.add(provider)
                    break
            if not mx.provider:
                mx.provider = "Unknown"

    def _check_starttls(self):
        """Test STARTTLS support on each MX host (port 25).

        Note: This check only verifies that the server advertises STARTTLS
        in the EHLO response. It does NOT initiate a TLS handshake, verify
        the certificate, or check TLS version. The result should be
        interpreted as "server claims STARTTLS support", not "TLS works."

        Timeouts are set to 20s to accommodate providers like Microsoft 365
        EOP which tarpit inbound port 25 connections from unknown sources.
        """
        resolver = self._make_resolver(timeout=10)
        for mx in self.records:
            if mx.is_null_mx:
                mx.starttls = None
                continue
            try:
                # Resolve MX hostname using dns.resolver (IPv4/IPv6 aware)
                ip_address, is_ipv6 = _resolve_host_ip(mx.host, resolver)
                if not ip_address:
                    logger.warning("Could not resolve %s to IP", mx.host)
                    mx.starttls = None
                    mx.starttls_note = "DNS resolution failed"
                    continue
                mx.ip_address = ip_address
                logger.debug("Testing STARTTLS on %s (%s):25", mx.host, mx.ip_address)

                sock = socket.create_connection((mx.ip_address, 25), timeout=20)
                banner = _read_smtp_response(sock, timeout=20)
                logger.debug("SMTP banner from %s: %s", mx.host, banner.strip())

                # Use .invalid TLD per RFC 6761 — most MTAs accept it,
                # won't leak as a real hostname, and avoids strict EHLO rejection.
                sock.sendall(b"EHLO spoofyvibe.scan.invalid\r\n")
                ehlo_resp = _read_smtp_response(sock, timeout=20)

                if "STARTTLS" in ehlo_resp.upper():
                    mx.starttls = True
                    mx.starttls_note = "Advertised in EHLO (handshake not verified)"
                    logger.debug("STARTTLS supported on %s", mx.host)
                else:
                    mx.starttls = False
                    logger.warning("STARTTLS NOT supported on %s", mx.host)

                sock.sendall(b"QUIT\r\n")
                sock.close()
            except socket.timeout:
                logger.warning("STARTTLS check timeout for %s", mx.host)
                mx.starttls = None
                mx.starttls_note = "Connection timeout (server may be tarpitting)"
            except ConnectionRefusedError:
                logger.warning("Port 25 connection refused on %s", mx.host)
                mx.starttls = None
                mx.starttls_note = "Port 25 refused"
            except OSError as e:
                logger.warning("STARTTLS check error for %s: %s", mx.host, e)
                mx.starttls = None
                mx.starttls_note = str(e)
            except Exception as e:
                logger.error("Unexpected STARTTLS error for %s: %s", mx.host, e)
                mx.starttls = None
                mx.starttls_note = str(e)

        # Three-state aggregation:
        #   True  — all checked hosts advertise STARTTLS
        #   False — at least one host definitively does NOT support STARTTLS
        #   None  — could not determine (all were timeouts/errors, or no records)
        checked = [mx for mx in self.records if not mx.is_null_mx]
        if not checked:
            self.all_starttls = None
        elif any(mx.starttls is False for mx in checked):
            self.all_starttls = False
        elif all(mx.starttls is True for mx in checked):
            self.all_starttls = True
        else:
            self.all_starttls = None

    def _check_ptr(self):
        """Check reverse DNS (PTR) and FCrDNS for each MX host.

        Uses dns.resolver + dns.reversename instead of socket.gethostbyaddr,
        which supports both IPv4 and IPv6 and has proper timeout control.
        """
        resolver = self._make_resolver(timeout=5)
        all_ptr = True
        for mx in self.records:
            if mx.is_null_mx:
                mx.ptr_record = None
                mx.fcrdns = None
                continue
            if not mx.ip_address:
                ip_address, _ = _resolve_host_ip(mx.host, resolver)
                if not ip_address:
                    mx.ptr_record = None
                    all_ptr = False
                    continue
                mx.ip_address = ip_address

            # Reverse DNS lookup
            ptr_hostname = _resolve_ptr(mx.ip_address, resolver)
            if ptr_hostname:
                mx.ptr_record = ptr_hostname
                logger.debug("PTR for %s (%s): %s", mx.host, mx.ip_address, mx.ptr_record)

                # Forward-Confirmed reverse DNS (FCrDNS) check
                fwd_ip, _ = _resolve_host_ip(ptr_hostname, resolver)
                mx.fcrdns = (fwd_ip == mx.ip_address) if fwd_ip else False
                if not mx.fcrdns:
                    logger.debug(
                        "FCrDNS failed for %s: %s resolved to %s instead of %s",
                        mx.host, mx.ptr_record, fwd_ip, mx.ip_address,
                    )
            else:
                logger.debug("No PTR for %s (%s)", mx.host, mx.ip_address)
                mx.ptr_record = None
                mx.fcrdns = False
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
            "MX_HAS_NULL_MX": self.has_null_mx,
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
