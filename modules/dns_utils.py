# modules/dns_utils.py

"""
Centralized DNS utility functions for SpoofyVibe.

Eliminates duplicated code across modules:
  1. IDNA encoding — 6 modules had their own _encode_idna() with varying
     fallback behavior. This module provides one canonical implementation.
  2. Resolver construction — modules duplicated resolver setup with
     inconsistent timeout and nameserver configuration.

Usage:
    from .dns_utils import encode_idna, make_recursive_resolver, make_auth_resolver

    # IDNA encoding for internationalized domains
    qname = encode_idna("münchen.de")  # → "xn--mnchen-3ya.de"

    # Create resolvers
    auth = make_auth_resolver("ns1.example.com")
    recursive = make_recursive_resolver()
"""

import logging
import dns.resolver

logger = logging.getLogger("spoofyvibe.dns_utils")


def encode_idna(domain):
    """Encode a domain name to IDNA A-label form (Punycode).

    Encodes each label independently to handle dotted domain names
    correctly (e.g. "münchen.de" → "xn--mnchen-3ya.de").

    Per RFC 5891, internationalized domain names must be converted
    to A-label form before DNS queries.

    Always returns a string (never None). On encoding failure, returns
    the original domain unchanged and logs a warning.

    Args:
        domain: Domain name string, possibly containing Unicode characters.

    Returns:
        The IDNA-encoded domain name as a string.
    """
    if not domain:
        return domain

    try:
        # Encode per-label to handle dotted domains correctly.
        # "münchen.de" → encode "münchen" and "de" separately.
        labels = domain.split(".")
        encoded_labels = []
        for label in labels:
            if not label:
                encoded_labels.append(label)
                continue
            try:
                encoded_labels.append(label.encode("idna").decode("ascii"))
            except (UnicodeError, UnicodeDecodeError):
                # Label contains characters that can't be IDNA-encoded
                # (e.g. invalid Unicode). Keep original label.
                encoded_labels.append(label)
        return ".".join(encoded_labels)
    except Exception as e:
        logger.warning("Failed to IDNA encode '%s': %s — using original", domain, e)
        return domain


def make_recursive_resolver(timeout=5):
    """Create a DNS resolver using public recursive resolvers.

    Used for cross-zone queries (DANE TLSA on third-party MX hosts,
    M365 tenant domains, DS records in parent zones, SPF include/redirect
    targets).

    Args:
        timeout: Query timeout in seconds (default: 5).

    Returns:
        A configured dns.resolver.Resolver instance.
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def make_auth_resolver(auth_server, timeout=5):
    """Create a DNS resolver using an authoritative nameserver.

    Used for same-zone queries (SPF, DMARC, BIMI, MX, MTA-STS TXT).
    Falls back to public recursive resolvers if auth_server is None.

    Args:
        auth_server: IP address of the authoritative NS, or None.
        timeout: Query timeout in seconds (default: 5).

    Returns:
        A configured dns.resolver.Resolver instance.
    """
    resolver = dns.resolver.Resolver()
    if auth_server:
        resolver.nameservers = [auth_server]
    else:
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver
