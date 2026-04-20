# modules/txt_utils.py

"""
Shared utilities for parsing DNS TXT records.

Eliminates two classes of bugs that recur across modules:
  1. Space injection from str(rdata).replace('"', "") on multi-string TXT records.
     dnspython renders long TXT as "chunk1" "chunk2"; naive quote-stripping
     produces "chunk1 chunk2" with a space injected at the 255-byte boundary.
  2. Tag-substring collisions from split("tag="). For example, split("p=")
     matches the "p=" inside "sp=reject", returning the wrong value.

Usage:
    from .txt_utils import parse_txt_record, parse_tag_value

    # In a DNS query loop:
    for rdata in answer:
        txt = parse_txt_record(rdata)    # safe multi-string join
        tags = parse_tag_value(txt)       # safe tag parser
        policy = tags.get("p")            # no substring collisions
"""


def parse_txt_record(rdata):
    """Join multi-string TXT rdata into a single string without space injection.

    DNS TXT records are split into 255-byte character-strings. dnspython's
    str(rdata) renders these as '"chunk1" "chunk2"'. Stripping quotes naively
    injects a space at the boundary. This function joins the raw byte strings
    directly, avoiding the issue entirely.

    Args:
        rdata: A dns.rdtypes.ANY.TXT.TXT rdata object (has .strings attribute).

    Returns:
        The complete TXT record as a decoded string.
    """
    return b"".join(rdata.strings).decode("utf-8", errors="replace")


def parse_tag_value(record):
    """Parse a semicolon-delimited tag=value record into a dict.

    Handles DMARC, BIMI, DKIM, SPF macro-like, and MTA-STS TXT records
    that follow the common format: "tag1=value1; tag2=value2; ..."

    Uses str.partition("=") on each token to split on the FIRST "=" only,
    avoiding substring collisions (e.g. "sp=" matching inside "aspf=",
    or "p=" matching inside "sp=").

    Per RFC 6376 §3.2 / RFC 7489: "Tags with duplicate names MUST NOT
    occur within a single tag-list; if a tag name does occur more than
    once, the entire tag-list is invalid."

    Args:
        record: The raw TXT record string.

    Returns:
        Dict mapping lowercase tag names to their string values.
        Returns empty dict if record is None, empty, or contains
        duplicate tag names.
    """
    tags = {}
    if not record:
        return tags
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            normalized_key = key.strip().lower()
            if normalized_key in tags:
                # Duplicate tag name — entire record is invalid per RFC
                return {}
            tags[normalized_key] = value.strip()
    return tags
