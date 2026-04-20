# modules/syntax.py

"""
Loose DNS record syntax validators.

These validators are used ONLY as a fallback in spoofing.py's exception
handler. They're intentionally permissive: they accept all valid real-world
records and only reject records that are structurally unparseable.

These are NOT strict RFC validators — the actual parsing is done by the
dedicated SPF/DMARC modules. These exist purely to classify records as
"probably valid" vs "structurally broken" when the main evaluation throws.
"""

import re


# SPF qualifiers per RFC 7208 §4.6.2
_SPF_QUALIFIERS = set("+-~?")

# SPF mechanisms per RFC 7208 §5
_SPF_MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}

# SPF modifiers per RFC 7208 §6
_SPF_MODIFIERS = {"redirect", "exp"}


def validate_record_syntax(record, record_type):
    """Validate the syntax of a DNS record (SPF or DMARC).

    Returns True if the record appears structurally valid, False if it's
    clearly broken. Intentionally loose — accepts all valid real-world
    records including edge cases like qualifier-prefixed mechanisms,
    mailto: URIs in rua/ruf, and compound fo values.
    """
    if not record or not isinstance(record, str):
        return False

    record = record.strip()

    if record_type == "SPF":
        return _validate_spf(record)
    elif record_type == "DMARC":
        return _validate_dmarc(record)
    return False


def _validate_spf(record):
    """Validate SPF record syntax (loose).

    Accepts:
        - Qualifier-prefixed mechanisms: -all, ~all, +include:, ?mx, etc.
        - Bare mechanisms: all, a, mx, include:..., ip4:..., ip6:...
        - Modifiers: redirect=..., exp=...
    """
    elements = record.split()

    if not elements or elements[0] != "v=spf1":
        return False

    for element in elements[1:]:
        element = element.strip()
        if not element:
            continue

        # Strip leading qualifier if present
        bare = element
        if bare and bare[0] in _SPF_QUALIFIERS:
            bare = bare[1:]

        if not bare:
            return False  # Just a qualifier with no mechanism

        # Check for modifier (contains =)
        if "=" in bare and ":" not in bare.split("=", 1)[0]:
            mod_name = bare.split("=", 1)[0].lower()
            if mod_name in _SPF_MODIFIERS:
                continue
            # Unknown modifier — accept gracefully (future extensions)
            continue

        # Check for mechanism
        if ":" in bare:
            mech_name = bare.split(":", 1)[0].lower()
        else:
            mech_name = bare.lower()

        if mech_name in _SPF_MECHANISMS:
            continue

        # Unknown term — reject (likely structurally broken)
        return False

    return True


def _validate_dmarc(record):
    """Validate DMARC record syntax (loose).

    Accepts:
        - mailto: URIs in rua/ruf (RFC 7489 §6.2)
        - Comma-separated rua/ruf lists
        - Compound fo values like 0:1, d:s (RFC 7489 §6.3)
        - Unknown tags (future extensions) — accepted gracefully
    """
    # DMARC records use semicolons as delimiters
    tags = record.split(";")

    if not tags:
        return False

    # First tag must be v=DMARC1
    first = tags[0].strip()
    if not first.startswith("v=DMARC1"):
        return False

    # Known DMARC tags and their loose patterns
    known_tags = {
        "v": r"^DMARC1$",
        "p": r"^(none|quarantine|reject)$",
        "sp": r"^(none|quarantine|reject)$",
        "pct": r"^\d{1,3}$",
        "rua": None,  # Accepts anything (mailto: URIs, comma-separated)
        "ruf": None,  # Same
        "rf": r"^(afrf|iodef)$",
        "fo": r"^[01ds]([:]?[01ds])*$",  # 0, 1, d, s, or combinations like 0:1:d
        "ri": r"^\d+$",
        "aspf": r"^[rs]$",
        "adkim": r"^[rs]$",
    }

    for tag in tags:
        tag = tag.strip()
        if not tag:
            continue

        if "=" not in tag:
            continue  # Tolerate trailing semicolons / empty segments

        key, _, value = tag.partition("=")
        key = key.strip().lower()
        value = value.strip()

        if key in known_tags:
            pattern = known_tags[key]
            if pattern is not None and not re.match(pattern, value, re.IGNORECASE):
                return False
        # Unknown tags: accept gracefully (RFC allows future extensions)

    return True
