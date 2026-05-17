# SpoofyVibe Utilities Reference

> Before creating a new parser or utility function, check this list.
> If what you need exists, use it. Don't reinvent it.

## modules/txt_utils.py

| Function | Purpose | Use instead of |
|----------|---------|---------------|
| `parse_txt_record(rdata)` | Joins multi-string TXT rdata into a single string without space injection at the 255-byte boundary. | `str(rdata).replace('"', '')` or `str(rdata)` |
| `parse_tag_value(record)` | Parses semicolon-delimited `tag=value` records into a dict. Uses `str.partition("=")` to split on the FIRST `=` only. Detects duplicate tags and returns `{}` (per RFC 6376 §3.2 / RFC 7489). | `record.split("p=")`, `.find("p=")`, or any custom tag parser |

## modules/dns_utils.py

| Function | Purpose | Use instead of |
|----------|---------|---------------|
| `encode_idna(domain)` | Encodes a domain to IDNA A-label form (Punycode). Per-label encoding handles dotted domains correctly. Always returns a string (never `None`). Logs a warning on failure. | Any inline `domain.encode("idna").decode("ascii")` with varying fallback behavior |
| `make_recursive_resolver(timeout=5)` | Creates a `dns.resolver.Resolver` using public recursive resolvers (1.1.1.1, 8.8.8.8). | Inline `resolver = dns.resolver.Resolver(); resolver.nameservers = [...]` |
| `make_auth_resolver(auth_server, timeout=5)` | Creates a resolver using the provided authoritative NS with recursive fallback. | Inline resolver construction with `if self.dns_server:` pattern |

## modules/schema.py

| Item | Purpose | Use instead of |
|------|---------|---------------|
| `ScanStatus` enum | Standardized status values (`OK`, `NOT_FOUND`, `PERMERROR`, `TEMPERROR`, `ERROR`). | Bare strings like `"MULTIPLE"`, `None`, or boolean flags |
| Key constants (`SPF_ALL`, `DMARC_POLICY`, etc.) | Canonical result dict key names. | Hardcoded string literals that may drift across modules |
| `CATEGORY_DISPLAY_NAMES` | Human-friendly names for scoring categories. | Hardcoded `category_labels` dicts in HTML/PDF report generators |

## modules/syntax.py

| Function | Purpose | When to use |
|----------|---------|-------------|
| `validate_record_syntax(record, type)` | Loose syntax validator for SPF/DMARC records. | **Fallback only** — used by `spoofing.py`'s exception handler. Do NOT use for primary parsing. |
