# SpoofyVibe Architecture

> **Read this file before making any code changes.**
> It defines the invariants, vocabulary, and patterns that every module must follow.

## Project Overview

SpoofyVibe is an email security posture analysis tool. It scans domains for
SPF, DMARC, DKIM, BIMI, MX, MTA-STS, DNSSEC, DANE, and CAA configurations,
produces a weighted security score, and generates remediation advice.

The tool runs in two modes:
- **CLI**: `python spoofy.py -d example.com` (single domain) or `-iL domains.txt`
- **Web Dashboard**: `python spoofy.py --serve` (FastAPI + static HTML dashboard)

---

## Module Layout

```
spoofy.py                 # CLI entrypoint + async orchestrator
api/
  app.py                  # FastAPI web server + REST API
modules/
  __init__.py             # Package marker
  schema.py               # Canonical field names, status enums, result contract
  dns_utils.py            # Centralized IDNA encoding + resolver utilities
  txt_utils.py            # TXT record parsing (multi-string join, tag=value)
  dns.py                  # Authoritative NS discovery (SOA → mname)
  spf.py                  # SPF record analysis
  dmarc.py                # DMARC record analysis
  dkim.py                 # DKIM selector enumeration
  bimi.py                 # BIMI record analysis
  mx.py                   # MX infrastructure analysis
  mta_sts.py              # MTA-STS + TLS-RPT analysis
  dnssec.py               # DNSSEC chain-of-trust validation
  dane.py                 # DANE/TLSA record checking
  caa.py                  # CAA tree-walk analysis
  m365.py                 # Microsoft 365 tenant discovery
  spoofing.py             # Spoofability verdict engine
  scoring.py              # Weighted security scoring engine
  remediation.py          # Remediation recommendation generator
  syntax.py               # Loose syntax validators (fallback only)
  report.py               # stdout/CSV/Excel/JSON/Markdown output
  html_report.py          # Self-contained HTML report
  pdf_report.py           # PDF executive report
  subdomain.py            # Certificate Transparency subdomain finder
  history.py              # SQLite scan history
tests/
  test_*.py               # Unit tests per module
```

---

## Invariants

These are the rules that MUST be followed across all modules.

### 1. Canonical Vocabulary

Every concept has ONE name across the entire codebase. See `modules/schema.py`
for the canonical field constants. Key examples:

| Concept | Canonical Name | NEVER use |
|---------|---------------|-----------|
| SPF terminal mechanism | `SPF_ALL` | `SPF_MULTIPLE_ALLS`, `spf_all`, `all_mechanism` |
| SPF DNS lookup count | `SPF_DNS_QUERY_COUNT` | `SPF_NUM_DNS_QUERIES`, `spf_dns_queries` |
| DMARC effective policy | `DMARC_EFFECTIVE_POLICY` | `effective_p`, `effective_policy` |

When a module attribute differs from the result dict key (e.g. `spf.all_mechanism`
vs dict key `SPF_ALL`), the mapping happens ONCE in `spoofy.py`'s `process_domain()`.

### 2. Two-Resolver Architecture

The project uses two classes of DNS resolvers:

- **Authoritative (auth_server)**: The domain's own NS, discovered via SOA mname.
  Used for queries within the target domain's zone (SPF, DMARC, BIMI, MX, MTA-STS TXT).

- **Recursive (1.1.1.1 / 8.8.8.8)**: Public recursive resolvers.
  Used for cross-zone queries (DANE TLSA on third-party MX hosts, M365 tenant
  domains, DS records in parent zones, include/redirect targets in SPF).

**Rule**: Use `dns_utils.make_auth_resolver()` for same-zone queries and
`dns_utils.make_recursive_resolver()` for cross-zone queries. When in doubt
about zone boundaries, use `dns_utils.smart_resolve()`.

### 3. TXT Record Parsing

**NEVER** use `str(rdata).replace('"', '')` to read a TXT record.
**ALWAYS** use `txt_utils.parse_txt_record(rdata)` — it joins multi-string
records safely without injecting spaces at the 255-byte boundary.

**NEVER** use `record.split("p=")` or `.find("p=")` to extract tag values.
**ALWAYS** use `txt_utils.parse_tag_value(record)` — it uses `str.partition("=")`
on each semicolon-delimited token to avoid substring collisions.

### 4. IDNA Encoding

**ALWAYS** use `dns_utils.encode_idna(domain)` for internationalized domains.
It encodes per-label (handles dotted domains correctly), always returns a string
(never `None`), and logs a warning on failure.

### 5. Result Dict Contract

Every scan module exposes a `to_dict()` method returning a flat dict. The
orchestrator (`spoofy.py`) merges these into a single result dict. The canonical
keys are defined in `modules/schema.py`.

### 6. Status Semantics

Use `ScanStatus` enum values (from `schema.py`) when reporting record status:
- `OK` — record found and valid
- `NOT_FOUND` — no record published
- `PERMERROR` — record exists but is invalid (multiple records, bad syntax)
- `TEMPERROR` — transient DNS failure
- `ERROR` — unexpected error

### 7. No Network I/O in Constructors (for new modules)

New modules should separate construction from network I/O:
- Constructor initializes state only
- A `fetch()` or `check()` method performs I/O
- An `evaluate()` method performs deterministic logic

Existing modules are grandfathered but should migrate over time.

### 8. Scoring Engine is the Single Source of Truth

Report generators (HTML, PDF, CSV) MUST iterate over `SCORE_BREAKDOWN` and
`SCORE_DETAILS` from the scoring engine. They MUST NOT maintain hardcoded
category lists or re-implement scoring logic.

### 9. Import Convention

- Modules within the `modules/` package use relative imports:
  `from .txt_utils import parse_txt_record`
- External consumers (`spoofy.py`, `api/app.py`) use absolute imports:
  `from modules.spf import SPF`

---

## Data Flow

```
                    ┌─────────────┐
                    │  spoofy.py  │  Orchestrator
                    │ (async loop)│
                    └──────┬──────┘
                           │
              ┌────────────┼────────────────┐
              │            │                │
         ┌────▼────┐  ┌────▼────┐    ┌──────▼──────┐
         │  DNS()  │  │  SPF()  │    │  DMARC()    │  ... (per module)
         │ auth NS │  │ records │    │  records    │
         └────┬────┘  └────┬────┘    └──────┬──────┘
              │            │                │
              ▼            ▼                ▼
         ┌────────────────────────────────────┐
         │         result = { ... }           │  Merged dict
         │  (canonical keys from schema.py)   │
         └──────────────────┬─────────────────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
         ┌────▼─────┐ ┌────▼─────┐ ┌─────▼──────┐
         │Spoofing()│ │ Score()  │ │Remediation│
         │ verdict  │ │ weighted │ │  advice    │
         └──────────┘ └──────────┘ └────────────┘
                            │
                            ▼
              ┌─────────────────────────┐
              │  Report Renderers       │
              │  (stdout/HTML/PDF/CSV)  │
              │  iterate SCORE_BREAKDOWN│
              └─────────────────────────┘
```

---

## Adding a New Scoring Category

1. Create the module in `modules/` with a `to_dict()` method.
2. Add result dict keys to `modules/schema.py` (both constants and RESULT_SCHEMA).
3. Add the scoring method to `scoring.py` (return score, max, details).
4. Add display name to `CATEGORY_DISPLAY_NAMES` in `schema.py`.
5. The HTML/PDF renderers will pick it up automatically via `SCORE_BREAKDOWN`.
6. Update tests.
