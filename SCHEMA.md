# SpoofyVibe Result Schema

> Canonical reference for all keys in the domain scan result dict.
> See `modules/schema.py` for the programmatic constants.

## Result Dict Keys

### Core

| Key | Type | Source | Default | Description |
|-----|------|--------|---------|-------------|
| `DOMAIN` | str | orchestrator | — | Target domain name |
| `DOMAIN_TYPE` | str | spoofing.py | `"domain"` | `"domain"` or `"subdomain"` |
| `DNS_SERVER` | str | dns.py | `"1.1.1.1"` | Resolver used (auth NS or recursive fallback) |

### SPF

| Key | Type | Source | Default | Description |
|-----|------|--------|---------|-------------|
| `SPF` | str\|None | spf.py | `None` | Raw SPF record text |
| `SPF_ALL` | str\|None | spf.py | `None` | Terminal `all` mechanism (`-all`, `~all`, `?all`, `+all`, `2many`, `None`) |
| `SPF_DNS_QUERY_COUNT` | int | spf.py | `0` | Count of DNS-causing mechanisms |
| `SPF_TOO_MANY_DNS_QUERIES` | bool | spf.py | `False` | True if count > 10 (PermError) |
| `SPF_PERMERROR` | bool | spf.py | `False` | True if multiple SPF records found |
| `SPF_MACROS` | list[str] | spf.py | `[]` | SPF macros used in the record |

### DMARC

| Key | Type | Source | Default | Description |
|-----|------|--------|---------|-------------|
| `DMARC` | str\|None | dmarc.py | `None` | Raw DMARC record text |
| `DMARC_POLICY` | str\|None | dmarc.py | `None` | `p=` tag value (`none`, `quarantine`, `reject`) |
| `DMARC_EFFECTIVE_POLICY` | str\|None | dmarc.py | `None` | Effective policy (considers sp, org-domain fallback) |
| `DMARC_ORG_DOMAIN_FALLBACK` | bool | dmarc.py | `False` | True if record was inherited from org domain |
| `DMARC_PCT` | int\|None | dmarc.py | `100` | Percentage of messages subject to policy |
| `DMARC_ASPF` | str | dmarc.py | `"r"` | SPF alignment mode (`r` or `s`) |
| `DMARC_SP` | str\|None | dmarc.py | `None` | Subdomain policy |
| `DMARC_FO` | str | dmarc.py | `"0"` | Failure reporting options |
| `DMARC_FORENSIC_REPORT` | str\|None | dmarc.py | `None` | `ruf=` URI |
| `DMARC_AGGREGATE_REPORT` | str\|None | dmarc.py | `None` | `rua=` URI |
| `DMARC_HAS_WILDCARD_DNS` | bool | dmarc.py | `False` | Wildcard DNS detected on domain |

### DKIM

| Key | Type | Source | Default | Description |
|-----|------|--------|---------|-------------|
| `DKIM` | str\|None | dkim.py | `None` | DKIM record summary |
| `DKIM_SELECTORS` | list[dict] | dkim.py | `[]` | Per-selector details |
| `DKIM_SELECTOR_COUNT` | int | dkim.py | `0` | Number of selectors found |
| `DKIM_HAS_WEAK_KEYS` | bool | dkim.py | `False` | Any selector has < 2048-bit RSA |
| `DKIM_HAS_REVOKED_KEYS` | bool | dkim.py | `False` | Any selector has empty p= tag |
| `DKIM_HAS_TESTING_KEYS` | bool | dkim.py | `False` | Any selector has t=y flag |
| `DKIM_SCANNED` | bool | orchestrator | `False` | Whether DKIM scan was enabled |

### BIMI

| Key | Type | Source | Default | Description |
|-----|------|--------|---------|-------------|
| `BIMI_RECORD` | str\|None | bimi.py | `None` | Raw BIMI record |
| `BIMI_VERSION` | str\|None | bimi.py | `None` | Version tag |
| `BIMI_LOCATION` | str\|None | bimi.py | `None` | Logo SVG URL |
| `BIMI_AUTHORITY` | str\|None | bimi.py | `None` | VMC certificate URL |

### MX

| Key | Type | Source | Default | Description |
|-----|------|--------|---------|-------------|
| `MX_RECORDS` | list[dict] | mx.py | `[]` | Per-host MX details |
| `MX_COUNT` | int | mx.py | `0` | Number of MX records |
| `MX_PROVIDERS` | list[str] | mx.py | `[]` | Detected mail providers |
| `MX_ALL_STARTTLS` | bool\|None | mx.py | `None` | All hosts support STARTTLS |
| `MX_ALL_PTR` | bool\|None | mx.py | `None` | All hosts have valid PTR |
| `MX_HAS_NULL_MX` | bool | mx.py | `False` | RFC 7505 null MX detected |
| `STARTTLS_SCANNED` | bool | orchestrator | `True` | Whether STARTTLS was checked |

### MTA-STS & TLS-RPT

| Key | Type | Source | Default | Description |
|-----|------|--------|---------|-------------|
| `MTA_STS_TXT` | str\|None | mta_sts.py | `None` | MTA-STS TXT record |
| `MTA_STS_ID` | str\|None | mta_sts.py | `None` | Policy ID |
| `MTA_STS_MODE` | str\|None | mta_sts.py | `None` | `enforce`, `testing`, or `none` |
| `MTA_STS_MAX_AGE` | int\|None | mta_sts.py | `None` | Policy max age in seconds |
| `MTA_STS_MX_PATTERNS` | list[str] | mta_sts.py | `[]` | Allowed MX patterns |
| `MTA_STS_POLICY_RAW` | str\|None | mta_sts.py | `None` | Raw policy file content |
| `MTA_STS_PERMERROR` | bool | mta_sts.py | `False` | Multiple TXT records found |
| `MTA_STS_MX_MISMATCH` | list[str] | orchestrator | `[]` | MX hosts not matching policy |
| `TLS_RPT_RECORD` | str\|None | mta_sts.py | `None` | TLS-RPT TXT record |
| `TLS_RPT_RUA` | str\|None | mta_sts.py | `None` | Reporting URI |
| `TLS_RPT_PERMERROR` | bool | mta_sts.py | `False` | Multiple TLS-RPT records |

### DNSSEC

| Key | Type | Source | Default | Description |
|-----|------|--------|---------|-------------|
| `DNSSEC_ENABLED` | bool | dnssec.py | `False` | DNSKEY + DS both present |
| `DNSSEC_DNSKEY_PRESENT` | bool | dnssec.py | `False` | DNSKEY record exists |
| `DNSSEC_HAS_DS` | bool | dnssec.py | `False` | DS record in parent zone |
| `DNSSEC_AD_FLAG` | bool | dnssec.py | `False` | AD flag validated |
| `DNSSEC_KEY_COUNT` | int | dnssec.py | `0` | Number of zone keys |
| `DNSSEC_DNSKEY_ALGORITHMS` | list[int] | dnssec.py | `[]` | Algorithm numbers |
| `DNSSEC_DS_ALGORITHMS` | list[int] | dnssec.py | `[]` | DS algorithm numbers |
| `DNSSEC_DS_DIGEST_TYPES` | list[int] | dnssec.py | `[]` | DS digest types |
| `DNSSEC_HAS_WEAK_DNSKEY` | bool | dnssec.py | `False` | Deprecated algo in use |
| `DNSSEC_HAS_WEAK_DS` | bool | dnssec.py | `False` | Weak digest type (SHA-1) |

### DANE

| Key | Type | Source | Default | Description |
|-----|------|--------|---------|-------------|
| `DANE_HAS_TLSA` | bool | dane.py | `False` | Real TLSA records found |
| `DANE_IS_SECURE` | bool | dane.py | `False` | Secure TLSA + AD flag |
| `DANE_MX_COUNT` | int | dane.py | `0` | MX hosts with secure TLSA |
| `DANE_TOTAL_MX` | int | dane.py | `0` | Total MX hosts checked |
| `DANE_TLSA_RECORDS` | list[dict] | dane.py | `[]` | Per-host TLSA details |
| `DANE_HAS_BOGUS_RECORDS` | bool | dane.py | `False` | SERVFAIL on TLSA query |
| `DANE_HAS_UNSUPPORTED_RECORDS` | bool | dane.py | `False` | Unusable TLSA params |

### CAA

| Key | Type | Source | Default | Description |
|-----|------|--------|---------|-------------|
| `CAA_RECORDS` | list[dict] | caa.py | `[]` | Parsed CAA records |
| `CAA_HAS_ISSUE` | bool | caa.py | `False` | Has `issue` tag |
| `CAA_HAS_ISSUEWILD` | bool | caa.py | `False` | Has `issuewild` tag |
| `CAA_HAS_IODEF` | bool | caa.py | `False` | Has `iodef` tag |
| `CAA_HAS_CONTACTEMAIL` | bool | caa.py | `False` | Has `contactemail` tag |
| `CAA_HAS_CONTACTPHONE` | bool | caa.py | `False` | Has `contactphone` tag |
| `CAA_HAS_CRITICAL` | bool | caa.py | `False` | Any critical-flagged record |
| `CAA_HAS_UNKNOWN_CRITICAL` | bool | caa.py | `False` | Unknown tag with critical flag |
| `CAA_HAS_RFC8657_EXT` | bool | caa.py | `False` | Account/validation binding |
| `CAA_DENY_ALL_REGULAR` | bool | caa.py | `False` | All issue records deny |
| `CAA_DENY_ALL_WILDCARD` | bool | caa.py | `False` | All issuewild records deny |
| `CAA_EFFECTIVE_DOMAIN` | str\|None | caa.py | `None` | Domain where CAA was found |
| `CAA_ERROR` | str\|None | caa.py | `None` | Fatal DNS error message |
| `CAA_ERROR_DOMAIN` | str\|None | caa.py | `None` | Domain where error occurred |

### Microsoft 365

| Key | Type | Source | Default | Description |
|-----|------|--------|---------|-------------|
| `M365_DETECTED` | bool | m365.py | `False` | M365 MX pattern found |
| `M365_MX_PREFIX` | str\|None | m365.py | `None` | MX hostname prefix |
| `M365_TENANT_NAME` | str\|None | m365.py | `None` | Tenant from DKIM CNAME |
| `M365_TENANT_DOMAINS` | list[str] | m365.py | `[]` | Discovered tenant domains |

### Spoofing

| Key | Type | Source | Default | Description |
|-----|------|--------|---------|-------------|
| `SPOOFING_POSSIBLE` | bool\|None | spoofing.py | `None` | `True`=spoofable, `False`=safe, `None`=maybe |
| `SPOOFING_TYPE` | str | spoofing.py | `""` | Human-readable verdict |

### Scoring

| Key | Type | Source | Default | Description |
|-----|------|--------|---------|-------------|
| `SECURITY_SCORE` | int | scoring.py | `0` | Raw weighted score |
| `SECURITY_SCORE_MAX` | int | scoring.py | `100` | Maximum possible score |
| `SECURITY_SCORE_PCT` | int | scoring.py | `0` | Percentage (score/max * 100) |
| `SECURITY_POSTURE` | str | scoring.py | `"Critical Risk"` | Posture label |
| `SCORE_BREAKDOWN` | dict | scoring.py | `{}` | Per-category {score, max, percentage} |
| `SCORE_DETAILS` | dict | scoring.py | `{}` | Per-category [(icon, text)] |

### Remediation

| Key | Type | Source | Default | Description |
|-----|------|--------|---------|-------------|
| `RECOMMENDATIONS` | list[dict] | remediation.py | `[]` | Prioritized recommendations |
