# SpoofyVibe — Email Security Report

## example.com — Grade: B- (70/100)

**Spoofability:** ✅ Not Spoofable

| Check | Value |
|-------|-------|
| SPF | `v=spf1 -all` |
| SPF_MULTIPLE_ALLS | `-all` |
| SPF_NUM_DNS_QUERIES | `0` |
| DMARC | `v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s` |
| DMARC_POLICY | `reject` |
| DMARC_PCT | `N/A` |
| DMARC_ASPF | `s` |
| DMARC_SP | `reject` |
| DMARC_AGGREGATE_REPORT | `N/A` |
| DKIM | `N/A` |
| BIMI_RECORD | `N/A` |
| DNS_SERVER | `172.64.35.228` |

### Remediation (3 items)

- **🟡 MEDIUM** [DMARC] No DMARC aggregate reporting (rua) configured
  ```
  Add 'rua=mailto:dmarc-reports@example.com' to your DMARC record.

You can also use a free DMARC report analyzer service like:
  • https://dmarc.postmarkapp.com
  • https://www.dmarcanalyzer.com
  ```
- **🟡 MEDIUM** [DKIM] No DKIM selectors found
  ```
  Configure DKIM signing on your email provider:

  • Microsoft 365: Admin Center → Settings → Domains → Enable DKIM
  • Google Workspace: Admin Console → Apps → Gmail → Authenticate email
  • Custom: Generate a 2048-bit RSA key pair and publish the public key:
    selector._domainkey.example.com.  IN  TXT  "v=DKIM1; k=rsa; p=<public_key>"
  ```
- **ℹ️  INFO** [BIMI] Consider adding a BIMI record for brand visibility
  ```
  default._bimi.example.com.  IN  TXT  "v=BIMI1; l=https://example.com/brand/logo.svg"

Requirements:
  • Logo must be in SVG Tiny Portable/Secure format
  • DMARC policy must be quarantine or reject
  • A Verified Mark Certificate (VMC) is recommended for Gmail
  ```

---
