<h1 align="center">
<br>
🛡️ SpoofyVibe
<br>
<sub>Email Security Posture Analysis Platform</sub>
</h1>

<p align="center">
<a href="https://www.python.org/"><img src="https://forthebadge.com/images/badges/made-with-python.svg"></a>
<a href="https://en.wikipedia.org/wiki/Vibe_coding"><img src="https://forthebadge.com/images/badges/powered-by-electricity.svg"></a>
<a href="https://www.youtube.com/watch?v=kyti25ol438"><img src="https://forthebadge.com/images/badges/it-works-why.svg"></a>
</p>

---

> **⚡ Fork Notice** — SpoofyVibe is a fork of [Spoofy](https://github.com/MattKeeley/Spoofy) by **Matt Keeley** and contributors. The original tool is an excellent SPF/DMARC spoofability checker with manually tested spoof logic — we owe huge credit to that foundation. SpoofyVibe extends it with scoring, remediation, MTA-STS/MX/DKIM/DNSSEC analysis, M365 tenant discovery, async scanning, a web dashboard, and more. All of this was heavily **vibe coded** with AI assistance. The spaghetti has only gotten spicier. 🍝

---

## What Is SpoofyVibe?

SpoofyVibe is a comprehensive email security posture analysis tool. Where the original Spoofy answers "can this domain be spoofed?", SpoofyVibe answers "how secure is this domain's entire email stack, what's the score, and what should we fix?"

### What's New vs. Original Spoofy

| Feature | Spoofy | SpoofyVibe |
|---------|--------|------------|
| SPF / DMARC analysis | ✅ | ✅ |
| DKIM selector enumeration | API only | API + DNS brute-force (40+ selectors) + key strength analysis |
| Spoofability detection | ✅ | ✅ (same battle-tested logic) |
| BIMI record detection | ✅ | ✅ |
| MTA-STS & TLS-RPT | ❌ | ✅ Full policy fetch + validation |
| MX enumeration | ❌ | ✅ Provider ID, STARTTLS, PTR checks |
| DNSSEC detection | ❌ | ✅ DNSKEY + DS chain-of-trust verification |
| M365 tenant discovery | ❌ | ✅ Tenant name extraction + `.onmicrosoft.com` domain enumeration |
| Security scoring | ❌ | ✅ 0-100 score, A+ to F grades, 8 categories |
| Remediation advice | ❌ | ✅ Prioritized recommendations per domain |
| Interactive HTML report | ❌ | ✅ Glassmorphism dark-themed report |
| Markdown report | ❌ | ✅ |
| Async I/O | Threads | Full `asyncio` with configurable concurrency |
| Web dashboard | ❌ | ✅ FastAPI + SPA dashboard |
| REST API | ❌ | ✅ 7 endpoints |
| Scan history | ❌ | ✅ SQLite with trends + stats |
| Subdomain discovery | ❌ | ✅ Certificate Transparency (crt.sh) |

## Features

### 🏗️ Core Analysis
- **Authoritative DNS lookups** with Cloudflare fallback (inherited from Spoofy)
- **SPF** — Record parsing, `all` mechanism analysis, DNS query counter (10-lookup limit)
- **DMARC** — Policy detection (`none`/`quarantine`/`reject`), subdomain policy, reporting URIs
- **DKIM** — API lookup + DNS brute-force across 40+ common selectors, RSA key strength analysis (flags weak 1024-bit keys)
- **BIMI** — Brand indicator record and VMC authority detection
- **MTA-STS** — TXT record, HTTPS policy fetch (`enforce`/`testing`/`none`), MX pattern validation
- **TLS-RPT** — Reporting URI detection
- **MX** — Full enumeration, 20+ provider identification (Google, Microsoft, Proofpoint, Mimecast, etc.), STARTTLS support check, reverse DNS (PTR) validation
- **DNSSEC** — DNSKEY record detection, DS record chain-of-trust verification in parent zone
- **M365 Tenant Discovery** — Automatic Microsoft 365 detection from MX records, tenant name extraction, `.onmicrosoft.com` domain enumeration
- **Spoofability** — Real-world tested SPF+DMARC combination logic

### 📊 Intelligence
- **Security Scoring** — 0–100 composite score across 8 weighted categories:
  - SPF (18pts), DMARC (25pts), DKIM (15pts), BIMI (5pts), Spoof Resistance (15pts), MTA-STS (10pts), MX (7pts), DNSSEC (5pts)
- **Letter Grades** — A+ through F with +/- modifiers
- **Remediation Engine** — Prioritized recommendations (Critical → Info) with category tagging
- **Scan History** — SQLite database with trend analysis, per-domain history, aggregate stats
- **Subdomain Discovery** — Certificate Transparency log queries via crt.sh

### 🌐 Web Platform
- **Web Dashboard** — Dark-themed single-page app with scan, history, and subdomain tabs
- **REST API** — FastAPI-powered with auto-generated docs at `/docs`
- **Score Visualizations** — Animated score bars, trend charts, grade badges
- **Remediation Cards** — Color-coded by severity with expandable protocol details
- **Bulk Operations** — Scan up to 50 domains concurrently via API

### 📄 Output Formats
- `stdout` — Color-coded terminal table
- `html` — Interactive dark-themed HTML report with executive summary
- `json` — Machine-readable JSON
- `csv` — Spreadsheet-compatible CSV
- `xls` — Excel workbook via openpyxl
- `md` — Markdown table

## Installation

**Requires Python 3.10+**

```bash
# Clone the repository
git clone https://github.com/fdhin/Spoofy.git SpoofyVibe
cd SpoofyVibe

# Install dependencies
pip3 install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `dnspython` | DNS resolution |
| `tldextract` | Domain parsing |
| `colorama` | Terminal colors |
| `pandas` | Data handling |
| `openpyxl` | Excel export |
| `requests` | HTTP (DKIM API, crt.sh, MTA-STS) |
| `fastapi` | Web API (optional, for `--serve`) |
| `uvicorn` | ASGI server (optional, for `--serve`) |

## Usage

### CLI Mode

```bash
# Scan a single domain
python3 spoofy.py -d example.com

# Scan with DKIM enumeration
python3 spoofy.py -d example.com --dkim

# Scan multiple domains from a file
python3 spoofy.py -iL domains.txt -o html

# Scan with subdomain discovery
python3 spoofy.py -d example.com --subdomains

# Auto-scan M365 tenant domains discovered during scan
python3 spoofy.py -d example.com --expand-tenant

# Save results to history database
python3 spoofy.py -iL domains.txt --save-history

# JSON output with 20 concurrent scans
python3 spoofy.py -iL domains.txt -o json -c 20

# Skip STARTTLS checks (faster, no port 25)
python3 spoofy.py -d example.com --no-starttls

# Verbose debug logging
python3 spoofy.py -d example.com -v
```

### Web Dashboard

```bash
# Launch the web dashboard and API
python3 spoofy.py --serve

# Custom port
python3 spoofy.py --serve --port 9090
```

Then open `http://localhost:8080` in your browser. API docs available at `http://localhost:8080/docs`.

### All CLI Options

```
Options:
    -d              Single domain to process
    -iL             File containing list of domains
    -o              Output: stdout (default), html, json, csv, xls, md
    -c, --concurrency  Max concurrent scans (default: 10)
    --dkim          Enable DKIM selector enumeration
    --no-remediation   Disable remediation advice
    --no-starttls   Skip STARTTLS checks on MX hosts
    --subdomains    Discover subdomains via CT logs before scanning
    --expand-tenant Auto-scan discovered M365 tenant domains
    --save-history  Save results to local SQLite database
    --serve         Launch web dashboard and REST API
    --port          Web server port (default: 8080)
    -v, --verbose   Debug logging
```

### REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/scan/{domain}` | Scan a single domain |
| `POST` | `/api/scan` | Bulk scan (up to 50 domains) |
| `GET` | `/api/history` | List scan history (paginated) |
| `GET` | `/api/history/{domain}` | Domain history + score trend |
| `GET` | `/api/history/detail/{id}` | Full scan detail |
| `GET` | `/api/stats` | Aggregate statistics |
| `GET` | `/api/subdomains/{domain}` | Subdomain discovery |
| `DELETE` | `/api/history/{domain}` | Delete domain history |

## Scoring System

Each domain receives a score out of 100 across 8 categories:

| Category | Max Points | What's Measured |
|----------|-----------|-----------------|
| SPF | 18 | Record exists, valid syntax, `-all`, DNS lookup count |
| DMARC | 25 | Record exists, `p=reject`, subdomain policy, `pct=100`, reporting |
| DKIM | 15 | Selectors found, 2048+ bit keys |
| BIMI | 5 | Record exists, VMC authority |
| Spoof Resistance | 15 | Not spoofable (15), maybe (8), spoofable (0) |
| MTA-STS | 10 | Policy exists, `enforce` mode, TLS-RPT |
| MX | 7 | Records exist, STARTTLS, multiple MX |
| DNSSEC | 5 | DNSKEY records present, DS chain of trust verified |

Grades: **A+** (95+), **A** (90+), **B+** (85+), **B** (80+), **B-** (75+), **C+** (65+), **C** (55+), **C-** (45+), **D+** (35+), **D** (25+), **D-** (15+), **F** (<15)

## Spoofability Logic

SpoofyVibe inherits the battle-tested spoofability table from the original Spoofy project. Every combination of SPF and DMARC configuration was manually tested using [emailspooftest](https://emailspooftest.com/) against Microsoft 365, Gmail, and Protonmail. See the methodology section in the [original project](https://github.com/MattKeeley/Spoofy) and download the [master table](/files/Master_Table.xlsx).

## Project Structure

```
SpoofyVibe/
├── spoofy.py              # Main entry point (CLI + server launcher)
├── api/
│   ├── app.py             # FastAPI REST API
│   └── static/
│       └── index.html     # Web dashboard SPA
├── modules/
│   ├── dns.py             # Authoritative DNS resolution
│   ├── spf.py             # SPF record analysis
│   ├── dmarc.py           # DMARC record analysis
│   ├── dkim.py            # DKIM enumeration + key analysis
│   ├── bimi.py            # BIMI record detection
│   ├── mta_sts.py         # MTA-STS + TLS-RPT analysis
│   ├── mx.py              # MX enumeration + provider ID
│   ├── dnssec.py          # DNSSEC (DNSKEY + DS) detection
│   ├── m365.py            # M365 tenant discovery
│   ├── scoring.py         # Security scoring engine (8 categories)
│   ├── remediation.py     # Remediation advice engine
│   ├── history.py         # SQLite scan history
│   ├── subdomain.py       # crt.sh subdomain discovery
│   ├── html_report.py     # Interactive HTML report generator
│   ├── report.py          # CSV / Excel / JSON / Markdown output
│   └── syntax.py          # SPF/DMARC parsing helpers
├── tests/
│   ├── test_scoring.py    # Scoring engine tests (16)
│   ├── test_remediation.py # Remediation engine tests (18)
│   ├── test_mta_sts.py    # MTA-STS tests (14)
│   ├── test_mx.py         # MX module tests (15)
│   ├── test_dnssec.py     # DNSSEC module tests (14)
│   ├── test_m365.py       # M365 tenant tests (16)
│   ├── test_history.py    # History module tests (22)
│   ├── test_subdomain.py  # Subdomain module tests (14)
│   └── test_spoofy.py     # Original Spoofy logic tests (30)
├── requirements.txt
└── LICENSE
```

## Tests

```bash
# Run all 159 tests
python3 -m unittest discover -s . -p "test*.py" -v
```

## 🍝 Vibe Coded

This project was heavily **vibe coded** — built collaboratively with AI assistance. The original Spoofy foundation is solid human-crafted work by Matt Keeley and contributors. The extensions (scoring, remediation, MTA-STS, MX analysis, DNSSEC, M365 tenant discovery, async rewrite, web dashboard, history, subdomain discovery, the 129 additional tests, and this README) were developed through AI pair programming. The spaghetti code badge from the original repo has never been more appropriate.

## Credits

- **[Spoofy](https://github.com/MattKeeley/Spoofy)** by **Matt Keeley** ([@MattKeeley](https://github.com/MattKeeley)) — the original tool and spoofability logic that made this fork possible
- **[emailspooftest](https://emailspooftest.com/)** — the testing platform used for the original spoofability research
- **[crt.sh](https://crt.sh/)** — Certificate Transparency log search used for subdomain discovery

## Disclaimer

> This tool is only for testing and academic purposes and can only be used where
> strict consent has been given. Do not use it for illegal purposes! It is the
> end user's responsibility to obey all applicable local, state and federal laws.
> Developers assume no liability and are not responsible for any misuse or damage
> caused by this tool and software.

## License

This project is licensed under the Creative Commons Zero v1.0 Universal — see the [LICENSE](LICENSE) file for details.
