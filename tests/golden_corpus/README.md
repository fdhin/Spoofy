# Golden Test Corpus

## Purpose

The golden corpus is a regression test that ensures CLI and Dashboard outputs
produce consistent security scores. It captures the output for a fixed set of
domains and detects drift when code changes alter the scoring.

## How it works

1. **domains.txt** — List of domains to scan (one per line). You populate this
   with domains that cover your edge cases.

2. **run_golden.sh** — Runs the scan and compares against `expected.json`.
   - First run: generates `expected.json` (the baseline).
   - Subsequent runs: diffs current output against baseline.

3. **expected.json** — Baseline output (auto-generated on first run).

## Usage

```bash
# First run (generates baseline):
cd tests/golden_corpus
./run_golden.sh --baseline

# Regression check:
./run_golden.sh
```

## Choosing domains

Pick 15-20 domains covering these scenarios:
- Strong protection (p=reject, -all, DKIM, DNSSEC, DANE)
- Weak protection (p=none, ~all, no DKIM)
- Missing records (no SPF, no DMARC)
- Edge cases (multiple SPF records, org-domain fallback, null MX)
- Internationalized domains (IDN / Punycode)
- Known-broken configs (for stable "bad score" baselines)

## Interpreting results

If `run_golden.sh` reports diffs:
- **Intentional** (you changed scoring logic): regenerate baseline with `--baseline`
- **Unintentional**: you've introduced scoring drift — investigate the diff
