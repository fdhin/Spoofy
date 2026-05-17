#!/usr/bin/env bash
# Golden Corpus Regression Test
#
# Usage:
#   ./run_golden.sh              # Compare current output to baseline
#   ./run_golden.sh --baseline   # Generate/regenerate baseline

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOMAINS_FILE="$SCRIPT_DIR/domains.txt"
EXPECTED_FILE="$SCRIPT_DIR/expected.json"
CURRENT_FILE="$SCRIPT_DIR/current.json"

# Check domains.txt exists and has content
if [ ! -f "$DOMAINS_FILE" ] || ! grep -q '^[^#]' "$DOMAINS_FILE" 2>/dev/null; then
    echo "ERROR: $DOMAINS_FILE is empty or missing."
    echo "Add domains (one per line) before running the golden corpus test."
    exit 1
fi

echo "=== SpoofyVibe Golden Corpus Test ==="
echo "Scanning domains from: $DOMAINS_FILE"

# Run the scan
cd "$ROOT_DIR"
python3 spoofy.py -iL "$DOMAINS_FILE" -o json > "$CURRENT_FILE" 2>/dev/null

# Extract only scoring fields for comparison (ignore timestamps, etc.)
python3 -c "
import json, sys

with open('$CURRENT_FILE') as f:
    results = json.load(f)

# Extract stable scoring fields only
stable = []
for r in results:
    stable.append({
        'DOMAIN': r.get('DOMAIN'),
        'SECURITY_SCORE': r.get('SECURITY_SCORE'),
        'SECURITY_SCORE_MAX': r.get('SECURITY_SCORE_MAX'),
        'SECURITY_SCORE_PCT': r.get('SECURITY_SCORE_PCT'),
        'SECURITY_POSTURE': r.get('SECURITY_POSTURE'),
        'SPOOFING_POSSIBLE': r.get('SPOOFING_POSSIBLE'),
        'SPOOFING_TYPE': r.get('SPOOFING_TYPE'),
        'SCORE_BREAKDOWN': r.get('SCORE_BREAKDOWN'),
    })

json.dump(stable, sys.stdout, indent=2, sort_keys=True)
print()
" > "${CURRENT_FILE}.scores"

if [ "\${1:-}" = "--baseline" ]; then
    cp "${CURRENT_FILE}.scores" "$EXPECTED_FILE"
    echo ""
    echo "Baseline generated: $EXPECTED_FILE"
    echo "$(python3 -c "import json; print(len(json.load(open('$EXPECTED_FILE'))))")" domains captured.
    exit 0
fi

# Compare
if [ ! -f "$EXPECTED_FILE" ]; then
    echo ""
    echo "ERROR: No baseline found. Run with --baseline first:"
    echo "  ./run_golden.sh --baseline"
    exit 1
fi

if diff -u "$EXPECTED_FILE" "${CURRENT_FILE}.scores" > /dev/null 2>&1; then
    echo ""
    echo "PASS: All scores match the baseline."
    rm -f "$CURRENT_FILE" "${CURRENT_FILE}.scores"
    exit 0
else
    echo ""
    echo "FAIL: Score drift detected!"
    echo ""
    diff -u "$EXPECTED_FILE" "${CURRENT_FILE}.scores" || true
    echo ""
    echo "If this change is intentional, regenerate the baseline:"
    echo "  ./run_golden.sh --baseline"
    rm -f "${CURRENT_FILE}.scores"
    exit 1
fi
