# modules/html_report.py

"""
Self-contained HTML report generator for SpoofyVibe.

Generates a single-file HTML report with:
  - Dark-themed modern design (all CSS inline)
  - Executive summary with domain count, average grade, top risks
  - Per-domain cards with grade badge, records, spoofability, remediation
  - Expandable detail sections
  - Sort/filter by grade using vanilla JS
"""

import html
from datetime import datetime


def _grade_color(grade):
    """Return CSS color for a letter grade."""
    colors = {
        "A+": "#00e676",
        "A": "#00e676",
        "A-": "#66bb6a",
        "B+": "#8bc34a",
        "B": "#cddc39",
        "B-": "#ffeb3b",
        "C+": "#ffc107",
        "C": "#ff9800",
        "C-": "#ff7043",
        "D+": "#f44336",
        "D": "#e53935",
        "D-": "#c62828",
        "F": "#b71c1c",
    }
    return colors.get(grade, "#9e9e9e")


def _priority_color(priority):
    """Return CSS color for a priority level."""
    return {
        1: "#f44336",
        2: "#ff9800",
        3: "#ffc107",
        4: "#2196f3",
        5: "#9e9e9e",
    }.get(priority, "#9e9e9e")


def _priority_label(priority):
    """Return label for a priority level."""
    return {
        1: "CRITICAL",
        2: "HIGH",
        3: "MEDIUM",
        4: "LOW",
        5: "INFO",
    }.get(priority, "UNKNOWN")


def _esc(text):
    """HTML-escape text safely."""
    if text is None:
        return '<span class="na">N/A</span>'
    return html.escape(str(text))


def _build_score_bar(score, max_score, label):
    """Build a mini progress bar for a score category."""
    pct = round(score / max_score * 100) if max_score > 0 else 0
    if pct >= 80:
        bar_color = "#00e676"
    elif pct >= 60:
        bar_color = "#ffc107"
    elif pct >= 40:
        bar_color = "#ff9800"
    else:
        bar_color = "#f44336"

    return f"""
    <div class="score-category">
      <div class="score-label">{_esc(label)} <span class="score-pts">{score}/{max_score}</span></div>
      <div class="score-bar-bg">
        <div class="score-bar-fill" style="width:{pct}%; background:{bar_color};"></div>
      </div>
    </div>"""


def _build_detail_items(details):
    """Build HTML for a list of (icon, text) detail items."""
    if not details:
        return ""
    items = []
    for icon, text in details:
        items.append(f'<div class="detail-item">{icon} {_esc(text)}</div>')
    return "\n".join(items)


def _build_remediation_card(rec):
    """Build a remediation recommendation card."""
    prio = rec.get("priority", 5)
    color = _priority_color(prio)
    label = _priority_label(prio)

    return f"""
    <div class="rec-card" style="border-left: 4px solid {color};">
      <div class="rec-header">
        <span class="rec-priority" style="background:{color};">{label}</span>
        <span class="rec-category">{_esc(rec.get('category', ''))}</span>
        <span class="rec-title">{_esc(rec.get('title', ''))}</span>
      </div>
      <div class="rec-body">
        <p><strong>Description:</strong> {_esc(rec.get('description', ''))}</p>
        <p><strong>Impact:</strong> {_esc(rec.get('impact', ''))}</p>
        <details>
          <summary>📋 View Fix</summary>
          <pre class="rec-fix">{_esc(rec.get('fix', ''))}</pre>
          <p class="rec-ref">📖 <a href="{_esc(rec.get('reference', ''))}" target="_blank" rel="noopener">{_esc(rec.get('reference', ''))}</a></p>
        </details>
      </div>
    </div>"""


def _build_domain_card(result):
    """Build a complete domain card."""
    domain = result.get("DOMAIN", "unknown")
    grade = result.get("SECURITY_GRADE", "?")
    score = result.get("SECURITY_SCORE", 0)
    grade_col = _grade_color(grade)
    spoofable = result.get("SPOOFING_POSSIBLE")
    spoof_type = result.get("SPOOFING_TYPE", "")
    breakdown = result.get("SCORE_BREAKDOWN", {})
    details = result.get("SCORE_DETAILS", {})
    recommendations = result.get("RECOMMENDATIONS", [])

    # Spoofability badge
    if spoofable is False:
        spoof_badge = '<span class="badge badge-safe">NOT SPOOFABLE</span>'
    elif spoofable is None:
        spoof_badge = '<span class="badge badge-warn">MAYBE SPOOFABLE</span>'
    else:
        spoof_badge = '<span class="badge badge-danger">SPOOFABLE</span>'

    # Score category bars
    score_bars = ""
    category_labels = {
        "spf": "SPF",
        "dmarc": "DMARC",
        "dkim": "DKIM",
        "bimi": "BIMI",
        "spoofability": "Spoof Resistance",
        "mta_sts": "MTA-STS & TLS-RPT",
        "mx": "MX Infrastructure",
        "dnssec": "DNSSEC",
    }
    for cat_key, cat_label in category_labels.items():
        cat = breakdown.get(cat_key, {})
        score_bars += _build_score_bar(
            cat.get("score", 0), cat.get("max", 1), cat_label
        )

    # Detail sections
    detail_sections = ""
    for cat_key, cat_label in category_labels.items():
        cat_details = details.get(cat_key, [])
        if cat_details:
            detail_sections += f"""
    <details class="record-details">
      <summary>{cat_label} Details</summary>
      <div class="detail-content">
        {_build_detail_items(cat_details)}
      </div>
    </details>"""

    # MX provider display
    mx_providers = result.get('MX_PROVIDERS', [])
    mx_provider_str = ', '.join(mx_providers) if mx_providers else 'N/A'
    mx_count = result.get('MX_COUNT', 0)

    # Records
    records_html = f"""
    <div class="records-grid">
      <div class="record-item">
        <div class="record-label">SPF Record</div>
        <div class="record-value"><code>{_esc(result.get('SPF'))}</code></div>
      </div>
      <div class="record-item">
        <div class="record-label">SPF All Mechanism</div>
        <div class="record-value"><code>{_esc(result.get('SPF_MULTIPLE_ALLS'))}</code></div>
      </div>
      <div class="record-item">
        <div class="record-label">SPF DNS Queries</div>
        <div class="record-value">{_esc(result.get('SPF_NUM_DNS_QUERIES'))} {'⚠️ Over limit!' if result.get('SPF_TOO_MANY_DNS_QUERIES') else ''}</div>
      </div>
      <div class="record-item">
        <div class="record-label">DMARC Record</div>
        <div class="record-value"><code>{_esc(result.get('DMARC'))}</code></div>
      </div>
      <div class="record-item">
        <div class="record-label">DMARC Policy</div>
        <div class="record-value"><code>{_esc(result.get('DMARC_POLICY'))}</code></div>
      </div>
      <div class="record-item">
        <div class="record-label">DMARC % Applied</div>
        <div class="record-value">{_esc(result.get('DMARC_PCT') or '100 (default)')}</div>
      </div>
      <div class="record-item">
        <div class="record-label">DMARC aspf</div>
        <div class="record-value"><code>{_esc(result.get('DMARC_ASPF'))}</code></div>
      </div>
      <div class="record-item">
        <div class="record-label">DMARC Subdomain Policy</div>
        <div class="record-value"><code>{_esc(result.get('DMARC_SP'))}</code></div>
      </div>
      <div class="record-item">
        <div class="record-label">DMARC Aggregate Reports</div>
        <div class="record-value"><code>{_esc(result.get('DMARC_AGGREGATE_REPORT'))}</code></div>
      </div>
      <div class="record-item">
        <div class="record-label">DKIM</div>
        <div class="record-value"><code>{_esc(result.get('DKIM'))}</code></div>
      </div>
      <div class="record-item">
        <div class="record-label">BIMI</div>
        <div class="record-value"><code>{_esc(result.get('BIMI_RECORD'))}</code></div>
      </div>
      <div class="record-item">
        <div class="record-label">MTA-STS Mode</div>
        <div class="record-value"><code>{_esc(result.get('MTA_STS_MODE'))}</code></div>
      </div>
      <div class="record-item">
        <div class="record-label">TLS-RPT</div>
        <div class="record-value"><code>{_esc(result.get('TLS_RPT_RECORD'))}</code></div>
      </div>
      <div class="record-item">
        <div class="record-label">MX Records ({mx_count})</div>
        <div class="record-value">{_esc(mx_provider_str)}</div>
      </div>
      <div class="record-item">
        <div class="record-label">DNSSEC</div>
        <div class="record-value">{'✅ Enabled' if result.get('DNSSEC_ENABLED') else '⚠️ Not enabled'}{' — DS verified' if result.get('DNSSEC_HAS_DS') else ''}</div>
      </div>
      <div class="record-item">
        <div class="record-label">Microsoft 365</div>
        <div class="record-value">{'☁️ Detected — Tenant: ' + _esc(result.get('M365_TENANT_NAME', '')) if result.get('M365_DETECTED') else 'Not detected'}</div>
      </div>
      <div class="record-item">
        <div class="record-label">DANE / TLSA</div>
        <div class="record-value">{'🔐 ' + str(result.get('DANE_MX_COUNT', 0)) + '/' + str(result.get('DANE_TOTAL_MX', 0)) + ' MX hosts have TLSA records' if result.get('DANE_HAS_TLSA') else 'No TLSA records found'}</div>
      </div>
      <div class="record-item">
        <div class="record-label">DNS Server</div>
        <div class="record-value"><code>{_esc(result.get('DNS_SERVER'))}</code></div>
      </div>
    </div>"""

    # Remediation section
    recs_html = ""
    if recommendations:
        rec_cards = "\n".join(_build_remediation_card(r) for r in recommendations)
        recs_html = f"""
    <div class="remediation-section">
      <h3>🩺 Remediation ({len(recommendations)} items)</h3>
      {rec_cards}
    </div>"""
    else:
        recs_html = """
    <div class="remediation-section">
      <h3>🩺 Remediation</h3>
      <p class="all-good">✅ No remediation items — configuration looks solid!</p>
    </div>"""

    return f"""
  <div class="domain-card" data-grade="{grade}" data-score="{score}" data-domain="{_esc(domain)}">
    <div class="card-header">
      <div class="grade-badge" style="background:{grade_col};">{grade}</div>
      <div class="card-title">
        <h2>{_esc(domain)}</h2>
        <div class="card-meta">
          Score: {score}/100 &nbsp;•&nbsp; {spoof_badge}
          &nbsp;•&nbsp; Type: {_esc(result.get('DOMAIN_TYPE', 'domain'))}
        </div>
      </div>
    </div>

    <div class="score-breakdown">
      {score_bars}
    </div>

    {detail_sections}

    <details class="record-details">
      <summary>📝 Raw DNS Records</summary>
      {records_html}
    </details>

    {recs_html}
  </div>"""


def generate_html_report(results, filename="output.html"):
    """
    Generate a self-contained HTML report.

    Args:
        results: list of result dicts (with SECURITY_SCORE, SECURITY_GRADE,
                 SCORE_BREAKDOWN, SCORE_DETAILS, RECOMMENDATIONS keys)
        filename: output file path
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Compute executive summary stats
    total = len(results)
    scores = [r.get("SECURITY_SCORE", 0) for r in results]
    avg_score = round(sum(scores) / total, 1) if total > 0 else 0
    spoofable_count = sum(
        1 for r in results if r.get("SPOOFING_POSSIBLE") is True
    )
    maybe_count = sum(
        1 for r in results if r.get("SPOOFING_POSSIBLE") is None
    )
    safe_count = sum(
        1 for r in results if r.get("SPOOFING_POSSIBLE") is False
    )

    # Grade distribution
    grade_counts = {}
    for r in results:
        g = r.get("SECURITY_GRADE", "?")
        grade_counts[g] = grade_counts.get(g, 0) + 1

    grade_dist_items = ""
    for g in ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F"]:
        count = grade_counts.get(g, 0)
        if count > 0:
            grade_dist_items += f'<span class="grade-pill" style="background:{_grade_color(g)};">{g}: {count}</span> '

    # Total recommendation counts by priority
    all_recs = []
    for r in results:
        all_recs.extend(r.get("RECOMMENDATIONS", []))
    critical_count = sum(1 for r in all_recs if r.get("priority") == 1)
    high_count = sum(1 for r in all_recs if r.get("priority") == 2)

    # Build domain cards
    domain_cards = "\n".join(_build_domain_card(r) for r in results)

    # Compute an overall average grade
    if avg_score >= 95:
        avg_grade = "A+"
    elif avg_score >= 90:
        avg_grade = "A"
    elif avg_score >= 80:
        avg_grade = "B"
    elif avg_score >= 70:
        avg_grade = "C"
    elif avg_score >= 60:
        avg_grade = "D"
    else:
        avg_grade = "F"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SpoofyVibe — Email Security Report</title>
<style>
  :root {{
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-tertiary: #21262d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --text-muted: #6e7681;
    --border: #30363d;
    --accent: #58a6ff;
    --green: #00e676;
    --yellow: #ffc107;
    --red: #f44336;
    --orange: #ff9800;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
  }}

  h1 {{
    font-size: 2rem;
    background: linear-gradient(135deg, #58a6ff, #bc8cff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 0.25rem;
  }}

  .header {{
    text-align: center;
    margin-bottom: 2rem;
    padding-bottom: 1.5rem;
    border-bottom: 1px solid var(--border);
  }}

  .header .subtitle {{
    color: var(--text-secondary);
    font-size: 0.9rem;
  }}

  /* Executive Summary */
  .summary {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }}

  .summary-card {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem;
    text-align: center;
  }}

  .summary-card .big-number {{
    font-size: 2.5rem;
    font-weight: 700;
    line-height: 1.2;
  }}

  .summary-card .label {{
    color: var(--text-secondary);
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}

  .grade-dist {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1rem 1.25rem;
    margin-bottom: 2rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    flex-wrap: wrap;
  }}

  .grade-dist .dist-label {{
    color: var(--text-secondary);
    font-weight: 600;
    font-size: 0.85rem;
    text-transform: uppercase;
    margin-right: 0.5rem;
  }}

  .grade-pill {{
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 6px;
    font-size: 0.8rem;
    font-weight: 700;
    color: #000;
  }}

  /* Controls */
  .controls {{
    display: flex;
    gap: 1rem;
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
    align-items: center;
  }}

  .controls input, .controls select {{
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    color: var(--text-primary);
    padding: 0.5rem 0.75rem;
    border-radius: 8px;
    font-size: 0.9rem;
  }}

  .controls input {{ flex: 1; min-width: 200px; }}
  .controls select {{ min-width: 120px; }}

  /* Domain Card */
  .domain-card {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    transition: border-color 0.2s;
  }}

  .domain-card:hover {{
    border-color: var(--accent);
  }}

  .card-header {{
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1rem;
  }}

  .grade-badge {{
    font-size: 1.5rem;
    font-weight: 800;
    color: #000;
    width: 56px;
    height: 56px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }}

  .card-title h2 {{
    font-size: 1.25rem;
    font-weight: 600;
  }}

  .card-meta {{
    color: var(--text-secondary);
    font-size: 0.85rem;
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.25rem;
  }}

  .badge {{
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
  }}

  .badge-safe {{ background: var(--green); color: #000; }}
  .badge-warn {{ background: var(--yellow); color: #000; }}
  .badge-danger {{ background: var(--red); color: #fff; }}

  /* Score breakdown */
  .score-breakdown {{
    margin-bottom: 1rem;
  }}

  .score-category {{
    margin-bottom: 0.4rem;
  }}

  .score-label {{
    font-size: 0.8rem;
    color: var(--text-secondary);
    margin-bottom: 0.15rem;
  }}

  .score-pts {{
    color: var(--text-muted);
    font-weight: 400;
  }}

  .score-bar-bg {{
    background: var(--bg-tertiary);
    border-radius: 4px;
    height: 6px;
    overflow: hidden;
  }}

  .score-bar-fill {{
    height: 100%;
    border-radius: 4px;
    transition: width 0.5s ease;
  }}

  /* Record details */
  .record-details {{
    margin-top: 0.75rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }}

  .record-details summary {{
    padding: 0.6rem 1rem;
    cursor: pointer;
    background: var(--bg-tertiary);
    font-weight: 500;
    font-size: 0.9rem;
    user-select: none;
  }}

  .record-details summary:hover {{
    background: #2d333b;
  }}

  .detail-content {{
    padding: 0.75rem 1rem;
  }}

  .detail-item {{
    padding: 0.25rem 0;
    font-size: 0.85rem;
  }}

  .records-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 0.5rem;
    padding: 1rem;
  }}

  .record-item {{
    padding: 0.5rem;
    border-radius: 6px;
    background: var(--bg-primary);
  }}

  .record-label {{
    font-size: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.03em;
    margin-bottom: 0.15rem;
  }}

  .record-value {{
    font-size: 0.85rem;
    word-break: break-all;
  }}

  .record-value code {{
    background: var(--bg-tertiary);
    padding: 0.1rem 0.3rem;
    border-radius: 4px;
    font-size: 0.8rem;
  }}

  .na {{
    color: var(--text-muted);
    font-style: italic;
  }}

  /* Remediation */
  .remediation-section {{
    margin-top: 1rem;
  }}

  .remediation-section h3 {{
    font-size: 1rem;
    margin-bottom: 0.75rem;
  }}

  .rec-card {{
    background: var(--bg-primary);
    border-radius: 8px;
    padding: 0.75rem 1rem;
    margin-bottom: 0.5rem;
  }}

  .rec-header {{
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin-bottom: 0.4rem;
  }}

  .rec-priority {{
    font-size: 0.7rem;
    font-weight: 700;
    padding: 0.15rem 0.4rem;
    border-radius: 4px;
    color: #fff;
    text-transform: uppercase;
  }}

  .rec-category {{
    font-size: 0.75rem;
    color: var(--accent);
    font-weight: 600;
  }}

  .rec-title {{
    font-weight: 600;
    font-size: 0.9rem;
  }}

  .rec-body {{
    font-size: 0.85rem;
    color: var(--text-secondary);
  }}

  .rec-body p {{
    margin-bottom: 0.3rem;
  }}

  .rec-fix {{
    background: var(--bg-tertiary);
    padding: 0.75rem;
    border-radius: 6px;
    font-size: 0.8rem;
    white-space: pre-wrap;
    word-break: break-word;
    margin: 0.5rem 0;
    border: 1px solid var(--border);
  }}

  .rec-ref {{
    font-size: 0.8rem;
  }}

  .rec-ref a {{
    color: var(--accent);
    text-decoration: none;
  }}

  .rec-ref a:hover {{
    text-decoration: underline;
  }}

  .all-good {{
    color: var(--green);
    font-weight: 500;
  }}

  /* Footer */
  .footer {{
    text-align: center;
    color: var(--text-muted);
    font-size: 0.8rem;
    margin-top: 2rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
  }}

  .footer a {{
    color: var(--accent);
    text-decoration: none;
  }}

  @media (max-width: 600px) {{
    body {{ padding: 1rem; }}
    .summary {{ grid-template-columns: 1fr 1fr; }}
    .grade-badge {{ width: 44px; height: 44px; font-size: 1.2rem; }}
  }}
</style>
</head>
<body>

<div class="header">
  <h1>🛡️ SpoofyVibe</h1>
  <p class="subtitle">Email Security Posture Report — Generated {now}</p>
</div>

<div class="summary">
  <div class="summary-card">
    <div class="big-number">{total}</div>
    <div class="label">Domains Scanned</div>
  </div>
  <div class="summary-card">
    <div class="big-number" style="color:{_grade_color(avg_grade)};">{avg_grade}</div>
    <div class="label">Average Grade ({avg_score}/100)</div>
  </div>
  <div class="summary-card">
    <div class="big-number" style="color:var(--red);">{spoofable_count}</div>
    <div class="label">Spoofable Domains</div>
  </div>
  <div class="summary-card">
    <div class="big-number" style="color:var(--yellow);">{maybe_count}</div>
    <div class="label">Maybe Spoofable</div>
  </div>
  <div class="summary-card">
    <div class="big-number" style="color:var(--green);">{safe_count}</div>
    <div class="label">Secure Domains</div>
  </div>
  <div class="summary-card">
    <div class="big-number" style="color:var(--red);">{critical_count}</div>
    <div class="label">Critical Findings</div>
  </div>
</div>

<div class="grade-dist">
  <span class="dist-label">Grade Distribution:</span>
  {grade_dist_items if grade_dist_items else '<span style="color:var(--text-muted);">No results</span>'}
</div>

<div class="controls">
  <input type="text" id="searchInput" placeholder="🔍 Search domains..." oninput="filterDomains()">
  <select id="gradeFilter" onchange="filterDomains()">
    <option value="">All Grades</option>
    <option value="A">A+ / A / A-</option>
    <option value="B">B+ / B / B-</option>
    <option value="C">C+ / C / C-</option>
    <option value="D">D+ / D / D-</option>
    <option value="F">F</option>
  </select>
  <select id="sortBy" onchange="sortDomains()">
    <option value="score-asc">Sort: Score ↑ (worst first)</option>
    <option value="score-desc">Sort: Score ↓ (best first)</option>
    <option value="alpha">Sort: A → Z</option>
  </select>
</div>

<div id="domainCards">
{domain_cards}
</div>

<div class="footer">
  <p>Generated by <a href="https://github.com/MattKeeley/Spoofy">SpoofyVibe</a> — Email Security Analysis Tool</p>
  <p>{now}</p>
</div>

<script>
function filterDomains() {{
  const search = document.getElementById('searchInput').value.toLowerCase();
  const gradeFilter = document.getElementById('gradeFilter').value;
  const cards = document.querySelectorAll('.domain-card');

  cards.forEach(card => {{
    const domain = card.dataset.domain.toLowerCase();
    const grade = card.dataset.grade;
    const matchSearch = !search || domain.includes(search);
    const matchGrade = !gradeFilter || grade.startsWith(gradeFilter);
    card.style.display = (matchSearch && matchGrade) ? '' : 'none';
  }});
}}

function sortDomains() {{
  const sortBy = document.getElementById('sortBy').value;
  const container = document.getElementById('domainCards');
  const cards = Array.from(container.querySelectorAll('.domain-card'));

  cards.sort((a, b) => {{
    if (sortBy === 'score-asc') {{
      return parseInt(a.dataset.score) - parseInt(b.dataset.score);
    }} else if (sortBy === 'score-desc') {{
      return parseInt(b.dataset.score) - parseInt(a.dataset.score);
    }} else {{
      return a.dataset.domain.localeCompare(b.dataset.domain);
    }}
  }});

  cards.forEach(card => container.appendChild(card));
}}
</script>

</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)

    return filename
