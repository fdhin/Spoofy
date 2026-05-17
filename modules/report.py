# modules/report.py

import os
import csv
import json
import logging
import pandas as pd
from colorama import init, Fore, Style

# Initialize colorama
init()

logger = logging.getLogger("spoofyvibe.report")


def output_message(symbol, message, level="info"):
    """Generic function to print messages with different colors and symbols based on the level."""
    colors = {
        "good": Fore.GREEN + Style.BRIGHT,
        "warning": Fore.YELLOW + Style.BRIGHT,
        "bad": Fore.RED + Style.BRIGHT,
        "indifferent": Fore.BLUE + Style.BRIGHT,
        "error": Fore.RED + Style.BRIGHT + "!!! ",
        "info": Fore.WHITE + Style.BRIGHT,
    }
    color = colors.get(level, Fore.WHITE + Style.BRIGHT)
    print(color + f"{symbol} {message}" + Style.RESET_ALL)


def write_to_excel(data, file_name="output.xlsx"):
    """Writes a DataFrame of data to an Excel file, appending if the file exists."""
    # Filter out complex nested fields for Excel export
    flat_data = _flatten_results(data)
    if os.path.exists(file_name) and os.path.getsize(file_name) > 0:
        existing_df = pd.read_excel(file_name)
        new_df = pd.DataFrame(flat_data)
        combined_df = pd.concat([existing_df, new_df])
        combined_df.to_excel(file_name, index=False)
    else:
        pd.DataFrame(flat_data).to_excel(file_name, index=False)


def write_to_csv(data, file_name="output.csv"):
    """Writes results to a CSV file."""
    flat_data = _flatten_results(data)
    if not flat_data:
        return

    fieldnames = list(flat_data[0].keys())
    with open(file_name, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flat_data)


def write_to_markdown(data, file_name="output.md"):
    """Writes results to a formatted Markdown file."""
    flat_data = _flatten_results(data)
    if not flat_data:
        return

    lines = ["# SpoofyVibe — Email Security Report\n"]

    for result in data:
        domain = result.get("DOMAIN", "unknown")
        posture = result.get("SECURITY_POSTURE", "?")
        score = result.get("SECURITY_SCORE", 0)
        spoofable = result.get("SPOOFING_POSSIBLE")

        if spoofable is False:
            spoof_str = "✅ Not Spoofable"
        elif spoofable is None:
            spoof_str = "⚠️ Maybe Spoofable"
        else:
            spoof_str = "❌ Spoofable"

        lines.append(f"## {domain} — Posture: {posture} ({score}/{result.get('SECURITY_SCORE_MAX', 100)})")
        lines.append("")
        lines.append(f"**Spoofability:** {spoof_str}")
        lines.append("")

        # Records table
        lines.append("| Check | Value |")
        lines.append("|-------|-------|")
        for key in ["SPF", "SPF_ALL", "SPF_DNS_QUERY_COUNT",
                     "DMARC", "DMARC_POLICY", "DMARC_PCT", "DMARC_ASPF",
                     "DMARC_SP", "DMARC_AGGREGATE_REPORT", "DMARC_FORENSIC_REPORT",
                     "DKIM", "BIMI_RECORD",
                     "MTA_STS_MODE", "MTA_STS_MAX_AGE", "TLS_RPT_RECORD",
                     "MX_COUNT", "MX_ALL_STARTTLS",
                     "DNSSEC_ENABLED", "DNSSEC_HAS_DS",
                     "DANE_HAS_TLSA",
                     "CAA_HAS_ISSUE", "CAA_HAS_ISSUEWILD",
                     "M365_DETECTED", "M365_TENANT_NAME", "M365_MX_PREFIX",
                     "DNS_SERVER"]:
            val = result.get(key)
            val_str = str(val) if val is not None else "N/A"
            # Escape pipes in values
            val_str = val_str.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {key} | `{val_str}` |")
        lines.append("")

        # Remediation
        recommendations = result.get("RECOMMENDATIONS", [])
        if recommendations:
            lines.append(f"### Remediation ({len(recommendations)} items)")
            lines.append("")
            for rec in recommendations:
                prio = rec.get("priority_label", "")
                title = rec.get("title", "")
                fix = rec.get("fix", "")
                lines.append(f"- **{prio}** [{rec.get('category', '')}] {title}")
                if fix:
                    lines.append(f"  ```")
                    lines.append(f"  {fix}")
                    lines.append(f"  ```")
            lines.append("")

        lines.append("---")
        lines.append("")

    with open(file_name, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def output_json(results):
    """Output results as JSON to stdout."""
    print(json.dumps(results, indent=2, default=str))


def _flatten_results(data):
    """Flatten results for tabular output (remove nested dicts/lists).

    Special handling:
      - SCORE_BREAKDOWN → expanded to Score_SPF, Score_DMARC, etc. columns
      - RECOMMENDATIONS → collapsed to a single newline-delimited summary
      - SCORE_DETAILS → skipped (too verbose for tabular format)
    """
    flat = []
    for result in data:
        row = {}
        for k, v in result.items():
            if k == "SCORE_BREAKDOWN":
                # Expand each scoring category into its own column
                if isinstance(v, dict):
                    for cat_key, cat_data in v.items():
                        label = cat_key.replace("_", " ").title()
                        if isinstance(cat_data, dict):
                            row[f"Score_{label}"] = cat_data.get("score", 0)
                            row[f"Score_{label}_Max"] = cat_data.get("max", 0)
                        else:
                            row[f"Score_{label}"] = cat_data
            elif k == "SCORE_DETAILS":
                continue  # Too verbose for tabular format
            elif k == "RECOMMENDATIONS":
                # Collapse to priority + title summary
                if isinstance(v, list) and v:
                    summaries = []
                    for rec in v:
                        pri = rec.get("priority", 5)
                        title = rec.get("title", "")
                        summaries.append(f"P{pri}: {title}")
                    row["RECOMMENDATIONS"] = "; ".join(summaries)
                else:
                    row["RECOMMENDATIONS"] = ""
            elif isinstance(v, (dict, list)):
                row[k] = str(v)
            else:
                row[k] = v
        flat.append(row)
    return flat


def printer(**kwargs):
    """Utility function to print the results of DMARC, SPF, and BIMI checks."""
    domain = kwargs.get("DOMAIN")
    subdomain = kwargs.get("DOMAIN_TYPE") == "subdomain"
    dns_server = kwargs.get("DNS_SERVER")
    spf_record = kwargs.get("SPF")
    spf_all = kwargs.get("SPF_ALL")
    spf_dns_query_count = kwargs.get("SPF_DNS_QUERY_COUNT")
    dmarc_record = kwargs.get("DMARC")
    p = kwargs.get("DMARC_POLICY")
    pct = kwargs.get("DMARC_PCT")
    aspf = kwargs.get("DMARC_ASPF")
    sp = kwargs.get("DMARC_SP")
    fo = kwargs.get("DMARC_FORENSIC_REPORT")
    rua = kwargs.get("DMARC_AGGREGATE_REPORT")
    dkim_record = kwargs.get("DKIM")
    bimi_record = kwargs.get("BIMI_RECORD")
    vbimi = kwargs.get("BIMI_VERSION")
    location = kwargs.get("BIMI_LOCATION")
    authority = kwargs.get("BIMI_AUTHORITY")
    spoofable = kwargs.get("SPOOFING_POSSIBLE")
    spoofing_type = kwargs.get("SPOOFING_TYPE")
    score = kwargs.get("SECURITY_SCORE")
    posture = kwargs.get("SECURITY_POSTURE")
    recommendations = kwargs.get("RECOMMENDATIONS", [])

    output_message("[*]", f"Domain: {domain}", "indifferent")
    output_message("[*]", f"Is subdomain: {subdomain}", "indifferent")
    output_message("[*]", f"DNS Server: {dns_server}", "indifferent")

    # Security Score
    if score is not None and posture is not None:
        posture_level = "good" if score >= 80 else "warning" if score >= 60 else "bad"
        output_message("[*]", f"Security Score: {score}/100 (Posture: {posture})", posture_level)

    if spf_record:
        output_message("[*]", f"SPF record: {spf_record}", "info")
        if spf_all is None:
            output_message("[*]", "SPF does not contain an `All` item.", "info")
        elif spf_all == "2many":
            output_message(
                "[?]", "SPF record contains multiple `All` items.", "warning"
            )
        else:
            output_message("[*]", f"SPF all record: {spf_all}", "info")
        output_message(
            "[*]",
            f"SPF DNS query count: {spf_dns_query_count}"
            if spf_dns_query_count <= 10
            else f"Too many SPF DNS query lookups {spf_dns_query_count}.",
            "info",
        )
    else:
        output_message("[?]", "No SPF record found.", "warning")

    if dmarc_record:
        output_message("[*]", f"DMARC record: {dmarc_record}", "info")
        output_message(
            "[*]", f"Found DMARC policy: {p}" if p else "No DMARC policy found.", "info"
        )
        output_message(
            "[*]", f"Found DMARC pct: {pct}" if pct is not None else "No DMARC pct found.", "info"
        )
        output_message(
            "[*]",
            f"Found DMARC aspf: {aspf}" if aspf else "No DMARC aspf found.",
            "info",
        )
        output_message(
            "[*]",
            f"Found DMARC subdomain policy: {sp}"
            if sp
            else "No DMARC subdomain policy found.",
            "info",
        )
        output_message(
            "[*]",
            f"Forensics reports will be sent: {fo}"
            if fo
            else "No DMARC forensics report location found.",
            "indifferent",
        )
        output_message(
            "[*]",
            f"Aggregate reports will be sent to: {rua}"
            if rua
            else "No DMARC aggregate report location found.",
            "indifferent",
        )
    else:
        output_message("[?]", "No DMARC record found.", "warning")

    if dkim_record:
        output_message("[*]", f"DKIM selectors: \r\n{dkim_record}", "info")
    else:
        output_message("[?]", f"No known DKIM selectors enumerated on {domain}.", "warning")

    if bimi_record:
        output_message("[*]", f"BIMI record: {bimi_record}", "info")
        output_message("[*]", f"BIMI version: {vbimi}", "info")
        output_message("[*]", f"BIMI location: {location}", "info")
        output_message("[*]", f"BIMI authority: {authority}", "info")

    # MTA-STS / TLS-RPT
    mta_sts_mode = kwargs.get("MTA_STS_MODE")
    tls_rpt = kwargs.get("TLS_RPT_RECORD")
    if mta_sts_mode:
        output_message("[*]", f"MTA-STS mode: {mta_sts_mode}", "info")
    else:
        output_message("[?]", "No MTA-STS policy configured.", "warning")
    if tls_rpt:
        output_message("[*]", f"TLS-RPT: {tls_rpt}", "info")

    # DNSSEC
    dnssec_enabled = kwargs.get("DNSSEC_ENABLED", False)
    dnssec_ds = kwargs.get("DNSSEC_HAS_DS", False)
    if dnssec_enabled:
        ds_str = " (DS verified)" if dnssec_ds else ""
        output_message("[+]", f"DNSSEC enabled{ds_str}", "good")
    else:
        output_message("[?]", "DNSSEC not enabled.", "warning")

    # DANE
    dane_has_tlsa = kwargs.get("DANE_HAS_TLSA", False)
    dane_is_secure = kwargs.get("DANE_IS_SECURE", False)
    if dane_is_secure:
        output_message("[+]", f"DANE: {kwargs.get('DANE_MX_COUNT', 0)}/{kwargs.get('DANE_TOTAL_MX', 0)} MX hosts have secure TLSA records", "good")
    elif dane_has_tlsa:
        if kwargs.get("DANE_HAS_BOGUS_RECORDS", False):
            output_message("[-]", "DANE: TLSA records exist but DNSSEC validation is BOGUS (SERVFAIL)", "bad")
        else:
            output_message("[?]", "DANE: TLSA records found but not DNSSEC-validated (AD flag absent)", "warning")

    # CAA
    caa_records = kwargs.get("CAA_RECORDS", [])
    caa_error = kwargs.get("CAA_ERROR")
    if caa_error:
        output_message("[-]", f"CAA: DNS lookup failed — {caa_error}", "bad")
    elif caa_records:
        has_issue = kwargs.get("CAA_HAS_ISSUE", False)
        has_issuewild = kwargs.get("CAA_HAS_ISSUEWILD", False)
        parts = []
        if has_issue:
            parts.append("issue")
        if has_issuewild:
            parts.append("issuewild")
        tag_summary = ", ".join(parts) if parts else "iodef only"
        output_message("[*]", f"CAA: {len(caa_records)} record(s) ({tag_summary})", "info")
    else:
        output_message("[?]", "No CAA records found.", "warning")

    # MX
    mx_count = kwargs.get("MX_COUNT", 0)
    mx_providers = kwargs.get("MX_PROVIDERS", [])
    if mx_count > 0:
        output_message("[*]", f"MX: {mx_count} record(s) — {', '.join(mx_providers) if mx_providers else 'Unknown'}", "info")

    if spoofing_type:
        if spoofable is True:
            level = "bad"
            symbol = "[-]"
        elif spoofable is False:
            level = "good"
            symbol = "[+]"
        else:
            level = "warning"  # None = mailbox-dependent
            symbol = "[?]"
        output_message(symbol, spoofing_type, level)

    # Remediation summary in stdout
    if recommendations:
        critical = [r for r in recommendations if r.get("priority") in (1, 2)]
        if critical:
            output_message("[!]", f"{len(critical)} critical/high priority findings:", "warning")
            for rec in critical:
                output_message(
                    "   ",
                    f"{rec.get('priority_label', '')} [{rec.get('category', '')}] {rec.get('title', '')}",
                    "warning",
                )

    print()  # Padding
