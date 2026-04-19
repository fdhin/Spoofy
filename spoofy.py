#! /usr/bin/env python3

# spoofy.py
import argparse
import asyncio
import logging
from modules.dns import DNS
from modules.spf import SPF
from modules.dmarc import DMARC
from modules.dkim import DKIM
from modules.bimi import BIMI
from modules.mx import MX
from modules.mta_sts import MTASTS
from modules.dnssec import DNSSEC
from modules.m365 import M365Tenant
from modules.caa import CAA
from modules.dane import DANE
from modules.spoofing import Spoofing
from modules.scoring import SecurityScore
from modules.remediation import RemediationEngine
from modules import report
from modules.html_report import generate_html_report
from modules.pdf_report import generate_pdf_report


async def process_domain(domain, enable_dkim=False, enable_remediation=True,
                          check_starttls=True):
    """Process a domain to gather DNS, SPF, DMARC, BIMI, MX, and MTA-STS records.

    Runs DNS-heavy operations in a thread pool to avoid blocking the event loop.
    """
    loop = asyncio.get_event_loop()

    # Run core DNS lookups concurrently in thread pool
    dns_info = await loop.run_in_executor(None, DNS, domain)

    # Two-resolver architecture:
    #   auth_server = authoritative NS for the target domain's zone.
    #                 Used for same-zone queries (SPF, DMARC, BIMI, MX, CAA, etc.)
    #   Cross-zone modules (DANE, M365) receive None so they use their
    #   internal recursive resolver default. Authoritative NSes only answer
    #   for their own zone — querying TLSA on a third-party MX host or
    #   .onmicrosoft.com via the domain's auth NS produces false negatives.
    auth_server = dns_info.dns_server

    # Run same-zone lookups concurrently
    spf_future = loop.run_in_executor(None, SPF, domain, auth_server)
    dmarc_future = loop.run_in_executor(None, DMARC, domain, auth_server)
    bimi_future = loop.run_in_executor(None, BIMI, domain, auth_server)
    mx_future = loop.run_in_executor(None, lambda: MX(domain, auth_server, check_starttls=check_starttls))
    mta_sts_future = loop.run_in_executor(None, MTASTS, domain, auth_server)
    dnssec_future = loop.run_in_executor(None, DNSSEC, domain, auth_server)
    caa_future = loop.run_in_executor(None, CAA, domain, auth_server)

    spf, dmarc, bimi_info, mx_info, mta_sts, dnssec_info, caa_info = await asyncio.gather(
        spf_future, dmarc_future, bimi_future, mx_future, mta_sts_future, dnssec_future, caa_future
    )

    # M365 tenant detection — cross-zone (queries .onmicrosoft.com),
    # so uses recursive resolver (None → module defaults to 1.1.1.1)
    m365_info = await loop.run_in_executor(
        None, lambda: M365Tenant(domain, mx_info.to_dict().get("MX_RECORDS", []))
    )

    # DKIM can be slow (API + DNS brute-force), run if enabled
    dkim_data = {}
    if enable_dkim:
        dkim = await loop.run_in_executor(None, DKIM, domain, auth_server)
        dkim_data = dkim.to_dict()
        dkim_data["DKIM_SCANNED"] = True
    else:
        dkim_data = {"DKIM": None, "DKIM_SELECTORS": [], "DKIM_SELECTOR_COUNT": 0,
                     "DKIM_HAS_WEAK_KEYS": False, "DKIM_SCANNED": False}

    # Validate MX hosts against MTA-STS policy
    mta_sts_mx_mismatch = mta_sts.validate_mx_against_policy(mx_info.get_mx_hosts())

    spoofing_info = Spoofing(
        domain,
        dmarc.dmarc_record,
        dmarc.effective_policy,
        dmarc.aspf,
        spf.spf_record,
        spf.all_mechanism,
        spf.spf_dns_query_count,
        dmarc.sp,
        dmarc.pct,
    )

    result = {
        "DOMAIN": domain,
        "DOMAIN_TYPE": spoofing_info.domain_type,
        "DNS_SERVER": dns_info.dns_server,
        "SPF": spf.spf_record,
        "SPF_MULTIPLE_ALLS": spf.all_mechanism,
        "SPF_NUM_DNS_QUERIES": spf.spf_dns_query_count,
        "SPF_TOO_MANY_DNS_QUERIES": spf.too_many_dns_queries,
        "DMARC": dmarc.dmarc_record,
        "DMARC_POLICY": dmarc.policy,
        "DMARC_EFFECTIVE_POLICY": dmarc.effective_policy,
        "DMARC_ORG_DOMAIN_FALLBACK": dmarc.is_org_domain_fallback,
        "DMARC_PCT": dmarc.pct,
        "DMARC_ASPF": dmarc.aspf,
        "DMARC_SP": dmarc.sp,
        "DMARC_FO": dmarc.fo,
        "DMARC_FORENSIC_REPORT": dmarc.ruf,
        "DMARC_AGGREGATE_REPORT": dmarc.rua,
        "BIMI_RECORD": bimi_info.bimi_record,
        "BIMI_VERSION": bimi_info.version,
        "BIMI_LOCATION": bimi_info.location,
        "BIMI_AUTHORITY": bimi_info.authority,
        "SPOOFING_POSSIBLE": spoofing_info.spoofing_possible,
        "SPOOFING_TYPE": spoofing_info.spoofing_type,
        "SPF_MACROS": spf.spf_macros,
        "DMARC_HAS_WILDCARD_DNS": dmarc.has_wildcard_dns,
    }

    # Add DKIM data
    result.update(dkim_data)

    # Add MX data
    result.update(mx_info.to_dict())
    result["STARTTLS_SCANNED"] = check_starttls

    # Add MTA-STS data
    result.update(mta_sts.to_dict())
    result["MTA_STS_MX_MISMATCH"] = mta_sts_mx_mismatch

    # Add DNSSEC data
    result.update(dnssec_info.to_dict())

    # Add CAA data
    result.update(caa_info.to_dict())

    # Add M365 data
    result.update(m365_info.to_dict())

    # DANE/TLSA check — cross-zone (queries _25._tcp.<third-party MX host>),
    # so uses recursive resolver (None → module defaults to 1.1.1.1)
    dane_info = await loop.run_in_executor(
        None, lambda: DANE(domain, mx_info.get_mx_hosts())
    )
    result.update(dane_info.to_dict())

    # Calculate security score
    score = SecurityScore(result)
    result.update(score.to_dict())

    # Generate remediation advice
    if enable_remediation:
        engine = RemediationEngine(result)
        result["RECOMMENDATIONS"] = engine.to_list()
    else:
        result["RECOMMENDATIONS"] = []

    return result


async def process_domains(domains, output, enable_dkim=False,
                           enable_remediation=True, concurrency=10,
                           check_starttls=True):
    """Process multiple domains with controlled concurrency using asyncio."""
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async def process_with_semaphore(domain):
        async with semaphore:
            return await process_domain(
                domain,
                enable_dkim=enable_dkim,
                enable_remediation=enable_remediation,
                check_starttls=check_starttls,
            )

    if output == "stdout":
        # For stdout, print results as they complete
        for domain in domains:
            result = await process_with_semaphore(domain)
            report.printer(**result)
    else:
        # For file outputs, gather all results
        tasks = [process_with_semaphore(d) for d in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        # Replace exceptions with stub error results so failed domains
        # appear in the output instead of silently disappearing.
        clean_results = []
        failed_count = 0
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                logging.error("Failed to process %s: %s", domains[i], r)
                clean_results.append({
                    "DOMAIN": domains[i],
                    "SCAN_ERROR": str(r),
                    "SECURITY_SCORE": 0,
                    "SECURITY_GRADE": "F",
                })
                failed_count += 1
            else:
                clean_results.append(r)
        if failed_count:
            logging.warning("%d domain(s) failed to scan", failed_count)
        results = clean_results

    return results


def main():
    parser = argparse.ArgumentParser(
        description="SpoofyVibe — Email Security Posture Analysis. "
        "Process domains to gather DNS, SPF, DMARC, DKIM, BIMI, MX, and MTA-STS records, "
        "calculate security scores, and generate remediation advice."
    )

    # --- Mode selection ---
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Launch the web dashboard and REST API server",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for the web server (default: 8080, used with --serve)",
    )

    # --- Domain selection (not required if --serve) ---
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-d", type=str, help="Single domain to process.")
    group.add_argument(
        "-iL", type=str, help="File containing a list of domains to process."
    )
    parser.add_argument(
        "-o",
        type=str,
        choices=["stdout", "xls", "json", "html", "pdf", "csv", "md"],
        default="stdout",
        help="Output format: stdout, xls, json, html, csv, or md (default: stdout).",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=10,
        help="Maximum concurrent domain scans (default: 10)",
    )
    parser.add_argument(
        "--dkim", action="store_true", help="Enable DKIM selector enumeration (API + DNS brute-force)"
    )
    parser.add_argument(
        "--no-remediation",
        action="store_true",
        help="Disable remediation advice generation",
    )
    parser.add_argument(
        "--no-starttls",
        action="store_true",
        help="Skip STARTTLS checks on MX hosts (faster, no port 25 connections)",
    )
    parser.add_argument(
        "--subdomains",
        action="store_true",
        help="Discover subdomains via Certificate Transparency and include them in scan",
    )
    parser.add_argument(
        "--save-history",
        action="store_true",
        help="Save scan results to local SQLite history database",
    )
    parser.add_argument(
        "--expand-tenant",
        action="store_true",
        help="If M365 tenant domains are discovered, add them to the scan scope",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose/debug logging output",
    )

    args = parser.parse_args()

    # Configure logging — use the spoofyvibe logger specifically,
    # not basicConfig, to avoid stomping global logging configuration
    # when imported as a library (e.g. --serve mode with FastAPI).
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    spoofyvibe_logger = logging.getLogger("spoofyvibe")
    spoofyvibe_logger.setLevel(log_level)
    if not spoofyvibe_logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(log_level)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%H:%M:%S",
        ))
        spoofyvibe_logger.addHandler(handler)

    # --- Web server mode ---
    if args.serve:
        try:
            import uvicorn
            from api.app import app as web_app
        except ImportError:
            print("Error: FastAPI and uvicorn are required for --serve mode.")
            print("Install with: pip install fastapi uvicorn[standard]")
            return

        print(f"\n🛡️  SpoofyVibe Web Dashboard")
        print(f"   http://localhost:{args.port}")
        print(f"   API docs: http://localhost:{args.port}/docs\n")
        uvicorn.run(web_app, host="0.0.0.0", port=args.port, log_level="info")
        return

    # --- CLI scan mode (requires -d or -iL) ---
    if not args.d and not args.iL:
        parser.error("CLI mode requires -d or -iL (or use --serve for web mode)")

    enable_remediation = not args.no_remediation
    check_starttls = not args.no_starttls

    if args.d:
        domains = [args.d]
    elif args.iL:
        with open(args.iL, "r") as file:
            domains = [line.strip() for line in file if line.strip()]

    # Discover subdomains if requested
    if args.subdomains:
        from modules.subdomain import SubdomainFinder
        all_domains = []
        for domain in domains:
            finder = SubdomainFinder(domain)
            subs = finder.discover()
            print(f"[*] Discovered {len(subs)} subdomains for {domain}")
            all_domains.extend(subs)
        domains = list(dict.fromkeys(all_domains))  # deduplicate, preserve order

    results = asyncio.run(
        process_domains(
            domains,
            args.o,
            enable_dkim=args.dkim,
            enable_remediation=enable_remediation,
            concurrency=args.concurrency,
            check_starttls=check_starttls,
        )
    )

    # Expand M365 tenant domains if requested
    if args.expand_tenant and results:
        tenant_domains = []
        existing = set(d.lower() for d in domains)
        for r in results:
            for td in r.get("M365_TENANT_DOMAINS", []):
                if td.lower() not in existing:
                    tenant_domains.append(td)
                    existing.add(td.lower())
                    print(f"[*] Microsoft tenant domain discovered: {td}")
        if tenant_domains:
            tenant_results = asyncio.run(
                process_domains(
                    tenant_domains,
                    args.o,
                    enable_dkim=args.dkim,
                    enable_remediation=enable_remediation,
                    concurrency=args.concurrency,
                    check_starttls=check_starttls,
                )
            )
            results.extend(tenant_results)

    # Save to history if requested
    if args.save_history and results:
        from modules.history import ScanHistory
        history = ScanHistory()
        history.save_bulk(results)
        print(f"[*] Saved {len(results)} scan results to history")

    if args.o == "xls" and results:
        report.write_to_excel(results)
        print("Results written to output.xlsx")
    elif args.o == "json" and results:
        report.output_json(results)
    elif args.o == "html" and results:
        fname = generate_html_report(results)
        print(f"HTML report written to {fname}")
    elif args.o == "pdf" and results:
        fname = generate_pdf_report(results)
        print(f"PDF report written to {fname}")
    elif args.o == "csv" and results:
        report.write_to_csv(results)
        print("Results written to output.csv")
    elif args.o == "md" and results:
        report.write_to_markdown(results)
        print("Results written to output.md")


if __name__ == "__main__":
    main()
