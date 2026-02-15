# api/app.py

"""
FastAPI application for SpoofyVibe web dashboard and REST API.

Launch with: python3 spoofy.py --serve [--port 8080]
"""

import asyncio
import logging
import os
from typing import Optional

from fastapi import FastAPI, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Import SpoofyVibe modules (parent package)
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from spoofy import process_domain  # noqa: E402
from modules.history import ScanHistory  # noqa: E402
from modules.subdomain import SubdomainFinder  # noqa: E402
from modules.pdf_report import generate_pdf_report  # noqa: E402

logger = logging.getLogger("spoofyvibe.api")

# --- App Setup ---

app = FastAPI(
    title="SpoofyVibe API",
    description="Email Security Posture Analysis",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files (dashboard)
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Initialize history
history = ScanHistory()


# --- Request/Response Models ---

class ScanRequest(BaseModel):
    domains: list[str]
    enable_dkim: bool = False
    check_starttls: bool = True


class ScanResponse(BaseModel):
    domain: str
    score: int
    grade: str
    spoofable: Optional[bool] = None
    result: dict


# --- Dashboard Route ---

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the web dashboard."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path, media_type="text/html")
    return HTMLResponse("<h1>SpoofyVibe API</h1><p>Dashboard not found. Visit /docs for API documentation.</p>")


# --- Scan Endpoints ---

@app.get("/api/scan/{domain}")
async def scan_single(
    domain: str,
    dkim: bool = Query(False, description="Enable DKIM enumeration"),
    starttls: bool = Query(True, description="Check STARTTLS on MX hosts"),
):
    """Scan a single domain and return the result."""
    try:
        result = await process_domain(
            domain.strip().lower(),
            enable_dkim=dkim,
            check_starttls=starttls,
        )
        # Save to history
        scan_id = history.save_scan(result)
        result["SCAN_ID"] = scan_id
        return {"status": "ok", "result": result}
    except Exception as e:
        logger.error("Scan failed for %s: %s", domain, e)
        return {"status": "error", "error": str(e), "domain": domain}


@app.post("/api/scan")
async def scan_bulk(req: ScanRequest, background_tasks: BackgroundTasks):
    """
    Scan multiple domains. Returns results inline for <=5 domains,
    or starts a background job for larger batches.
    """
    domains = [d.strip().lower() for d in req.domains if d.strip()]

    if not domains:
        return {"status": "error", "error": "No domains provided"}

    if len(domains) > 50:
        return {"status": "error", "error": "Maximum 50 domains per request"}

    results = []
    errors = []

    # Process concurrently with semaphore
    semaphore = asyncio.Semaphore(5)

    async def scan_one(d):
        async with semaphore:
            return await process_domain(
                d, enable_dkim=req.enable_dkim, check_starttls=req.check_starttls
            )

    tasks = [scan_one(d) for d in domains]
    raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    for i, r in enumerate(raw_results):
        if isinstance(r, Exception):
            errors.append({"domain": domains[i], "error": str(r)})
            logger.error("Scan failed for %s: %s", domains[i], r)
        else:
            results.append(r)

    # Save all successful results to history
    if results:
        history.save_bulk(results)

    return {
        "status": "ok",
        "count": len(results),
        "results": results,
        "errors": errors,
    }


# --- History Endpoints ---

@app.get("/api/history")
async def get_history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    domain: Optional[str] = Query(None, description="Filter by domain"),
):
    """Get scan history."""
    scans = history.get_scans(limit=limit, offset=offset, domain_filter=domain)
    return {"status": "ok", "scans": scans, "count": len(scans)}


@app.get("/api/history/{domain}")
async def get_domain_history(domain: str, limit: int = Query(20, ge=1, le=100)):
    """Get scan history for a specific domain."""
    scans = history.get_domain_history(domain, limit=limit)
    trend = history.get_trend(domain, limit=limit)
    return {"status": "ok", "domain": domain, "scans": scans, "trend": trend}


@app.get("/api/history/detail/{scan_id}")
async def get_scan_detail(scan_id: int):
    """Get full detail for a specific scan."""
    detail = history.get_scan_detail(scan_id)
    if detail:
        return {"status": "ok", "scan": detail}
    return {"status": "error", "error": "Scan not found"}


@app.get("/api/stats")
async def get_stats():
    """Get aggregate statistics."""
    stats = history.get_stats()
    domains = history.get_unique_domains()
    return {"status": "ok", "stats": stats, "domains": domains}


# --- Subdomain Endpoint ---

@app.get("/api/subdomains/{domain}")
async def discover_subdomains(domain: str):
    """Discover subdomains via Certificate Transparency logs."""
    loop = asyncio.get_event_loop()
    finder = SubdomainFinder(domain.strip().lower())
    subdomains = await loop.run_in_executor(None, finder.discover)
    return {
        "status": "ok" if not finder.error else "partial",
        "domain": domain,
        "subdomains": subdomains,
        "count": len(subdomains),
        "error": finder.error,
    }


@app.delete("/api/history/{domain}")
async def delete_domain_history(domain: str):
    """Delete all scan history for a domain."""
    history.delete_domain(domain)
    return {"status": "ok", "message": f"History deleted for {domain}"}


# --- PDF Report Endpoint ---

class PDFReportRequest(BaseModel):
    results: list[dict]


@app.post("/api/report/pdf")
async def generate_pdf(req: PDFReportRequest):
    """Generate a PDF executive report from scan results."""
    import tempfile
    loop = asyncio.get_event_loop()

    tmp_dir = tempfile.mkdtemp(prefix="spoofyvibe_")
    pdf_path = os.path.join(tmp_dir, "spoofyvibe_report.pdf")

    await loop.run_in_executor(None, generate_pdf_report, req.results, pdf_path)

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename="spoofyvibe_report.pdf",
    )
