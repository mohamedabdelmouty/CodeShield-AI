"""
CodeShield AI — FastAPI Backend v3.0
Main application entry point with all REST API endpoints.

New in v3.0:
  POST /api/fix          — Generate AI-powered secure fix
  POST /api/fix/pr       — Create GitHub PR with the fix
  POST /api/explain      — AI explanation for a vulnerability
  POST /api/explain/bulk — Bulk explain multiple vulnerabilities
  GET  /api/history      — Scan history list
  GET  /api/history/{id} — Single history entry
  DELETE /api/history/{id} — Delete history entry
  DELETE /api/history    — Clear all history
  GET  /api/models       — AI model status
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import asyncio
from concurrent.futures import ThreadPoolExecutor

from .models import (
    ScanRequest, ScanResult,
    AutoFixRequest, AutoFixResult,
    GitHubPRRequest, GitHubPRResult,
    ExplainRequest, ExplainResult,
    BulkExplainRequest,
    HistoryEntry, HistoryList, HistoryStats,
    ModelStatus,
)
from .scanner import scan_repo
from .security import validate_github_url, check_rate_limit
from .auto_fix import generate_autofix, create_github_pr
from .explainer import explain, bulk_explain
from .history import init_db, save_scan, get_history, get_history_entry, delete_history_entry, clear_history, get_stats
from .ai_engine import get_model_status

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("codeshield.main")

# ─── Startup / Shutdown ───────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB on startup."""
    init_db()
    logger.info("CodeShield AI v3.0 started")
    yield
    logger.info("CodeShield AI shutting down")

# ─── App Setup ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="CodeShield AI API",
    description="AI-powered code security analyzer for GitHub repositories",
    version="3.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

executor = ThreadPoolExecutor(max_workers=4)

# ─── Health Check ─────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "service": "CodeShield AI", "version": "3.0.0"}

# ─── Core Scan ────────────────────────────────────────────────────────────────

@app.post("/api/scan", response_model=ScanResult)
async def scan_repository(request: Request, body: ScanRequest):
    """Scan a GitHub repository for security vulnerabilities."""
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests. Please wait before scanning again.")

    is_valid, error = validate_github_url(body.repo_url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error)

    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(executor, scan_repo, body.repo_url)
        result_dict = result.model_dump()

        # Persist to history
        history_id = save_scan(result_dict)
        result.history_id = history_id

        return result
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error("Scan failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

# ─── Auto-Fix Endpoints ───────────────────────────────────────────────────────

@app.post("/api/fix", response_model=AutoFixResult)
async def generate_fix(body: AutoFixRequest):
    """
    Generate an AI-powered secure fix for a single vulnerability.
    Returns the original code, fixed code, unified diff, and explanation.
    """
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(executor, generate_autofix, body.vuln)
        return AutoFixResult(**result)
    except Exception as e:
        logger.error("Fix generation failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Fix generation failed: {str(e)}")


@app.post("/api/fix/pr", response_model=GitHubPRResult)
async def create_pr(body: GitHubPRRequest):
    """
    Create a GitHub Pull Request containing the security fix.
    Requires GITHUB_TOKEN env var or token in request body.
    """
    is_valid, error = validate_github_url(body.repo_url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error)
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            executor, create_github_pr,
            body.repo_url, body.vuln, body.fixed_code, body.github_token
        )
        return GitHubPRResult(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("PR creation failed: %s", e)
        raise HTTPException(status_code=500, detail=f"PR creation failed: {str(e)}")

# ─── Explain Endpoints ────────────────────────────────────────────────────────

@app.post("/api/explain", response_model=ExplainResult)
async def explain_vulnerability(body: ExplainRequest):
    """
    Generate an AI explanation for a single vulnerability.
    Returns: why_dangerous, attack_scenario, best_practices, references.
    """
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(executor, explain, body.vuln)
        result["vuln_id"] = body.vuln.get("id", "")
        return ExplainResult(**result)
    except Exception as e:
        logger.error("Explain failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Explanation failed: {str(e)}")


@app.post("/api/explain/bulk")
async def explain_bulk(body: BulkExplainRequest):
    """Explain multiple vulnerabilities at once (max 10 per call)."""
    try:
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(executor, bulk_explain, body.vulns, min(body.max_items, 10))
        return {"explanations": results, "count": len(results)}
    except Exception as e:
        logger.error("Bulk explain failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

# ─── History Endpoints ────────────────────────────────────────────────────────

@app.get("/api/history", response_model=HistoryList)
async def list_history(limit: int = 20, offset: int = 0):
    """Get paginated scan history."""
    entries_raw = get_history(limit=limit, offset=offset)
    return HistoryList(entries=[HistoryEntry(**e) for e in entries_raw], total=len(entries_raw))


@app.get("/api/history/stats", response_model=HistoryStats)
async def history_statistics():
    """Get aggregate statistics across all scans."""
    return HistoryStats(**get_stats())


@app.get("/api/history/{entry_id}", response_model=HistoryEntry)
async def get_history_item(entry_id: int):
    """Get a single scan history entry."""
    entry = get_history_entry(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail=f"History entry {entry_id} not found")
    return HistoryEntry(**entry)


@app.delete("/api/history/{entry_id}")
async def delete_history_item(entry_id: int):
    """Delete a single scan history entry."""
    deleted = delete_history_entry(entry_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"History entry {entry_id} not found")
    return {"deleted": True, "id": entry_id}


@app.delete("/api/history")
async def clear_all_history():
    """Delete all scan history entries."""
    count = clear_history()
    return {"deleted": count, "message": f"Cleared {count} history entries"}

# ─── Model Status ─────────────────────────────────────────────────────────────

@app.get("/api/models", response_model=ModelStatus)
async def model_status():
    """Return which AI models are currently available."""
    return ModelStatus(**get_model_status())

# ─── Global Exception Handler ─────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal server error: {str(exc)}"}
    )
