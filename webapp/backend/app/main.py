"""
CodeShield AI — FastAPI Backend
Main application entry point with REST API endpoints.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import asyncio
from concurrent.futures import ThreadPoolExecutor

from .models import ScanRequest, ScanResult
from .scanner import scan_repo
from .security import validate_github_url, check_rate_limit

# ─── App Setup ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="CodeShield AI API",
    description="Security vulnerability scanner for GitHub repositories",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

executor = ThreadPoolExecutor(max_workers=4)

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "service": "CodeShield AI", "version": "2.0.0"}


@app.post("/api/scan", response_model=ScanResult)
async def scan_repository(request: Request, body: ScanRequest):
    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please wait before scanning again."
        )

    # Validate GitHub URL
    is_valid, error = validate_github_url(body.repo_url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error)

    # Run scan in thread pool (non-blocking for async)
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(executor, scan_repo, body.repo_url)
        return result
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal server error: {str(exc)}"}
    )
