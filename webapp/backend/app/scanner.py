"""
CodeShield AI — Scanner Module v3.0
Handles GitHub repo cloning, file walking, rule application (regex + AST), and scoring.
"""

import os
import tempfile
import zipfile
import urllib.request
import subprocess
# Silence gitpython startup error — git may not be in PATH on serverless
os.environ.setdefault("GIT_PYTHON_REFRESH", "quiet")
import time
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Tuple, Optional

from .models import (
    Vulnerability, VulnerabilityLocation, VulnerabilitySeverity,
    RiskScore, ScanSummary, ScanStats, ScanResult
)
from .rules import get_rules_for_extension
from .security import cleanup_temp_dir, get_repo_name_from_url
from .ast_analyzer import analyze_with_ast


MAX_FILE_SIZE_BYTES = 500_000
MAX_TOTAL_FILES = 2000
IGNORE_DIRS = {
    ".git", "node_modules", "dist", "build", "__pycache__",
    ".venv", "venv", "env", "vendor", ".next", ".nuxt",
    "coverage", ".pytest_cache", "target", "out",
    "examples", "tests", "test", "docs", "fixtures", ".github"
}
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".java", ".php", ".rb", ".go", ".cs", ".cpp", ".c", ".html",
    ".dart", ".yaml", ".yml", ".json", ".sh"
}
SEVERITY_WEIGHTS = {
    "CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 3, "INFO": 1,
}


def clone_repo(repo_url: str) -> str:
    """
    Download a GitHub repo as a ZIP using the GitHub API and extract to /tmp.
    Works on Vercel serverless where git binary is not available.
    """
    # Normalize URL — strip trailing slash and .git
    url = repo_url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]

    # Extract owner/repo from URL
    # Supports: https://github.com/owner/repo
    parts = url.rstrip("/").split("/")
    if len(parts) < 2:
        raise ValueError(f"Cannot parse GitHub URL: {repo_url}")
    owner, repo = parts[-2], parts[-1]

    # Try main then master branch
    tmp_base = "/tmp" if os.path.isdir("/tmp") and os.access("/tmp", os.W_OK) else None
    zip_path = tempfile.mktemp(suffix=".zip", dir=tmp_base)
    extract_dir = tempfile.mkdtemp(prefix="codeshield_", dir=tmp_base)

    downloaded = False
    last_error = None

    for branch in ("main", "master"):
        zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
        try:
            req = urllib.request.Request(
                zip_url,
                headers={"User-Agent": "CodeShield-AI/1.0"}
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                with open(zip_path, "wb") as f:
                    f.write(response.read())
            downloaded = True
            break
        except Exception as e:
            last_error = e
            continue

    if not downloaded:
        cleanup_temp_dir(extract_dir)
        raise ValueError(
            f"Failed to download repository '{owner}/{repo}'. "
            f"Make sure the repo is public. Last error: {last_error}"
        )

    # Extract ZIP
    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(extract_dir)
    except zipfile.BadZipFile as e:
        cleanup_temp_dir(extract_dir)
        raise ValueError(f"Downloaded file is not a valid ZIP: {e}")
    finally:
        # Clean up zip file
        if os.path.exists(zip_path):
            os.remove(zip_path)

    # GitHub ZIP contains a single top-level folder: repo-branch/
    # Return the inner folder so scanner sees the actual repo files
    inner_dirs = [
        d for d in os.listdir(extract_dir)
        if os.path.isdir(os.path.join(extract_dir, d))
    ]
    if inner_dirs:
        return os.path.join(extract_dir, inner_dirs[0])
    return extract_dir


def collect_files(repo_dir: str) -> List[Path]:
    files: List[Path] = []
    root = Path(repo_dir)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".")]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() in SCANNABLE_EXTENSIONS:
                try:
                    if fpath.stat().st_size <= MAX_FILE_SIZE_BYTES:
                        files.append(fpath)
                except OSError:
                    continue
            if len(files) >= MAX_TOTAL_FILES:
                return files
    return files


def _make_id(rule_id: str, file_path: str, line: int) -> str:
    raw = f"{rule_id}:{file_path}:{line}"
    return hashlib.md5(raw.encode()).hexdigest()[:8].upper()


def _get_snippet(lines: List[str], line_idx: int, context: int = 3) -> str:
    start = max(0, line_idx - context - 1)
    end = min(len(lines), line_idx + context)
    return "\n".join(lines[start:end])


def scan_file(fpath: Path, repo_dir: str) -> Tuple[List[Vulnerability], int]:
    vulns: List[Vulnerability] = []
    ext = fpath.suffix.lower().lstrip(".")
    rules = get_rules_for_extension(ext)
    try:
        content = fpath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return [], 0
    lines = content.splitlines()
    rel_path = str(fpath.relative_to(repo_dir)).replace("\\", "/")

    # ── Pass 1: Regex-based rule scan ─────────────────────────────────────────
    seen_keys: set = set()   # deduplicate by (rule_id, line)
    for rule in rules:
        for line_idx, line in enumerate(lines, start=1):
            if rule.pattern.search(line):
                key = (rule.id, line_idx)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                vulns.append(Vulnerability(
                    id=_make_id(rule.id, rel_path, line_idx),
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=VulnerabilitySeverity(rule.severity),
                    message=rule.message,
                    remediation=rule.remediation,
                    remediation_code=rule.remediation_code,
                    location=VulnerabilityLocation(
                        file=rel_path, line=line_idx,
                        snippet=_get_snippet(lines, line_idx),
                    ),
                    cwe_id=rule.cwe_id,
                    owasp_category=rule.owasp_category,
                    explain_why=rule.explain_why,
                ))

    # ── Pass 2: AST-based deeper analysis ─────────────────────────────────────
    try:
        ast_findings = analyze_with_ast(content, str(fpath), rel_path)
        for f in ast_findings:
            key = (f["rule_id"], f["line"])
            if key in seen_keys:
                continue   # already found by regex pass
            seen_keys.add(key)
            severity_str = f.get("severity", "MEDIUM")
            try:
                sev = VulnerabilitySeverity(severity_str)
            except ValueError:
                sev = VulnerabilitySeverity.MEDIUM
            vulns.append(Vulnerability(
                id=_make_id(f["rule_id"], rel_path, f["line"]),
                rule_id=f["rule_id"],
                rule_name=f["rule_name"],
                severity=sev,
                message=f["message"],
                remediation="Apply the secure alternative shown in the message.",
                location=VulnerabilityLocation(
                    file=rel_path, line=f["line"],
                    snippet=f.get("snippet", ""),
                ),
            ))
    except Exception:
        pass  # AST pass is best-effort; never block the scan

    return vulns, len(lines)


def calculate_score(vulns: List[Vulnerability]) -> RiskScore:
    if not vulns:
        return RiskScore(score=100, grade="A", passed=True, label="No vulnerabilities found")
    
    raw_penalty = sum(SEVERITY_WEIGHTS.get(v.severity.value, 1) for v in vulns)
    
    # Asymptotic decay formula: score = 100 / (1 + penalty / 150)
    score = int(100 / (1 + (raw_penalty / 150.0)))
    # Ensure it never goes below 1 for aesthetic reasons, unless there are no vulns
    score = max(1, score)

    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 35 else "F"
    passed = score >= 70
    labels = {
        "A": "Excellent", 
        "B": "Good", 
        "C": "Fair — Action recommended", 
        "D": "Poor", 
        "F": "Critical — Immediate action"
    }
    return RiskScore(score=score, grade=grade, passed=passed, label=labels[grade])


def scan_repo(repo_url: str, progress_cb=None) -> ScanResult:
    """Scan a GitHub repository. progress_cb(event_type, data) is called at key milestones."""
    start_ms = time.time()
    repo_dir: Optional[str] = None
    try:
        repo_dir = clone_repo(repo_url)
        # Fix A5: emit clone_done milestone
        if progress_cb:
            progress_cb("clone_done", {"message": "Repository cloned"})

        files = collect_files(repo_dir)
        total = len(files)
        all_vulns: List[Vulnerability] = []
        total_lines = 0
        affected: set = set()

        for idx, fpath in enumerate(files):
            fv, lc = scan_file(fpath, repo_dir)
            all_vulns.extend(fv)
            total_lines += lc
            if fv:
                affected.add(str(fpath.relative_to(repo_dir)).replace("\\", "/"))

            # Fix A5: emit scanning progress every ~10% of files (or at least every 10 files)
            notify_every = max(1, total // 10)
            if progress_cb and (idx + 1) % notify_every == 0:
                pct = round((idx + 1) / total * 100) if total else 100
                progress_cb("scanning", {
                    "progress": pct,
                    "file": str(fpath.name),
                    "files_scanned": idx + 1,
                    "total": total,
                })

        # Fix A5: emit analyzing milestone before score calculation
        if progress_cb:
            progress_cb("analyzing", {"message": "Calculating security score..."})

        score = calculate_score(all_vulns)
        summary = ScanSummary(
            CRITICAL=sum(1 for v in all_vulns if v.severity == VulnerabilitySeverity.CRITICAL),
            HIGH=sum(1 for v in all_vulns if v.severity == VulnerabilitySeverity.HIGH),
            MEDIUM=sum(1 for v in all_vulns if v.severity == VulnerabilitySeverity.MEDIUM),
            LOW=sum(1 for v in all_vulns if v.severity == VulnerabilitySeverity.LOW),
            INFO=sum(1 for v in all_vulns if v.severity == VulnerabilitySeverity.INFO),
        )
        duration_ms = int((time.time() - start_ms) * 1000)
        stats = ScanStats(
            files_scanned=len(files), lines_scanned=total_lines,
            duration_ms=duration_ms,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )
        result = ScanResult(
            repo_url=repo_url, repo_name=get_repo_name_from_url(repo_url),
            score=score, summary=summary, vulnerabilities=all_vulns,
            stats=stats, affected_files=sorted(affected),
        )
        # Fix A5: emit done milestone
        if progress_cb:
            progress_cb("done", {})
        return result
    finally:
        if repo_dir:
            cleanup_temp_dir(repo_dir)

