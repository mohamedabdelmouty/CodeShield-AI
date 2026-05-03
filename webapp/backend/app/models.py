"""
CodeShield AI — Pydantic Data Models (v3.0)
"""

from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from enum import Enum


# ─── Scan Models ─────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    repo_url: str

    @classmethod
    def model_validator_repo(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("https://github.com/"):
            raise ValueError("Only GitHub URLs are supported (https://github.com/...)")
        return v


class VulnerabilitySeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class VulnerabilityLocation(BaseModel):
    file:    str
    line:    int
    snippet: Optional[str] = None


class Vulnerability(BaseModel):
    id:               str
    rule_id:          str
    rule_name:        str
    severity:         VulnerabilitySeverity
    message:          str
    remediation:      str
    remediation_code: Optional[str] = None
    location:         VulnerabilityLocation
    cwe_id:           Optional[str] = None
    owasp_category:   Optional[str] = None
    explain_why:      Optional[str] = None


class RiskScore(BaseModel):
    score:  int    # 0-100
    grade:  str    # A, B, C, D, F
    passed: bool
    label:  str


class ScanSummary(BaseModel):
    CRITICAL: int = 0
    HIGH:     int = 0
    MEDIUM:   int = 0
    LOW:      int = 0
    INFO:     int = 0


class ScanStats(BaseModel):
    files_scanned: int
    lines_scanned: int
    duration_ms:   int
    timestamp:     str


class ScanResult(BaseModel):
    repo_url:       str
    repo_name:      str
    score:          RiskScore
    summary:        ScanSummary
    vulnerabilities: List[Vulnerability]
    stats:          ScanStats
    affected_files: List[str]
    history_id:     Optional[int] = None   # ID in scan history table


# ─── Auto-Fix Models ──────────────────────────────────────────────────────────

class AutoFixRequest(BaseModel):
    """Request to generate a secure fix for one vulnerability."""
    vuln: Dict[str, Any]                    # Raw vulnerability dict from scan result


class AutoFixResult(BaseModel):
    vuln_id:             str
    rule_name:           str
    severity:            str
    file:                str
    line:                int
    original_code:       str
    fixed_code:          str
    diff:                str                # Unified diff patch
    explanation:         str
    breaking_changes:    str
    security_improvement: str
    model_used:          str


class GitHubPRRequest(BaseModel):
    """Request to create a GitHub PR with a fix."""
    repo_url:     str
    vuln:         Dict[str, Any]
    fixed_code:   str
    github_token: Optional[str] = None     # Falls back to GITHUB_TOKEN env var


class GitHubPRResult(BaseModel):
    pr_url:    str
    pr_number: int
    branch:    str
    status:    str


# ─── Explanation Models ───────────────────────────────────────────────────────

class ExplainRequest(BaseModel):
    """Request to explain a single vulnerability."""
    vuln: Dict[str, Any]


class ExplainResult(BaseModel):
    vuln_id:           str
    why_dangerous:     str
    attack_scenario:   str
    best_practices:    List[str]
    severity_rationale: str
    references:        List[str]
    model_used:        str


class BulkExplainRequest(BaseModel):
    """Request to explain multiple vulnerabilities at once."""
    vulns:     List[Dict[str, Any]]
    max_items: int = 5


# ─── History Models ───────────────────────────────────────────────────────────

class HistoryEntry(BaseModel):
    id:            int
    repo_url:      str
    repo_name:     str
    score:         int
    grade:         str
    passed:        bool
    total_vulns:   int
    summary:       Dict[str, int]
    files_scanned: int
    lines_scanned: int
    duration_ms:   int
    timestamp:     Optional[str] = None


class HistoryList(BaseModel):
    entries: List[HistoryEntry]
    total:   int


class HistoryStats(BaseModel):
    total_scans: int
    avg_score:   float
    pass_rate:   float


# ─── Model Status ─────────────────────────────────────────────────────────────

class ModelStatus(BaseModel):
    openai:       bool
    anthropic:    bool
    gemini:       bool
    active_model: str
