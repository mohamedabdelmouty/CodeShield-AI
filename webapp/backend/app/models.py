from pydantic import BaseModel, HttpUrl, field_validator
from typing import Optional, List
from enum import Enum


class ScanRequest(BaseModel):
    repo_url: str

    @field_validator("repo_url")
    @classmethod
    def must_be_github(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("https://github.com/"):
            raise ValueError("Only GitHub URLs are supported (https://github.com/...)")
        return v


class VulnerabilitySeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityLocation(BaseModel):
    file: str
    line: int
    snippet: Optional[str] = None


class Vulnerability(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    severity: VulnerabilitySeverity
    message: str
    remediation: str
    remediation_code: Optional[str] = None
    location: VulnerabilityLocation
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    explain_why: Optional[str] = None


class RiskScore(BaseModel):
    score: int          # 0-100
    grade: str          # A, B, C, D, F
    passed: bool
    label: str


class ScanSummary(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    INFO: int = 0


class ScanStats(BaseModel):
    files_scanned: int
    lines_scanned: int
    duration_ms: int
    timestamp: str


class ScanResult(BaseModel):
    repo_url: str
    repo_name: str
    score: RiskScore
    summary: ScanSummary
    vulnerabilities: List[Vulnerability]
    stats: ScanStats
    affected_files: List[str]
