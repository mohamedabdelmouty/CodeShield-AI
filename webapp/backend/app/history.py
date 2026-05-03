"""
CodeShield AI — Scan History (SQLite via SQLAlchemy)
Persists scan results locally with zero-config SQLite.
Swap DATABASE_URL to postgresql:// or mongodb+srv:// for production.
"""

import os
import logging
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    create_engine, Column, Integer, String, Float,
    DateTime, Text, Boolean, event
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.pool import StaticPool

logger = logging.getLogger("codeshield.history")

# ─── DB Setup ─────────────────────────────────────────────────────────────────

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./codeshield_history.db"
)

# SQLite-specific: enable WAL mode for concurrent reads
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    poolclass=StaticPool if DATABASE_URL.startswith("sqlite") else None,
)

# Enable WAL journal for SQLite
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_conn, _):
    if DATABASE_URL.startswith("sqlite"):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ─── ORM Model ────────────────────────────────────────────────────────────────

class ScanHistoryEntry(Base):
    __tablename__ = "scan_history"

    id            = Column(Integer, primary_key=True, index=True)
    repo_url      = Column(String(512), nullable=False, index=True)
    repo_name     = Column(String(256), nullable=False)
    score         = Column(Integer, nullable=False)         # 0-100
    grade         = Column(String(2), nullable=False)       # A–F
    passed        = Column(Boolean, nullable=False)
    total_vulns   = Column(Integer, nullable=False, default=0)
    critical      = Column(Integer, nullable=False, default=0)
    high          = Column(Integer, nullable=False, default=0)
    medium        = Column(Integer, nullable=False, default=0)
    low           = Column(Integer, nullable=False, default=0)
    files_scanned = Column(Integer, nullable=False, default=0)
    lines_scanned = Column(Integer, nullable=False, default=0)
    duration_ms   = Column(Integer, nullable=False, default=0)
    timestamp     = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    scan_json     = Column(Text, nullable=True)   # Optional: store full JSON result

    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "repo_url":      self.repo_url,
            "repo_name":     self.repo_name,
            "score":         self.score,
            "grade":         self.grade,
            "passed":        self.passed,
            "total_vulns":   self.total_vulns,
            "summary": {
                "CRITICAL": self.critical,
                "HIGH":     self.high,
                "MEDIUM":   self.medium,
                "LOW":      self.low,
            },
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "duration_ms":   self.duration_ms,
            "timestamp":     self.timestamp.isoformat() if self.timestamp else None,
        }

class FixHistoryEntry(Base):
    __tablename__ = "fix_history"

    id            = Column(String(36), primary_key=True, index=True)
    vuln_id       = Column(String(64), nullable=False)
    file_path     = Column(String(512), nullable=False)
    original_code = Column(Text, nullable=False)
    fixed_code    = Column(Text, nullable=False)
    timestamp     = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "vuln_id":       self.vuln_id,
            "file_path":     self.file_path,
            "original_code": self.original_code,
            "fixed_code":    self.fixed_code,
            "timestamp":     self.timestamp.isoformat() if self.timestamp else None,
        }

def init_db() -> None:
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized: %s", DATABASE_URL)


# ─── Fix History Operations ───────────────────────────────────────────────────

def save_fix_history(fix_id: str, vuln_id: str, file_path: str, original: str, fixed: str) -> bool:
    db: Session = SessionLocal()
    try:
        entry = FixHistoryEntry(
            id=fix_id, vuln_id=vuln_id, file_path=file_path,
            original_code=original, fixed_code=fixed
        )
        db.add(entry)
        db.commit()
        return True
    except Exception as exc:
        db.rollback()
        logger.error("Failed to save fix history: %s", exc)
        return False
    finally:
        db.close()

def get_fix_history(fix_id: str) -> Optional[dict]:
    db: Session = SessionLocal()
    try:
        entry = db.query(FixHistoryEntry).filter(FixHistoryEntry.id == fix_id).first()
        return entry.to_dict() if entry else None
    finally:
        db.close()

# ─── CRUD Operations ──────────────────────────────────────────────────────────

def save_scan(scan_result: dict) -> int:
    """
    Persist a scan result to history.
    scan_result should match the ScanResult schema.
    Returns the new entry ID.
    """
    import json
    db: Session = SessionLocal()
    try:
        summary = scan_result.get("summary", {})
        score_data = scan_result.get("score", {})
        stats = scan_result.get("stats", {})

        entry = ScanHistoryEntry(
            repo_url      = scan_result.get("repo_url", ""),
            repo_name     = scan_result.get("repo_name", ""),
            score         = score_data.get("score", 0),
            grade         = score_data.get("grade", "F"),
            passed        = score_data.get("passed", False),
            total_vulns   = len(scan_result.get("vulnerabilities", [])),
            critical      = summary.get("CRITICAL", 0),
            high          = summary.get("HIGH", 0),
            medium        = summary.get("MEDIUM", 0),
            low           = summary.get("LOW", 0),
            files_scanned = stats.get("files_scanned", 0),
            lines_scanned = stats.get("lines_scanned", 0),
            duration_ms   = stats.get("duration_ms", 0),
            # Store lightweight scan summary JSON (without full vuln list)
            scan_json     = json.dumps({
                "repo_url":       scan_result.get("repo_url"),
                "repo_name":      scan_result.get("repo_name"),
                "score":          score_data,
                "summary":        summary,
                "stats":          stats,
                "affected_files": scan_result.get("affected_files", [])[:20],
            }),
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        logger.info("Saved scan history entry #%d for %s", entry.id, entry.repo_name)
        return entry.id
    except Exception as exc:
        db.rollback()
        logger.error("Failed to save scan history: %s", exc)
        return -1
    finally:
        db.close()


def get_history(limit: int = 20, offset: int = 0) -> List[dict]:
    """Retrieve scan history entries, most recent first."""
    db: Session = SessionLocal()
    try:
        entries = (
            db.query(ScanHistoryEntry)
            .order_by(ScanHistoryEntry.timestamp.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [e.to_dict() for e in entries]
    finally:
        db.close()


def get_history_entry(entry_id: int) -> Optional[dict]:
    """Retrieve a single scan history entry by ID."""
    db: Session = SessionLocal()
    try:
        entry = db.query(ScanHistoryEntry).filter(ScanHistoryEntry.id == entry_id).first()
        return entry.to_dict() if entry else None
    finally:
        db.close()


def delete_history_entry(entry_id: int) -> bool:
    """Delete a scan history entry. Returns True if deleted."""
    db: Session = SessionLocal()
    try:
        entry = db.query(ScanHistoryEntry).filter(ScanHistoryEntry.id == entry_id).first()
        if not entry:
            return False
        db.delete(entry)
        db.commit()
        return True
    except Exception as exc:
        db.rollback()
        logger.error("Failed to delete history entry %d: %s", entry_id, exc)
        return False
    finally:
        db.close()


def clear_history() -> int:
    """Delete all scan history entries. Returns count deleted."""
    db: Session = SessionLocal()
    try:
        count = db.query(ScanHistoryEntry).count()
        db.query(ScanHistoryEntry).delete()
        db.commit()
        return count
    except Exception as exc:
        db.rollback()
        logger.error("Failed to clear history: %s", exc)
        return 0
    finally:
        db.close()


def get_stats() -> dict:
    """Return aggregate statistics across all scans."""
    db: Session = SessionLocal()
    try:
        total = db.query(ScanHistoryEntry).count()
        if total == 0:
            return {"total_scans": 0, "avg_score": 0, "pass_rate": 0}
        from sqlalchemy import func
        row = db.query(
            func.avg(ScanHistoryEntry.score).label("avg_score"),
            func.sum(func.cast(ScanHistoryEntry.passed, Integer)).label("passed_count"),
        ).first()
        return {
            "total_scans": total,
            "avg_score":   round(row.avg_score or 0, 1),
            "pass_rate":   round((row.passed_count or 0) / total * 100, 1),
        }
    finally:
        db.close()
