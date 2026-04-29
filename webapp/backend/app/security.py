import re
import os
import shutil
from urllib.parse import urlparse
from pathlib import Path
from typing import Optional
import time
from collections import defaultdict


# ─── Rate Limiting ─────────────────────────────────────────────────────────────

_request_times: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW = 60  # seconds


def check_rate_limit(client_ip: str) -> bool:
    """Returns True if allowed, False if rate-limited."""
    now = time.time()
    times = _request_times[client_ip]
    # Remove old entries
    _request_times[client_ip] = [t for t in times if now - t < RATE_LIMIT_WINDOW]
    if len(_request_times[client_ip]) >= RATE_LIMIT_REQUESTS:
        return False
    _request_times[client_ip].append(now)
    return True


# ─── GitHub URL Validation ─────────────────────────────────────────────────────

GITHUB_URL_PATTERN = re.compile(
    r'^https://github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(/.*)?$'
)

# Block known huge / system repos
BLOCKED_REPOS = {
    "torvalds/linux",
    "microsoft/windows",
}

MAX_REPO_SIZE_MB = 50


def validate_github_url(url: str) -> tuple[bool, Optional[str]]:
    """Validate and sanitize a GitHub URL.
    Returns (is_valid, error_message)."""
    url = url.strip()

    if not url.startswith("https://"):
        return False, "URL must use HTTPS"

    if not GITHUB_URL_PATTERN.match(url):
        return False, "Invalid GitHub repository URL format"

    parsed = urlparse(url)
    if parsed.netloc != "github.com":
        return False, "Only github.com URLs are allowed"

    path_parts = parsed.path.strip("/").split("/")
    if len(path_parts) < 2:
        return False, "URL must point to a repository (owner/repo)"

    repo_key = f"{path_parts[0]}/{path_parts[1]}"
    if repo_key.lower() in BLOCKED_REPOS:
        return False, f"Repository '{repo_key}' is blocked (too large or restricted)"

    # Prevent path traversal in repo path
    if ".." in parsed.path or "%2e%2e" in parsed.path.lower():
        return False, "Path traversal detected in URL"

    return True, None


def sanitize_repo_path(path: str) -> str:
    """Prevent path traversal and shell injection in file paths."""
    # Remove any null bytes
    path = path.replace("\x00", "")
    # Resolve and normalize
    resolved = os.path.realpath(path)
    return resolved


def get_repo_name_from_url(url: str) -> str:
    """Extract 'owner/repo' from a GitHub URL."""
    parsed = urlparse(url.strip())
    parts = parsed.path.strip("/").split("/")
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parsed.path.strip("/")


def cleanup_temp_dir(temp_dir: str) -> None:
    """Safely remove a temporary directory."""
    try:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception:
        pass
