"""
CodeShield AI — Auto-Fix Engine
Generates secure code fixes and optionally creates GitHub Pull Requests.
"""

import os
import re
import logging
from typing import Optional, Dict, Any, List

import httpx

from .ai_engine import generate_fix

logger = logging.getLogger("codeshield.autofix")

GITHUB_API = "https://api.github.com"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")


# ─── Diff Generator ───────────────────────────────────────────────────────────

def _make_unified_diff(original: str, fixed: str, filename: str = "code") -> str:
    """Create a simple unified diff between original and fixed code."""
    orig_lines = original.splitlines(keepends=True)
    fix_lines  = fixed.splitlines(keepends=True)
    import difflib
    diff = difflib.unified_diff(
        orig_lines, fix_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
        lineterm=""
    )
    return "\n".join(diff)


# ─── Main Auto-Fix Function ───────────────────────────────────────────────────

def generate_autofix(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a complete auto-fix for a vulnerability.

    Args:
        vuln: A vulnerability dict (matches the Vulnerability Pydantic model)

    Returns:
        {
          original_code: str,
          fixed_code:    str,
          diff:          str,      # unified diff patch
          explanation:   str,
          breaking_changes: str,
          security_improvement: str,
          model_used:    str,
        }
    """
    snippet = vuln.get("location", {}).get("snippet", "")
    filename = vuln.get("location", {}).get("file", "unknown")

    # Get AI-generated fix
    fix_result = generate_fix(vuln)

    fixed_code = fix_result.get("fixed_code", snippet)
    diff_patch = _make_unified_diff(snippet, fixed_code, filename)

    # Derive confidence and risk (either from AI directly, or basic heuristics)
    confidence = fix_result.get("confidence_score", 85)
    risk = fix_result.get("risk_level", "Safe")

    # If it's a critical vulnerability or uses eval/exec, lower confidence and increase risk
    if vuln.get("severity") == "CRITICAL" or "eval" in fixed_code or "exec" in fixed_code:
        confidence = min(confidence, 60)
        risk = "Needs Review"
    if "delete" in fixed_code.lower() or "drop" in fixed_code.lower():
        risk = "High Risk"

    return {
        "original_code":        snippet,
        "fixed_code":           fixed_code,
        "diff":                 diff_patch,
        "explanation":          fix_result.get("explanation", "Apply the secure coding pattern."),
        "breaking_changes":     fix_result.get("breaking_changes", "None"),
        "security_improvement": fix_result.get("security_improvement", "Reduces attack surface."),
        "model_used":           fix_result.get("model_used", "static"),
        "confidence_score":     confidence,
        "risk_level":           risk,
        "vuln_id":              vuln.get("id", ""),
        "rule_name":            vuln.get("rule_name", ""),
        "severity":             vuln.get("severity", ""),
        "file":                 filename,
        "line":                 vuln.get("location", {}).get("line", 0),
    }


# ─── GitHub PR Creator ────────────────────────────────────────────────────────

class GitHubPRCreator:
    """
    Creates a GitHub Pull Request with the auto-fix patch.
    Requires GITHUB_TOKEN env var with repo write access.
    """

    def __init__(self, token: Optional[str] = None):
        self.token = token or GITHUB_TOKEN
        if not self.token:
            raise ValueError(
                "GITHUB_TOKEN is not set. "
                "Please add GITHUB_TOKEN=<your PAT> to api.env"
            )
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _parse_repo(self, repo_url: str) -> tuple[str, str]:
        """Extract owner and repo name from GitHub URL."""
        match = re.match(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?$", repo_url)
        if not match:
            raise ValueError(f"Invalid GitHub URL: {repo_url}")
        return match.group(1), match.group(2)

    def _get_default_branch(self, owner: str, repo: str) -> str:
        """Get the default branch of a repository."""
        with httpx.Client(timeout=15) as client:
            resp = client.get(f"{GITHUB_API}/repos/{owner}/{repo}", headers=self.headers)
            resp.raise_for_status()
            return resp.json().get("default_branch", "main")

    def _get_branch_sha(self, owner: str, repo: str, branch: str) -> str:
        """Get the latest commit SHA for a branch."""
        with httpx.Client(timeout=15) as client:
            resp = client.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/{branch}",
                headers=self.headers,
            )
            resp.raise_for_status()
            return resp.json()["object"]["sha"]

    def _create_branch(self, owner: str, repo: str, branch_name: str, sha: str) -> None:
        """Create a new branch from a SHA."""
        with httpx.Client(timeout=15) as client:
            resp = client.post(
                f"{GITHUB_API}/repos/{owner}/{repo}/git/refs",
                headers=self.headers,
                json={"ref": f"refs/heads/{branch_name}", "sha": sha},
            )
            if resp.status_code not in (201, 422):  # 422 = branch already exists
                resp.raise_for_status()

    def _get_file_sha(self, owner: str, repo: str, path: str, branch: str) -> Optional[str]:
        """Get the blob SHA of an existing file (needed for update)."""
        with httpx.Client(timeout=15) as client:
            resp = client.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
                headers=self.headers,
                params={"ref": branch},
            )
            if resp.status_code == 200:
                return resp.json().get("sha")
        return None

    def _update_file(
        self, owner: str, repo: str, path: str,
        content: str, message: str, branch: str,
        file_sha: Optional[str]
    ) -> None:
        """Create or update a file in the repository."""
        import base64
        encoded = base64.b64encode(content.encode()).decode()
        payload: Dict[str, Any] = {
            "message": message,
            "content": encoded,
            "branch": branch,
        }
        if file_sha:
            payload["sha"] = file_sha
        with httpx.Client(timeout=15) as client:
            resp = client.put(
                f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
                headers=self.headers,
                json=payload,
            )
            resp.raise_for_status()

    def _create_pr(
        self, owner: str, repo: str,
        title: str, body: str,
        head: str, base: str
    ) -> Dict[str, Any]:
        """Create the Pull Request."""
        with httpx.Client(timeout=15) as client:
            resp = client.post(
                f"{GITHUB_API}/repos/{owner}/{repo}/pulls",
                headers=self.headers,
                json={"title": title, "body": body, "head": head, "base": base},
            )
            resp.raise_for_status()
            return resp.json()

    def create_pr_for_fix(
        self,
        repo_url: str,
        file_path: str,
        fixed_content: str,
        vuln_id: str,
        rule_name: str,
        explanation: str,
    ) -> Dict[str, Any]:
        """
        Full flow: create branch → update file → open PR.

        Returns the PR URL and number.
        """
        owner, repo = self._parse_repo(repo_url)
        default_branch = self._get_default_branch(owner, repo)
        sha = self._get_branch_sha(owner, repo, default_branch)

        # Create fix branch
        branch_name = f"codeshield/fix-{vuln_id.lower()}"
        self._create_branch(owner, repo, branch_name, sha)

        # Update the file
        file_sha = self._get_file_sha(owner, repo, file_path, branch_name)
        commit_msg = f"fix(security): remediate {rule_name} in {file_path}\n\nGenerated by CodeShield AI"
        self._update_file(owner, repo, file_path, fixed_content, commit_msg, branch_name, file_sha)

        # PR body
        pr_body = (
            f"## 🛡️ CodeShield AI — Security Fix\n\n"
            f"**Vulnerability:** {rule_name}  \n"
            f"**File:** `{file_path}`  \n"
            f"**ID:** `{vuln_id}`\n\n"
            f"### What was fixed\n{explanation}\n\n"
            f"*This PR was automatically generated by [CodeShield AI](https://github.com/mohamedabdelmouty/CodeShield-AI).*"
        )

        pr = self._create_pr(
            owner, repo,
            title=f"🛡️ Security Fix: {rule_name} [{vuln_id}]",
            body=pr_body,
            head=branch_name,
            base=default_branch,
        )
        return {
            "pr_url":    pr.get("html_url", ""),
            "pr_number": pr.get("number", 0),
            "branch":    branch_name,
            "status":    "created",
        }


# ─── Convenience wrapper ──────────────────────────────────────────────────────

def create_github_pr(
    repo_url: str,
    vuln: Dict[str, Any],
    fixed_code: str,
    github_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    High-level function to create a GitHub PR for a vulnerability fix.
    Raises ValueError if GITHUB_TOKEN is not available.
    """
    creator = GitHubPRCreator(token=github_token)
    file_path = vuln.get("location", {}).get("file", "unknown")
    return creator.create_pr_for_fix(
        repo_url=repo_url,
        file_path=file_path,
        fixed_content=fixed_code,
        vuln_id=vuln.get("id", "UNKNOWN"),
        rule_name=vuln.get("rule_name", "Security Issue"),
        explanation=vuln.get("remediation", "Apply secure coding practices."),
    )
