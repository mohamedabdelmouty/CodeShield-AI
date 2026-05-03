"""
CodeShield AI — AI Explanation Engine
Enriches vulnerabilities with AI-generated explanations, attack scenarios, and best practices.
"""

import logging
from typing import Dict, Any, List

from .ai_engine import explain_vulnerability as _ai_explain

logger = logging.getLogger("codeshield.explainer")


def explain(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a full AI explanation for a single vulnerability.

    The returned dict has:
      - why_dangerous:     str
      - attack_scenario:   str
      - best_practices:    List[str]
      - severity_rationale: str
      - references:        List[str]
      - model_used:        str
    """
    try:
        return _ai_explain(vuln)
    except Exception as exc:
        logger.error("Explainer failed for %s: %s", vuln.get("id"), exc)
        return {
            "why_dangerous": vuln.get("explain_why") or "This vulnerability can be exploited by attackers.",
            "attack_scenario": "An attacker could leverage this vulnerability to compromise the application.",
            "best_practices": ["Follow OWASP guidelines", "Apply input validation", "Use security-aware libraries"],
            "severity_rationale": f"Severity {vuln.get('severity', 'UNKNOWN')} based on potential impact.",
            "references": [
                f"https://cwe.mitre.org/data/definitions/{vuln.get('cwe_id', '').replace('CWE-', '')}.html"
                if vuln.get("cwe_id") else "https://owasp.org/www-project-top-ten/"
            ],
            "model_used": "static",
        }


def bulk_explain(vulns: List[Dict[str, Any]], max_items: int = 10) -> List[Dict[str, Any]]:
    """
    Explain multiple vulnerabilities.
    Limits to `max_items` to avoid excessive API calls.
    Each result includes the original vuln id for correlation.
    """
    results = []
    for vuln in vulns[:max_items]:
        explanation = explain(vuln)
        explanation["vuln_id"] = vuln.get("id", "")
        results.append(explanation)
    return results
