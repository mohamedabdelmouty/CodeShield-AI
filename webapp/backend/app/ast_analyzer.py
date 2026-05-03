"""
CodeShield AI — AST-Based Code Analyzer
Provides deeper vulnerability detection using Abstract Syntax Trees.
Falls back to regex for unsupported languages.

Supported:
  - Python: stdlib `ast` module (zero dependencies)
  - JavaScript/TypeScript: pattern-based taint analysis (regex-AST hybrid)
"""

import ast
import re
import logging
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional

logger = logging.getLogger("codeshield.ast")

# ─── Python AST Analysis ──────────────────────────────────────────────────────

# Dangerous sinks: function calls that are unsafe with untrusted input
PYTHON_DANGEROUS_CALLS: Dict[str, str] = {
    "eval":         "Code Injection via eval()",
    "exec":         "Code Injection via exec()",
    "compile":      "Code Injection via compile()",
    "pickle.loads": "Deserialization Attack via pickle",
    "marshal.loads": "Deserialization Attack via marshal",
    "subprocess.call": "Command Injection via subprocess",
    "subprocess.Popen": "Command Injection via subprocess",
    "subprocess.run":  "Command Injection via subprocess",
    "os.system":    "Command Injection via os.system()",
    "os.popen":     "Command Injection via os.popen()",
    "os.execv":     "Command Injection via os.execv()",
    "os.execve":    "Command Injection via os.execve()",
    "__import__":   "Dynamic Import Injection",
    "importlib.import_module": "Dynamic Import Injection",
    "open":         "File Path Traversal potential",  # only flagged with string concat
    "yaml.load":    "Unsafe YAML deserialization (use yaml.safe_load)",
}

# Dangerous SQL patterns in string operations
SQL_KEYWORDS = re.compile(
    r"(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\s",
    re.IGNORECASE
)

# User-input sources (taint sources)
TAINT_SOURCES = {
    "input", "request.args", "request.form", "request.json",
    "request.data", "request.get", "sys.argv",
}


class PythonASTVisitor(ast.NodeVisitor):
    """
    Walks a Python AST and collects security findings.
    Each finding: { rule_id, rule_name, severity, line, col, message }
    """

    def __init__(self, source_lines: List[str]):
        self.findings: List[Dict[str, Any]] = []
        self.source_lines = source_lines
        self._tainted_vars: set = set()  # simple single-function taint tracking

    def _add(self, node: ast.AST, rule_id: str, rule_name: str,
              severity: str, message: str) -> None:
        line = getattr(node, "lineno", 0)
        col  = getattr(node, "col_offset", 0)
        snippet = self.source_lines[line - 1].rstrip() if 0 < line <= len(self.source_lines) else ""
        self.findings.append({
            "rule_id":   rule_id,
            "rule_name": rule_name,
            "severity":  severity,
            "line":      line,
            "col":       col,
            "message":   message,
            "snippet":   snippet,
        })

    # ── Taint tracking: detect variable assignments from user input ────────────

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track variables assigned from user-input sources."""
        if isinstance(node.value, ast.Call):
            func_name = _get_call_name(node.value)
            if any(src in (func_name or "") for src in TAINT_SOURCES):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._tainted_vars.add(target.id)
        self.generic_visit(node)

    # ── Detect dangerous function calls ───────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:
        func_name = _get_call_name(node.func)
        if func_name:
            for dangerous, desc in PYTHON_DANGEROUS_CALLS.items():
                if func_name == dangerous or func_name.endswith(f".{dangerous.split('.')[-1]}"):
                    sev = "CRITICAL" if dangerous in ("eval", "exec", "os.system") else "HIGH"
                    self._add(node, f"AST-PY-{dangerous.upper().replace('.', '_')[:15]}",
                              desc, sev, f"Dangerous function `{func_name}()` detected. {desc}.")
                    break

            # SQL injection: string formatting in DB calls
            if func_name and any(db in func_name.lower() for db in ("execute", "cursor", "query", "raw")):
                for arg in node.args:
                    if isinstance(arg, (ast.BinOp, ast.JoinedStr, ast.Call)):
                        self._add(node, "AST-PY-SQL001", "SQL Injection via String Concatenation",
                                  "CRITICAL",
                                  f"Dynamic SQL construction in `{func_name}()`. Use parameterized queries.")
                        break

        self.generic_visit(node)

    # ── Detect hardcoded secrets in assignments ────────────────────────────────

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._check_hardcoded_string(node, node.value)
        self.generic_visit(node)

    def _check_hardcoded_string(self, node: ast.AST, value_node: Optional[ast.expr]) -> None:
        if not isinstance(value_node, ast.Constant) or not isinstance(value_node.value, str):
            return
        val = value_node.value
        # Only flag long enough strings that look like secrets
        if len(val) > 16 and re.search(
            r"(password|passwd|secret|api[_-]?key|token|credential|auth)", "", re.IGNORECASE
        ):
            self._add(node, "AST-PY-SEC001", "Hardcoded Secret",
                      "HIGH", f"Possible hardcoded secret value detected.")

    # ── Assert statement misuse (security bypass) ─────────────────────────────

    def visit_Assert(self, node: ast.Assert) -> None:
        # Flag assert used for authentication checks
        test_str = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
        if any(kw in test_str.lower() for kw in ("auth", "user", "admin", "login", "permission")):
            self._add(node, "AST-PY-ASSERT001",
                      "Security Check via assert (disabled in optimized mode)",
                      "MEDIUM",
                      "Security checks via `assert` are disabled when Python runs with -O. Use proper if/raise.")
        self.generic_visit(node)


def _get_call_name(node: ast.expr) -> Optional[str]:
    """Extract a dotted function name from a Call node's func attribute."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _get_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def analyze_python(content: str, rel_path: str) -> List[Dict[str, Any]]:
    """
    Parse Python source with ast and return security findings.
    Returns [] on parse error (falls back to regex scanner gracefully).
    """
    try:
        tree = ast.parse(content)
    except SyntaxError as e:
        logger.debug("AST parse failed for %s: %s", rel_path, e)
        return []

    source_lines = content.splitlines()
    visitor = PythonASTVisitor(source_lines)
    visitor.visit(tree)
    return visitor.findings


# ─── JavaScript / TypeScript Pattern-AST Hybrid ───────────────────────────────

# Patterns that indicate dangerous patterns beyond what regex rules catch
JS_ADVANCED_PATTERNS = [
    {
        "pattern": re.compile(r"eval\s*\(.*\+.*\)", re.MULTILINE),
        "rule_id": "AST-JS-EVAL001",
        "rule_name": "Dynamic eval() with string concatenation",
        "severity": "CRITICAL",
        "message": "eval() with dynamic string concatenation allows arbitrary code execution.",
    },
    {
        "pattern": re.compile(r"new\s+Function\s*\(", re.MULTILINE),
        "rule_id": "AST-JS-FUNC001",
        "rule_name": "Dynamic Function Constructor",
        "severity": "HIGH",
        "message": "new Function() is equivalent to eval(). Use static function definitions instead.",
    },
    {
        "pattern": re.compile(r"document\.write\s*\(", re.MULTILINE),
        "rule_id": "AST-JS-XSS001",
        "rule_name": "DOM XSS via document.write()",
        "severity": "HIGH",
        "message": "document.write() can introduce DOM-based XSS. Use createElement/textContent instead.",
    },
    {
        "pattern": re.compile(r"window\[.*\]\s*\(", re.MULTILINE),
        "rule_id": "AST-JS-PROTO001",
        "rule_name": "Dynamic Property Access as Function Call",
        "severity": "HIGH",
        "message": "Dynamic property access (window[variable]()) can enable Prototype Pollution attacks.",
    },
    {
        "pattern": re.compile(r"__proto__\s*:", re.MULTILINE),
        "rule_id": "AST-JS-PROTO002",
        "rule_name": "Prototype Pollution",
        "severity": "HIGH",
        "message": "__proto__ property can be used for prototype pollution attacks.",
    },
    {
        "pattern": re.compile(r"postMessage\s*\([^,]+,\s*['\"]?\*['\"]?\s*\)", re.MULTILINE),
        "rule_id": "AST-JS-MSG001",
        "rule_name": "Insecure postMessage (wildcard origin)",
        "severity": "MEDIUM",
        "message": "postMessage with '*' origin allows any site to receive the message. Specify the target origin.",
    },
    {
        "pattern": re.compile(r"localStorage\.setItem\s*\(.*(?:token|jwt|auth|session)", re.IGNORECASE | re.MULTILINE),
        "rule_id": "AST-JS-STOR001",
        "rule_name": "Sensitive Data in localStorage",
        "severity": "MEDIUM",
        "message": "Storing tokens/auth data in localStorage exposes them to XSS. Use HttpOnly cookies.",
    },
    {
        "pattern": re.compile(r"crypto\.createHash\s*\(['\"]md5['\"]", re.IGNORECASE),
        "rule_id": "AST-JS-HASH001",
        "rule_name": "Weak Hash Algorithm (MD5)",
        "severity": "MEDIUM",
        "message": "MD5 is cryptographically broken. Use SHA-256 or bcrypt for passwords.",
    },
]


def analyze_javascript(content: str, rel_path: str) -> List[Dict[str, Any]]:
    """
    Analyze JavaScript/TypeScript with advanced pattern matching.
    Returns a list of AST-level findings.
    """
    findings = []
    lines = content.splitlines()

    for rule in JS_ADVANCED_PATTERNS:
        for match in rule["pattern"].finditer(content):
            line_num = content[:match.start()].count("\n") + 1
            snippet  = lines[line_num - 1].strip() if 0 < line_num <= len(lines) else match.group(0)
            findings.append({
                "rule_id":   rule["rule_id"],
                "rule_name": rule["rule_name"],
                "severity":  rule["severity"],
                "line":      line_num,
                "col":       match.start() - content.rfind("\n", 0, match.start()) - 1,
                "message":   rule["message"],
                "snippet":   snippet,
            })

    return findings


# ─── Unified AST Entry Point ──────────────────────────────────────────────────

def analyze_with_ast(content: str, file_path: str, rel_path: str) -> List[Dict[str, Any]]:
    """
    Route file to the appropriate AST analyzer based on extension.
    Returns a (potentially empty) list of findings.
    """
    ext = Path(file_path).suffix.lower()

    if ext == ".py":
        return analyze_python(content, rel_path)
    elif ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
        return analyze_javascript(content, rel_path)
    else:
        # Not yet AST-supported — return empty (regex scanner handles it)
        return []
