"""
CodeShield AI — Security Detection Rules (Python-native)
Mirrors VibeGuard core's detection patterns across multiple languages.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class SecurityRule:
    id: str
    name: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    pattern: re.Pattern
    message: str
    remediation: str
    remediation_code: Optional[str]
    cwe_id: Optional[str]
    owasp_category: Optional[str]
    explain_why: str
    languages: List[str]   # file extensions this rule applies to


def _r(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern:
    return re.compile(pattern, flags)


RULES: List[SecurityRule] = [

    # ─── SQL Injection ─────────────────────────────────────────────────────────
    SecurityRule(
        id="CS-SQL-001",
        name="SQL Injection via String Concatenation",
        severity="CRITICAL",
        pattern=_r(r'(execute|query|cursor\.execute|db\.query|connection\.execute)\s*\(\s*["\'].*\+|f["\'].*SELECT|f["\'].*INSERT|f["\'].*UPDATE|f["\'].*DELETE'),
        message="Detected SQL query built using string concatenation or f-string. This allows attackers to inject malicious SQL.",
        remediation="Use parameterized queries / prepared statements instead of string formatting.",
        remediation_code='# BAD:  cursor.execute("SELECT * FROM users WHERE id=" + user_id)\n# GOOD: cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))',
        cwe_id="CWE-89",
        owasp_category="A03:2021 Injection",
        explain_why="SQL Injection is the #1 most exploited web vulnerability. By injecting ' OR '1'='1 an attacker can bypass authentication, dump entire databases, or delete data.",
        languages=["py", "php", "java", "js", "ts", "rb"],
    ),

    # ─── XSS ───────────────────────────────────────────────────────────────────
    SecurityRule(
        id="CS-XSS-001",
        name="Cross-Site Scripting (XSS) — innerHTML",
        severity="HIGH",
        pattern=_r(r'\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\('),
        message="Directly setting innerHTML with user data enables XSS attacks.",
        remediation="Use textContent for plain text, or DOMPurify to sanitize HTML before insertion.",
        remediation_code='// BAD:  el.innerHTML = userInput;\n// GOOD: el.textContent = userInput;\n// GOOD: el.innerHTML = DOMPurify.sanitize(userInput);',
        cwe_id="CWE-79",
        owasp_category="A03:2021 Injection",
        explain_why="XSS lets attackers inject JavaScript into your page to steal session cookies, redirect users to phishing sites, or perform actions on behalf of victims.",
        languages=["js", "ts", "jsx", "tsx", "html"],
    ),

    SecurityRule(
        id="CS-XSS-002",
        name="Cross-Site Scripting — dangerouslySetInnerHTML",
        severity="HIGH",
        pattern=_r(r'dangerouslySetInnerHTML\s*=\s*\{'),
        message="dangerouslySetInnerHTML bypasses React's XSS protection. Ensure input is sanitized.",
        remediation="Sanitize input with DOMPurify before using dangerouslySetInnerHTML, or avoid it entirely.",
        remediation_code=None,
        cwe_id="CWE-79",
        owasp_category="A03:2021 Injection",
        explain_why="React's dangerouslySetInnerHTML intentionally bypasses its XSS protections. Any unsanitized user content will be executed as HTML/JS.",
        languages=["js", "ts", "jsx", "tsx"],
    ),

    # ─── Hardcoded Secrets ─────────────────────────────────────────────────────
    SecurityRule(
        id="CS-SEC-001",
        name="Hardcoded API Key / Secret",
        severity="CRITICAL",
        pattern=_r(r'(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[=:]\s*["\'][A-Za-z0-9+/\-_]{20,}["\']'),
        message="Hardcoded credential or API key detected. Secrets must never be committed to source code.",
        remediation="Store secrets in environment variables or a secrets manager (e.g., AWS Secrets Manager, Vault).",
        remediation_code='# BAD:  api_key = "sk-abc123xyz789..."\n# GOOD: api_key = os.environ["API_KEY"]',
        cwe_id="CWE-798",
        owasp_category="A07:2021 Identification and Authentication Failures",
        explain_why="Hardcoded secrets in source code are trivially discoverable via GitHub search, git history, or decompilation. Attackers automate scanning for these patterns.",
        languages=["py", "js", "ts", "java", "rb", "go", "php", "cs", "cpp", "c"],
    ),

    SecurityRule(
        id="CS-SEC-002",
        name="Hardcoded Password",
        severity="CRITICAL",
        pattern=_r(r'password\s*[=:]\s*["\'][^"\']{6,}["\']'),
        message="Hardcoded password found in source code.",
        remediation="Use environment variables or a secrets manager. Never store passwords in code.",
        remediation_code='# BAD:  password = "SuperSecret123"\n# GOOD: password = os.environ["DB_PASSWORD"]',
        cwe_id="CWE-259",
        owasp_category="A07:2021 Identification and Authentication Failures",
        explain_why="Hardcoded passwords cannot be rotated without a code change and deployment. They are permanently stored in git history even after deletion.",
        languages=["py", "js", "ts", "java", "rb", "go", "php", "cs"],
    ),

    # ─── Insecure Functions ────────────────────────────────────────────────────
    SecurityRule(
        id="CS-EXEC-001",
        name="Dangerous eval() Usage",
        severity="HIGH",
        pattern=_r(r'\beval\s*\('),
        message="Use of eval() can execute arbitrary code injected by attackers.",
        remediation="Avoid eval() entirely. Use JSON.parse() for JSON, or safer alternatives.",
        remediation_code='// BAD:  eval(userInput);\n// GOOD: JSON.parse(userInput);',
        cwe_id="CWE-95",
        owasp_category="A03:2021 Injection",
        explain_why="eval() interprets its argument as code. If user input reaches eval(), attackers can execute arbitrary commands on your server or steal data from browsers.",
        languages=["js", "ts", "jsx", "tsx", "py", "php", "rb"],
    ),

    SecurityRule(
        id="CS-EXEC-002",
        name="OS Command Injection",
        severity="CRITICAL",
        pattern=_r(r'(os\.system|subprocess\.call|subprocess\.run|exec\s*\(|shell_exec|popen)\s*\(\s*[^)]*(\+|format|f["\'])'),
        message="OS command built with user-controlled data. Attackers can inject arbitrary shell commands.",
        remediation="Use subprocess with a list of arguments (no shell=True) and never include user input in commands.",
        remediation_code='# BAD:  os.system("ls " + user_dir)\n# GOOD: subprocess.run(["ls", user_dir], shell=False)',
        cwe_id="CWE-78",
        owasp_category="A03:2021 Injection",
        explain_why="Command injection allows attackers to run any OS command on your server — reading /etc/passwd, installing backdoors, exfiltrating data, or destroying the system.",
        languages=["py", "php", "rb", "java"],
    ),

    # ─── Path Traversal ────────────────────────────────────────────────────────
    SecurityRule(
        id="CS-PATH-001",
        name="Path Traversal Vulnerability",
        severity="HIGH",
        pattern=_r(r'(open|readfile|include|require|file_get_contents)\s*\(\s*[^)]*(\+|\.format|f["\'])'),
        message="File path built with user input may allow path traversal (../../etc/passwd).",
        remediation="Validate and sanitize file paths. Use os.path.realpath() and verify the resolved path is within the expected directory.",
        remediation_code='# BAD:  open(base_dir + user_file)\n# GOOD: safe = os.path.realpath(os.path.join(base_dir, user_file))\n#        assert safe.startswith(base_dir)',
        cwe_id="CWE-22",
        owasp_category="A01:2021 Broken Access Control",
        explain_why="Path traversal lets attackers read sensitive files outside the web root like /etc/passwd, SSH keys, or application config files.",
        languages=["py", "php", "js", "ts", "java", "rb"],
    ),

    # ─── Insecure Random ───────────────────────────────────────────────────────
    SecurityRule(
        id="CS-RAND-001",
        name="Insecure Random Number Generator",
        severity="MEDIUM",
        pattern=_r(r'\b(Math\.random|random\.random|rand\(\)|mt_rand)\s*\('),
        message="Non-cryptographic random number generator used. Predictable output is unsuitable for security tokens.",
        remediation="Use a cryptographically secure PRNG: secrets.token_hex() (Python) or crypto.randomBytes() (Node.js).",
        remediation_code='# BAD:  token = str(random.random())\n# GOOD: import secrets; token = secrets.token_hex(32)',
        cwe_id="CWE-338",
        owasp_category="A02:2021 Cryptographic Failures",
        explain_why="Predictable random numbers make session tokens, CSRF tokens, and password reset links guessable. Attackers can enumerate or predict values to hijack accounts.",
        languages=["py", "js", "ts", "php", "rb"],
    ),

    # ─── Insecure Deserialization ──────────────────────────────────────────────
    SecurityRule(
        id="CS-DESER-001",
        name="Insecure Deserialization",
        severity="CRITICAL",
        pattern=_r(r'\b(pickle\.loads|pickle\.load|yaml\.load\s*\([^,)]+\)|unserialize\s*\(|ObjectInputStream)'),
        message="Unsafe deserialization detected. Deserializing untrusted data can lead to Remote Code Execution.",
        remediation="Use safe alternatives: yaml.safe_load() instead of yaml.load(), avoid pickle with user data, use JSON for data exchange.",
        remediation_code='# BAD:  data = pickle.loads(user_input)\n# BAD:  data = yaml.load(stream)  # vulnerable\n# GOOD: data = yaml.safe_load(stream)',
        cwe_id="CWE-502",
        owasp_category="A08:2021 Software and Data Integrity Failures",
        explain_why="Insecure deserialization allows attackers to craft malicious serialized objects that execute arbitrary code when deserialized — a common path to full server compromise.",
        languages=["py", "php", "java", "rb"],
    ),

    # ─── SSRF ─────────────────────────────────────────────────────────────────
    SecurityRule(
        id="CS-SSRF-001",
        name="Server-Side Request Forgery (SSRF)",
        severity="HIGH",
        pattern=_r(r'(requests\.get|requests\.post|urllib\.request|fetch|axios\.get|axios\.post|http\.get)\s*\(\s*[^)]*(\+|format|f["\'])'),
        message="HTTP request URL constructed from user input may enable SSRF attacks.",
        remediation="Validate and allowlist URLs. Never forward user-supplied URLs directly to HTTP clients.",
        remediation_code='# BAD:  requests.get(user_url)\n# GOOD: ALLOWED = ["https://api.example.com"]\n#        assert user_url in ALLOWED\n#        requests.get(user_url)',
        cwe_id="CWE-918",
        owasp_category="A10:2021 Server-Side Request Forgery",
        explain_why="SSRF allows attackers to make your server fetch internal resources like AWS metadata (http://169.254.169.254), internal databases, or other microservices.",
        languages=["py", "js", "ts", "php", "rb", "java"],
    ),

    # ─── Weak Cryptography ────────────────────────────────────────────────────
    SecurityRule(
        id="CS-CRYPTO-001",
        name="Weak Cryptographic Algorithm",
        severity="HIGH",
        pattern=_r(r'\b(MD5|SHA1|DES|RC4|hashlib\.md5|hashlib\.sha1|createHash\(["\']md5|createHash\(["\']sha1)\b'),
        message="Weak or broken cryptographic algorithm detected (MD5/SHA1/DES/RC4).",
        remediation="Use SHA-256 or stronger. For passwords, use bcrypt, scrypt, or Argon2.",
        remediation_code='# BAD:  hashlib.md5(password)\n# GOOD: hashlib.sha256(password)\n# BEST: bcrypt.hashpw(password, bcrypt.gensalt())',
        cwe_id="CWE-327",
        owasp_category="A02:2021 Cryptographic Failures",
        explain_why="MD5 and SHA1 are cryptographically broken. MD5 collisions can be computed in seconds. Passwords hashed with MD5 are trivially cracked with rainbow tables.",
        languages=["py", "js", "ts", "java", "php", "rb", "go"],
    ),

    # ─── Debug/Logging Secrets ────────────────────────────────────────────────
    SecurityRule(
        id="CS-LOG-001",
        name="Sensitive Data in Logs",
        severity="MEDIUM",
        pattern=_r(r'(print|console\.log|logger\.\w+|logging\.\w+)\s*\([^)]*(?:password|token|secret|key|credential)[^)]*\)'),
        message="Potentially sensitive data (password/token/secret) being logged.",
        remediation="Never log sensitive data. Mask or omit credentials in log statements.",
        remediation_code='# BAD:  print(f"Login: user={user}, password={password}")\n# GOOD: print(f"Login attempt for user={user}")',
        cwe_id="CWE-532",
        owasp_category="A09:2021 Security Logging and Monitoring Failures",
        explain_why="Log files are often stored insecurely, rotated to cold storage, or accessible to support teams. Logging passwords means they can be extracted from log management systems.",
        languages=["py", "js", "ts", "java", "go", "rb", "php"],
    ),
]

# Lookup by extension → applicable rules
_EXT_RULE_MAP: dict[str, List[SecurityRule]] = {}
for _rule in RULES:
    for _ext in _rule.languages:
        _EXT_RULE_MAP.setdefault(_ext, []).append(_rule)


def get_rules_for_extension(ext: str) -> List[SecurityRule]:
    """Return all rules that apply to a given file extension."""
    ext = ext.lower().lstrip(".")
    return _EXT_RULE_MAP.get(ext, [])
