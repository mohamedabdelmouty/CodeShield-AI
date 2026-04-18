/**
 * VibeGuard Rules — Python Security Rules (v2)
 *
 * Context-aware rules for Python files (.py).
 * Uses comment-stripping to eliminate false positives from:
 *   - Commented-out code (# eval(user_input))
 *   - Docstrings describing vulnerabilities
 *   - String literals that mention dangerous functions
 *
 * Covers: eval/exec injection, command injection, pickle deserialization,
 * hardcoded secrets, insecure random, SQL injection patterns, XML vulnerabilities.
 */

import { Rule, RuleContext } from '../types';
import { scanExecutableLines } from '../language-utils';

const PY_EXT = /\.py$/i;

function isPython(filePath: string): boolean {
    return PY_EXT.test(filePath);
}

// ─── Helper: scan only real code lines ───────────────────────────────────────

function scanPython(
    context: RuleContext,
    pattern: RegExp,
    report: (line: string, lineNum: number, match: RegExpMatchArray) => Parameters<RuleContext['reportVulnerability']>[0]
): void {
    if (!isPython(context.filePath)) return;

    const matches = scanExecutableLines(context.fileContent, pattern, 'hash');
    for (const { lineNum, lineContent, match } of matches) {
        context.reportVulnerability(report(lineContent, lineNum, match));
    }
}

// ─── Rules ────────────────────────────────────────────────────────────────────

const pythonEvalRule: Rule = {
    id: 'PY-001',
    name: 'Python eval/exec Injection',
    description: 'Detects use of eval() or exec() with non-literal expressions in Python code (not comments).',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['injection', 'python', 'code-execution'],
    type: 'text',
    check(context: RuleContext): void {
        scanPython(context, /\b(eval|exec)\s*\((?!['"][^'"]*['"]\s*\))/, (_line, lineNum) => ({
            ruleId: 'PY-001',
            ruleName: 'Python eval/exec Injection',
            severity: 'CRITICAL',
            message: `eval()/exec() used with dynamic input on line ${lineNum} — potential code injection.`,
            description: 'Using eval() or exec() with dynamic or user-supplied input allows arbitrary code execution.',
            remediation: 'Avoid eval()/exec() entirely. Use ast.literal_eval() for safe evaluation of literals, or refactor to avoid dynamic code execution.',
            cweId: 'CWE-95',
            owaspCategory: 'A03:2021 – Injection',
            location: { line: lineNum, column: 0 },
        }));
    },
};

const pythonCommandInjectionRule: Rule = {
    id: 'PY-002',
    name: 'Python Command Injection',
    description: 'Detects os.system or subprocess calls with shell=True in executable Python code.',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['injection', 'python', 'command-injection', 'owasp-a03'],
    type: 'text',
    check(context: RuleContext): void {
        scanPython(context, /\bos\s*\.\s*system\s*\(|\bsubprocess\s*\.\s*(call|run|Popen)\s*\(.*shell\s*=\s*True/, (_line, lineNum) => ({
            ruleId: 'PY-002',
            ruleName: 'Python Command Injection',
            severity: 'CRITICAL',
            message: `Shell command execution detected at line ${lineNum}. If user input is included, this is exploitable.`,
            description: 'os.system() and subprocess with shell=True pass arguments through the shell, enabling injection if user-controlled data is included.',
            remediation: 'Use subprocess.run() with a list of arguments (shell=False). Example: subprocess.run(["ls", "-la"], shell=False)',
            cweId: 'CWE-78',
            owaspCategory: 'A03:2021 – Injection',
            location: { line: lineNum, column: 0 },
        }));
    },
};

const pythonPickleRule: Rule = {
    id: 'PY-003',
    name: 'Python Insecure Deserialization (pickle)',
    description: 'Detects use of pickle.loads() or pickle.load() in real executable code.',
    severity: 'HIGH',
    enabled: true,
    tags: ['deserialization', 'python', 'owasp-a08'],
    type: 'text',
    check(context: RuleContext): void {
        scanPython(context, /\bpickle\s*\.\s*loads?\s*\(/, (_line, lineNum) => ({
            ruleId: 'PY-003',
            ruleName: 'Python Insecure Deserialization (pickle)',
            severity: 'HIGH',
            message: `pickle.load/loads() at line ${lineNum} — deserializing untrusted data can execute arbitrary code.`,
            description: "Python's pickle module can execute arbitrary code during deserialization. Never unpickle data from untrusted sources.",
            remediation: 'Use JSON, MessagePack, or other safe serialization formats. If pickle is required, use HMAC signatures to verify data integrity before deserializing.',
            cweId: 'CWE-502',
            owaspCategory: 'A08:2021 – Software and Data Integrity Failures',
            location: { line: lineNum, column: 0 },
        }));
    },
};

const pythonSqlInjectionRule: Rule = {
    id: 'PY-004',
    name: 'Python SQL Injection',
    description: 'Detects SQL queries built with string formatting/concatenation in executable Python code.',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['injection', 'sql', 'python', 'owasp-a03'],
    type: 'text',
    check(context: RuleContext): void {
        scanPython(
            context,
            /(?:query|sql|cursor\.execute)\s*(?:=|\()\s*(?:f['"]|['"][^'"]*['"\\s]*%\s*\(|['"][^'"]*['"\\s]*\.format\s*\(|[^'"]*\+\s*(?:user|input|request|param|id|name))/i,
            (_line, lineNum) => ({
                ruleId: 'PY-004',
                ruleName: 'Python SQL Injection',
                severity: 'CRITICAL',
                message: `SQL query with dynamic string construction at line ${lineNum}.`,
                description: 'Building SQL queries with f-strings, % formatting, or .format() introduces SQL injection vulnerabilities.',
                remediation: 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                cweId: 'CWE-89',
                owaspCategory: 'A03:2021 – Injection',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

const pythonHardcodedSecretRule: Rule = {
    id: 'PY-005',
    name: 'Python Hardcoded Secret',
    description: 'Detects hardcoded passwords, API keys, or secrets in Python files.',
    severity: 'HIGH',
    enabled: true,
    tags: ['secrets', 'python', 'credentials', 'owasp-a02'],
    type: 'text',
    check(context: RuleContext): void {
        scanPython(
            context,
            /(?:password|passwd|secret|api_key|apikey|token|auth_token|private_key)\s*=\s*['"][^'"]{4,}['"]/i,
            (_line, lineNum) => ({
                ruleId: 'PY-005',
                ruleName: 'Python Hardcoded Secret',
                severity: 'HIGH',
                message: `Possible hardcoded credential at line ${lineNum}.`,
                description: 'Hardcoded secrets in source code are a major security risk if the repository is exposed.',
                remediation: 'Use environment variables: import os; password = os.environ.get("PASSWORD"). Consider python-dotenv or a secrets manager.',
                cweId: 'CWE-798',
                owaspCategory: 'A02:2021 – Cryptographic Failures',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

const pythonXmlRule: Rule = {
    id: 'PY-006',
    name: 'Python XML External Entity (XXE)',
    description: 'Detects use of unsafe XML parsers vulnerable to XXE attacks.',
    severity: 'HIGH',
    enabled: true,
    tags: ['xxe', 'python', 'xml', 'owasp-a05'],
    type: 'text',
    check(context: RuleContext): void {
        scanPython(
            context,
            /\b(?:xml\.etree|minidom|expat|lxml\.etree).*parse\b|\bElementTree\s*\(\s*file/i,
            (_line, lineNum) => ({
                ruleId: 'PY-006',
                ruleName: 'Python XML External Entity (XXE)',
                severity: 'HIGH',
                message: `Potentially unsafe XML parsing at line ${lineNum}. May be vulnerable to XXE.`,
                description: 'Default XML parsers in Python may process external entities, allowing XXE attacks that can read arbitrary files.',
                remediation: 'Use defusedxml library: import defusedxml.ElementTree as ET. Or disable external entity processing manually.',
                cweId: 'CWE-611',
                owaspCategory: 'A05:2021 – Security Misconfiguration',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

const pythonInsecureRandomRule: Rule = {
    id: 'PY-007',
    name: 'Python Insecure Random',
    description: 'Detects use of the random module for security-sensitive operations in real code.',
    severity: 'MEDIUM',
    enabled: true,
    tags: ['cryptography', 'python', 'random'],
    type: 'text',
    check(context: RuleContext): void {
        scanPython(
            context,
            /\brandom\s*\.\s*(?:random|randint|choice|shuffle|sample|seed)\s*\(/,
            (_line, lineNum) => ({
                ruleId: 'PY-007',
                ruleName: 'Python Insecure Random',
                severity: 'MEDIUM',
                message: `random module used at line ${lineNum}. Not suitable for cryptographic operations.`,
                description: 'The random module is not cryptographically secure and should not be used for generating tokens, passwords, or session IDs.',
                remediation: 'Use secrets module: import secrets; token = secrets.token_hex(32). Or use os.urandom() for raw bytes.',
                cweId: 'CWE-338',
                owaspCategory: 'A02:2021 – Cryptographic Failures',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

const pythonOpenRedirectRule: Rule = {
    id: 'PY-008',
    name: 'Python Open Redirect',
    description: 'Detects potential open redirects in Flask/Django request handlers.',
    severity: 'MEDIUM',
    enabled: true,
    tags: ['redirect', 'python', 'web', 'owasp-a01'],
    type: 'text',
    check(context: RuleContext): void {
        scanPython(
            context,
            /redirect\s*\(\s*request\s*\.\s*(?:args|form|get)\s*\[/i,
            (_line, lineNum) => ({
                ruleId: 'PY-008',
                ruleName: 'Python Open Redirect',
                severity: 'MEDIUM',
                message: `Potential open redirect using user-supplied URL at line ${lineNum}.`,
                description: 'Redirecting to a URL directly from user input enables phishing and credential theft.',
                remediation: 'Validate the redirect URL against a whitelist of allowed domains before redirecting.',
                cweId: 'CWE-601',
                owaspCategory: 'A01:2021 – Broken Access Control',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

const pythonRules: Rule[] = [
    pythonEvalRule,
    pythonCommandInjectionRule,
    pythonPickleRule,
    pythonSqlInjectionRule,
    pythonHardcodedSecretRule,
    pythonXmlRule,
    pythonInsecureRandomRule,
    pythonOpenRedirectRule,
];

export default pythonRules;
