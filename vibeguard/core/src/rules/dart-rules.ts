/**
 * VibeGuard Rules — Dart Security Rules
 *
 * Text-based regex rules for Dart files (.dart).
 * Covers: command injection, insecure HTTP, SSL bypass, hardcoded secrets,
 * insecure random, SQL injection, path traversal, and eval-equivalent patterns.
 */

import { Rule, RuleContext } from '../types';

const DART_EXT = /\.dart$/i;

// ─── Helper ───────────────────────────────────────────────────────────────────

function isDart(filePath: string): boolean {
    return DART_EXT.test(filePath);
}

function scanLines(
    context: RuleContext,
    pattern: RegExp,
    report: (line: string, lineNum: number, match: RegExpMatchArray) => Parameters<RuleContext['reportVulnerability']>[0]
): void {
    if (!isDart(context.filePath)) return;
    const lines = context.fileContent.split('\n');
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const match = line.match(pattern);
        if (match) {
            context.reportVulnerability(report(line, i + 1, match));
        }
    }
}

// ─── Rules ────────────────────────────────────────────────────────────────────

/**
 * DART-001: Command Injection via Process.run / Process.start
 * Using user-controlled arguments in Process execution can lead to arbitrary command execution.
 */
const dartCommandInjectionRule: Rule = {
    id: 'DART-001',
    name: 'Dart Command Injection',
    description: 'Detects use of Process.run() or Process.start() which may execute untrusted commands.',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['dart', 'injection', 'command-injection', 'owasp-a03'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(
            context,
            /\bProcess\s*\.\s*(run|start|runSync)\s*\(/,
            (_line, lineNum) => ({
                ruleId: 'DART-001',
                ruleName: 'Dart Command Injection',
                severity: 'CRITICAL',
                message: `Process execution detected at line ${lineNum}. Ensure arguments are not user-controlled.`,
                description: 'Process.run() and Process.start() execute shell commands. Passing untrusted input as arguments enables command injection.',
                remediation: 'Always pass arguments as a fixed list, never concatenate user input into command strings. Validate and sanitize all inputs before execution.',
                cweId: 'CWE-78',
                owaspCategory: 'A03:2021 – Injection',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

/**
 * DART-002: Insecure HTTP (non-HTTPS)
 * Using plain HTTP exposes data to man-in-the-middle attacks.
 */
const dartInsecureHttpRule: Rule = {
    id: 'DART-002',
    name: 'Dart Insecure HTTP Usage',
    description: 'Detects plain HTTP URLs in Dart code which transmit data unencrypted.',
    severity: 'HIGH',
    enabled: true,
    tags: ['dart', 'network', 'tls', 'owasp-a02'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(
            context,
            /['"]http:\/\/(?!localhost|127\.0\.0\.1)/i,
            (_line, lineNum) => ({
                ruleId: 'DART-002',
                ruleName: 'Dart Insecure HTTP Usage',
                severity: 'HIGH',
                message: `Plain HTTP URL found at line ${lineNum}. Data is transmitted without encryption.`,
                description: 'Using HTTP instead of HTTPS exposes data to interception and man-in-the-middle attacks.',
                remediation: 'Replace all http:// URLs with https://. Enable network security config to block cleartext traffic.',
                cweId: 'CWE-319',
                owaspCategory: 'A02:2021 – Cryptographic Failures',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

/**
 * DART-003: SSL/TLS Certificate Verification Bypass
 * Disabling certificate checks exposes the app to MITM attacks.
 */
const dartSslBypassRule: Rule = {
    id: 'DART-003',
    name: 'Dart SSL Certificate Bypass',
    description: 'Detects disabled SSL/TLS certificate verification in HttpClient.',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['dart', 'tls', 'ssl', 'network', 'owasp-a02'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(
            context,
            /badCertificateCallback\s*=\s*\([^)]*\)\s*=>\s*true|badCertificateCallback\s*=\s*\(_[^)]*\)\s*\{?\s*return\s+true/,
            (_line, lineNum) => ({
                ruleId: 'DART-003',
                ruleName: 'Dart SSL Certificate Bypass',
                severity: 'CRITICAL',
                message: `SSL certificate verification disabled at line ${lineNum}. All certificates are accepted including invalid ones.`,
                description: 'Setting badCertificateCallback to always return true disables certificate validation, making the app vulnerable to man-in-the-middle attacks.',
                remediation: 'Remove the badCertificateCallback override or implement proper certificate pinning. Never return true for all certificates in production.',
                cweId: 'CWE-295',
                owaspCategory: 'A02:2021 – Cryptographic Failures',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

/**
 * DART-004: Hardcoded Secrets / Credentials
 * Hardcoding API keys, passwords, or tokens in Dart source exposes them.
 */
const dartHardcodedSecretRule: Rule = {
    id: 'DART-004',
    name: 'Dart Hardcoded Secret',
    description: 'Detects hardcoded passwords, API keys, or secret tokens in Dart files.',
    severity: 'HIGH',
    enabled: true,
    tags: ['dart', 'secrets', 'credentials', 'owasp-a02'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(
            context,
            /(?:password|passwd|secret|apiKey|api_key|token|authToken|auth_token|privateKey|private_key|clientSecret|client_secret)\s*=\s*['"][^'"]{4,}['"]/i,
            (_line, lineNum) => ({
                ruleId: 'DART-004',
                ruleName: 'Dart Hardcoded Secret',
                severity: 'HIGH',
                message: `Possible hardcoded credential or secret at line ${lineNum}.`,
                description: 'Hardcoded secrets in Dart source code are exposed to anyone with access to the compiled binary or the repository.',
                remediation: 'Use Flutter\'s --dart-define for build-time secrets, or load credentials from a secure backend. Never hardcode secrets in source code.',
                cweId: 'CWE-798',
                owaspCategory: 'A02:2021 – Cryptographic Failures',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

/**
 * DART-005: Insecure Random Number Generation
 * math.Random() is not cryptographically secure.
 */
const dartInsecureRandomRule: Rule = {
    id: 'DART-005',
    name: 'Dart Insecure Random',
    description: 'Detects use of dart:math Random for security-sensitive operations.',
    severity: 'MEDIUM',
    enabled: true,
    tags: ['dart', 'cryptography', 'random', 'owasp-a02'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(
            context,
            /\bRandom\s*\(\s*\)\s*\.\s*(nextInt|nextDouble|nextBool)|new\s+Random\s*\(/,
            (_line, lineNum) => ({
                ruleId: 'DART-005',
                ruleName: 'Dart Insecure Random',
                severity: 'MEDIUM',
                message: `math.Random() used at line ${lineNum}. Not suitable for cryptographic operations.`,
                description: 'The dart:math Random class is a pseudo-random number generator and should not be used for security-sensitive purposes like generating tokens or session IDs.',
                remediation: 'Use dart:math Random.secure() for cryptographically secure random numbers: final random = Random.secure(); Or use the crypto package for hashing.',
                cweId: 'CWE-338',
                owaspCategory: 'A02:2021 – Cryptographic Failures',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

/**
 * DART-006: SQL Injection via rawQuery / rawInsert
 * Building raw SQL queries with string interpolation is dangerous.
 */
const dartSqlInjectionRule: Rule = {
    id: 'DART-006',
    name: 'Dart SQL Injection',
    description: 'Detects raw SQL queries built with string interpolation in Dart (sqflite).',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['dart', 'sql', 'injection', 'owasp-a03'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(
            context,
            /\b(?:rawQuery|rawInsert|rawUpdate|rawDelete|execute)\s*\(\s*['"`][^'"`)]*\$[^'"`)]*['"`]/,
            (_line, lineNum) => ({
                ruleId: 'DART-006',
                ruleName: 'Dart SQL Injection',
                severity: 'CRITICAL',
                message: `Raw SQL query with string interpolation at line ${lineNum}.`,
                description: 'Using Dart string interpolation ($variable) inside raw SQL queries allows SQL injection if variables contain user input.',
                remediation: 'Use parameterized queries in sqflite: db.rawQuery("SELECT * FROM t WHERE id = ?", [userId]). Never interpolate user input into SQL strings.',
                cweId: 'CWE-89',
                owaspCategory: 'A03:2021 – Injection',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

/**
 * DART-007: Path Traversal via File operations
 * Using user input in file paths can allow directory traversal attacks.
 */
const dartPathTraversalRule: Rule = {
    id: 'DART-007',
    name: 'Dart Path Traversal',
    description: 'Detects potentially unsafe File() or Directory() construction with dynamic paths.',
    severity: 'HIGH',
    enabled: true,
    tags: ['dart', 'path-traversal', 'file', 'owasp-a01'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(
            context,
            /\bFile\s*\(\s*['"`][^'"}`]*\$[^'"}`]*['"`]\s*\)|\bDirectory\s*\(\s*['"`][^'"}`]*\$[^'"}`]*['"`]\s*\)/,
            (_line, lineNum) => ({
                ruleId: 'DART-007',
                ruleName: 'Dart Path Traversal',
                severity: 'HIGH',
                message: `Dynamic file path construction detected at line ${lineNum}. May be vulnerable to path traversal.`,
                description: 'Constructing file paths with user-controlled input using string interpolation can allow attackers to access files outside the intended directory.',
                remediation: 'Use path.normalize() and validate that the resolved path starts with the expected base directory. Reject any path containing ".." sequences.',
                cweId: 'CWE-22',
                owaspCategory: 'A01:2021 – Broken Access Control',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

/**
 * DART-008: SharedPreferences for Sensitive Data
 * SharedPreferences stores data unencrypted on disk — not safe for secrets.
 */
const dartInsecureStorageRule: Rule = {
    id: 'DART-008',
    name: 'Dart Insecure Local Storage',
    description: 'Detects use of SharedPreferences for potentially sensitive data.',
    severity: 'MEDIUM',
    enabled: true,
    tags: ['dart', 'flutter', 'storage', 'owasp-a02'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(
            context,
            /SharedPreferences.*\.\s*set(?:String|Int|Bool|Double)\s*\(\s*['"][^'"]*(?:password|secret|token|key|auth|credential)[^'"]*['"]/i,
            (_line, lineNum) => ({
                ruleId: 'DART-008',
                ruleName: 'Dart Insecure Local Storage',
                severity: 'MEDIUM',
                message: `Sensitive data stored in SharedPreferences at line ${lineNum}. Data is unencrypted on disk.`,
                description: 'SharedPreferences stores data in plain text XML files. Storing passwords, tokens, or keys here exposes them to anyone with root access or file backup access.',
                remediation: 'Use the flutter_secure_storage package for sensitive credentials. It uses the OS Keychain (iOS) and Android Keystore for encrypted storage.',
                cweId: 'CWE-312',
                owaspCategory: 'A02:2021 – Cryptographic Failures',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

/**
 * DART-009: Logging Sensitive Information
 * Printing sensitive data to logs can expose it in production.
 */
const dartSensitiveLogRule: Rule = {
    id: 'DART-009',
    name: 'Dart Sensitive Data in Logs',
    description: 'Detects printing of potentially sensitive data using print() or debugPrint().',
    severity: 'LOW',
    enabled: true,
    tags: ['dart', 'logging', 'information-disclosure', 'owasp-a09'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(
            context,
            /\b(?:print|debugPrint|log)\s*\([^)]*(?:password|passwd|secret|token|apiKey|api_key|auth)[^)]*\)/i,
            (_line, lineNum) => ({
                ruleId: 'DART-009',
                ruleName: 'Dart Sensitive Data in Logs',
                severity: 'LOW',
                message: `Potentially sensitive data logged at line ${lineNum}.`,
                description: 'Printing sensitive information like passwords or tokens to logs can expose them in logcat, crash reports, or monitoring tools.',
                remediation: 'Remove logging of sensitive data in production code. Use conditional logging (kDebugMode) during development only.',
                cweId: 'CWE-532',
                owaspCategory: 'A09:2021 – Security Logging and Monitoring Failures',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

/**
 * DART-010: Implicit HttpClient with no security config
 * Creating HttpClient without configuring security settings may use defaults.
 */
const dartHttpClientRule: Rule = {
    id: 'DART-010',
    name: 'Dart Unconfigured HttpClient',
    description: 'Detects HttpClient instantiation that may lack security configuration.',
    severity: 'LOW',
    enabled: true,
    tags: ['dart', 'network', 'tls', 'owasp-a05'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(
            context,
            /\bHttpClient\s*\(\s*\)/,
            (_line, lineNum) => ({
                ruleId: 'DART-010',
                ruleName: 'Dart Unconfigured HttpClient',
                severity: 'LOW',
                message: `HttpClient created at line ${lineNum}. Ensure proper TLS and certificate settings are configured.`,
                description: 'Creating an HttpClient without explicit security configuration may result in insecure defaults in some environments.',
                remediation: 'Configure the HttpClient with appropriate security settings. Consider using the http or dio packages which provide safer defaults and interceptors.',
                cweId: 'CWE-16',
                owaspCategory: 'A05:2021 – Security Misconfiguration',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

// ─── Registry ─────────────────────────────────────────────────────────────────

const dartRules: Rule[] = [
    dartCommandInjectionRule,
    dartInsecureHttpRule,
    dartSslBypassRule,
    dartHardcodedSecretRule,
    dartInsecureRandomRule,
    dartSqlInjectionRule,
    dartPathTraversalRule,
    dartInsecureStorageRule,
    dartSensitiveLogRule,
    dartHttpClientRule,
];

export default dartRules;
