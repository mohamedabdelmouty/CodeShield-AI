/**
 * VibeGuard Rules — Java Security Rules
 *
 * Text-based rules for Java files (.java).
 * Covers: SQL injection, command injection, deserialization, XXE,
 * hardcoded secrets, path traversal, insecure crypto.
 */

import { Rule, RuleContext } from '../types';

const JAVA_EXT = /\.java$/i;

function isJava(filePath: string): boolean {
    return JAVA_EXT.test(filePath);
}

function scanLines(
    context: RuleContext,
    pattern: RegExp,
    report: (line: string, lineNum: number, match: RegExpMatchArray) => Parameters<RuleContext['reportVulnerability']>[0]
): void {
    if (!isJava(context.filePath)) return;
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

const javaSqlInjectionRule: Rule = {
    id: 'JAVA-001',
    name: 'Java SQL Injection',
    description: 'Detects SQL queries built with string concatenation in Java.',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['injection', 'sql', 'java', 'owasp-a03'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(context, /(?:Statement|createStatement|executeQuery|executeUpdate)\s*\(.*\+/, (_line, lineNum) => ({
            ruleId: 'JAVA-001',
            ruleName: 'Java SQL Injection',
            severity: 'CRITICAL',
            message: `SQL query with string concatenation at line ${lineNum}.`,
            description: 'Building SQL queries with string concatenation in Java allows SQL injection attacks.',
            remediation: 'Use PreparedStatement with parameterized queries: PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setInt(1, userId);',
            cweId: 'CWE-89',
            owaspCategory: 'A03:2021 – Injection',
            location: { line: lineNum, column: 0 },
        }));
    },
};

const javaCommandInjectionRule: Rule = {
    id: 'JAVA-002',
    name: 'Java Command Injection',
    description: 'Detects Runtime.exec() or ProcessBuilder with dynamic arguments.',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['injection', 'java', 'command-injection', 'owasp-a03'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(context, /Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|new\s+ProcessBuilder\s*\(/, (_line, lineNum) => ({
            ruleId: 'JAVA-002',
            ruleName: 'Java Command Injection',
            severity: 'CRITICAL',
            message: `System command execution at line ${lineNum}. Verify input is not user-controlled.`,
            description: 'Runtime.exec() and ProcessBuilder can execute arbitrary system commands if user input is included without sanitization.',
            remediation: 'Validate and whitelist command arguments. Avoid passing user input directly to system commands. Use ProcessBuilder with fixed argument lists.',
            cweId: 'CWE-78',
            owaspCategory: 'A03:2021 – Injection',
            location: { line: lineNum, column: 0 },
        }));
    },
};

const javaDeserializationRule: Rule = {
    id: 'JAVA-003',
    name: 'Java Insecure Deserialization',
    description: 'Detects ObjectInputStream.readObject() which can lead to remote code execution.',
    severity: 'HIGH',
    enabled: true,
    tags: ['deserialization', 'java', 'owasp-a08'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(context, /ObjectInputStream|\.readObject\s*\(/, (_line, lineNum) => ({
            ruleId: 'JAVA-003',
            ruleName: 'Java Insecure Deserialization',
            severity: 'HIGH',
            message: `Java deserialization at line ${lineNum}. Deserializing untrusted data can lead to RCE.`,
            description: 'Java native serialization via ObjectInputStream is notoriously vulnerable to gadget chain attacks that lead to remote code execution.',
            remediation: 'Use a safe serialization format (JSON, Protobuf). If native serialization is required, use ObjectInputFilter (Java 9+) to whitelist allowed classes.',
            cweId: 'CWE-502',
            owaspCategory: 'A08:2021 – Software and Data Integrity Failures',
            location: { line: lineNum, column: 0 },
        }));
    },
};

const javaXxeRule: Rule = {
    id: 'JAVA-004',
    name: 'Java XML External Entity (XXE)',
    description: 'Detects XML parsers without safe configuration.',
    severity: 'HIGH',
    enabled: true,
    tags: ['xxe', 'java', 'xml', 'owasp-a05'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(context, /DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory/, (_line, lineNum) => {
            // Check if there's feature disabling nearby (simplified)
            const content = context.fileContent;
            const hasDisable = content.includes('FEATURE_SECURE_PROCESSING') ||
                content.includes('disallow-doctype-decl') ||
                content.includes('external-general-entities');
            if (hasDisable) return null as any; // Skip if already configured
            return {
                ruleId: 'JAVA-004',
                ruleName: 'Java XML External Entity (XXE)',
                severity: 'HIGH',
                message: `XML parser created at line ${lineNum} without visible XXE protection.`,
                description: 'Java XML parsers process external entities by default, making them vulnerable to XXE attacks that can read local files and perform SSRF.',
                remediation: 'Set factory features: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);',
                cweId: 'CWE-611',
                owaspCategory: 'A05:2021 – Security Misconfiguration',
                location: { line: lineNum, column: 0 },
            };
        });
    },
};

const javaHardcodedSecretRule: Rule = {
    id: 'JAVA-005',
    name: 'Java Hardcoded Secret',
    description: 'Detects hardcoded passwords, keys, and tokens in Java code.',
    severity: 'HIGH',
    enabled: true,
    tags: ['secrets', 'java', 'credentials', 'owasp-a02'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(
            context,
            /(?:password|passwd|secret|apiKey|api_key|token|authToken|privateKey)\s*=\s*"[^"]{4,}"/i,
            (_line, lineNum) => ({
                ruleId: 'JAVA-005',
                ruleName: 'Java Hardcoded Secret',
                severity: 'HIGH',
                message: `Possible hardcoded credential at line ${lineNum}.`,
                description: 'Hardcoded secrets in Java source code are exposed if the repository or compiled classes are accessed.',
                remediation: 'Use environment variables, system properties, or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Example: System.getenv("API_KEY")',
                cweId: 'CWE-798',
                owaspCategory: 'A02:2021 – Cryptographic Failures',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

const javaPathTraversalRule: Rule = {
    id: 'JAVA-006',
    name: 'Java Path Traversal',
    description: 'Detects file operations with user-controlled path input.',
    severity: 'HIGH',
    enabled: true,
    tags: ['path-traversal', 'java', 'owasp-a01'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(
            context,
            /new\s+File\s*\(.*(?:request|param|input|getParameter|getHeader).*\)|Paths\s*\.\s*get\s*\(.*(?:request|param|input)/i,
            (_line, lineNum) => ({
                ruleId: 'JAVA-006',
                ruleName: 'Java Path Traversal',
                severity: 'HIGH',
                message: `File path constructed from user input at line ${lineNum}.`,
                description: 'Using user-controlled data in file paths allows attackers to access files outside the intended directory using ../ sequences.',
                remediation: 'Canonicalize the path and validate it starts with the expected base directory: File file = new File(baseDir, userInput).getCanonicalFile(); if (!file.toPath().startsWith(baseDir.toPath())) throw new SecurityException();',
                cweId: 'CWE-22',
                owaspCategory: 'A01:2021 – Broken Access Control',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

const javaInsecureCryptoRule: Rule = {
    id: 'JAVA-007',
    name: 'Java Insecure Cryptography',
    description: 'Detects use of weak or broken crypto algorithms in Java.',
    severity: 'MEDIUM',
    enabled: true,
    tags: ['cryptography', 'java', 'owasp-a02'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(
            context,
            /Cipher\s*\.\s*getInstance\s*\(\s*"(?:DES|RC4|RC2|Blowfish|DESede|AES\/ECB)"/i,
            (_line, lineNum) => ({
                ruleId: 'JAVA-007',
                ruleName: 'Java Insecure Cryptography',
                severity: 'MEDIUM',
                message: `Weak cryptographic algorithm at line ${lineNum}.`,
                description: 'DES, RC4, RC2, Blowfish, and AES/ECB are considered weak or insecure for modern use.',
                remediation: 'Use AES with GCM mode: Cipher.getInstance("AES/GCM/NoPadding"). Use at least 256-bit keys.',
                cweId: 'CWE-327',
                owaspCategory: 'A02:2021 – Cryptographic Failures',
                location: { line: lineNum, column: 0 },
            })
        );
    },
};

const javaRules: Rule[] = [
    javaSqlInjectionRule,
    javaCommandInjectionRule,
    javaDeserializationRule,
    javaXxeRule,
    javaHardcodedSecretRule,
    javaPathTraversalRule,
    javaInsecureCryptoRule,
];

export default javaRules;
