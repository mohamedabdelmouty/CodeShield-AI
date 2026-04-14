/**
 * VibeGuard Rules — Universal Language Rules
 *
 * Text-based regex rules for C++, PHP, Ruby, Go, and Bash.
 * Detects common vulnerabilities like command injection, SQL injection,
 * buffer overflows, and hardcoded secrets across multiple languages.
 */

import { Rule, RuleContext } from '../types';

const CPP_EXT = /\.(cpp|cc|c|h|hpp)$/i;
const PHP_EXT = /\.php$/i;
const RUBY_EXT = /\.rb$/i;
const GO_EXT = /\.go$/i;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function scanLines(
    context: RuleContext,
    extPattern: RegExp,
    regex: RegExp,
    report: (line: string, lineNum: number, match: RegExpMatchArray) => Parameters<RuleContext['reportVulnerability']>[0]
): void {
    if (!extPattern.test(context.filePath)) return;
    const lines = context.fileContent.split('\n');
    for (let i = 0; i < lines.length; i++) {
        const match = lines[i].match(regex);
        if (match) {
            context.reportVulnerability(report(lines[i], i + 1, match));
        }
    }
}

// ─── C++ Rules ───────────────────────────────────────────────────────────────

const cppBufferOverflowRule: Rule = {
    id: 'CPP-001',
    name: 'C/C++ Buffer Overflow',
    description: 'Detects unsafe string manipulation functions.',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['c', 'cpp', 'buffer-overflow', 'owasp-a03'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(context, CPP_EXT, /\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(/, (_line, lineNum, match) => ({
            ruleId: 'CPP-001',
            ruleName: 'C/C++ Buffer Overflow',
            severity: 'CRITICAL',
            message: `Unsafe function ${match[1]}() used at line ${lineNum}.`,
            description: 'These functions do not check buffer lengths and are a primary cause of buffer overflow vulnerabilities.',
            remediation: 'Use secure alternatives like strncpy, strncat, snprintf, or std::string in C++.',
            cweId: 'CWE-120',
            owaspCategory: 'A03:2021 – Injection',
            location: { line: lineNum, column: 0 },
        }));
    },
};

const cppCommandInjectionRule: Rule = {
    id: 'CPP-002',
    name: 'C/C++ Command Injection',
    description: 'Detects system command execution functions.',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['c', 'cpp', 'command-injection'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(context, CPP_EXT, /\b(system|popen|execl|execv)\s*\(/, (_line, lineNum, match) => ({
            ruleId: 'CPP-002',
            ruleName: 'C/C++ Command Injection',
            severity: 'CRITICAL',
            message: `Command execution ${match[1]}() at line ${lineNum}. Verify arguments.`,
            description: 'Executing shell commands with untrusted input leads to command injection.',
            remediation: 'Use secure execution APIs avoiding the shell, and validate all inputs.',
            cweId: 'CWE-78',
            location: { line: lineNum, column: 0 },
        }));
    },
};

// ─── PHP Rules ───────────────────────────────────────────────────────────────

const phpEvalRule: Rule = {
    id: 'PHP-001',
    name: 'PHP eval Injection',
    description: 'Detects unsafe use of eval() and assert().',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['php', 'injection'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(context, PHP_EXT, /\b(eval|assert)\s*\(/, (_line, lineNum, match) => ({
            ruleId: 'PHP-001',
            ruleName: 'PHP Code Injection',
            severity: 'CRITICAL',
            message: `Unsafe use of ${match[1]}() at line ${lineNum}.`,
            description: 'eval() and assert() allow arbitrary code execution in PHP.',
            remediation: 'Avoid eval() entirely. Refactor code to use alternative logic or safe sanitization.',
            cweId: 'CWE-94',
            location: { line: lineNum, column: 0 },
        }));
    },
};

const phpSqlInjectionRule: Rule = {
    id: 'PHP-002',
    name: 'PHP SQL Injection',
    description: 'Detects SQL queries built with variable interpolation.',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['php', 'sql', 'owasp-a03'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(context, PHP_EXT, /query\s*\(\s*["'](?:.*)?\$.*["']\s*\)/i, (_line, lineNum) => ({
            ruleId: 'PHP-002',
            ruleName: 'PHP SQL Injection',
            severity: 'CRITICAL',
            message: `SQL query with variable interpolation at line ${lineNum}.`,
            description: 'Using variables directly in SQL query strings allows SQL injection.',
            remediation: 'Use PDO or MySQLi prepared statements (e.g., bindParam).',
            cweId: 'CWE-89',
            location: { line: lineNum, column: 0 },
        }));
    },
};

// ─── Ruby Rules ──────────────────────────────────────────────────────────────

const rubyCommandInjectionRule: Rule = {
    id: 'RB-001',
    name: 'Ruby Command Injection',
    description: 'Detects use of system, exec, or backticks.',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['ruby', 'injection'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(context, RUBY_EXT, /\b(system|exec)\s*\(|`.*\#\{.*\}/, (_line, lineNum) => ({
            ruleId: 'RB-001',
            ruleName: 'Ruby Command Injection',
            severity: 'CRITICAL',
            message: `Shell execution at line ${lineNum} may contain untrusted input.`,
            description: 'Executing shell commands via system, exec, or interpolation in backticks is inherently dangerous.',
            remediation: 'Pass arguments as an array to system() to avoid shell interpretation.',
            cweId: 'CWE-78',
            location: { line: lineNum, column: 0 },
        }));
    },
};

// ─── Go Rules ────────────────────────────────────────────────────────────────

const goSqlInjectionRule: Rule = {
    id: 'GO-001',
    name: 'Go SQL Injection',
    description: 'Detects fmt.Sprintf used to build SQL queries.',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['go', 'sql'],
    type: 'text',
    check(context: RuleContext): void {
        scanLines(context, GO_EXT, /fmt\.Sprintf\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE|DROP).*["']\s*,/i, (_line, lineNum) => ({
            ruleId: 'GO-001',
            ruleName: 'Go SQL Injection',
            severity: 'CRITICAL',
            message: `SQL query constructed with fmt.Sprintf at line ${lineNum}.`,
            description: 'Formatting SQL queries using Sprintf bypasses parameter binding and allows injection.',
            remediation: 'Use standard database/sql prepared statements with ? or $ placeholders.',
            cweId: 'CWE-89',
            location: { line: lineNum, column: 0 },
        }));
    },
};

const multiLangRules: Rule[] = [
    cppBufferOverflowRule,
    cppCommandInjectionRule,
    phpEvalRule,
    phpSqlInjectionRule,
    rubyCommandInjectionRule,
    goSqlInjectionRule,
];

export default multiLangRules;
