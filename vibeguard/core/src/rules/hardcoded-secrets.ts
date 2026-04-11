/**
 * VibeGuard Rule — Hardcoded Secrets Detection
 *
 * Detects API keys, passwords, tokens, and private keys hardcoded in source.
 * CWE-798: Use of Hard-coded Credentials
 */

import { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import { Rule, RuleContext } from '../types';
import { BabelFile, traverse } from '../scanner';

// Variable/property names that suggest a secret
const SECRET_KEY_PATTERNS = [
    /api[_-]?key/i,
    /api[_-]?secret/i,
    /auth[_-]?token/i,
    /access[_-]?token/i,
    /secret[_-]?key/i,
    /private[_-]?key/i,
    /client[_-]?secret/i,
    /password/i,
    /passwd/i,
    /pwd/i,
    /jwt[_-]?secret/i,
    /signing[_-]?key/i,
    /encryption[_-]?key/i,
    /webhook[_-]?secret/i,
    /db[_-]?password/i,
    /database[_-]?password/i,
    /stripe[_-]?key/i,
    /twilio[_-]?token/i,
    /sendgrid[_-]?key/i,
    /firebase[_-]?key/i,
    /aws[_-]?secret/i,
    /github[_-]?token/i,
    /slack[_-]?token/i,
];

// Value patterns that look like real secrets (not empty/placeholder strings)
const SECRET_VALUE_PATTERNS = [
    // AWS Secret Access Key
    /(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])/,
    // Generic high-entropy base64-like string (length > 20)
    /^[A-Za-z0-9+/=]{20,}$/,
    // JWT-like tokens
    /^eyJ[A-Za-z0-9_-]{10,}/,
    // GitHub/npm tokens
    /^(gh[ps]_|npm_)[A-Za-z0-9]{20,}/,
    // Hex secrets (32+ chars)
    /^[a-fA-F0-9]{32,}$/,
    // Generic secrets with special chars
    /^[A-Za-z0-9!@#$%^&*_\-+=]{16,}$/,
];

const PLACEHOLDER_VALUES = [
    'yourpassword', 'your_password', 'password123', 'changeme',
    'secret', 'example', 'placeholder', 'xxxx', 'test',
    '***', '...', 'YOUR_KEY_HERE', 'INSERT_KEY', '<key>', '<secret>',
    'undefined', 'null', '', ' ',
];

function isLikelyRealSecret(value: string): boolean {
    if (value.length < 8) return false;
    const lower = value.toLowerCase();
    for (const placeholder of PLACEHOLDER_VALUES) {
        if (lower === placeholder.toLowerCase()) return false;
    }
    return SECRET_VALUE_PATTERNS.some((p) => p.test(value));
}

function isSecretKeyName(name: string): boolean {
    return SECRET_KEY_PATTERNS.some((p) => p.test(name));
}

function extractIdentifierName(node: t.Node): string | null {
    if (t.isIdentifier(node)) return node.name;
    if (t.isMemberExpression(node) && t.isIdentifier(node.property)) return node.property.name;
    if (t.isStringLiteral(node)) return node.value;
    return null;
}

const hardcodedSecretsRule: Rule = {
    id: 'VG-SEC-001',
    name: 'Hardcoded Secret',
    description: 'Detects API keys, passwords, tokens, and private keys hardcoded in source code.',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['secrets', 'credentials', 'configuration', 'owasp-a07'],
    type: 'ast',
    check(context: RuleContext, ast?: BabelFile | null): void {
        if (!ast) return;
        traverse(ast, {
            // Detect: const apiKey = "sk-abc123..."
            VariableDeclarator(nodePath: NodePath<t.VariableDeclarator>) {
                const { id, init } = nodePath.node;
                if (!init || !t.isStringLiteral(init)) return;

                const name = extractIdentifierName(id);
                if (!name || !isSecretKeyName(name)) return;
                if (!isLikelyRealSecret(init.value)) return;

                const loc = nodePath.node.loc;
                if (!loc) return;

                context.reportVulnerability({
                    ruleId: 'VG-SEC-001',
                    ruleName: 'Hardcoded Secret',
                    severity: 'CRITICAL',
                    message: `Potential hardcoded secret detected in variable "${name}".`,
                    description: 'Hardcoding secrets in source code exposes them in version control history and to anyone with code access.',
                    remediation: 'Store secrets in environment variables (process.env.SECRET_KEY) or a secrets manager (AWS Secrets Manager, HashiCorp Vault).',
                    cweId: 'CWE-798',
                    owaspCategory: 'A07:2021 – Identification and Authentication Failures',
                    location: {
                        line: loc.start.line,
                        column: loc.start.column,
                    },
                });
            },

            // Detect: obj.apiKey = "sk-abc123..."
            AssignmentExpression(nodePath: NodePath<t.AssignmentExpression>) {
                const { left, right } = nodePath.node;
                if (!t.isStringLiteral(right)) return;

                const name = extractIdentifierName(left);
                if (!name || !isSecretKeyName(name)) return;
                if (!isLikelyRealSecret(right.value)) return;

                const loc = nodePath.node.loc;
                if (!loc) return;

                context.reportVulnerability({
                    ruleId: 'VG-SEC-001',
                    ruleName: 'Hardcoded Secret',
                    severity: 'CRITICAL',
                    message: `Potential hardcoded secret assigned to "${name}".`,
                    description: 'Hardcoding secrets in source code exposes them in version control and to anyone with code access.',
                    remediation: 'Use environment variables or a secrets management service.',
                    cweId: 'CWE-798',
                    owaspCategory: 'A07:2021 – Identification and Authentication Failures',
                    location: {
                        line: loc.start.line,
                        column: loc.start.column,
                    },
                });
            },

            // Detect: { password: "hardcoded" } in object literals
            ObjectProperty(nodePath: NodePath<t.ObjectProperty>) {
                const { key, value } = nodePath.node;
                if (!t.isStringLiteral(value)) return;

                const name = extractIdentifierName(key);
                if (!name || !isSecretKeyName(name)) return;
                if (!isLikelyRealSecret(value.value)) return;

                const loc = nodePath.node.loc;
                if (!loc) return;

                context.reportVulnerability({
                    ruleId: 'VG-SEC-001',
                    ruleName: 'Hardcoded Secret',
                    severity: 'CRITICAL',
                    message: `Object property "${name}" contains a potential hardcoded secret.`,
                    description: 'Secrets embedded in object literals are exposed in source control and runtime logs.',
                    remediation: 'Load secrets from environment variables at runtime.',
                    cweId: 'CWE-798',
                    owaspCategory: 'A07:2021 – Identification and Authentication Failures',
                    location: {
                        line: loc.start.line,
                        column: loc.start.column,
                    },
                });
            },
        });
    },
};

export default hardcodedSecretsRule;
