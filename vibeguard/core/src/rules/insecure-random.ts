/**
 * VibeGuard Rule — Insecure Random Number Generation
 *
 * Detects Math.random() usage in security-sensitive contexts.
 * CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator
 */

import { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import { Rule, RuleContext } from '../types';
import { BabelFile, traverse } from '../scanner';

// Variable names suggesting cryptographic/security use
const SECURITY_CONTEXT_PATTERNS = [
    /token/i, /secret/i, /password/i, /passwd/i, /nonce/i, /salt/i,
    /key/i, /iv/i, /seed/i, /random/i, /uuid/i, /session/i, /csrf/i,
    /otp/i, /pin/i, /code/i, /hash/i, /id/i,
];

function hasSecurityContextName(name: string): boolean {
    return SECURITY_CONTEXT_PATTERNS.some((p) => p.test(name));
}

function extractAssignedName(path: NodePath): string | null {
    const parent = path.parent;
    if (t.isVariableDeclarator(parent) && t.isIdentifier(parent.id)) {
        return parent.id.name;
    }
    if (t.isAssignmentExpression(parent)) {
        const left = parent.left;
        if (t.isIdentifier(left)) return left.name;
        if (t.isMemberExpression(left) && t.isIdentifier(left.property)) return left.property.name;
    }
    if (t.isObjectProperty(parent) && t.isIdentifier(parent.key)) {
        return parent.key.name;
    }
    return null;
}

const insecureRandomRule: Rule = {
    id: 'VG-RAND-001',
    name: 'Insecure Random Number Generator',
    description: 'Detects Math.random() usage in security-sensitive contexts where cryptographically secure randomness is required.',
    severity: 'MEDIUM',
    enabled: true,
    tags: ['randomness', 'cryptography', 'weak-crypto', 'cwe-338'],
    type: 'ast',
    check(context: RuleContext, ast?: BabelFile | null): void {
        if (!ast) return;
        traverse(ast, {
            CallExpression(nodePath: NodePath<t.CallExpression>) {
                const { callee } = nodePath.node;
                const loc = nodePath.node.loc;
                if (!loc) return;

                // Detect: Math.random()
                if (
                    !t.isMemberExpression(callee) ||
                    !t.isIdentifier(callee.object, { name: 'Math' }) ||
                    !t.isIdentifier(callee.property, { name: 'random' })
                ) return;

                // Check if it's in a security-sensitive context
                const assignedName = extractAssignedName(nodePath);

                if (assignedName && hasSecurityContextName(assignedName)) {
                    context.reportVulnerability({
                        ruleId: 'VG-RAND-001',
                        ruleName: 'Insecure Random Number Generator',
                        severity: 'MEDIUM',
                        message: `Math.random() used for "${assignedName}" — not cryptographically secure.`,
                        description: 'Math.random() is a pseudo-random generator that is NOT cryptographically secure. Attackers can predict or brute-force its output.',
                        remediation: 'Use crypto.randomBytes() or crypto.randomUUID():\n  import { randomBytes } from "crypto";\n  const token = randomBytes(32).toString("hex");',
                        cweId: 'CWE-338',
                        owaspCategory: 'A02:2021 – Cryptographic Failures',
                        location: { line: loc.start.line, column: loc.start.column },
                    });
                } else {
                    // Flag all Math.random in non-UI contexts (heuristic: not in a .js file doing front-end stuff)
                    // At minimum, report as INFO for awareness
                    context.reportVulnerability({
                        ruleId: 'VG-RAND-001',
                        ruleName: 'Insecure Random Number Generator',
                        severity: 'INFO',
                        message: 'Math.random() detected — review if this is used in any security-sensitive context.',
                        description: 'Math.random() produces predictable output and should not be used for security tokens, passwords, or cryptographic operations.',
                        remediation: 'For security purposes, use crypto.randomBytes() or crypto.randomUUID() from the built-in crypto module.',
                        cweId: 'CWE-338',
                        owaspCategory: 'A02:2021 – Cryptographic Failures',
                        location: { line: loc.start.line, column: loc.start.column },
                    });
                }
            },
        });
    },
};

export default insecureRandomRule;
