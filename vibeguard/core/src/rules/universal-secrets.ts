/**
 * VibeGuard Rule — Universal Text Secrets Detection
 *
 * Detects obvious API keys and tokens in ANY file type using raw regex.
 * CWE-798: Use of Hard-coded Credentials
 */

import { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import { Rule, RuleContext } from '../types';
import { BabelFile, traverse } from '../scanner';
import { isTestFile } from './rule-utils';

// Value patterns that look like real secrets (not empty strings or placeholders)
const UNIVERSAL_SECRET_PATTERNS = [
    // AWS Access Key ID (A bit more strict since we lack AST context, we look for key=value patterns or raw assignments)
    // Here we'll search for things that look like common tokens
    { desc: 'AWS Access Key ID', regex: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g },
    { desc: 'GitHub Token', regex: /(gh[pso]_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{82})/g },
    { desc: 'Slack Token', regex: /xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}/g },
    { desc: 'Stripe Secret Key', regex: /sk_(?:test|live)_[0-9a-zA-Z]{24}/g },
    { desc: 'NPM Token', regex: /npm_[0-9a-zA-Z]{36}/g },
    { desc: 'Discord Token', regex: /[MNO][a-zA-Z0-9_-]{23,27}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}/g },
    { desc: 'JSON Web Token (JWT)', regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g }
];

const universalSecretsRule: Rule = {
    id: 'VG-SEC-007',
    name: 'Exposed Cloud Tokens',
    description: 'Detects cloud provider tokens and API keys leaked in plain text files.',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['secrets', 'credentials', 'text-scan', 'owasp-a07'],
    type: 'text',
    check(context: RuleContext, ast?: BabelFile | null): void {
        const filePath = context.filePath;
        // Fix 3: skip scanning test files
        if (isTestFile(filePath)) return;

        const ext = filePath.slice(filePath.lastIndexOf('.')).toLowerCase();
        const isJsTs = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'].includes(ext);

        const reportMatch = (desc: string, loc: { line: number, column: number }) => {
            context.reportVulnerability({
                ruleId: 'VG-SEC-007',
                ruleName: 'Exposed Cloud Tokens',
                severity: 'CRITICAL',
                message: `Potential ${desc} exposed in file.`,
                description: 'Hardcoding secrets in source files exposes them to anyone with code access.',
                remediation: 'Remove the secret and load it from environment variables or a secure vault.',
                cweId: 'CWE-798',
                owaspCategory: 'A07:2021 – Identification flow Failures',
                location: loc,
            });
        };

        const checkValue = (val: string, locStart: { line: number, column: number }) => {
            if (!val) return;
            for (const patternObj of UNIVERSAL_SECRET_PATTERNS) {
                patternObj.regex.lastIndex = 0;
                let match;
                while ((match = patternObj.regex.exec(val)) !== null) {
                    reportMatch(patternObj.desc, {
                        line: locStart.line,
                        column: locStart.column + match.index,
                    });
                }
            }
        };

        if (isJsTs) {
            // Fix 3: Use AST visitor pattern for JS/TS files to avoid false positives in comments/identifiers
            if (!ast) return;
            traverse(ast, {
                StringLiteral(path: NodePath<t.StringLiteral>) {
                    const loc = path.node.loc;
                    if (loc) {
                        checkValue(path.node.value, { line: loc.start.line, column: loc.start.column });
                    }
                },
                TemplateLiteral(path: NodePath<t.TemplateLiteral>) {
                    for (const quasi of path.node.quasis) {
                        const val = quasi.value.cooked || quasi.value.raw;
                        const loc = quasi.loc || path.node.loc;
                        if (val && loc) {
                            checkValue(val, { line: loc.start.line, column: loc.start.column });
                        }
                    }
                }
            });
        } else {
            const text = context.fileContent;
            if (!text) return;

            const lines = text.split('\n');

            for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
                const line = lines[lineIndex];

                // Heuristic optimization: if line is too long or empty, skip or process carefully
                if (line.length > 500) continue; 

                for (const patternObj of UNIVERSAL_SECRET_PATTERNS) {
                    patternObj.regex.lastIndex = 0;
                    let match;
                    while ((match = patternObj.regex.exec(line)) !== null) {
                        reportMatch(patternObj.desc, {
                            line: lineIndex + 1, // 1-indexed
                            column: match.index, // 0-indexed
                        });
                    }
                }
            }
        }
    },
};

export default universalSecretsRule;
