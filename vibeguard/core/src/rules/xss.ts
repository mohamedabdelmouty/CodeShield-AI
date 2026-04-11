/**
 * VibeGuard Rule — XSS (Cross-Site Scripting) Detection
 *
 * Detects unsafe DOM manipulation patterns that can lead to XSS.
 * CWE-79: Improper Neutralization of Input During Web Page Generation
 */

import { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import { Rule, RuleContext } from '../types';
import { BabelFile, traverse } from '../scanner';

// Dangerous DOM properties that accept HTML
const DANGEROUS_DOM_SINKS = ['innerHTML', 'outerHTML', 'insertAdjacentHTML'];

function isUserDataSource(node: t.Node): boolean {
    // Heuristic: if the RHS is not solely a string literal, it might contain user data
    return !t.isStringLiteral(node) && !t.isTemplateLiteral(node) && !t.isNullLiteral(node);
}

const xssRule: Rule = {
    id: 'VG-XSS-001',
    name: 'Cross-Site Scripting (XSS)',
    description: 'Detects unsafe assignments to innerHTML/outerHTML and calls to document.write that may execute arbitrary HTML/JS.',
    severity: 'HIGH',
    enabled: true,
    tags: ['xss', 'dom', 'injection', 'owasp-a03'],
    type: 'ast',
    check(context: RuleContext, ast?: BabelFile | null): void {
        if (!ast) return;
        traverse(ast, {
            // Detect: element.innerHTML = someVariable
            AssignmentExpression(nodePath: NodePath<t.AssignmentExpression>) {
                const { left, right } = nodePath.node;
                if (!t.isMemberExpression(left)) return;

                const property = left.property;
                const propName = t.isIdentifier(property) ? property.name : '';
                if (!DANGEROUS_DOM_SINKS.includes(propName)) return;
                if (!isUserDataSource(right)) return;

                const loc = nodePath.node.loc;
                if (!loc) return;

                context.reportVulnerability({
                    ruleId: 'VG-XSS-001',
                    ruleName: 'Cross-Site Scripting (XSS)',
                    severity: 'HIGH',
                    message: `Unsafe assignment to "${propName}" may allow XSS if the value contains user-controlled input.`,
                    description: 'Assigning unsanitized values to innerHTML/outerHTML causes the browser to parse and execute the string as HTML, enabling XSS attacks.',
                    remediation: 'Use textContent instead of innerHTML for plain text. For HTML, sanitize using DOMPurify: element.innerHTML = DOMPurify.sanitize(userInput)',
                    cweId: 'CWE-79',
                    owaspCategory: 'A03:2021 – Injection',
                    location: {
                        line: loc.start.line,
                        column: loc.start.column,
                        endLine: loc.end.line,
                        endColumn: loc.end.column,
                    },
                });
            },

            // Detect: document.write(userInput) or document.writeln(userInput)
            CallExpression(nodePath: NodePath<t.CallExpression>) {
                const callee = nodePath.node.callee;
                if (!t.isMemberExpression(callee)) return;

                const obj = callee.object;
                const method = callee.property;
                if (!t.isIdentifier(obj, { name: 'document' })) return;
                if (!t.isIdentifier(method) || !['write', 'writeln'].includes(method.name)) return;

                const args = nodePath.node.arguments;
                if (args.length === 0) return;
                // Flag if first argument is not a plain string literal
                if (!isUserDataSource(args[0])) return;

                const loc = nodePath.node.loc;
                if (!loc) return;

                context.reportVulnerability({
                    ruleId: 'VG-XSS-001',
                    ruleName: 'Cross-Site Scripting (XSS)',
                    severity: 'HIGH',
                    message: `document.${method.name}() called with a non-literal argument — potential XSS vector.`,
                    description: 'document.write() and document.writeln() are deprecated and dangerous. They parse the input as HTML, which can execute injected scripts.',
                    remediation: 'Avoid document.write() entirely. Use DOM methods like document.createElement() and textContent assignment.',
                    cweId: 'CWE-79',
                    owaspCategory: 'A03:2021 – Injection',
                    location: {
                        line: loc.start.line,
                        column: loc.start.column,
                    },
                });
            },
        });
    },
};

export default xssRule;
