/**
 * VibeGuard Rule — Dangerous eval() and Code Execution Detection
 *
 * Detects use of eval(), new Function(), and string-based setTimeout/setInterval.
 * CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
 */

import { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import { Rule, RuleContext } from '../types';
import { BabelFile, traverse } from '../scanner';

const evalRule: Rule = {
    id: 'VG-EVAL-001',
    name: 'Dangerous Code Evaluation',
    description: 'Detects eval(), new Function(), and string-based setTimeout/setInterval which can execute arbitrary code.',
    severity: 'HIGH',
    enabled: true,
    tags: ['eval', 'code-injection', 'rce', 'owasp-a03'],
    type: 'ast',
    check(context: RuleContext, ast?: BabelFile | null): void {
        if (!ast) return;
        traverse(ast, {
            CallExpression(nodePath: NodePath<t.CallExpression>) {
                const { callee, arguments: callArgs } = nodePath.node;
                const loc = nodePath.node.loc;
                if (!loc) return;

                // Only handle plain identifier calls (eval, setTimeout, setInterval)
                if (!t.isIdentifier(callee)) return;

                const fnName = callee.name;

                // Detect: eval(...)
                if (fnName === 'eval') {
                    context.reportVulnerability({
                        ruleId: 'VG-EVAL-001',
                        ruleName: 'Dangerous Code Evaluation',
                        severity: 'HIGH',
                        message: 'eval() is dangerous and can execute arbitrary code.',
                        description: 'eval() executes a string as JavaScript code. If the string contains user input, it leads to code injection / RCE.',
                        remediation: 'Remove eval() entirely. Use JSON.parse() for JSON, or refactor to use static code patterns.',
                        cweId: 'CWE-95',
                        owaspCategory: 'A03:2021 – Injection',
                        location: { line: loc.start.line, column: loc.start.column },
                    });
                    return;
                }

                // Detect: setTimeout("string", ...) or setInterval("string", ...)
                if (
                    ['setTimeout', 'setInterval'].includes(fnName) &&
                    callArgs.length > 0 &&
                    (t.isStringLiteral(callArgs[0]) || t.isTemplateLiteral(callArgs[0]))
                ) {
                    context.reportVulnerability({
                        ruleId: 'VG-EVAL-001',
                        ruleName: 'Dangerous Code Evaluation',
                        severity: 'MEDIUM',
                        message: `${fnName}() called with a string argument — this evaluates code like eval().`,
                        description: `${fnName}() accepts a function OR a string. When passed a string, it evaluates it as JavaScript code, similar to eval().`,
                        remediation: `Pass a function reference instead: ${fnName}(() => { /* code */ }, delay)`,
                        cweId: 'CWE-95',
                        owaspCategory: 'A03:2021 – Injection',
                        location: { line: loc.start.line, column: loc.start.column },
                    });
                }
            },

            // Detect: new Function("code")
            NewExpression(nodePath: NodePath<t.NewExpression>) {
                const { callee } = nodePath.node;
                const loc = nodePath.node.loc;
                if (!loc) return;

                if (!t.isIdentifier(callee, { name: 'Function' })) return;

                context.reportVulnerability({
                    ruleId: 'VG-EVAL-001',
                    ruleName: 'Dangerous Code Evaluation',
                    severity: 'HIGH',
                    message: 'new Function() dynamically creates a function from a string — equivalent to eval().',
                    description: 'new Function(body) compiles and executes a string as JavaScript. This is a code injection vector particularly dangerous with external input.',
                    remediation: 'Avoid new Function(). Use static function definitions or import() for dynamic modules.',
                    cweId: 'CWE-95',
                    owaspCategory: 'A03:2021 – Injection',
                    location: { line: loc.start.line, column: loc.start.column },
                });
            },
        });
    },
};

export default evalRule;
