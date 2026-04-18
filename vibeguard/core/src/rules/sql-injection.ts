/**
 * VibeGuard Rule — SQL Injection Detection
 *
 * Detects string concatenation and template literals used in SQL query contexts.
 * CWE-89: Improper Neutralization of Special Elements used in an SQL Command
 */

import { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import { Rule, RuleContext } from '../types';
import { BabelFile } from '../scanner';
import { traverse } from '../scanner';
import { TaintEngine } from '../taint-engine';

export const sqlInjectionRule: Rule = {
    id: 'VG-SQL-001',
    name: 'SQL Injection',
    description: 'Detects potentially unsafe SQL queries where user input might be concatenated directly into the query instead of using parameterized queries.',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['sql', 'injection', 'security'],
    type: 'ast',
    check(context: RuleContext, ast?: BabelFile | null) {
        if (!ast) return;

        const taintEngine = new TaintEngine();
        taintEngine.analyze(ast as t.File);

        const sqlMethods = ['query', 'execute', 'run', 'raw', 'rawQuery'];

        traverse(ast, {
            CallExpression(path: NodePath<t.CallExpression>) {
                const { callee, arguments: args } = path.node;

                if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
                    if (sqlMethods.includes(callee.property.name)) {
                        const firstArg = args[0];
                        if (!firstArg || !t.isExpression(firstArg)) return;

                        if (t.isStringLiteral(firstArg)) {
                            // Safe static string
                            return;
                        }

                        const isTainted = taintEngine.isExpressionTainted(firstArg);
                        const isTemplate = t.isTemplateLiteral(firstArg) && firstArg.expressions.length > 0;
                        const isBinaryConcat = t.isBinaryExpression(firstArg) && firstArg.operator === '+';

                        if (isTainted || isTemplate || isBinaryConcat) {
                            const loc = path.node.loc;
                            if (!loc) return;

                            context.reportVulnerability({
                                ruleId: sqlInjectionRule.id,
                                ruleName: sqlInjectionRule.name,
                                message: 'Detected dynamic variables or string concatenation inside a SQL query.',
                                description: sqlInjectionRule.description,
                                severity: sqlInjectionRule.severity,
                                cweId: 'CWE-89',
                                remediation: 'Use parameterized queries or an ORM/Query Builder to safely bind parameters.',
                                location: {
                                    line: loc.start.line,
                                    column: loc.start.column,
                                    endLine: loc.end.line,
                                    endColumn: loc.end.column,
                                },
                            });
                        }
                    }
                }
            },
        });
    },
};

export default sqlInjectionRule;
