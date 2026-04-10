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

// Pattern to identify SQL-related variable/function names
const SQL_PATTERNS = /\b(query|sql|select|insert|update|delete|where|from|table|execute|exec|prepare|statement|db|database|knex|sequelize|mysql|postgres|sqlite)\b/i;

function isStringConcatWithVariable(node: t.Node): boolean {
    if (!t.isBinaryExpression(node, { operator: '+' })) return false;
    const hasNonLiteral = (n: t.Node): boolean => {
        if (t.isBinaryExpression(n, { operator: '+' })) {
            return hasNonLiteral(n.left) || hasNonLiteral(n.right);
        }
        return !t.isStringLiteral(n) && !t.isNumericLiteral(n) && !t.isTemplateLiteral(n);
    };
    return hasNonLiteral(node);
}

function containsSQLKeywords(str: string): boolean {
    return /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|WHERE|FROM|JOIN)\b/i.test(str);
}

const sqlInjectionRule: Rule = {
    id: 'VG-SQL-001',
    name: 'SQL Injection',
    description: 'Detects dynamic SQL query construction using string concatenation or template literals with user-controlled variables.',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['injection', 'sql', 'database', 'owasp-a03'],
    check(context: RuleContext, ast: BabelFile): void {
        traverse(ast, {
            // Detect template literals with SQL keywords: `SELECT * FROM users WHERE id = ${userId}`
            TemplateLiteral(nodePath: NodePath<t.TemplateLiteral>) {
                if (nodePath.node.expressions.length === 0) return;
                const rawText = nodePath.node.quasis.map((q) => q.value.raw).join('');
                if (!containsSQLKeywords(rawText)) return;

                const loc = nodePath.node.loc;
                if (!loc) return;

                context.reportVulnerability({
                    ruleId: 'VG-SQL-001',
                    ruleName: 'SQL Injection',
                    severity: 'CRITICAL',
                    message: 'Template literal used to construct SQL query with dynamic expressions.',
                    description: 'Dynamic SQL queries built with template literals allow SQL injection if inputs are not properly sanitized.',
                    remediation: 'Use parameterized queries or prepared statements. Example: db.query("SELECT * FROM users WHERE id = ?", [userId])',
                    cweId: 'CWE-89',
                    owaspCategory: 'A03:2021 – Injection',
                    location: {
                        line: loc.start.line,
                        column: loc.start.column,
                        endLine: loc.end.line,
                        endColumn: loc.end.column,
                    },
                });
            },

            // Detect string concatenation used in SQL contexts
            AssignmentExpression(nodePath: NodePath<t.AssignmentExpression>) {
                const { left, right } = nodePath.node;
                if (!isStringConcatWithVariable(right)) return;

                // Check if the variable name hints at SQL usage
                const varName = t.isIdentifier(left) ? left.name : t.isMemberExpression(left) && t.isIdentifier(left.property) ? left.property.name : '';
                if (!SQL_PATTERNS.test(varName)) return;

                const loc = nodePath.node.loc;
                if (!loc) return;

                context.reportVulnerability({
                    ruleId: 'VG-SQL-001',
                    ruleName: 'SQL Injection',
                    severity: 'CRITICAL',
                    message: `Variable "${varName}" appears to be a SQL query built with string concatenation.`,
                    description: 'Building SQL queries via string concatenation with non-literal values is a classic SQL injection vector.',
                    remediation: 'Use parameterized queries, prepared statements, or an ORM with built-in protection.',
                    cweId: 'CWE-89',
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

export default sqlInjectionRule;
