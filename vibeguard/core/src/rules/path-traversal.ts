/**
 * VibeGuard Rule — Path Traversal Detection
 *
 * Detects file system operations with non-literal path arguments.
 * CWE-22: Improper Limitation of a Pathname to a Restricted Directory
 */

import { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import { Rule, RuleContext } from '../types';
import { BabelFile, traverse } from '../scanner';

// fs module methods that accept file paths
const FS_READ_METHODS = [
    'readFile', 'readFileSync', 'writeFile', 'writeFileSync',
    'appendFile', 'appendFileSync', 'unlink', 'unlinkSync',
    'stat', 'statSync', 'lstat', 'lstatSync',
    'access', 'accessSync', 'open', 'openSync',
    'createReadStream', 'createWriteStream',
    'readdir', 'readdirSync', 'mkdir', 'mkdirSync', 'rmdir', 'rmdirSync',
];

function isLiteralPath(node: t.Node): boolean {
    return t.isStringLiteral(node) || t.isTemplateLiteral(node) && node.expressions.length === 0;
}

const pathTraversalRule: Rule = {
    id: 'VG-PATH-001',
    name: 'Path Traversal',
    description: 'Detects file system operations with dynamic, potentially user-controlled path arguments that may allow directory traversal.',
    severity: 'HIGH',
    enabled: true,
    tags: ['path-traversal', 'lfi', 'file-system', 'owasp-a01'],
    check(context: RuleContext, ast: BabelFile): void {
        traverse(ast, {
            CallExpression(nodePath: NodePath<t.CallExpression>) {
                const { callee, arguments: args } = nodePath.node;
                const loc = nodePath.node.loc;
                if (!loc || args.length === 0) return;

                // Detect: fs.readFile(userPath, ...) / fs.readFileSync(userPath)
                if (t.isMemberExpression(callee)) {
                    const obj = callee.object;
                    const method = callee.property;

                    // Check if it's fs.<method>
                    const objName = t.isIdentifier(obj) ? obj.name : '';
                    const methodName = t.isIdentifier(method) ? method.name : '';

                    const isFsCall = ['fs', 'promises', 'fsPromises'].includes(objName) &&
                        FS_READ_METHODS.includes(methodName);

                    if (isFsCall && !isLiteralPath(args[0])) {
                        context.reportVulnerability({
                            ruleId: 'VG-PATH-001',
                            ruleName: 'Path Traversal',
                            severity: 'HIGH',
                            message: `fs.${methodName}() called with a non-literal path — potential path traversal.`,
                            description: 'If path is derived from user input without validation, attackers can use "../../../etc/passwd" to read arbitrary files.',
                            remediation: 'Validate and sanitize all path inputs. Use path.resolve() and verify the result stays within an allowed base directory:\n  const safePath = path.resolve(baseDir, userInput);\n  if (!safePath.startsWith(baseDir)) throw new Error("Access denied")',
                            cweId: 'CWE-22',
                            owaspCategory: 'A01:2021 – Broken Access Control',
                            location: { line: loc.start.line, column: loc.start.column },
                        });
                    }

                    // Detect: path.join() with suspicious concatenation
                    if (['path', 'nodePath'].includes(objName) && methodName === 'join') {
                        for (const arg of args) {
                            // If any argument is a function call or identifier (not a literal), flag it
                            if (t.isCallExpression(arg) || t.isIdentifier(arg) || t.isMemberExpression(arg)) {
                                context.reportVulnerability({
                                    ruleId: 'VG-PATH-001',
                                    ruleName: 'Path Traversal',
                                    severity: 'MEDIUM',
                                    message: 'path.join() called with a non-literal argument — verify that path segments are validated.',
                                    description: 'Dynamic segments in path.join() may introduce traversal vulnerabilities if they come from user-controlled sources.',
                                    remediation: 'After path.join(), verify the result is within your intended base directory using path.resolve().',
                                    cweId: 'CWE-22',
                                    owaspCategory: 'A01:2021 – Broken Access Control',
                                    location: { line: loc.start.line, column: loc.start.column },
                                });
                                break; // Only report once per path.join call
                            }
                        }
                    }
                }
            },
        });
    },
};

export default pathTraversalRule;
