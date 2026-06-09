import traverse from '@babel/traverse';
import * as t from '@babel/types';

/**
 * Very basic intra-procedural Taint Analysis Engine for JavaScript/TypeScript.
 * Tracks data flowing from untrusted sources (e.g. req.body) into sinks.
 */
export class TaintEngine {
    private sources = new Set<string>(['req.body', 'req.query', 'req.params', 'req.headers']);

    // Maps variable names to whether they are tainted
    private taintedVars = new Map<string, boolean>();

    // Fix: inter-procedural taint tracking — tracks function names whose return value is tainted
    private taintedFunctions = new Set<string>();

    constructor() {}

    /**
     * Resets the taint state.
     */
    public reset() {
        this.taintedVars.clear();
        this.taintedFunctions.clear();
    }

    /**
     * Mark a variable as tainted.
     */
    public markTainted(identifierName: string) {
        this.taintedVars.set(identifierName, true);
    }

    /**
     * Check if a variable is tainted.
     */
    public isTainted(identifierName: string): boolean {
        return this.taintedVars.get(identifierName) || false;
    }

    /**
     * Run a taint analysis pass over the AST.
     * This establishes which local variables are tainted based on initial sources.
     */
    public analyze(ast: t.File) {
        this.reset();

        traverse(ast, {
            VariableDeclarator: (path) => {
                const { id, init } = path.node;

                if (t.isIdentifier(id) && init) {
                    // Check if initialized from a known source like req.body
                    if (this.isUntrustedSource(init)) {
                        this.markTainted(id.name);
                    }
                    // Check if initialized from another tainted variable
                    else if (t.isIdentifier(init) && this.isTainted(init.name)) {
                        this.markTainted(id.name);
                    }
                    // Fix: inter-procedural taint tracking — propagate taint through call expressions
                    // If the called function is known-tainted OR any argument is tainted, mark result as tainted
                    else if (t.isCallExpression(init)) {
                        const calleeName = t.isIdentifier(init.callee) ? init.callee.name : null;
                        const calleeIsTainted = calleeName != null && this.taintedFunctions.has(calleeName);
                        const anyArgTainted = init.arguments.some(
                            (arg) => t.isIdentifier(arg) && this.isTainted(arg.name)
                        );
                        if (calleeIsTainted || anyArgTainted) {
                            this.markTainted(id.name);
                        }
                    }
                }

                // Handle Object Destructuring: const { id } = req.body
                if (t.isObjectPattern(id) && init) {
                    if (this.isUntrustedSource(init) || (t.isIdentifier(init) && this.isTainted(init.name))) {
                        id.properties.forEach(prop => {
                            if (t.isObjectProperty(prop) && t.isIdentifier(prop.value)) {
                                this.markTainted(prop.value.name);
                            }
                        });
                    }
                }

                // Fix: array destructuring support — const [a, b] = req.body.items → both a and b tainted
                // If the RHS is an untrusted source or a tainted variable, taint all bound identifiers
                if (t.isArrayPattern(id) && init) {
                    if (this.isUntrustedSource(init) || (t.isIdentifier(init) && this.isTainted(init.name))) {
                        id.elements.forEach(element => {
                            if (t.isIdentifier(element)) {
                                this.markTainted(element.name);
                            }
                        });
                    }
                }
            },

            AssignmentExpression: (path) => {
                const { left, right } = path.node;
                if (t.isIdentifier(left)) {
                    if (this.isUntrustedSource(right) || (t.isIdentifier(right) && this.isTainted(right.name))) {
                        this.markTainted(left.name);
                    } else {
                        // If overwritten with clean data, untaint
                        this.taintedVars.delete(left.name);
                    }
                }
            },

            /**
             * Fix: inter-procedural taint tracking — ReturnStatement visitor.
             * If a function returns a tainted identifier, mark the function name as tainted
             * so callers of this function can be tracked as tainted too.
             */
            ReturnStatement: (path) => {
                const { argument } = path.node;
                if (!argument || !t.isIdentifier(argument)) return;
                if (!this.isTainted(argument.name)) return;

                // Walk up the AST to find the enclosing function and get its name
                let fnPath = path.getFunctionParent();
                if (!fnPath) return;

                const fnNode = fnPath.node;

                // Named function declaration: function getUser(...) { ... }
                if (t.isFunctionDeclaration(fnNode) && fnNode.id) {
                    this.taintedFunctions.add(fnNode.id.name);
                }
                // Variable assigned arrow/function expression: const getUser = (req) => ...
                else if (
                    (t.isFunctionExpression(fnNode) || t.isArrowFunctionExpression(fnNode)) &&
                    fnPath.parentPath &&
                    t.isVariableDeclarator(fnPath.parentPath.node) &&
                    t.isIdentifier((fnPath.parentPath.node as t.VariableDeclarator).id)
                ) {
                    this.taintedFunctions.add(
                        ((fnPath.parentPath.node as t.VariableDeclarator).id as t.Identifier).name
                    );
                }
            },
        });
    }

    /**
     * Checks if a given AST expression represents an untrusted source.
     */
    private isUntrustedSource(node: t.Expression): boolean {
        if (t.isMemberExpression(node)) {
            const objectName = t.isIdentifier(node.object) ? node.object.name : '';
            const propertyName = t.isIdentifier(node.property) ? node.property.name : '';
            if (this.sources.has(`${objectName}.${propertyName}`)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if an expression flowing into a sink is tainted.
     */
    public isExpressionTainted(node: t.Expression): boolean {
        if (t.isIdentifier(node)) {
            return this.isTainted(node.name);
        }
        if (t.isTemplateLiteral(node)) {
            return node.expressions.some(expr => t.isIdentifier(expr) && this.isTainted(expr.name));
        }
        if (t.isBinaryExpression(node) && node.operator === '+') {
            return (t.isExpression(node.left) && this.isExpressionTainted(node.left)) ||
                   (this.isExpressionTainted(node.right));
        }
        // Fix: inter-procedural taint tracking — CallExpression in sink position
        // If the called function is tainted OR any argument is tainted, the expression is tainted
        if (t.isCallExpression(node)) {
            const calleeName = t.isIdentifier(node.callee) ? node.callee.name : null;
            const calleeIsTainted = calleeName != null && this.taintedFunctions.has(calleeName);
            const anyArgTainted = node.arguments.some(
                (arg) => t.isExpression(arg) && this.isExpressionTainted(arg)
            );
            return calleeIsTainted || anyArgTainted;
        }
        return false;
    }
}
