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

    constructor() {}

    /**
     * Resets the taint state.
     */
    public reset() {
        this.taintedVars.clear();
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
            }
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
        return false;
    }
}
