/**
 * VibeGuard — Clean Sample File
 *
 * A secure implementation of common patterns — no vulnerabilities.
 * Used to verify that VibeGuard returns exit code 0 on clean code.
 */

import { randomBytes } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

// ✅ Secrets from environment variables
const apiKey = process.env.API_KEY;
const dbPassword = process.env.DB_PASSWORD;
const jwtSecret = process.env.JWT_SECRET;

// ✅ Parameterized SQL (using placeholder syntax)
async function getUserByName(db: { query: (sql: string, params: unknown[]) => Promise<unknown[]> }, username: string) {
    return await db.query('SELECT * FROM users WHERE username = ? AND active = 1', [username]);
}

// ✅ Safe DOM manipulation using textContent
function renderUserName(name: string) {
    const el = document.getElementById('username');
    if (el) {
        el.textContent = name; // Never innerHTML
    }
}

// ✅ Cryptographically secure token generation
function generateSessionToken(): string {
    return randomBytes(32).toString('hex');
}

function generateCSRFToken(): string {
    return randomBytes(16).toString('hex');
}

// ✅ Safe file reading with path validation
const ALLOWED_BASE = '/var/www/public';

function safeReadFile(userInput: string): string {
    const safePath = path.resolve(ALLOWED_BASE, userInput);
    if (!safePath.startsWith(ALLOWED_BASE + path.sep)) {
        throw new Error('Access denied: path traversal detected');
    }
    return fs.readFileSync(safePath, 'utf-8');
}

// ✅ No eval, no dynamic code execution
function executeOperation(operation: string, a: number, b: number): number {
    const ops: Record<string, (a: number, b: number) => number> = {
        add: (a, b) => a + b,
        subtract: (a, b) => a - b,
        multiply: (a, b) => a * b,
    };
    const fn = ops[operation];
    if (!fn) throw new Error(`Unknown operation: ${operation}`);
    return fn(a, b);
}

// Math.random() used for non-security-sensitive UI shuffle
function shuffleArray<T>(arr: T[]): T[] {
    return [...arr].sort(() => Math.random() - 0.5);
}

export {
    getUserByName,
    renderUserName,
    generateSessionToken,
    generateCSRFToken,
    safeReadFile,
    executeOperation,
    shuffleArray,
};
