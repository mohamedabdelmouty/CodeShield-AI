/**
 * VibeGuard — Vulnerable Sample File
 *
 * This file intentionally contains multiple security vulnerabilities
 * for demonstration and testing purposes.
 * DO NOT DEPLOY THIS CODE.
 */

const mysql = require('mysql');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─── CRITICAL: Hardcoded Secret (VG-SEC-001) ───────────────────────────────
const apiKey = 'sk-proj-abc123XYZ789supersecretpassword!';
const password = 'MySuperSecretP@ssw0rd2024!';
const jwtSecret = 'eyJhbGciOiJIUzI1NiJ9.supersecret.abc123';

const dbConfig = {
    host: 'localhost',
    user: 'root',
    password: 'productionPassword123!',   // ← Hardcoded DB password
};

// ─── CRITICAL: SQL Injection (VG-SQL-001) ─────────────────────────────────

function getUserByName(username) {
    // BAD: Template literal with user input directly in SQL
    const query = `SELECT * FROM users WHERE username = '${username}' AND active = 1`;
    return mysql.query(query);
}

function deleteUser(userId) {
    // BAD: String concatenation for SQL
    let sql = 'DELETE FROM users WHERE id = ' + userId;
    mysql.query(sql);
}

// ─── HIGH: XSS (VG-XSS-001) ─────────────────────────────────────────────

function renderUserProfile(userHtml) {
    // BAD: Directly injecting user content as HTML
    document.getElementById('profile').innerHTML = userHtml;
}

function writeDebugInfo(data) {
    // BAD: document.write with dynamic data
    document.write(data);
}

// ─── HIGH: Eval Usage (VG-EVAL-001) ──────────────────────────────────────

function executeUserScript(userCode) {
    // BAD: eval() with user-provided code
    return eval(userCode);
}

function dynamicFunction(body) {
    // BAD: new Function() is equivalent to eval
    const fn = new Function('params', body);
    return fn({ user: 'admin' });
}

function delayedExec(code, delay) {
    // BAD: setTimeout with string argument
    setTimeout(code, delay);
}

// ─── HIGH: Path Traversal (VG-PATH-001) ──────────────────────────────────

function readUserFile(filename) {
    // BAD: No validation on filename before passing to fs
    return fs.readFileSync(filename, 'utf-8');
}

function serveStaticFile(req, res) {
    const userPath = req.query.file;
    // BAD: Path join with unvalidated user input
    const filePath = path.join('/var/www/public', userPath);
    res.send(fs.readFileSync(filePath));
}

// ─── MEDIUM: Insecure Random (VG-RAND-001) ────────────────────────────────

function generateSessionToken() {
    // BAD: Math.random() is not cryptographically secure
    const token = Math.random().toString(36).substring(2);
    return token;
}

function generateCSRFToken() {
    // BAD: Math.random() for security-sensitive CSRF token
    return Math.random().toString(16).substring(2);
}

// ─── CORRECT Patterns (for comparison) ───────────────────────────────────

// ✅ Parameterized query
function safeGetUser(username) {
    return mysql.query('SELECT * FROM users WHERE username = ?', [username]);
}

// ✅ DOMPurify sanitization
function safeRenderContent(html) {
    // document.getElementById('content').innerHTML = DOMPurify.sanitize(html);
}

// ✅ Crypto random for tokens
function safeGenerateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// ✅ Path validation
function safeReadFile(filename) {
    const safePath = path.resolve('/var/www/public', filename);
    if (!safePath.startsWith('/var/www/public')) {
        throw new Error('Access denied');
    }
    return fs.readFileSync(safePath, 'utf-8');
}
