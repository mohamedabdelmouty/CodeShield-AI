/**
 * VibeGuard Extension — esbuild script
 *
 * Reads BUILT_IN_GEMINI_API_KEY from .env (gitignored) and injects it
 * into the compiled bundle at build time.
 * The source code never contains the real key — safe to commit to GitHub.
 */

const esbuild = require('esbuild');
const path = require('path');
const fs = require('fs');

// ── Load .env from vscode-extension dir or fall back to root api.env ──────────
function loadEnv() {
    const locations = [
        path.join(__dirname, '.env'),
        path.join(__dirname, '..', '..', 'api.env'),  // CodeShield AI/api.env
        path.join(__dirname, '..', 'api.env'),
    ];
    for (const loc of locations) {
        if (fs.existsSync(loc)) {
            require('dotenv').config({ path: loc });
            console.log(`[build] Loaded env from: ${loc}`);
            return;
        }
    }
    console.warn('[build] Warning: No .env or api.env found. BUILT_IN_GEMINI_API_KEY will be empty.');
}

loadEnv();

const apiKey = process.env.GEMINI_API_KEY || '';
const endpoint = process.env.VIBEGUARD_AI_ENDPOINT || 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions';
const model = process.env.VIBEGUARD_AI_MODEL || 'gemini-2.0-flash';

if (!apiKey) {
    console.warn('[build] Warning: GEMINI_API_KEY is not set. AI features will require user configuration.');
}

esbuild.build({
    entryPoints: ['src/extension.ts'],
    bundle: true,
    outfile: 'dist/extension.js',
    external: ['vscode'],           // vscode is provided by the host — never bundle it
    platform: 'node',
    target: 'node18',
    format: 'cjs',
    sourcemap: false,
    minify: false,
    define: {
        // These string replacements happen at compile time — not visible in source
        'process.env.BUILT_IN_KEY':      JSON.stringify(apiKey),
        'process.env.BUILT_IN_ENDPOINT': JSON.stringify(endpoint),
        'process.env.BUILT_IN_MODEL':    JSON.stringify(model),
    },
}).then(() => {
    console.log('[build] ✅ Extension bundled successfully → dist/extension.js');
}).catch((err) => {
    console.error('[build] ❌ Build failed:', err.message);
    process.exit(1);
});
