/**
 * VibeGuard Core — AST-Based Scanner
 *
 * Orchestrates file discovery, parsing, and rule execution.
 * Uses @babel/parser for AST generation and @babel/traverse for AST walking.
 */

import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import { parse } from '@babel/parser';
import traverse from '@babel/traverse';
import type { File as BabelFile } from '@babel/types';
import { enrichWithAi } from './ai-detector';
import { getAllRules } from './rules';
import { calculateSecurityScore } from './score';
import { runScaScan } from './sca-engine';
import {
    Rule,
    RuleContext,
    ScanOptions,
    ScanStats,
    SecurityReport,
    Vulnerability,
    VulnerabilityLocation,
} from './types';

// ─── Constants ────────────────────────────────────────────────────────────────

export const VIBEGUARD_VERSION = '1.4.0';
const DEFAULT_MAX_FILE_SIZE = 1024 * 1024; // 1 MB
const SUPPORTED_EXTENSIONS = [
    '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
    '.py', '.java', '.dart', '.html', '.php', '.go', '.rb', '.c', '.cpp', '.cs', '.sh', '.yaml', '.yml', '.json',
    '.tf'
];
const DOCKERFILE_PATTERN = '**/Dockerfile*'; // Matches Dockerfile, Dockerfile.prod, etc.
const DEFAULT_IGNORE_PATTERNS = [
    '**/node_modules/**',
    '**/dist/**',
    '**/build/**',
    '**/.git/**',
    '**/coverage/**',
    '**/*.min.js',
    '**/*.bundle.js',
];

// Files that must never be scanned — they contain pattern strings that look like
// vulnerabilities but are not executable code (rule definitions, test files, etc.)
const SKIP_FILE_PATTERNS = [
    /\/rules\/[^/]+\.[jt]sx?$/,    // rule definition files
    /\.test\.[jt]sx?$/,             // test files
    /\.spec\.[jt]sx?$/,             // spec files
    /__tests__\//,                  // test directories
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

// ─── Parser ───────────────────────────────────────────────────────────────────

function parseFileToAST(content: string, filePath: string): BabelFile | null {
    try {
        return parse(content, {
            sourceType: 'unambiguous',
            allowImportExportEverywhere: true,
            allowReturnOutsideFunction: true,
            errorRecovery: true,
            plugins: [
                'typescript',
                'jsx',
                'decorators-legacy',
                'classProperties',
                'classPrivateProperties',
                'classPrivateMethods',
                'dynamicImport',
                'optionalChaining',
                'nullishCoalescingOperator',
                'bigInt',
                'importMeta',
            ],
        });
    } catch {
        // If parsing fails, return null — the file will be skipped gracefully
        console.warn(`[VibeGuard] Could not parse: ${filePath}`);
        return null;
    }
}

// ─── File Discovery ───────────────────────────────────────────────────────────

async function discoverFiles(target: string, ignore: string[]): Promise<string[]> {
    const absoluteTarget = path.resolve(target);
    const stat = fs.statSync(absoluteTarget);

    if (stat.isFile()) {
        return [absoluteTarget];
    }

    const patterns = SUPPORTED_EXTENSIONS.map((ext) => `**/*${ext}`);
    patterns.push(DOCKERFILE_PATTERN);
    const allIgnore = [...DEFAULT_IGNORE_PATTERNS, ...ignore];
    const files: string[] = [];

    for (const pattern of patterns) {
        const found = await glob(pattern, {
            cwd: absoluteTarget,
            ignore: allIgnore,
            absolute: true,
            nodir: true,
        });
        files.push(...found);
    }

    // Deduplicate
    return [...new Set(files)];
}

// ─── Scanner ─────────────────────────────────────────────────────────────────

// Fix: race condition in parallel scans — replaced module-level mutable counter
// with a local closure factory so each scan() / scanCode() gets its own independent counter.
function makeIdGenerator(): () => string {
    let counter = 0;
    return () => `VG-${String(++counter).padStart(5, '0')}`;
}

async function scanFile(
    filePath: string,
    rules: Rule[],
    options: ScanOptions,
    makeVulnId: () => string   // Fix: race condition — generator is passed in, not shared globally
): Promise<{ vulnerabilities: Vulnerability[]; linesScanned: number }> {
    // Skip rule definition files and test files — they contain pattern
    // strings that look like vulnerabilities but are not executable code
    const normalizedPath = filePath.replace(/\\/g, '/');
    if (SKIP_FILE_PATTERNS.some(p => p.test(normalizedPath))) {
        return { vulnerabilities: [], linesScanned: 0 };
    }

    const maxFileSize = options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
    const absolutePath = path.resolve(filePath);
    const stat = fs.statSync(absolutePath);

    if (stat.size > maxFileSize) {
        return { vulnerabilities: [], linesScanned: 0 };
    }

    const fileContent = fs.readFileSync(absolutePath, 'utf-8');
    const lines = fileContent.split('\n');
    const vulnerabilities: Vulnerability[] = [];

    const ast = parseFileToAST(fileContent, filePath);
    // Even if AST is null, we continue to allow AI and text-based rules to run

    for (const rule of rules) {
        if (!rule.enabled) continue;

        const context: RuleContext = {
            filePath,
            fileContent,
            reportVulnerability: (partial) => {
                const loc = partial.location;
                const snippet = options.includeSnippets !== false
                    ? getSnippet(lines, loc.line, loc.endLine)
                    : undefined;

                vulnerabilities.push({
                    id: makeVulnId(),
                    ...partial,
                    location: {
                        file: filePath,
                        snippet,
                        ...loc,
                    },
                });
            },
        };

        try {
            rule.check(context, ast);
        } catch {
            // Swallow rule errors — one bad rule shouldn't crash the entire scan
        }
    }

    // AI-powered enrichment (only if static rules found issues, to save tokens)
    if (options.enableAi && options.aiEndpoint && vulnerabilities.length > 0) {
        try {
            const aiFindings = await enrichWithAi(
                filePath,
                fileContent,
                vulnerabilities,
                {
                    endpoint: options.aiEndpoint,
                    apiKey: options.aiApiKey,
                    model: options.aiModel,
                }
            );
            // Fix: silent AI data loss — only replace static findings when AI returned results.
            // If aiFindings is unexpectedly empty, keep the static findings untouched.
            if (aiFindings.length >= vulnerabilities.length) {
                // AI returned at least as many findings — safe to replace
                vulnerabilities.length = 0;
                vulnerabilities.push(...aiFindings);
            } else if (aiFindings.length > 0) {
                // AI returned fewer findings — use AI results but warn the user
                vulnerabilities.length = 0;
                vulnerabilities.push(...aiFindings);
                console.warn(`[VibeGuard] AI returned fewer findings (${aiFindings.length}) than static scan. Using AI results.`);
            } else {
                // AI returned nothing — keep static findings untouched
                console.warn(`[VibeGuard] AI enrichment returned empty results for ${filePath}. Keeping static findings.`);
            }
        } catch (err: any) {
            // Keep the static vulnerabilities, just log the AI warning
            console.warn(`[VibeGuard] AI enrichment failed for ${filePath}:`, err);
        }
    }

    return { vulnerabilities, linesScanned: lines.length };
}

function getSnippet(lines: string[], startLine: number, endLine?: number): string {
    const start = Math.max(0, startLine - 2);
    const end = Math.min(lines.length - 1, (endLine ?? startLine) + 1);
    return lines.slice(start, end + 1).join('\n');
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Main entry point for VibeGuard scanning.
 * Resolves files, runs all enabled rules, calculates score, and returns a full report.
 */
export async function scan(options: ScanOptions): Promise<SecurityReport> {
    const startTime = Date.now();
    // Fix: race condition — each scan() call gets its own local ID generator
    const makeVulnId = makeIdGenerator();

    // Load and filter rules
    const allRules = getAllRules();
    const rulesToRun = options.rules && options.rules.length > 0
        ? allRules.filter((r) => options.rules!.includes(r.id))
        : allRules.filter((r) => r.enabled);

    // Discover files
    const ignore = options.ignore ?? [];
    let files: string[];
    let skipped = 0;

    try {
        files = await discoverFiles(options.target, ignore);
    } catch (err) {
        throw new Error(`VibeGuard: Failed to discover files in "${options.target}": ${err}`);
    }

    // Scan each file
    const allVulnerabilities: Vulnerability[] = [];
    let totalLinesScanned = 0;

    for (const file of files) {
        try {
            const { vulnerabilities, linesScanned } = await scanFile(file, rulesToRun, options, makeVulnId);
            allVulnerabilities.push(...vulnerabilities);
            totalLinesScanned += linesScanned;
        } catch {
            skipped++;
        }
    }

    // ── SCA Scan (Dependency Vulnerability Scanning) ──────────────────────────
    if (options.enableSca !== false) {
        // Only run if target is a directory (not a single file)
        try {
            const stat = fs.statSync(path.resolve(options.target));
            if (stat.isDirectory()) {
                const scaResults = await runScaScan(options.target);
                for (const result of scaResults) {
                    allVulnerabilities.push(...result.vulnerabilities);
                }
            }
        } catch {
            // SCA failure should not crash the whole scan
        }
    }

    // Calculate score
    const score = calculateSecurityScore(allVulnerabilities, 70, files.length);

    // Build summary
    const summary = {
        CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
    };
    for (const v of allVulnerabilities) {
        summary[v.severity]++;
    }

    const stats: ScanStats = {
        filesScanned: files.length - skipped,
        filesSkipped: skipped,
        linesScanned: totalLinesScanned,
        durationMs: Date.now() - startTime,
        timestamp: new Date().toISOString(),
    };

    return {
        version: VIBEGUARD_VERSION,
        target: options.target,
        score,
        vulnerabilities: allVulnerabilities,
        summary,
        stats,
    };
}

/**
 * Scan a raw string of code (useful for VS Code extension — no file I/O).
 */
export async function scanCode(
    code: string,
    filePath: string,
    options?: ScanOptions
): Promise<Vulnerability[]> {
    // Fix: race condition — scanCode() gets its own local ID generator, independent of scan()
    const makeVulnId = makeIdGenerator();
    const allRules = getAllRules();
    const rulesToRun = options?.rules && options.rules.length > 0
        ? allRules.filter((r) => options.rules!.includes(r.id))
        : allRules.filter((r) => r.enabled);

    const lines = code.split('\n');
    const vulnerabilities: Vulnerability[] = [];

    const ast = parseFileToAST(code, filePath);
    // Again, we do not return early so text-based rules can still run

    for (const rule of rulesToRun) {
        const context: RuleContext = {
            filePath,
            fileContent: code,
            reportVulnerability: (partial) => {
                const loc = partial.location;
                vulnerabilities.push({
                    id: makeVulnId(),
                    ...partial,
                    location: {
                        file: filePath,
                        snippet: getSnippet(lines, loc.line, loc.endLine),
                        ...loc,
                    },
                });
            },
        };

        try {
            rule.check(context, ast);
        } catch {
            // Swallow errors
        }
    }

    // AI-powered enrichment (only if static rules found issues, to save tokens)
    if (options?.enableAi && options.aiEndpoint && vulnerabilities.length > 0) {
        try {
            const aiFindings = await enrichWithAi(
                filePath,
                code,
                vulnerabilities,
                {
                    endpoint: options.aiEndpoint,
                    apiKey: options.aiApiKey,
                    model: options.aiModel,
                }
            );
            // Fix: silent AI data loss (scanCode) — same safe merge logic as scanFile
            if (aiFindings.length >= vulnerabilities.length) {
                vulnerabilities.length = 0;
                vulnerabilities.push(...aiFindings);
            } else if (aiFindings.length > 0) {
                vulnerabilities.length = 0;
                vulnerabilities.push(...aiFindings);
                console.warn(`[VibeGuard] AI returned fewer findings (${aiFindings.length}) than static scan. Using AI results.`);
            } else {
                console.warn(`[VibeGuard] AI enrichment returned empty results for ${filePath}. Keeping static findings.`);
            }
        } catch (err: any) {
            console.warn(`[VibeGuard] AI enrichment failed for ${filePath}:`, err);
        }
    }

    return vulnerabilities;
}

// Re-export traverse for rules that need it
export { traverse };
export type { BabelFile };
export type { VulnerabilityLocation };
