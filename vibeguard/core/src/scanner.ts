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
import { detectWithAi } from './ai-detector';
import { getAllRules } from './rules';
import { calculateSecurityScore } from './score';
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

export const VIBEGUARD_VERSION = '1.0.0';
const DEFAULT_MAX_FILE_SIZE = 1024 * 1024; // 1 MB
const SUPPORTED_EXTENSIONS = [
    '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
    '.py', '.java', '.dart', '.html', '.php', '.go', '.rb', '.c', '.cpp', '.cs', '.sh', '.yaml', '.yml', '.json'
];
const DEFAULT_IGNORE_PATTERNS = [
    '**/node_modules/**',
    '**/dist/**',
    '**/build/**',
    '**/.git/**',
    '**/coverage/**',
    '**/*.min.js',
    '**/*.bundle.js',
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

let _vulnIdCounter = 0;

function makeVulnId(): string {
    return `VG-${String(++_vulnIdCounter).padStart(5, '0')}`;
}

async function scanFile(
    filePath: string,
    rules: Rule[],
    options: ScanOptions
): Promise<{ vulnerabilities: Vulnerability[]; linesScanned: number }> {
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

    // AI-powered detection (optional)
    if (options.enableAi && options.aiEndpoint) {
        try {
            const aiFindings = await detectWithAi(
                filePath,
                fileContent,
                {
                    endpoint: options.aiEndpoint,
                    apiKey: options.aiApiKey,
                    model: options.aiModel,
                },
                () => makeVulnId()
            );
            for (const v of aiFindings) {
                const snippet = options.includeSnippets !== false ? v.location.snippet : undefined;
                vulnerabilities.push({
                    ...v,
                    location: { ...v.location, file: filePath, snippet },
                });
            }
        } catch (err) {
            // Don't fail scan if AI is unavailable
            console.warn(`[VibeGuard] AI detection failed for ${filePath}:`, err);
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
    _vulnIdCounter = 0;

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
            const { vulnerabilities, linesScanned } = await scanFile(file, rulesToRun, options);
            allVulnerabilities.push(...vulnerabilities);
            totalLinesScanned += linesScanned;
        } catch {
            skipped++;
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
export function scanCode(
    code: string,
    filePath: string,
    enabledRuleIds?: string[]
): Vulnerability[] {
    _vulnIdCounter = 0;
    const allRules = getAllRules();
    const rulesToRun = enabledRuleIds && enabledRuleIds.length > 0
        ? allRules.filter((r) => enabledRuleIds.includes(r.id))
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

    return vulnerabilities;
}

// Re-export traverse for rules that need it
export { traverse };
export type { BabelFile };
export type { VulnerabilityLocation };
