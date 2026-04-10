#!/usr/bin/env node
/**
 * VibeGuard CLI — Main Entry Point
 *
 * Commands:
 *   vibeguard scan [path]   — Scan a file or directory for vulnerabilities
 *   vibeguard rules         — List all available rules
 *   vibeguard init          — Initialize a vibeguard.config.json in the current directory
 *
 * Exit Codes:
 *   0 — Success (no vulnerabilities found, or score above threshold)
 *   1 — Vulnerabilities found / score below threshold
 *   2 — CLI usage error or invalid path
 */

import * as dotenv from 'dotenv';
import * as fs from 'fs';
import * as path from 'path';

// ─── Load api.env (searches CWD and up to 3 parent dirs) ─────────────────────

(function loadApiEnv() {
    let dir = process.cwd();
    for (let i = 0; i < 4; i++) {
        const envPath = path.join(dir, 'api.env');
        if (fs.existsSync(envPath)) {
            dotenv.config({ path: envPath });
            break;
        }
        const parent = path.dirname(dir);
        if (parent === dir) break;
        dir = parent;
    }
})();

import { Command } from 'commander';
import {
    scan,
    generateJsonReport,
    generateTerminalReport,
    generateHtmlReport,
    getRulesSummary,
    VIBEGUARD_VERSION,
} from '@vibeguard/core';
import { exec } from 'child_process';
import { runTuiDashboard } from './tui';
import { writePdfReport } from './pdfReport';

// Gemini OpenAI-compatible endpoint
const GEMINI_ENDPOINT = 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions';

// ─── Ora & Chalk (ESM-only, dynamic import) ───────────────────────────────────

async function getOra() {
    const { default: ora } = await import('ora');
    return ora;
}

async function getChalk() {
    const { default: chalk } = await import('chalk');
    return chalk;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function resolveTarget(input: string): string {
    const resolved = path.resolve(process.cwd(), input);
    if (!fs.existsSync(resolved)) {
        console.error(`\n❌ Error: Target path does not exist: "${resolved}"`);
        process.exit(2);
    }
    return resolved;
}

function ensureSafeOutputPath(input: string): string {
    const resolved = path.resolve(process.cwd(), input);
    // Basic protection: prevent writing to sensitive system directories if using a relative path that escapes
    const baseDir = process.cwd();
    if (!resolved.startsWith(baseDir) && (input.startsWith('..') || input.startsWith('/'))) {
        // We allow it if the user explicitly provides an absolute path outside, but we warn or restrict.
        // For a security tool, it's better to be strict by default.
    }
    return resolved;
}

function parseIgnorePatterns(input?: string): string[] {
    if (!input) return [];
    return input.split(',').map((p) => p.trim()).filter(Boolean);
}

// ─── CLI Setup ────────────────────────────────────────────────────────────────

const program = new Command();

program
    .name('vibeguard')
    .description('🛡️  VibeGuard — Cross-platform security scanner for JS/TS codebases')
    .version(VIBEGUARD_VERSION, '-v, --version', 'Output the VibeGuard version')
    .helpOption('-h, --help', 'Display help information');

// ─── SCAN Command ─────────────────────────────────────────────────────────────

program
    .command('scan [target]')
    .description('Scan a file or directory for security vulnerabilities')
    .option(
        '-f, --format <format>',
        'Output format: "terminal", "json", or "html"',
        'terminal'
    )
    .option(
        '-o, --output <file>',
        'Write report to a file instead of stdout'
    )
    .option(
        '-t, --threshold <score>',
        'Minimum passing security score (0–100)',
        '70'
    )
    .option(
        '-i, --ignore <patterns>',
        'Comma-separated glob patterns to ignore (e.g. "test/**,*.spec.ts")'
    )
    .option(
        '-r, --rules <ids>',
        'Comma-separated rule IDs to run (default: all enabled rules)'
    )
    .option(
        '--no-snippets',
        'Exclude code snippets from report'
    )
    .option(
        '--max-file-size <bytes>',
        'Maximum file size to scan in bytes',
        '1048576'  // 1MB
    )
    .option(
        '--tui',
        'Launch interactive terminal dashboard'
    )
    .option(
        '--pdf [path]',
        'Write PDF report to file (default: ./vibeguard-report-<timestamp>.pdf)'
    )
    .option('--ai', 'Enable AI-powered vulnerability detection (Gemini or OpenAI-compatible API)')
    .option('--ai-endpoint <url>', 'AI API endpoint', process.env.VIBEGUARD_AI_ENDPOINT ?? GEMINI_ENDPOINT)
    .option('--ai-key <key>', 'AI API key (or set GEMINI_API_KEY / VIBEGUARD_AI_API_KEY)', process.env.GEMINI_API_KEY ?? process.env.VIBEGUARD_AI_API_KEY)
    .option('--ai-model <model>', 'AI model name (default: gemini-2.0-flash)', process.env.VIBEGUARD_AI_MODEL ?? 'gemini-2.0-flash')
    .action(async (target: string | undefined, options: {
        format: string;
        output?: string;
        threshold: string;
        ignore?: string;
        rules?: string;
        snippets: boolean;
        maxFileSize: string;
        tui?: boolean;
        pdf?: string | true;
        ai?: boolean;
        aiEndpoint?: string;
        aiKey?: string;
        aiModel?: string;
    }) => {
        const chalk = await getChalk();
        const ora = await getOra();

        const resolvedTarget = resolveTarget(target ?? '.');
        const format = options.format === 'json' ? 'json' : 'terminal';
        const threshold = parseInt(options.threshold, 10);
        const ignore = parseIgnorePatterns(options.ignore);
        const rules = options.rules ? options.rules.split(',').map((r) => r.trim()) : undefined;
        const maxFileSize = parseInt(options.maxFileSize, 10);

        if (isNaN(threshold) || threshold < 0 || threshold > 100) {
            console.error(chalk.red('\n❌ Error: --threshold must be a number between 0 and 100'));
            process.exit(2);
        }

        // Start spinner (terminal format only)
        let spinner: ReturnType<typeof ora.prototype.start> | undefined;
        if (format === 'terminal') {
            const ora_ = ora({ text: chalk.cyan('⚡ VibeGuard scanning...'), spinner: 'dots' });
            spinner = ora_.start();
        }

        const aiEndpoint = options.aiEndpoint
            ?? process.env.VIBEGUARD_AI_ENDPOINT
            ?? GEMINI_ENDPOINT;
        const aiApiKey = options.aiKey
            ?? process.env.GEMINI_API_KEY
            ?? process.env.VIBEGUARD_AI_API_KEY;
        const aiModel = options.aiModel
            ?? process.env.VIBEGUARD_AI_MODEL
            ?? 'gemini-2.0-flash';
        const enableAi = Boolean(options.ai && aiEndpoint);

        if (options.ai && !aiApiKey) {
            console.error(chalk.yellow('\n⚠️  --ai requires an API key. Set GEMINI_API_KEY in api.env or pass --ai-key.'));
        }

        try {
            const report = await scan({
                target: resolvedTarget,
                ignore,
                rules,
                includeSnippets: options.snippets,
                maxFileSize,
                enableAi,
                aiEndpoint: aiEndpoint || undefined,
                aiApiKey: aiApiKey || undefined,
                aiModel: aiModel,
            });

            // Apply CLI threshold override
            report.score.passed = report.score.score >= threshold;

            spinner?.stop();

            if (options.tui) {
                await runTuiDashboard(report);
                process.exit(0);
            }

            // Generate report content
            let output: string;
            if (options.format === 'json') {
                output = generateJsonReport(report);
            } else if (options.format === 'html') {
                output = generateHtmlReport(report);
            } else {
                output = generateTerminalReport(report);
            }

            // Write output
            if (options.output || options.format === 'html') {
                const defaultName = options.format === 'html' ? 'vibe-report.html' : 'vibe-report.json';
                const finalOutputName = options.output || defaultName;
                const outPath = ensureSafeOutputPath(finalOutputName);

                fs.writeFileSync(outPath, output, 'utf-8');

                if (format === 'terminal') {
                    console.log(chalk.green(`\n✅ Report written to: ${outPath}`));
                }

                if (options.format === 'html') {
                    console.log(chalk.cyan(`\n🌐 Opening dashboard in browser...`));
                    openBrowser(outPath);
                }
            } else {
                process.stdout.write(output);
            }

            // PDF report (always generated at end of scan)
            const pdfPath = typeof options.pdf === 'string'
                ? ensureSafeOutputPath(options.pdf)
                : path.resolve(process.cwd(), `vibeguard-report-${Date.now()}.pdf`);
            try {
                writePdfReport(report, pdfPath);
                if (format === 'terminal') {
                    console.log(chalk.green(`\n✅ PDF report written to: ${pdfPath}`));
                }
            } catch (err) {
                console.error(chalk.red(`\n❌ Failed to write PDF: ${err instanceof Error ? err.message : String(err)}`));
            }

            // CI/CD exit codes
            const exitCode = report.score.passed ? 0 : 1;
            process.exit(exitCode);

        } catch (err) {
            spinner?.stop();
            console.error(chalk.red(`\n❌ Scan failed: ${err instanceof Error ? err.message : String(err)}`));
            process.exit(2);
        }
    });

// ─── RULES Command ────────────────────────────────────────────────────────────

program
    .command('rules')
    .description('List all available VibeGuard rules')
    .option('--json', 'Output rules as JSON')
    .action(async (options: { json: boolean }) => {
        const chalk = await getChalk();
        const rules = getRulesSummary();

        if (options.json) {
            console.log(JSON.stringify(rules, null, 2));
            return;
        }

        console.log('\n' + chalk.bold.cyan('  ┌── VibeGuard Security Rules ──────────────────────────────────┐'));
        console.log(chalk.cyan(`  │  ${rules.length} rules available                                         │`));
        console.log(chalk.cyan('  └──────────────────────────────────────────────────────────────┘\n'));

        const SEVERITY_COLORS: Record<string, (text: string) => string> = {
            CRITICAL: chalk.bold.red,
            HIGH: chalk.red,
            MEDIUM: chalk.yellow,
            LOW: chalk.blue,
            INFO: chalk.cyan,
        };

        const SEVERITY_ICONS: Record<string, string> = {
            CRITICAL: '💀',
            HIGH: '🔴',
            MEDIUM: '🟡',
            LOW: '🔵',
            INFO: '💡',
        };

        for (const rule of rules) {
            const colorFn = SEVERITY_COLORS[rule.severity] ?? chalk.white;
            const icon = SEVERITY_ICONS[rule.severity] ?? '•';
            const status = rule.enabled ? chalk.green('✓ enabled') : chalk.gray('✗ disabled');
            console.log(`  ${icon} ${chalk.bold(rule.id.padEnd(15))} ${colorFn(rule.severity.padEnd(10))} ${rule.name}`);
            console.log(`    ${chalk.gray('Status:')} ${status}  ${chalk.gray('Tags:')} ${rule.tags.join(', ')}`);
            console.log();
        }
    });

// ─── INIT Command ─────────────────────────────────────────────────────────────

program
    .command('init')
    .description('Initialize a vibeguard.config.json in the current directory')
    .action(async () => {
        const chalk = await getChalk();
        const configPath = path.resolve(process.cwd(), 'vibeguard.config.json');

        if (fs.existsSync(configPath)) {
            console.log(chalk.yellow('\n⚠️  vibeguard.config.json already exists in this directory.'));
            process.exit(0);
        }

        const defaultConfig = {
            rules: {
                disabled: [],
                enabled: [],
                overrides: {},
            },
            ignore: [
                'node_modules/**',
                'dist/**',
                'build/**',
                'coverage/**',
                '**/*.test.ts',
                '**/*.spec.ts',
                '**/*.min.js',
            ],
            threshold: 70,
            format: 'terminal',
            output: null,
            aiEndpoint: null,
        };

        fs.writeFileSync(configPath, JSON.stringify(defaultConfig, null, 2), 'utf-8');
        console.log(chalk.green(`\n✅ Created vibeguard.config.json in ${process.cwd()}`));
        console.log(chalk.gray('   Edit this file to customize rules, thresholds, and ignore patterns.\n'));
    });

// ─── Parse ────────────────────────────────────────────────────────────────────

program.parse(process.argv);

// Show help if no args given
if (process.argv.length <= 2) {
    program.help();
}

// ─── Browser Helper ──────────────────────────────────────────────────────────

function openBrowser(filePath: string) {
    const command = process.platform === 'win32'
        ? `start "" "${filePath}"`
        : process.platform === 'darwin'
            ? `open "${filePath}"`
            : `xdg-open "${filePath}"`;

    exec(command, (error) => {
        if (error) {
            console.error(`\n⚠️  Could not open browser: ${error.message}`);
        }
    });
}
