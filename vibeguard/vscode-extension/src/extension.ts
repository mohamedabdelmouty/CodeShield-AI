/**
 * VibeGuard VS Code Extension v3.0 — Main Entry Point
 *
 * Activates the extension, registers commands, and binds event listeners.
 * Compatible with VS Code, Cursor, and Windsurf.
 *
 * New in v3.0:
 *  - vibeguard.autoFix      — AI-powered code fix via CodeShield backend
 *  - vibeguard.explainVuln  — AI explanation WebView panel
 *  - vibeguard.toggleRealtime — Toggle real-time typing scan
 *  - Real-time debounced scan on document change
 *  - Pre-push Git hook installer
 */

import { spawn } from 'child_process';
import * as vscode from 'vscode';
import { VibeguardDiagnosticsProvider } from './diagnostics';
import { VibeguardCodeLensProvider } from './codelens';
import { VibeguardPanel } from './panel';
import { exportToPdf, exportToPdfToPath } from './pdf-exporter';
import { scan, scanCode, getAllRules, VIBEGUARD_VERSION, calculateSecurityScore, Vulnerability, SecurityReport } from '@vibeguard/core';
import { VibeguardCodeActionProvider } from './code-actions';
import { VibeguardChatProvider } from './chat-panel';
import { VulnerabilityHistoryProvider } from './history-provider';
import { AutoFixProvider, executeAutoFix, vulnDataMap, diagKey } from './auto-fix-provider';
import { showExplainPanel } from './explain-panel';

// ─── Supported Language IDs ───────────────────────────────────────────────────

const SUPPORTED_LANGUAGES = [
    'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
    'python', 'java', 'dart', 'html', 'php', 'go', 'ruby', 'c', 'cpp', 'csharp', 'shellscript', 'yaml', 'json'
];
const SUPPORTED_EXTENSIONS = /\.(js|ts|jsx|tsx|mjs|cjs|py|java|dart|html|php|go|rb|c|cpp|cs|sh|yaml|yml|json)$/i;

// ─── Built-in AI Config (injected by build.js at build time) ─────────────────
const BUILT_IN_GEMINI_KEY      = (process.env as any).BUILT_IN_KEY          ?? '';
const BUILT_IN_GEMINI_ENDPOINT = (process.env as any).BUILT_IN_ENDPOINT     ?? 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions';
const BUILT_IN_GEMINI_MODEL    = (process.env as any).BUILT_IN_MODEL        ?? 'gemini-2.0-flash';
const BUILT_IN_GROQ_KEY        = (process.env as any).BUILT_IN_GROQ_KEY     ?? '';
const BUILT_IN_GROQ_MODEL      = (process.env as any).BUILT_IN_GROQ_MODEL   ?? 'llama-3.3-70b-versatile';
const GROQ_ENDPOINT            = 'https://api.groq.com/openai/v1/chat/completions';

/** Returns the effective AI config, preferring user settings over built-in defaults. */
function getAiConfig(): {
    enabled: boolean;
    provider: 'Gemini' | 'Groq' | 'OpenRouter';
    endpoint: string;
    apiKey: string;
    model: string;
} {
    const config = vscode.workspace.getConfiguration('vibeguard');
    const enabled  = config.get<boolean>('enableAi') ?? true;
    const provider = (config.get<string>('aiProvider') ?? 'Groq') as 'Gemini' | 'Groq' | 'OpenRouter';

    if (provider === 'Groq') {
        const apiKey = config.get<string>('groqApiKey')?.trim() || BUILT_IN_GROQ_KEY;
        const model  = config.get<string>('groqModel')?.trim()  || BUILT_IN_GROQ_MODEL;
        return { enabled, provider, endpoint: GROQ_ENDPOINT, apiKey, model };
    }

    if (provider === 'OpenRouter') {
        return { enabled, provider, endpoint: 'https://openrouter.ai/api/v1/chat/completions', apiKey: '', model: '' };
    }

    // Gemini
    const endpoint = config.get<string>('aiEndpoint')?.trim() || BUILT_IN_GEMINI_ENDPOINT;
    const apiKey   = config.get<string>('aiApiKey')?.trim()   || BUILT_IN_GEMINI_KEY;
    const model    = config.get<string>('aiModel')?.trim()    || BUILT_IN_GEMINI_MODEL;
    return { enabled, provider, endpoint, apiKey, model };
}

let diagnosticsProvider: VibeguardDiagnosticsProvider;
let statusBarItem: vscode.StatusBarItem;
let outputChannel: vscode.OutputChannel;
let historyProvider: VulnerabilityHistoryProvider;

// Real-time scan debounce timer
let realtimeScanTimer: NodeJS.Timeout | undefined;
let realtimeScanEnabled = true;

// Fix B2: dirty-range tracker — skip scan if the document hasn't changed since the last scan
let _lastScannedVersion = new Map<string, number>(); // uri → document version
let _lastScanHadVulns   = new Map<string, boolean>(); // uri → had vulns

// ─── Activation ───────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
    outputChannel = vscode.window.createOutputChannel('VibeGuard');
    outputChannel.appendLine(`[VibeGuard v${VIBEGUARD_VERSION}] Extension activated.`);
    historyProvider = new VulnerabilityHistoryProvider(context);

    // Initialize providers
    diagnosticsProvider = new VibeguardDiagnosticsProvider();
    const codeLensProvider = new VibeguardCodeLensProvider(diagnosticsProvider);

    // Status bar
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'vibeguard.showReport';
    statusBarItem.tooltip = 'VibeGuard Security Score — Click to view full report';
    statusBarItem.text = '$(shield) VibeGuard';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // ── Register Code Lens Provider ───────────────────────────────
    const codeLensDisposable = vscode.languages.registerCodeLensProvider(
        SUPPORTED_LANGUAGES.map((lang) => ({ language: lang })),
        codeLensProvider
    );
    context.subscriptions.push(codeLensDisposable);

    // ── Register Code Action Providers ────────────────────────────
    // Legacy provider (existing)
    const codeActionProvider = new VibeguardCodeActionProvider(diagnosticsProvider);
    const codeActionDisposable = vscode.languages.registerCodeActionsProvider(
        SUPPORTED_LANGUAGES.map((lang) => ({ language: lang })),
        codeActionProvider,
        { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    );
    context.subscriptions.push(codeActionDisposable);

    // NEW v3.0: AI-powered auto-fix provider
    const autoFixProvider = new AutoFixProvider();
    const autoFixDisposable = vscode.languages.registerCodeActionsProvider(
        SUPPORTED_LANGUAGES.map((lang) => ({ language: lang })),
        autoFixProvider,
        { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    );
    context.subscriptions.push(autoFixDisposable);

    // ── Register Chat Provider ──────────────────────────────────────
    // Fix B1: pass context so chat history can be persisted across sidebar reopens
    const chatProvider = new VibeguardChatProvider(context.extensionUri, context);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(VibeguardChatProvider.viewType, chatProvider)
    );

    // Command to open/focus the VibeGuard AI Chat sidebar
    context.subscriptions.push(
        vscode.commands.registerCommand('vibeguard.focusChat', async () => {
            // Reveal the sidebar container first, then focus the chat view
            await vscode.commands.executeCommand('workbench.view.extension.vibeguard-sidebar');
            await vscode.commands.executeCommand('vibeguard.chatView.focus');
        })
    );

    // Command to send a vulnerability to the AI chat
    context.subscriptions.push(
        vscode.commands.registerCommand('vibeguard.askAi', async (vuln?: any) => {
            // If called from Command Palette without args, just open the chat
            if (!vuln) {
                await vscode.commands.executeCommand('vibeguard.focusChat');
                return;
            }
            // Reveal the chat first, then send the context
            await vscode.commands.executeCommand('vibeguard.focusChat');
            setTimeout(() => chatProvider.sendToChat(vuln), 400);
        })
    );

    // ── Register Commands ─────────────────────────────────────────

    // Scan current file
    context.subscriptions.push(
        vscode.commands.registerCommand('vibeguard.scanFile', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('VibeGuard: Open a file first to scan it.');
                return;
            }
            if (!SUPPORTED_EXTENSIONS.test(editor.document.uri.fsPath)) {
                vscode.window.showWarningMessage(`VibeGuard: File type not supported. Supported: JS, TS, Python, Java, PHP, Go, and more.`);
                return;
            }

            await vscode.window.withProgress(
                { location: vscode.ProgressLocation.Notification, title: '🛡️ VibeGuard: Scanning file...', cancellable: false },
                async () => {
                    await scanActiveFile(editor.document);
                }
            );
        })
    );

    // Scan entire workspace
    context.subscriptions.push(
        vscode.commands.registerCommand('vibeguard.scanWorkspace', async () => {
            const config = vscode.workspace.getConfiguration('vibeguard');
            if (!config.get<boolean>('enabled')) {
                vscode.window.showWarningMessage('VibeGuard is disabled in settings.');
                return;
            }

            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (!workspaceFolders || workspaceFolders.length === 0) {
                vscode.window.showWarningMessage('VibeGuard: No workspace folder open.');
                return;
            }

            await vscode.window.withProgress(
                {
                    location: vscode.ProgressLocation.Notification,
                    title: '🛡️ VibeGuard: Scanning workspace...',
                    cancellable: true,
                },
                async (_progress, token) => {
                    for (const folder of workspaceFolders) {
                        if (token.isCancellationRequested) break;

                        try {
                            const ai = getAiConfig();
                            const disabledRules = config.get<string[]>('disabledRules') ?? [];
                            const allRules = getAllRules();
                            const enabledRuleIds = allRules
                                .filter((r) => r.enabled && !disabledRules.includes(r.id))
                                .map((r) => r.id);

                            const ignorePatterns = config.get<string[]>('ignorePatterns') ?? [];
                            const defaultExcludes = [
                                '**/node_modules/**',
                                '**/dist/**',
                                '**/build/**',
                                '**/.git/**',
                                '**/rules/*.ts',       // skip rule definition files
                                '**/*.test.ts',        // skip test files
                                '**/*.spec.ts',
                                '**/__tests__/**',
                            ];
                            const extraExcludes = ignorePatterns.length > 0 ? ignorePatterns : [];
                            const allExcludes = [...defaultExcludes, ...extraExcludes];
                            const excludePattern = `{${allExcludes.join(',')}}`;

                            // Fix 4: Find workspace files matching language patterns
                            const files = await vscode.workspace.findFiles(
                                new vscode.RelativePattern(folder, '**/*.{js,ts,jsx,tsx,mjs,cjs,py,java,dart}'),
                                excludePattern,
                                undefined,
                                token
                            );

                            const total = files.length;
                            let scanned = 0;
                            let totalLinesScanned = 0;
                            const allVulnerabilities: Vulnerability[] = [];
                            const startTime = Date.now();

                            statusBarItem.text = `$(sync~spin) VibeGuard: Scanning 0/${total}...`;
                            statusBarItem.show();

                            for (const fileUri of files) {
                                if (token.isCancellationRequested) break;

                                const doc = await vscode.workspace.openTextDocument(fileUri);
                                const linesCount = doc.getText().split('\n').length;
                                totalLinesScanned += linesCount;

                                const result = await scanCode(doc.getText(), fileUri.fsPath, {
                                    target: fileUri.fsPath,
                                    rules: enabledRuleIds,
                                    enableAi: ai.enabled,
                                    aiEndpoint: ai.endpoint,
                                    aiApiKey: ai.apiKey,
                                    aiModel: ai.model,
                                });

                                allVulnerabilities.push(...result);
                                scanned++;
                                statusBarItem.text = `$(sync~spin) VibeGuard: Scanning ${scanned}/${total}...`;
                                // Yield to keep UI responsive
                                await new Promise(resolve => setTimeout(resolve, 0));
                            }

                            if (token.isCancellationRequested) {
                                outputChannel.appendLine(`[VibeGuard] Workspace scan cancelled by user.`);
                                statusBarItem.text = '$(shield) VibeGuard: Scan Cancelled';
                                break;
                            }

                            const scoreThreshold = config.get<number>('threshold') ?? 70;
                            const score = calculateSecurityScore(allVulnerabilities, scoreThreshold, scanned);

                            const summary = {
                                CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
                            };
                            for (const v of allVulnerabilities) {
                                summary[v.severity]++;
                            }

                            const report: SecurityReport = {
                                version: VIBEGUARD_VERSION,
                                target: folder.uri.fsPath,
                                score,
                                vulnerabilities: allVulnerabilities,
                                summary,
                                stats: {
                                    filesScanned: scanned,
                                    filesSkipped: total - scanned,
                                    linesScanned: totalLinesScanned,
                                    durationMs: Date.now() - startTime,
                                    timestamp: new Date().toISOString(),
                                }
                            };

                            diagnosticsProvider.setWorkspaceReport(report);
                            updateStatusBar(report.score.score, report.score.grade);
                            outputChannel.appendLine(`[VibeGuard] Workspace scan: Score ${report.score.score}/100 (${report.score.grade}). Vulnerabilities: ${report.vulnerabilities.length}`);
                            // Record in history
                            historyProvider.addEntry({
                                timestamp: new Date().toISOString(),
                                target: folder.uri.fsPath,
                                score: report.score.score,
                                grade: report.score.grade,
                                issueCount: report.vulnerabilities.length,
                                critical: report.summary['CRITICAL'] ?? 0,
                                high: report.summary['HIGH'] ?? 0,
                                medium: report.summary['MEDIUM'] ?? 0,
                                low: report.summary['LOW'] ?? 0,
                            });

                            const pdfDir = folder.uri.fsPath;
                            const pdfPath = `${pdfDir}/vibeguard-report-${Date.now()}.pdf`;
                            try {
                                exportToPdfToPath(report, pdfPath);
                                outputChannel.appendLine(`[VibeGuard] PDF report saved to ${pdfPath}`);
                            } catch (err) {
                                outputChannel.appendLine(`[VibeGuard] Failed to write PDF: ${err}`);
                            }

                            // Show the report panel automatically after workspace scan
                            VibeguardPanel.createOrShow(context.extensionUri, report);

                            // Also show a notification with quick actions
                            const msg = `VibeGuard: Scan complete — Score ${report.score.score}/100 (${report.score.grade}). ${report.vulnerabilities.length} issue${report.vulnerabilities.length !== 1 ? 's' : ''} found.`;
                            vscode.window.showInformationMessage(
                                msg,
                                'View Report',
                                'Export PDF',
                                'Dismiss'
                            ).then(async (action) => {
                                if (action === 'View Report') {
                                    VibeguardPanel.createOrShow(context.extensionUri, report);
                                } else if (action === 'Export PDF') {
                                    await exportToPdf(report);
                                }
                            });
                        } catch (err) {
                            outputChannel.appendLine(`[VibeGuard] Error scanning workspace: ${err}`);
                            vscode.window.showErrorMessage(`VibeGuard: Scan failed — ${err}`);
                        }
                    }
                }
            );
        })
    );

    // Show security report panel
    context.subscriptions.push(
        vscode.commands.registerCommand('vibeguard.showReport', () => {
            const lastReport = diagnosticsProvider.getLastReport();
            if (!lastReport) {
                vscode.window.showInformationMessage('VibeGuard: No scan report available. Run a scan first.', 'Scan Workspace').then((action) => {
                    if (action === 'Scan Workspace') {
                        vscode.commands.executeCommand('vibeguard.scanWorkspace');
                    }
                });
                return;
            }
            VibeguardPanel.createOrShow(context.extensionUri, lastReport);
        })
    );

    // Clear all diagnostics
    context.subscriptions.push(
        vscode.commands.registerCommand('vibeguard.clearDiagnostics', () => {
            diagnosticsProvider.clearAll();
            statusBarItem.text = '$(shield) VibeGuard';
            statusBarItem.backgroundColor = undefined;
            vscode.window.showInformationMessage('VibeGuard: Diagnostics cleared.');
        })
    );

    // ── NEW v3.0: AI Auto-Fix Command ─────────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand(
            'vibeguard.autoFix',
            async (docUri?: vscode.Uri, diag?: vscode.Diagnostic, vuln?: any) => {
                // Fix 2: Support QuickPick fallback when run from Command Palette without arguments
                if (!vuln) {
                    const editor = vscode.window.activeTextEditor;
                    if (editor) {
                        const line = editor.selection.active.line + 1;
                        const uri  = editor.document.uri;

                        // Search vulnDataMap for a match on the current cursor line
                        for (const [key, v] of vulnDataMap.entries()) {
                            if (key.startsWith(uri.fsPath) && key.includes(`:${line}:`)) {
                                vuln = v;
                                break;
                            }
                        }

                        if (vuln) {
                            // Build a synthetic diagnostic covering the current line
                            const lineRange = editor.document.lineAt(editor.selection.active.line).range;
                            diag = new vscode.Diagnostic(lineRange, vuln.message ?? 'Security vulnerability', vscode.DiagnosticSeverity.Warning);
                            docUri = uri;
                        }
                    }

                    if (!vuln) {
                        const allVulns = [...vulnDataMap.values()];
                        if (allVulns.length === 0) {
                            vscode.window.showInformationMessage('VibeGuard: No vulnerabilities found. Run a scan first.');
                            return;
                        }
                        const items = allVulns.map(v => ({
                            label: `$(warning) ${v.rule_id || v.id} — ${(v.message || '').slice(0, 60)}`,
                            description: `${v.location.file}:${v.location.line}`,
                            vuln: v,
                        }));
                        const picked = await vscode.window.showQuickPick(items, {
                            placeHolder: 'Select a vulnerability to auto-fix',
                            title: 'VibeGuard: AI Auto-Fix',
                        });
                        if (!picked) return;
                        vuln = picked.vuln;
                        docUri = vscode.Uri.file(vuln.location.file);
                        const doc = await vscode.workspace.openTextDocument(docUri);
                        const lineIndex = Math.max(0, vuln.location.line - 1);
                        const lineRange = doc.lineAt(lineIndex).range;
                        diag = new vscode.Diagnostic(lineRange, vuln.message ?? 'Security vulnerability', vscode.DiagnosticSeverity.Warning);
                    }
                }

                if (!docUri || !diag || !vuln) {
                    vscode.window.showWarningMessage('VibeGuard: Unable to determine vulnerability context.');
                    return;
                }

                const doc = await vscode.workspace.openTextDocument(docUri);
                await executeAutoFix(doc, diag, vuln);
            }
        )
    );

    // ── NEW v3.0: AI Explain Vulnerability Command ────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand(
            'vibeguard.explainVuln',
            async (vuln?: any) => {
                // Fix 2: Support QuickPick fallback when run from Command Palette without arguments
                if (!vuln) {
                    const editor = vscode.window.activeTextEditor;
                    if (editor) {
                        const line = editor.selection.active.line + 1;
                        const uri  = editor.document.uri;
                        for (const [key, v] of vulnDataMap.entries()) {
                            if (key.startsWith(uri.fsPath) && key.includes(`:${line}:`)) {
                                vuln = v;
                                break;
                            }
                        }
                    }

                    if (!vuln) {
                        const allVulns = [...vulnDataMap.values()];
                        if (allVulns.length === 0) {
                            vscode.window.showInformationMessage('VibeGuard: No vulnerabilities found. Run a scan first.');
                            return;
                        }
                        const items = allVulns.map(v => ({
                            label: `$(warning) ${v.rule_id || v.id} — ${(v.message || '').slice(0, 60)}`,
                            description: `${v.location.file}:${v.location.line}`,
                            vuln: v,
                        }));
                        const picked = await vscode.window.showQuickPick(items, {
                            placeHolder: 'Select a vulnerability to explain',
                            title: 'VibeGuard: Explain Vulnerability',
                        });
                        if (!picked) return;
                        vuln = picked.vuln;
                    }
                }
                if (!vuln) {
                    vscode.window.showWarningMessage('VibeGuard: No vulnerability selected.');
                    return;
                }
                // Normalize: @vibeguard/core uses camelCase, explain-panel expects snake_case
                const normalized = {
                    id:             vuln.id ?? vuln.rule_id ?? vuln.ruleId ?? 'unknown',
                    rule_id:        vuln.rule_id ?? vuln.ruleId ?? 'unknown',
                    rule_name:      vuln.rule_name ?? vuln.ruleName ?? vuln.ruleId ?? 'Security Issue',
                    severity:       vuln.severity ?? 'LOW',
                    message:        vuln.message ?? '',
                    remediation:    vuln.remediation ?? '',
                    cwe_id:         vuln.cwe_id ?? vuln.cweId,
                    owasp_category: vuln.owasp_category ?? vuln.owaspCategory,
                    location: {
                        file:    vuln.location?.file ?? '',
                        line:    vuln.location?.line ?? 1,
                        snippet: vuln.location?.snippet ?? vuln.snippet,
                    },
                };
                await showExplainPanel(context, normalized);
            }
        )
    );

    // ── NEW v3.0: Toggle Real-time Scan ───────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('vibeguard.toggleRealtime', () => {
            realtimeScanEnabled = !realtimeScanEnabled;
            const state = realtimeScanEnabled ? 'enabled' : 'disabled';
            vscode.window.showInformationMessage(`VibeGuard: Real-time scanning ${state}.`);
            outputChannel.appendLine(`[VibeGuard] Real-time scanning ${state}`);
        })
    );

    // ── Pre-commit Hook ───────────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('vibeguard.installPreCommitHook', async () => {
            const folders = vscode.workspace.workspaceFolders;
            if (!folders || folders.length === 0) {
                vscode.window.showWarningMessage('VibeGuard: No workspace folder open.');
                return;
            }
            const folderPath = folders[0].uri.fsPath;
            const hookDir = `${folderPath}/.git/hooks`;
            const hookPath = `${hookDir}/pre-commit`;
            const fs = await import('fs');
            const path = await import('path');

            if (!fs.existsSync(path.join(folderPath, '.git'))) {
                vscode.window.showErrorMessage('VibeGuard: Not a git repository.');
                return;
            }

            const hookContent = `#!/bin/sh
# VibeGuard Pre-commit Security Hook
echo "🛡️ VibeGuard: Running security scan before commit..."
npx vibeguard scan . --threshold 70
if [ $? -ne 0 ]; then
  echo "❌ VibeGuard: Security check failed. Fix critical/high vulnerabilities before committing."
  exit 1
fi
echo "✅ VibeGuard: Security check passed."
`;
            try {
                if (!fs.existsSync(hookDir)) { fs.mkdirSync(hookDir, { recursive: true }); }
                fs.writeFileSync(hookPath, hookContent, { mode: 0o755 });
                vscode.window.showInformationMessage(`✅ VibeGuard: Pre-commit hook installed at ${hookPath}. Commits will be blocked if critical vulnerabilities are found.`);
                outputChannel.appendLine(`[VibeGuard] Pre-commit hook installed: ${hookPath}`);
            } catch (err) {
                vscode.window.showErrorMessage(`VibeGuard: Failed to install hook — ${err}`);
            }
        })
    );

    // ── Show Vulnerability History ────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('vibeguard.showHistory', () => {
            const panel = vscode.window.createWebviewPanel(
                'vibeguardHistory',
                '🛡️ VibeGuard Scan History',
                vscode.ViewColumn.One,
                { enableScripts: true, retainContextWhenHidden: true }
            );
            panel.webview.html = historyProvider.getHistoryHtml();
            panel.webview.onDidReceiveMessage(msg => {
                if (msg.command === 'clearHistory') {
                    historyProvider.clearHistory();
                    panel.webview.html = historyProvider.getHistoryHtml();
                    vscode.window.showInformationMessage('VibeGuard: Scan history cleared.');
                }
            });
        })
    );

    // Scan in system terminal (opens OS terminal and runs CLI)
    context.subscriptions.push(
        vscode.commands.registerCommand('vibeguard.scanInSystemTerminal', async () => {
            const folders = vscode.workspace.workspaceFolders;
            if (!folders || folders.length === 0) {
                vscode.window.showWarningMessage('VibeGuard: No workspace folder open.');
                return;
            }
            const folderPath = folders[0].uri.fsPath;
            try {
                openSystemTerminalAndScan(folderPath);
                outputChannel.appendLine(`[VibeGuard] Opened system terminal to scan: ${folderPath}`);
            } catch (err) {
                outputChannel.appendLine(`[VibeGuard] Failed to open system terminal: ${err}`);
                vscode.window.showErrorMessage(`VibeGuard: Could not open system terminal — ${err}`);
            }
        })
    );

    // Export PDF Report
    context.subscriptions.push(
        vscode.commands.registerCommand('vibeguard.exportPdfReport', async (reportFromPanel?: any) => {
            const lastReport = reportFromPanel || diagnosticsProvider.getLastReport();
            if (!lastReport) {
                vscode.window.showWarningMessage('VibeGuard: No scan report available to export. Run a scan first.');
                return;
            }
            await exportToPdf(lastReport);
        })
    );

    // ── Event Listeners ───────────────────────────────────────────

    const config = vscode.workspace.getConfiguration('vibeguard');
    // Fix B2: increased default debounce from 1500ms to 2500ms to reduce lag on large files
    const realtimeDelay = config.get<number>('realtimeScanDelay', 2500);

    // Auto-scan on file save
    if (config.get<boolean>('scanOnSave')) {
        context.subscriptions.push(
            vscode.workspace.onDidSaveTextDocument(async (doc) => {
                if (!SUPPORTED_EXTENSIONS.test(doc.uri.fsPath)) return;
                if (!config.get<boolean>('enabled')) return;
                await scanActiveFile(doc);
            })
        );
    }

    // Auto-scan on file open
    if (config.get<boolean>('scanOnOpen')) {
        context.subscriptions.push(
            vscode.window.onDidChangeActiveTextEditor(async (editor) => {
                if (!editor) return;
                if (!SUPPORTED_EXTENSIONS.test(editor.document.uri.fsPath)) return;
                if (!config.get<boolean>('enabled')) return;
                await scanActiveFile(editor.document);
            })
        );
    }

    // ── NEW v3.0: Real-time scan on document change (debounced) ───────────────
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument((event) => {
            if (!realtimeScanEnabled) return;
            if (!config.get<boolean>('enabled')) return;
            const doc = event.document;
            if (!SUPPORTED_EXTENSIONS.test(doc.uri.fsPath)) return;
            if (event.contentChanges.length === 0) return;

            // Fix B2: track document key for version-based dedup
            const docKey = doc.uri.toString();

            // Clear existing timer and set a new debounced one
            if (realtimeScanTimer) clearTimeout(realtimeScanTimer);
            realtimeScanTimer = setTimeout(async () => {
                // Fix B2: skip scan if document version hasn't changed since last scan
                const currentVersion = doc.version;
                if (_lastScannedVersion.get(docKey) === currentVersion) return;
                _lastScannedVersion.set(docKey, currentVersion);

                await scanActiveFile(doc);
            }, realtimeDelay);
        })
    );

    // Fix B2: scan-on-save mode — faster feedback on save, complements debounced typing scan
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (doc) => {
            if (!config.get<boolean>('enabled')) return;
            if (!SUPPORTED_EXTENSIONS.test(doc.uri.fsPath)) return;
            // Cancel any pending realtime scan — save scan takes priority
            if (realtimeScanTimer) { clearTimeout(realtimeScanTimer); realtimeScanTimer = undefined; }
            await scanActiveFile(doc);
        })
    );

    // Scan the currently active file on startup
    if (vscode.window.activeTextEditor) {
        const doc = vscode.window.activeTextEditor.document;
        if (SUPPORTED_EXTENSIONS.test(doc.uri.fsPath)) {
            scanActiveFile(doc).catch(console.error);
        }
    }

    outputChannel.appendLine(`[VibeGuard] ${getAllRules().length} rules loaded. Ready.`);
}

// ─── Deactivation ─────────────────────────────────────────────────────────────

export function deactivate(): void {
    diagnosticsProvider?.dispose();
    statusBarItem?.dispose();
    outputChannel?.dispose();
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function scanActiveFile(document: vscode.TextDocument): Promise<void> {
    const config = vscode.workspace.getConfiguration('vibeguard');
    const disabledRules = config.get<string[]>('disabledRules') ?? [];
    const filePath = document.uri.fsPath;

    try {
        const code = document.getText();

        const allRules = getAllRules();
        const enabledRuleIds = allRules
            .filter((r) => r.enabled && !disabledRules.includes(r.id))
            .map((r) => r.id);

        // Run local scan without AI to ensure reliability
        const vulnerabilities = await scanCode(code, filePath, {
            target: filePath,
            rules: enabledRuleIds,
            enableAi: false,
        });

        diagnosticsProvider.updateFileDiagnostics(document, vulnerabilities);

        const count = vulnerabilities.length;
        const fileScore = Math.max(0, 100 - count * 10);
        const grade = fileScore >= 90 ? 'A' : fileScore >= 75 ? 'B' : fileScore >= 55 ? 'C' : fileScore >= 35 ? 'D' : 'F';
        updateStatusBar(fileScore, grade, count);

        outputChannel.appendLine(`[VibeGuard] Scanned: ${filePath} — ${count} issue(s)`);

        const fileName = filePath.split(/[\\/]/).pop() ?? filePath;
        if (count === 0) {
            vscode.window.showInformationMessage(`✅ VibeGuard: ${fileName} — No security issues found.`);
        } else {
            const sev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
            for (const v of vulnerabilities) { sev[v.severity] = (sev[v.severity] || 0) + 1; }
            const parts = (Object.entries(sev) as [string, number][])
                .filter(([, n]) => n > 0)
                .map(([k, n]) => `${n} ${k}`).join(', ');
            vscode.window.showWarningMessage(
                `🛡️ VibeGuard: ${fileName} — ${count} issue(s): ${parts}`,
                'View in Editor'
            ).then(action => {
                if (action === 'View in Editor') {
                    // Diagnostics are already shown as squiggly lines
                    vscode.window.showTextDocument(document);
                }
            });
        }
    } catch (err) {
        outputChannel.appendLine(`[VibeGuard] Error scanning ${filePath}: ${err}`);
        vscode.window.showErrorMessage(`VibeGuard: Scan failed — ${err instanceof Error ? err.message : String(err)}`);
    }
}

/**
 * Opens the system (OS) terminal and runs `npx vibeguard scan .` in the given folder.
 * Uses platform-specific commands so the scan runs in a separate terminal window.
 */
function openSystemTerminalAndScan(folderPath: string): void {
    const isWin = process.platform === 'win32';
    const command = 'npx vibeguard scan .';

    if (isWin) {
        // On Windows, build the entire command as a single string for shell execution.
        // Quotes around the path handle spaces. Double-quotes the title for 'start'.
        const safePath = folderPath.replace(/"/g, '\\"');
        const fullCmd = `start "VibeGuard Scan" cmd /k "cd /d \"${safePath}\" && ${command}"`;
        spawn('cmd', ['/c', fullCmd], {
            detached: true,
            stdio: 'ignore',
            shell: true,
        }).unref();
    } else if (process.platform === 'darwin') {
        const escapedPath = folderPath.replace(/'/g, "''");
        const script = `cd '${escapedPath}' && ${command}`;
        spawn('osascript', ['-e', `tell application "Terminal" to do script "${script.replace(/"/g, '\\"')}"`], {
            detached: true,
            stdio: 'ignore',
        }).unref();
    } else {
        const escapedPath = folderPath.replace(/"/g, '\\"');
        const bashCmd = `cd "${escapedPath}" && ${command}; exec bash`;
        const child = spawn('gnome-terminal', ['--', 'bash', '-c', bashCmd], {
            detached: true,
            stdio: 'ignore',
        });
        child.on('error', () => {
            spawn('xterm', ['-e', `bash -c 'cd "${folderPath.replace(/'/g, "'\"'\"'")}" && ${command}; exec bash'`], {
                detached: true,
                stdio: 'ignore',
            }).unref();
        });
        child.unref();
    }
}

function updateStatusBar(score: number, grade: string, issueCount?: number): void {
    const icon = score >= 75 ? '$(shield)' : score >= 50 ? '$(warning)' : '$(error)';
    const label = issueCount !== undefined
        ? `${icon} VG: ${score}/100 ${grade} (${issueCount} issue${issueCount !== 1 ? 's' : ''})`
        : `${icon} VG: ${score}/100 ${grade}`;

    statusBarItem.text = label;

    if (score >= 75) {
        statusBarItem.backgroundColor = undefined;
    } else if (score >= 50) {
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    } else {
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    }
}
