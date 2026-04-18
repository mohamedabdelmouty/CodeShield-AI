/**
 * VibeGuard VS Code Extension — Main Entry Point
 *
 * Activates the extension, registers commands, and binds event listeners.
 * Compatible with VS Code, Cursor, and Windsurf.
 */

import { spawn } from 'child_process';
import * as vscode from 'vscode';
import { VibeguardDiagnosticsProvider } from './diagnostics';
import { VibeguardCodeLensProvider } from './codelens';
import { VibeguardPanel } from './panel';
import { exportToPdf, exportToPdfToPath } from './pdf-exporter';
import { scan, scanCode, getAllRules, VIBEGUARD_VERSION } from '@vibeguard/core';
import { VibeguardCodeActionProvider } from './code-actions';
import { VibeguardChatProvider } from './chat-panel';

// ─── Supported Language IDs ───────────────────────────────────────────────────

const SUPPORTED_LANGUAGES = [
    'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
    'python', 'java', 'dart', 'html', 'php', 'go', 'ruby', 'c', 'cpp', 'csharp', 'shellscript', 'yaml', 'json'
];
const SUPPORTED_EXTENSIONS = /\.(js|ts|jsx|tsx|mjs|cjs|py|java|dart|html|php|go|rb|c|cpp|cs|sh|yaml|yml|json)$/i;

// ─── Built-in Gemini AI Config ────────────────────────────────────────────────
// Embedded key is injected by build.js using esbuild at BUILD TIME.
// Source code never contains the real key - safe for GitHub.

const BUILT_IN_GEMINI_API_KEY = (process.env as any).BUILT_IN_KEY ?? '';
const BUILT_IN_GEMINI_ENDPOINT = (process.env as any).BUILT_IN_ENDPOINT ?? 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions';
const BUILT_IN_GEMINI_MODEL = (process.env as any).BUILT_IN_MODEL ?? 'gemini-2.0-flash';

/** Returns the effective AI config, preferring user settings over built-in defaults. */
function getAiConfig(): { enabled: boolean; endpoint: string; apiKey: string; model: string } {
    const config = vscode.workspace.getConfiguration('vibeguard');
    const enabled = config.get<boolean>('enableAi') ?? true;
    const endpoint = config.get<string>('aiEndpoint')?.trim() || BUILT_IN_GEMINI_ENDPOINT;
    const apiKey = config.get<string>('aiApiKey')?.trim() || BUILT_IN_GEMINI_API_KEY;
    const model = config.get<string>('aiModel')?.trim() || BUILT_IN_GEMINI_MODEL;
    return { enabled, endpoint, apiKey, model };
}

let diagnosticsProvider: VibeguardDiagnosticsProvider;
let statusBarItem: vscode.StatusBarItem;
let outputChannel: vscode.OutputChannel;

// ─── Activation ───────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
    outputChannel = vscode.window.createOutputChannel('VibeGuard');
    outputChannel.appendLine(`[VibeGuard v${VIBEGUARD_VERSION}] Extension activated.`);

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

    // ── Register Code Action Provider (AI Auto-Fix) ────────────────
    const codeActionProvider = new VibeguardCodeActionProvider(diagnosticsProvider);
    const codeActionDisposable = vscode.languages.registerCodeActionsProvider(
        SUPPORTED_LANGUAGES.map((lang) => ({ language: lang })),
        codeActionProvider,
        { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    );
    context.subscriptions.push(codeActionDisposable);

    // ── Register Chat Provider ──────────────────────────────────────
    const chatProvider = new VibeguardChatProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(VibeguardChatProvider.viewType, chatProvider)
    );

    // Command to open chat
    context.subscriptions.push(
        vscode.commands.registerCommand('vibeguard.askAi', (vuln: any) => {
            chatProvider.sendToChat(vuln);
        })
    );

    // ── Register Commands ─────────────────────────────────────────

    // Scan current file
    context.subscriptions.push(
        vscode.commands.registerCommand('vibeguard.scanFile', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('VibeGuard: No active file to scan.');
                return;
            }
            if (!SUPPORTED_EXTENSIONS.test(editor.document.uri.fsPath)) {
                vscode.window.showWarningMessage('VibeGuard: This file type is not supported.');
                return;
            }
            await scanActiveFile(editor.document);
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
                            const report = await scan({
                                target: folder.uri.fsPath,
                                ignore: config.get<string[]>('ignorePatterns') ?? [],
                                includeSnippets: true,
                                enableAi: ai.enabled,
                                aiEndpoint: ai.endpoint,
                                aiApiKey: ai.apiKey,
                                aiModel: ai.model,
                            });

                            diagnosticsProvider.setWorkspaceReport(report);
                            updateStatusBar(report.score.score, report.score.grade);
                            outputChannel.appendLine(`[VibeGuard] Workspace scan: Score ${report.score.score}/100 (${report.score.grade}). Vulnerabilities: ${report.vulnerabilities.length}`);

                            const pdfDir = folder.uri.fsPath;
                            const pdfPath = `${pdfDir}/vibeguard-report-${Date.now()}.pdf`;
                            try {
                                exportToPdfToPath(report, pdfPath);
                                outputChannel.appendLine(`[VibeGuard] PDF report saved to ${pdfPath}`);
                            } catch (err) {
                                outputChannel.appendLine(`[VibeGuard] Failed to write PDF: ${err}`);
                            }

                            vscode.window.showInformationMessage(
                                `🛡️ VibeGuard: Score ${report.score.score}/100 (Grade ${report.score.grade}). Found ${report.vulnerabilities.length} issue${report.vulnerabilities.length !== 1 ? 's' : ''}. PDF saved.`,
                                'Show Report'
                            ).then((action) => {
                                if (action === 'Show Report') {
                                    VibeguardPanel.createOrShow(context.extensionUri, report);
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

    try {
        const code = document.getText();
        const filePath = document.uri.fsPath;

        const allRules = getAllRules();
        const enabledRuleIds = allRules
            .filter((r) => r.enabled && !disabledRules.includes(r.id))
            .map((r) => r.id);

        const ai = getAiConfig();
        const vulnerabilities = await scanCode(code, filePath, {
            target: filePath,
            rules: enabledRuleIds,
            enableAi: ai.enabled,
            aiEndpoint: ai.endpoint,
            aiApiKey: ai.apiKey,
            aiModel: ai.model,
        });

        diagnosticsProvider.updateFileDiagnostics(document, vulnerabilities);

        // Update status bar with file-level info
        const fileScore = Math.max(0, 100 - vulnerabilities.length * 10);
        const grade = fileScore >= 90 ? 'A' : fileScore >= 75 ? 'B' : fileScore >= 55 ? 'C' : fileScore >= 35 ? 'D' : 'F';
        updateStatusBar(fileScore, grade, vulnerabilities.length);

        outputChannel.appendLine(`[VibeGuard] Scanned: ${filePath} — ${vulnerabilities.length} issue(s)`);
    } catch (err) {
        outputChannel.appendLine(`[VibeGuard] Error scanning ${document.uri.fsPath}: ${err}`);
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
        const safePath = folderPath.replace(/"/g, '""');
        const kArg = `cd /d "${safePath}" && ${command}`;
        spawn('cmd', ['/c', 'start', 'VibeGuard Scan', 'cmd', '/k', kArg], {
            detached: true,
            stdio: 'ignore',
            shell: false,
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
