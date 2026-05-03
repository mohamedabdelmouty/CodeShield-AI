/**
 * CodeShield AI — VS Code Auto-Fix Provider (v3.0)
 *
 * Implements a CodeActionProvider that:
 *  1. Offers "🔧 AI Fix" as a Quick Fix for every VibeGuard diagnostic
 *  2. Calls the CodeShield backend /api/fix endpoint (or falls back to Gemini directly)
 *  3. Applies the fix as a WorkspaceEdit to the document
 */

import * as vscode from 'vscode';

/** Shape of the autofix API response */
interface AutoFixResult {
    original_code: string;
    fixed_code: string;
    diff: string;
    explanation: string;
    breaking_changes: string;
    security_improvement: string;
    model_used: string;
    vuln_id: string;
    rule_name: string;
    severity: string;
    file: string;
    line: number;
}

/** Shape of a VibeGuard vulnerability attached to a diagnostic */
interface VulnData {
    id: string;
    rule_id: string;
    rule_name: string;
    severity: string;
    message: string;
    remediation: string;
    remediation_code?: string;
    location: { file: string; line: number; snippet?: string };
    cwe_id?: string;
    owasp_category?: string;
}

const BACKEND_URL = 'http://localhost:8000';
const DIAGNOSTIC_SOURCE = 'VibeGuard';

// Map from diagnostic key → VulnData (populated by diagnostics.ts)
export const vulnDataMap = new Map<string, VulnData>();

/** Build a unique key to correlate a diagnostic with its vuln metadata */
export function diagKey(doc: vscode.Uri, line: number, ruleId: string): string {
    return `${doc.fsPath}:${line}:${ruleId}`;
}

// ─── Code Action Provider ─────────────────────────────────────────────────────

export class AutoFixProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        for (const diag of context.diagnostics) {
            if (diag.source !== DIAGNOSTIC_SOURCE) continue;

            // Extract rule_id from diagnostic code
            const ruleId = typeof diag.code === 'object' ? String(diag.code.value) : String(diag.code ?? '');
            const lineNum = diag.range.start.line + 1; // 1-indexed
            const key = diagKey(document.uri, lineNum, ruleId);
            const vuln = vulnDataMap.get(key);

            if (vuln) {
                // Primary: AI-powered fix
                const aiFixAction = this._makeAIFixAction(document, diag, vuln);
                actions.push(aiFixAction);

                // Secondary: apply remediation_code if available
                if (vuln.remediation_code) {
                    const quickAction = this._makeReplacementAction(document, diag, vuln);
                    actions.push(quickAction);
                }
            }
        }

        return actions;
    }

    /** Create a "🔧 AI Fix" code action that calls the backend */
    private _makeAIFixAction(
        document: vscode.TextDocument,
        diag: vscode.Diagnostic,
        vuln: VulnData,
    ): vscode.CodeAction {
        const action = new vscode.CodeAction(
            `🛡️ CodeShield: AI Fix — ${vuln.rule_name}`,
            vscode.CodeActionKind.QuickFix,
        );
        action.diagnostics = [diag];
        action.isPreferred = true;
        action.command = {
            command: 'vibeguard.autoFix',
            title: 'Apply AI Fix',
            arguments: [document.uri, diag, vuln],
        };
        return action;
    }

    /** Create a "⚡ Apply Suggested Fix" action using remediation_code */
    private _makeReplacementAction(
        document: vscode.TextDocument,
        diag: vscode.Diagnostic,
        vuln: VulnData,
    ): vscode.CodeAction {
        const action = new vscode.CodeAction(
            `⚡ CodeShield: Apply Suggested Fix`,
            vscode.CodeActionKind.QuickFix,
        );
        action.diagnostics = [diag];
        const edit = new vscode.WorkspaceEdit();
        // Replace the flagged line with the remediation code
        const lineRange = document.lineAt(diag.range.start.line).range;
        edit.replace(document.uri, lineRange, vuln.remediation_code!);
        action.edit = edit;
        return action;
    }
}

// ─── Auto-Fix Executor ────────────────────────────────────────────────────────

/**
 * Called by `vibeguard.autoFix` command.
 * Fetches a fix from the backend, shows a diff, and applies it on confirmation.
 */
export async function executeAutoFix(
    document: vscode.TextDocument,
    diag: vscode.Diagnostic,
    vuln: VulnData,
): Promise<void> {
    await vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: `🛡️ CodeShield: Generating AI fix for ${vuln.rule_name}…`,
            cancellable: false,
        },
        async () => {
            try {
                const result = await _fetchFix(vuln);
                await _showFixPreview(document, diag, vuln, result);
            } catch (err: unknown) {
                const msg = err instanceof Error ? err.message : String(err);
                vscode.window.showErrorMessage(`CodeShield Auto-Fix failed: ${msg}`);
            }
        },
    );
}

/** Call the CodeShield backend /api/fix */
async function _fetchFix(vuln: VulnData): Promise<AutoFixResult> {
    const config = vscode.workspace.getConfiguration('vibeguard');
    const backendUrl = config.get<string>('backendUrl', BACKEND_URL);

    const resp = await fetch(`${backendUrl}/api/fix`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vuln }),
        signal: AbortSignal.timeout(30_000),
    });

    if (!resp.ok) {
        throw new Error(`Backend returned ${resp.status}: ${await resp.text()}`);
    }
    return resp.json() as Promise<AutoFixResult>;
}

/** Show the diff in a preview and ask the user to confirm before applying */
async function _showFixPreview(
    document: vscode.TextDocument,
    diag: vscode.Diagnostic,
    vuln: VulnData,
    result: AutoFixResult,
): Promise<void> {
    const choice = await vscode.window.showInformationMessage(
        `🛡️ AI Fix ready for **${vuln.rule_name}** (line ${diag.range.start.line + 1})\n\n` +
        `**Explanation:** ${result.explanation}\n\n` +
        `**Security improvement:** ${result.security_improvement}\n\n` +
        `**Model used:** ${result.model_used}`,
        { modal: true },
        'Apply Fix',
        'Show Diff',
        'Cancel',
    );

    if (choice === 'Apply Fix') {
        await _applyFix(document, diag, result.fixed_code);
    } else if (choice === 'Show Diff') {
        await _showDiffView(document, result);
    }
}

/** Apply the fixed code to the document */
async function _applyFix(
    document: vscode.TextDocument,
    diag: vscode.Diagnostic,
    fixedCode: string,
): Promise<void> {
    const edit = new vscode.WorkspaceEdit();

    // Determine replacement range from diagnostic
    const lineText = document.lineAt(diag.range.start.line).text;
    const indent   = lineText.match(/^(\s*)/)?.[1] ?? '';

    // For multi-line snippets, replace the entire diagnostic range's line(s)
    const startLine = diag.range.start.line;
    const endLine   = diag.range.end.line;
    const replaceRange = new vscode.Range(
        new vscode.Position(startLine, 0),
        document.lineAt(endLine).range.end,
    );

    // Preserve original indentation
    const indented = fixedCode.split('\n').map(l => (l.trim() ? indent + l : l)).join('\n');
    edit.replace(document.uri, replaceRange, indented);

    const success = await vscode.workspace.applyEdit(edit);
    if (success) {
        vscode.window.showInformationMessage('✅ CodeShield: Fix applied successfully!');
    } else {
        vscode.window.showErrorMessage('❌ CodeShield: Failed to apply fix. Please apply manually.');
    }
}

/** Open a virtual diff document to preview the change */
async function _showDiffView(
    document: vscode.TextDocument,
    result: AutoFixResult,
): Promise<void> {
    // Write fixed code to a temp virtual document for diffing
    const originalUri = document.uri;
    const fixedUri = originalUri.with({ scheme: 'untitled', path: `${document.fileName}.fixed` });

    // For simplicity, show the diff in a notification with the fixed code
    const panel = vscode.window.createWebviewPanel(
        'codeshieldDiff',
        `🛡️ CodeShield Fix Preview — ${result.rule_name}`,
        vscode.ViewColumn.Beside,
        { enableScripts: false },
    );

    panel.webview.html = _buildDiffHtml(result);
}

function _buildDiffHtml(result: AutoFixResult): string {
    const escape = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const diffLines = result.diff.split('\n').map(line => {
        let cls = '';
        if (line.startsWith('+') && !line.startsWith('+++')) cls = 'add';
        else if (line.startsWith('-') && !line.startsWith('---')) cls = 'del';
        else if (line.startsWith('@@')) cls = 'hunk';
        return `<div class="${cls}">${escape(line)}</div>`;
    }).join('');

    return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  body { font-family: 'JetBrains Mono', 'Consolas', monospace; font-size: 13px; background: #0d1117; color: #e6edf3; padding: 16px; }
  h2  { color: #7ee787; margin-bottom: 8px; }
  pre { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; overflow-x: auto; }
  .add  { background: rgba(46,160,67,0.15); color: #7ee787; }
  .del  { background: rgba(248,81,73,0.15); color: #f85149; }
  .hunk { color: #58a6ff; }
  .info { background: #1c2128; border-left: 3px solid #388bfd; padding: 12px 16px; margin-bottom: 16px; border-radius: 0 6px 6px 0; }
  .label { color: #8b949e; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
</style>
</head>
<body>
<h2>🛡️ CodeShield AI — Fix Preview</h2>
<div class="info">
  <div class="label">Rule</div>
  <div>${escape(result.rule_name)} (${escape(result.severity)})</div>
  <br>
  <div class="label">Explanation</div>
  <div>${escape(result.explanation)}</div>
  <br>
  <div class="label">Security Improvement</div>
  <div>${escape(result.security_improvement)}</div>
  <br>
  <div class="label">Model Used</div>
  <div>${escape(result.model_used)}</div>
</div>
<h3 style="color:#8b949e">Diff</h3>
<pre>${diffLines}</pre>
</body>
</html>`;
}
