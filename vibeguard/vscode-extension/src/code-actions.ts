import * as vscode from 'vscode';
import { VibeguardDiagnosticsProvider } from './diagnostics';

/**
 * Provides Quick Fix actions for VibeGuard AI-detected vulnerabilities.
 */
export class VibeguardCodeActionProvider implements vscode.CodeActionProvider {
    constructor(private readonly diagnosticsProvider: VibeguardDiagnosticsProvider) {}

    public provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        _token: vscode.CancellationToken
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        // Only look at VibeGuard diagnostics
        const vgDiagnostics = context.diagnostics.filter(d => d.source?.startsWith('VibeGuard'));
        if (vgDiagnostics.length === 0) return actions;

        // Get vulnerabilities for the active file
        const vulns = this.diagnosticsProvider.getFileVulnerabilities(document.uri.fsPath);

        for (const diagnostic of vgDiagnostics) {
            // Find the matching vulnerability object
            const vuln = vulns.find(v => `[${v.severity}] ${v.message}` === diagnostic.message);
            
            if (vuln?.remediationCode) {
                // If there's an AI-generated fix, offer an auto-fix!
                const fixAction = new vscode.CodeAction(`⚡ VibeGuard AI: Fix ${vuln.ruleId}`, vscode.CodeActionKind.QuickFix);
                fixAction.edit = new vscode.WorkspaceEdit();
                
                // Replace the vulnerable code with the suggested AI fix
                fixAction.edit.replace(document.uri, diagnostic.range, vuln.remediationCode);
                fixAction.diagnostics = [diagnostic];
                fixAction.isPreferred = true; // Makes it show up as a primary quick fix lightbulb
                actions.push(fixAction);
            }
            
            // Add an action to chat about this vulnerability if they just want context
            const chatAction = new vscode.CodeAction(`💬 VibeGuard: Ask AI about this issue`, vscode.CodeActionKind.Empty);
            chatAction.command = {
                command: 'vibeguard.askAi',
                title: 'Ask AI about this issue',
                arguments: [vuln || diagnostic]
            };
            actions.push(chatAction);
        }

        return actions;
    }
}
