/**
 * VibeGuard VS Code Extension — CodeLens Provider
 *
 * Shows inline security hints above vulnerable code lines.
 * Example: "⚠️ SQL Injection Risk (CRITICAL) — Click for details"
 */

import * as vscode from 'vscode';
import { Vulnerability, VulnerabilitySeverity } from '@vibeguard/core';
import { VibeguardDiagnosticsProvider } from './diagnostics';

// ─── Severity Labels ──────────────────────────────────────────────────────────

const SEVERITY_ICONS: Record<VulnerabilitySeverity, string> = {
    CRITICAL: '💀',
    HIGH: '🔴',
    MEDIUM: '🟡',
    LOW: '🔵',
    INFO: '💡',
};

// ─── CodeLens Provider ────────────────────────────────────────────────────────

export class VibeguardCodeLensProvider implements vscode.CodeLensProvider {
    private _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
    public readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;

    constructor(private readonly diagnosticsProvider: VibeguardDiagnosticsProvider) { }

    provideCodeLenses(
        document: vscode.TextDocument,
        _token: vscode.CancellationToken
    ): vscode.CodeLens[] {
        const config = vscode.workspace.getConfiguration('vibeguard');
        if (!config.get<boolean>('showCodeLens')) return [];
        if (!config.get<boolean>('enabled')) return [];

        const vulnerabilities = this.diagnosticsProvider.getFileVulnerabilities(document.uri.fsPath);
        if (vulnerabilities.length === 0) return [];

        const lenses: vscode.CodeLens[] = [];

        // Group by line to avoid stacking too many lenses on one line
        const byLine = new Map<number, Vulnerability[]>();
        for (const vuln of vulnerabilities) {
            const line = Math.max(0, vuln.location.line - 1); // 0-indexed
            const existing = byLine.get(line) ?? [];
            existing.push(vuln);
            byLine.set(line, existing);
        }

        for (const [lineNum, vulns] of byLine) {
            const range = new vscode.Range(lineNum, 0, lineNum, 0);

            // Primary CodeLens — first/most severe vulnerability
            const primary = vulns[0];
            const icon = SEVERITY_ICONS[primary.severity];
            const severityLabel = primary.severity;

            const label = vulns.length === 1
                ? `${icon} VibeGuard: ${severityLabel} — ${primary.ruleName}`
                : `${icon} VibeGuard: ${vulns.length} issues on this line — ${primary.ruleName} and more`;

            lenses.push(
                new vscode.CodeLens(range, {
                    title: label,
                    command: 'vibeguard.showReport',
                    arguments: [],
                    tooltip: `Remediation: ${primary.remediation}`,
                })
            );

            // Secondary lens showing remediation hint
            lenses.push(
                new vscode.CodeLens(range, {
                    title: `💊 Fix: ${primary.remediation.split('\n')[0].substring(0, 80)}${primary.remediation.length > 80 ? '…' : ''}`,
                    command: '', // No-op, informational only
                    arguments: [],
                })
            );
        }

        return lenses;
    }

    refresh(): void {
        this._onDidChangeCodeLenses.fire();
    }

    dispose(): void {
        this._onDidChangeCodeLenses.dispose();
    }
}
