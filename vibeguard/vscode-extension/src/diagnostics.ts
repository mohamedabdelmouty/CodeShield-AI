/**
 * VibeGuard VS Code Extension — Diagnostics Provider
 *
 * Maps VibeGuard vulnerabilities to VS Code Diagnostic objects,
 * shown as squiggles in the editor and entries in the Problems panel.
 */

import * as vscode from 'vscode';
import { Vulnerability, VulnerabilitySeverity, SecurityReport } from '@vibeguard/core';
import { vulnDataMap, diagKey } from './auto-fix-provider';

// ─── Severity Mapping ─────────────────────────────────────────────────────────

function toDiagnosticSeverity(severity: VulnerabilitySeverity): vscode.DiagnosticSeverity {
    switch (severity) {
        case 'CRITICAL':
        case 'HIGH':
            return vscode.DiagnosticSeverity.Error;
        case 'MEDIUM':
            return vscode.DiagnosticSeverity.Warning;
        case 'LOW':
            return vscode.DiagnosticSeverity.Information;
        case 'INFO':
        default:
            return vscode.DiagnosticSeverity.Hint;
    }
}

// ─── Diagnostics Provider ─────────────────────────────────────────────────────

export class VibeguardDiagnosticsProvider {
    private readonly _diagnosticCollection: vscode.DiagnosticCollection;
    private _lastReport: SecurityReport | null = null;
    private _fileDiagnostics = new Map<string, Vulnerability[]>();

    constructor() {
        this._diagnosticCollection = vscode.languages.createDiagnosticCollection('vibeguard');
    }

    /**
     * Update diagnostics for a single file (from in-memory scanCode() results).
     */
    updateFileDiagnostics(document: vscode.TextDocument, vulnerabilities: Vulnerability[]): void {
        this._fileDiagnostics.set(document.uri.fsPath, vulnerabilities);

        const diagnostics: vscode.Diagnostic[] = vulnerabilities.map((vuln) => {
            const loc = vuln.location;
            // VS Code uses 0-based line numbers
            const startLine = Math.max(0, loc.line - 1);
            const startCol = Math.max(0, loc.column);
            const endLine = loc.endLine ? Math.max(0, loc.endLine - 1) : startLine;
            const endCol = loc.endColumn ?? (startCol + 30);

            const range = new vscode.Range(startLine, startCol, endLine, endCol);

            const diagnostic = new vscode.Diagnostic(
                range,
                `[${vuln.severity}] ${vuln.message}`,
                toDiagnosticSeverity(vuln.severity)
            );

            // Source must exactly match DIAGNOSTIC_SOURCE in auto-fix-provider
            diagnostic.source = 'VibeGuard';
            diagnostic.code = {
                value: vuln.ruleId,
                target: vuln.cweId
                    ? vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${vuln.cweId.replace('CWE-', '')}.html`)
                    : vscode.Uri.parse('https://github.com/vibeguard/vibeguard'),
            };

            // Add related information with remediation
            diagnostic.relatedInformation = [
                new vscode.DiagnosticRelatedInformation(
                    new vscode.Location(document.uri, range),
                    `Remediation: ${vuln.remediation}`
                ),
            ];

            // Populate vulnDataMap so autoFix & explainVuln can find this vuln
            const key = diagKey(document.uri, loc.line, vuln.ruleId);
            vulnDataMap.set(key, {
                id:             vuln.id ?? vuln.ruleId,
                rule_id:        vuln.ruleId,
                rule_name:      (vuln as any).ruleName ?? (vuln as any).rule_name ?? vuln.ruleId,
                severity:       vuln.severity,
                message:        vuln.message,
                remediation:    vuln.remediation ?? '',
                remediation_code: (vuln as any).remediation_code,
                cwe_id:         vuln.cweId,
                owasp_category: (vuln as any).owaspCategory ?? (vuln as any).owasp_category,
                location: {
                    file:    document.uri.fsPath,
                    line:    loc.line,
                    snippet: (vuln as any).snippet ?? (vuln.location as any)?.snippet,
                },
            });

            return diagnostic;
        });

        this._diagnosticCollection.set(document.uri, diagnostics);
    }

    /**
     * Apply workspace-wide scan results (from scan() using file paths).
     */
    setWorkspaceReport(report: SecurityReport): void {
        this._lastReport = report;
        this._diagnosticCollection.clear();

        // Group vulnerabilities by file
        const byFile = new Map<string, Vulnerability[]>();
        for (const vuln of report.vulnerabilities) {
            const existing = byFile.get(vuln.location.file) ?? [];
            existing.push(vuln);
            byFile.set(vuln.location.file, existing);
        }

        // Set diagnostics per file
        for (const [filePath, vulns] of byFile) {
            this._fileDiagnostics.set(filePath, vulns);
            const uri = vscode.Uri.file(filePath);
            const diagnostics: vscode.Diagnostic[] = vulns.map((vuln) => {
                const loc = vuln.location;
                const startLine = Math.max(0, loc.line - 1);
                const startCol = Math.max(0, loc.column);
                const endLine = loc.endLine ? Math.max(0, loc.endLine - 1) : startLine;
                const endCol = loc.endColumn ?? (startCol + 30);

                const range = new vscode.Range(startLine, startCol, endLine, endCol);
                const diagnostic = new vscode.Diagnostic(
                    range,
                    `[${vuln.severity}] ${vuln.message}`,
                    toDiagnosticSeverity(vuln.severity)
                );

                // Source must exactly match DIAGNOSTIC_SOURCE in auto-fix-provider
                diagnostic.source = 'VibeGuard';
                diagnostic.code = {
                    value: vuln.ruleId,
                    target: vuln.cweId
                        ? vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${vuln.cweId.replace('CWE-', '')}.html`)
                        : vscode.Uri.parse('https://github.com/vibeguard/vibeguard'),
                };

                // Populate vulnDataMap for workspace-wide vulns too
                const fileUri = vscode.Uri.file(filePath);
                const key = diagKey(fileUri, vuln.location.line, vuln.ruleId);
                vulnDataMap.set(key, {
                    id:             vuln.id ?? vuln.ruleId,
                    rule_id:        vuln.ruleId,
                    rule_name:      (vuln as any).ruleName ?? (vuln as any).rule_name ?? vuln.ruleId,
                    severity:       vuln.severity,
                    message:        vuln.message,
                    remediation:    vuln.remediation ?? '',
                    remediation_code: (vuln as any).remediation_code,
                    cwe_id:         vuln.cweId,
                    owasp_category: (vuln as any).owaspCategory ?? (vuln as any).owasp_category,
                    location: {
                        file:    filePath,
                        line:    vuln.location.line,
                        snippet: (vuln as any).snippet ?? (vuln.location as any)?.snippet,
                    },
                });

                return diagnostic;
            });

            this._diagnosticCollection.set(uri, diagnostics);
        }
    }

    /**
     * Returns vulnerabilities for a specific file (for CodeLens).
     */
    getFileVulnerabilities(filePath: string): Vulnerability[] {
        return this._fileDiagnostics.get(filePath) ?? [];
    }

    /**
     * Returns the last workspace report.
     */
    getLastReport(): SecurityReport | null {
        return this._lastReport;
    }

    /**
     * Clears all diagnostics from all files.
     */
    clearAll(): void {
        this._diagnosticCollection.clear();
        this._fileDiagnostics.clear();
        this._lastReport = null;
        vulnDataMap.clear(); // also clear the auto-fix map
    }

    dispose(): void {
        this._diagnosticCollection.dispose();
    }
}
