/**
 * VibeGuard VS Code Extension — Security Report Webview Panel
 *
 * A rich HTML/CSS dashboard showing the security score, grade,
 * vulnerability breakdown, and detailed findings.
 */

import * as vscode from 'vscode';
import { SecurityReport, VulnerabilitySeverity } from '@vibeguard/core';

// ─── Panel ────────────────────────────────────────────────────────────────────

export class VibeguardPanel {
    public static currentPanel: VibeguardPanel | undefined;
    private static readonly _viewType = 'vibeguardReport';

    private readonly _panel: vscode.WebviewPanel;
    private _disposables: vscode.Disposable[] = [];

    static createOrShow(extensionUri: vscode.Uri, report: SecurityReport): void {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (VibeguardPanel.currentPanel) {
            VibeguardPanel.currentPanel._panel.reveal(column);
            VibeguardPanel.currentPanel._update(report);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            VibeguardPanel._viewType,
            '🛡️ VibeGuard Security Report',
            column ?? vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'assets')],
            }
        );

        // Handle messages from the webview
        panel.webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'exportPdf':
                        vscode.commands.executeCommand('vibeguard.exportPdfReport', report);
                        return;
                }
            },
            null
        );

        VibeguardPanel.currentPanel = new VibeguardPanel(panel, report);
    }

    private constructor(panel: vscode.WebviewPanel, report: SecurityReport) {
        this._panel = panel;
        this._update(report);
        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
    }

    private _update(report: SecurityReport): void {
        this._panel.webview.html = getHtmlReport(report);
    }

    dispose(): void {
        VibeguardPanel.currentPanel = undefined;
        this._panel.dispose();
        while (this._disposables.length) {
            this._disposables.pop()?.dispose();
        }
    }
}

// ─── HTML Generation ──────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<VulnerabilitySeverity, string> = {
    CRITICAL: '#ff4757',
    HIGH: '#ff6b6b',
    MEDIUM: '#ffd43b',
    LOW: '#74c0fc',
    INFO: '#63e6be',
};

const SEVERITY_BG: Record<VulnerabilitySeverity, string> = {
    CRITICAL: '#ff475720',
    HIGH: '#ff6b6b18',
    MEDIUM: '#ffd43b15',
    LOW: '#74c0fc15',
    INFO: '#63e6be15',
};

const GRADE_COLORS: Record<string, string> = {
    A: '#69db7c',
    B: '#74c0fc',
    C: '#ffd43b',
    D: '#ff922b',
    F: '#ff4757',
};

function getHtmlReport(report: SecurityReport): string {
    const { score, vulnerabilities, summary, stats, target } = report;
    const gradeColor = GRADE_COLORS[score.grade] ?? '#ffffff';
    const totalIssues = Object.values(summary).reduce((a, b) => a + b, 0);

    const scorePercent = score.score;
    const scoreBarColor = score.score >= 75 ? '#69db7c' : score.score >= 50 ? '#ffd43b' : '#ff4757';

    const severityRows = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as VulnerabilitySeverity[])
        .map((sev) => {
            const count = summary[sev];
            if (count === 0) return '';
            return `
        <div class="sev-row">
          <span class="sev-badge" style="background:${SEVERITY_COLORS[sev]}22; color:${SEVERITY_COLORS[sev]}; border:1px solid ${SEVERITY_COLORS[sev]}44">${sev}</span>
          <div class="sev-bar-wrap">
            <div class="sev-bar" style="width:${Math.min(100, (count / totalIssues) * 100)}%; background:${SEVERITY_COLORS[sev]}"></div>
          </div>
          <span class="sev-count">${count}</span>
        </div>`;
        }).join('');

    const vulnCards = [...vulnerabilities]
        .sort((a, b) => {
            const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
            return order[a.severity] - order[b.severity];
        })
        .map((vuln) => {
            const c = SEVERITY_COLORS[vuln.severity];
            const bg = SEVERITY_BG[vuln.severity];
            const fileShort = vuln.location.file.split(/[\\/]/).slice(-2).join('/');
            return `
      <div class="vuln-card" style="border-left: 3px solid ${c}; background: ${bg}">
        <div class="vuln-header">
          <span class="vuln-sev" style="color:${c}">${vuln.severity}</span>
          <span class="vuln-rule">${vuln.ruleId}</span>
          <span class="vuln-id">${vuln.id}</span>
        </div>
        <div class="vuln-name">${vuln.ruleName}</div>
        <div class="vuln-msg">${escapeHtml(vuln.message)}</div>
        <div class="vuln-loc">📍 ${escapeHtml(fileShort)}:${vuln.location.line}:${vuln.location.column}</div>
        ${vuln.cweId ? `<div class="vuln-meta"><a href="https://cwe.mitre.org/data/definitions/${vuln.cweId.replace('CWE-', '')}.html" class="cwe-link">${vuln.cweId}</a> ${vuln.owaspCategory ? `· ${escapeHtml(vuln.owaspCategory)}` : ''}</div>` : ''}
        <div class="vuln-remediation">
          <span class="rem-label">💊 Remediation:</span>
          <span>${escapeHtml(vuln.remediation)}</span>
        </div>
        ${vuln.remediationCode ? `
        <div class="vuln-diff">
          <div class="diff-before">
             <div class="diff-label">🔴 Vulnerable Code</div>
             <pre class="vuln-snippet line-numbers"><code class="language-${getFileExtension(vuln.location.file)}">${formatSnippetWithLineNumbers(vuln.location.snippet || '', Math.max(1, vuln.location.line - 2))}</code></pre>
          </div>
          <div class="diff-after">
             <div class="diff-label">🟢 Fixed Code</div>
             <pre class="vuln-snippet fixed-code line-numbers"><code class="language-${getFileExtension(vuln.location.file)}">${formatSnippetWithLineNumbers(vuln.remediationCode, Math.max(1, vuln.location.line - 2))}</code></pre>
          </div>
        </div>
        ` : (vuln.location.snippet ? `<div class="diff-before"><div class="diff-label">🔴 Vulnerable Code</div><pre class="vuln-snippet line-numbers"><code class="language-${getFileExtension(vuln.location.file)}">${formatSnippetWithLineNumbers(vuln.location.snippet, Math.max(1, vuln.location.line - 2))}</code></pre></div>` : '')}
      </div>`;
        }).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline' https://cdnjs.cloudflare.com; script-src 'unsafe-inline' https://cdnjs.cloudflare.com; img-src https:;">
  <title>VibeGuard Security Report</title>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet" />
  <style>
    :root {
      --bg: #0d1117;
      --surface: #161b22;
      --surface2: #1c2128;
      --border: #30363d;
      --text: #e6edf3;
      --text-muted: #7d8590;
      --accent: #58a6ff;
      --radius: 8px;
      --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
      --mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: var(--font); font-size: 13px; line-height: 1.6; padding: 24px; min-height: 100vh; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }

    /* Header */
    .header { display: flex; align-items: center; gap: 16px; margin-bottom: 28px; padding-bottom: 20px; border-bottom: 1px solid var(--border); }
    .header-icon { font-size: 36px; }
    .header-title { font-size: 22px; font-weight: 700; }
    .header-sub { color: var(--text-muted); font-size: 12px; margin-top: 2px; }
    .header-actions { margin-left: auto; display: flex; align-items: center; gap: 10px; }
    .header-version { background: var(--surface2); border: 1px solid var(--border); border-radius: 20px; padding: 3px 12px; font-size: 11px; color: var(--text-muted); }
    .export-btn { background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 6px 12px; font-size: 12px; color: var(--text); cursor: pointer; display: flex; align-items: center; gap: 6px; transition: background 0.2s; }
    .export-btn:hover { background: var(--border); }

    /* Grid */
    .grid { display: grid; grid-template-columns: 260px 1fr; gap: 20px; margin-bottom: 28px; }
    @media (max-width: 700px) { .grid { grid-template-columns: 1fr; } }

    /* Cards */
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 20px; }
    .card-title { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.8px; color: var(--text-muted); margin-bottom: 16px; }

    /* Score */
    .score-circle { display: flex; flex-direction: column; align-items: center; padding: 8px 0 16px; }
    .score-num { font-size: 56px; font-weight: 800; line-height: 1; }
    .score-label { font-size: 12px; color: var(--text-muted); margin-top: 4px; }
    .score-grade { font-size: 28px; font-weight: 800; margin-top: 12px; padding: 6px 24px; border-radius: 8px; border: 2px solid; }
    .score-desc { text-align: center; font-size: 12px; color: var(--text-muted); margin-top: 10px; }
    .score-bar-wrap { margin: 16px 0 4px; height: 8px; background: var(--surface2); border-radius: 4px; overflow: hidden; }
    .score-bar { height: 100%; border-radius: 4px; transition: width 0.6s ease; }
    .score-pass { display: inline-block; margin-top: 12px; padding: 4px 14px; border-radius: 20px; font-size: 12px; font-weight: 600; }

    /* Severity rows */
    .sev-row { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
    .sev-badge { font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; min-width: 72px; text-align: center; }
    .sev-bar-wrap { flex: 1; height: 6px; background: var(--surface2); border-radius: 3px; overflow: hidden; }
    .sev-bar { height: 100%; border-radius: 3px; min-width: 4px; }
    .sev-count { font-weight: 700; min-width: 24px; text-align: right; font-size: 13px; }

    /* Stats */
    .stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .stat-item { background: var(--surface2); border-radius: 6px; padding: 12px 14px; }
    .stat-value { font-size: 20px; font-weight: 700; }
    .stat-label { font-size: 11px; color: var(--text-muted); margin-top: 2px; }

    /* Vulnerabilities */
    .vulns-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
    .vulns-title { font-size: 15px; font-weight: 700; }
    .vuln-count-badge { background: var(--surface2); border: 1px solid var(--border); border-radius: 20px; padding: 2px 12px; font-size: 12px; }
    .vuln-card { border-radius: var(--radius); padding: 14px 16px; margin-bottom: 12px; border: 1px solid var(--border); }
    .vuln-header { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
    .vuln-sev { font-size: 10px; font-weight: 800; letter-spacing: 0.5px; }
    .vuln-rule { font-size: 11px; color: var(--accent); font-family: var(--mono); }
    .vuln-id { margin-left: auto; font-size: 10px; color: var(--text-muted); font-family: var(--mono); }
    .vuln-name { font-size: 14px; font-weight: 600; margin-bottom: 4px; }
    .vuln-msg { color: var(--text-muted); margin-bottom: 8px; font-size: 12px; }
    .vuln-loc { font-size: 11px; font-family: var(--mono); color: var(--accent); margin-bottom: 6px; }
    .vuln-meta { font-size: 11px; color: var(--text-muted); margin-bottom: 8px; }
    .cwe-link { color: #da77f2; }
    .vuln-remediation { background: var(--surface2); border-radius: 6px; padding: 10px 12px; font-size: 12px; line-height: 1.5; }
    .rem-label { font-weight: 600; margin-right: 6px; }
    
    /* Code Snippets & Diffs */
    .vuln-diff { display: flex; flex-direction: column; gap: 12px; margin-top: 12px; }
    .diff-label { font-size: 11px; font-weight: 700; margin-bottom: 4px; padding-left: 4px; }
    .diff-before .diff-label { color: #ff6b6b; }
    .diff-after .diff-label { color: #69db7c; }
    
    /* PrismJS Override & Line Numbers */
    .vuln-snippet { background: #0d1117 !important; border: 1px solid var(--border); border-radius: 6px; margin: 0 !important; padding: 12px !important; font-size: 12px; font-family: var(--mono); overflow-x: auto; line-height: 1.5; counter-reset: line var(--start-line, 0); }
    .fixed-code { border-color: #2ea04340; background: #0d1117 !important; }
    .code-line { display: block; }
    .code-line::before { counter-increment: line; content: counter(line); display: inline-block; width: 24px; margin-right: 12px; text-align: right; color: var(--text-muted); opacity: 0.5; border-right: 1px solid var(--border); padding-right: 6px; user-select: none; }
    .code-line.code-highlight { background: #b3590020; border-radius: 2px; }

    .empty-state { text-align: center; padding: 48px 24px; color: var(--text-muted); }
    .empty-state .big { font-size: 48px; margin-bottom: 12px; }
    .empty-state .title { font-size: 16px; font-weight: 600; color: var(--text); margin-bottom: 8px; }
    .footer { text-align: center; color: var(--text-muted); font-size: 11px; padding-top: 20px; border-top: 1px solid var(--border); margin-top: 8px; }
  </style>
</head>
<body>
  <div class="header">
    <span class="header-icon">🛡️</span>
    <div>
      <div class="header-title">VibeGuard Security Report</div>
      <div class="header-sub">${escapeHtml(target)} · ${stats.timestamp}</div>
    </div>
    <div class="header-actions">
        <button id="export-pdf-btn" class="export-btn">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
          Export PDF
        </button>
        <span class="header-version">v${report.version}</span>
    </div>
  </div>

  <div class="grid">
    <!-- Score Panel -->
    <div>
      <div class="card">
        <div class="card-title">Security Score</div>
        <div class="score-circle">
          <div class="score-num" style="color:${scoreBarColor}">${scorePercent}</div>
          <div class="score-label">out of 100</div>
          <div class="score-grade" style="color:${gradeColor}; border-color:${gradeColor}40">${score.grade}</div>
          <div class="score-desc">${getGradeDesc(score.grade)}</div>
        </div>
        <div class="score-bar-wrap">
          <div class="score-bar" style="width:${scorePercent}%; background:${scoreBarColor}"></div>
        </div>
        <div style="text-align:center;">
          <span class="score-pass" style="background:${score.passed ? '#69db7c20' : '#ff475720'}; color:${score.passed ? '#69db7c' : '#ff4757'}">
            ${score.passed ? '✅ PASSED' : '❌ FAILED'}
          </span>
        </div>
      </div>

      <div class="card" style="margin-top:16px;">
        <div class="card-title">By Severity</div>
        ${severityRows || '<div style="color:var(--text-muted);font-size:12px;">No issues found</div>'}
      </div>

      <div class="card" style="margin-top:16px;">
        <div class="card-title">Scan Stats</div>
        <div class="stats-grid">
          <div class="stat-item">
            <div class="stat-value">${stats.filesScanned}</div>
            <div class="stat-label">Files Scanned</div>
          </div>
          <div class="stat-item">
            <div class="stat-value">${totalIssues}</div>
            <div class="stat-label">Total Issues</div>
          </div>
          <div class="stat-item">
            <div class="stat-value">${stats.linesScanned.toLocaleString()}</div>
            <div class="stat-label">Lines Scanned</div>
          </div>
          <div class="stat-item">
            <div class="stat-value">${stats.durationMs}ms</div>
            <div class="stat-label">Duration</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Vulnerabilities -->
    <div>
      <div class="vulns-header">
        <span class="vulns-title">Vulnerability Findings</span>
        <span class="vuln-count-badge">${vulnerabilities.length} issue${vulnerabilities.length !== 1 ? 's' : ''}</span>
      </div>

      ${vulnerabilities.length === 0 ? `
        <div class="empty-state">
          <div class="big">✅</div>
          <div class="title">No vulnerabilities detected!</div>
          <div>Your code passed all VibeGuard security checks.</div>
        </div>
      ` : vulnCards}
    </div>
  </div>

  <div class="footer">
    Generated by VibeGuard v${report.version} · ${stats.timestamp}
  </div>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-javascript.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-typescript.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-python.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-java.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-c.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-cpp.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-php.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-ruby.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-go.min.js"></script>
  <script>
    const vscode = acquireVsCodeApi();
    document.getElementById('export-pdf-btn').addEventListener('click', () => {
        vscode.postMessage({
            command: 'exportPdf'
        });
    });
  </script>
</body>
</html>`;
}

function getGradeDesc(grade: string): string {
    const d: Record<string, string> = {
        A: 'Excellent — Very low risk',
        B: 'Good — Minor issues found',
        C: 'Fair — Action recommended',
        D: 'Poor — Significant issues',
        F: 'Critical — Immediate action',
    };
    return d[grade] ?? '';
}

function escapeHtml(str: string): string {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function getFileExtension(filename: string): string {
    const parts = filename.split('.');
    let ext = parts.length > 1 ? parts.pop()?.toLowerCase() || 'text' : 'text';
    const langMap: Record<string, string> = {
        'ts': 'typescript',
        'tsx': 'tsx',
        'js': 'javascript',
        'jsx': 'jsx',
        'py': 'python',
        'rb': 'ruby',
        'java': 'java',
        'cpp': 'cpp',
        'c': 'c',
        'cs': 'csharp',
        'php': 'php',
        'go': 'go'
    };
    return langMap[ext] || ext;
}

function formatSnippetWithLineNumbers(snippet: string, startLine: number): string {
    const lines = snippet.replace(/\n$/, '').split('\n');
    let html = '';
    // We inject css variable for line counter in the parent element
    html += `<style scoped>:scope { --start-line: ${startLine - 1}; }</style>`;
    lines.forEach((line) => {
        html += `<span class="code-line">${escapeHtml(line)}</span>\n`;
    });
    return html;
}
