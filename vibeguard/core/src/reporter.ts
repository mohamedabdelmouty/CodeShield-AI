/**
 * VibeGuard Core — Terminal & JSON Reporter
 *
 * Two output formats:
 *   1. Terminal: Colorful ANSI-formatted human-readable output
 *   2. JSON: Structured machine-readable SecurityReport
 */

import * as path from 'path';
import { SecurityReport, Vulnerability, VulnerabilitySeverity } from './types';
import { gradeDescription, gradeBadge } from './score';

// ─── ANSI Colors ──────────────────────────────────────────────────────────────

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

const COLORS: Record<string, string> = {
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  white: '\x1b[37m',
  brightRed: '\x1b[91m',
  brightYellow: '\x1b[93m',
  brightGreen: '\x1b[92m',
  brightBlue: '\x1b[94m',
  brightCyan: '\x1b[96m',
  gray: '\x1b[90m',
};

function color(text: string, c: string): string {
  return `${c}${text}${RESET}`;
}

function bold(text: string): string {
  return `${BOLD}${text}${RESET}`;
}

function dim(text: string): string {
  return `${DIM}${text}${RESET}`;
}

// ─── Severity Colors ──────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<VulnerabilitySeverity, string> = {
  CRITICAL: COLORS.brightRed,
  HIGH: COLORS.red,
  MEDIUM: COLORS.brightYellow,
  LOW: COLORS.yellow,
  INFO: COLORS.cyan,
};

const SEVERITY_ICONS: Record<VulnerabilitySeverity, string> = {
  CRITICAL: '💀',
  HIGH: '🔴',
  MEDIUM: '🟡',
  LOW: '🔵',
  INFO: '💡',
};

function severityBadge(severity: VulnerabilitySeverity): string {
  return color(
    `${SEVERITY_ICONS[severity]} ${severity.padEnd(8)}`,
    SEVERITY_COLORS[severity]
  );
}

// ─── Terminal Reporter ────────────────────────────────────────────────────────

function separator(char = '─', width = 80): string {
  return color(char.repeat(width), COLORS.gray);
}

function formatVulnerability(vuln: Vulnerability, index: number): string {
  const lines: string[] = [];
  const loc = vuln.location;
  const fileRef = `${loc.file}:${loc.line}:${loc.column}`;

  lines.push(`  ${bold(`${index + 1}.`)} ${severityBadge(vuln.severity)} ${bold(vuln.ruleName)}`);
  lines.push(`     ${color('ID:', COLORS.gray)}          ${color(vuln.id, COLORS.gray)}`);
  lines.push(`     ${color('Rule:', COLORS.gray)}        ${color(vuln.ruleId, COLORS.blue)}`);
  lines.push(`     ${color('Message:', COLORS.gray)}     ${vuln.message}`);
  lines.push(`     ${color('Location:', COLORS.gray)}    ${color(fileRef, COLORS.cyan)}`);
  if (vuln.cweId) {
    lines.push(`     ${color('CWE:', COLORS.gray)}         ${color(vuln.cweId, COLORS.magenta)}`);
  }
  if (vuln.owaspCategory) {
    lines.push(`     ${color('OWASP:', COLORS.gray)}       ${vuln.owaspCategory}`);
  }
  lines.push(`     ${color('Remediation:', COLORS.gray)} ${dim(vuln.remediation)}`);

  if (vuln.location.snippet) {
    lines.push(`     ${color('Snippet:', COLORS.gray)}`);
    const snippetLines = vuln.location.snippet.split('\n');
    for (const snippetLine of snippetLines) {
      lines.push(`       ${color('│', COLORS.gray)} ${dim(snippetLine)}`);
    }
  }

  return lines.join('\n');
}

export function generateTerminalReport(report: SecurityReport): string {
  const lines: string[] = [];
  const { score, vulnerabilities, summary, stats } = report;

  // ── Header ──
  lines.push('');
  lines.push(bold(color('  ╔══════════════════════════════════════════════╗', COLORS.brightCyan)));
  lines.push(bold(color('  ║         VibeGuard Security Scanner           ║', COLORS.brightCyan)));
  lines.push(bold(color('  ╚══════════════════════════════════════════════╝', COLORS.brightCyan)));
  lines.push('');

  // ── Score Dashboard ──
  const gradeColor = score.grade === 'A' ? COLORS.brightGreen
    : score.grade === 'B' ? COLORS.green
      : score.grade === 'C' ? COLORS.brightYellow
        : score.grade === 'D' ? COLORS.yellow
          : COLORS.brightRed;

  lines.push(`  ${gradeBadge(score.grade)} ${bold('Security Score:')} ${bold(color(`${score.score}/100`, gradeColor))}   Grade: ${bold(color(score.grade, gradeColor))}`);
  lines.push(`  ${color(gradeDescription(score.grade), COLORS.gray)}`);
  lines.push('');

  // Score bar
  const filledBars = Math.round(score.score / 5);
  const emptyBars = 20 - filledBars;
  const bar = color('█'.repeat(filledBars), gradeColor) + color('░'.repeat(emptyBars), COLORS.gray);
  lines.push(`  [${bar}] ${score.score}%`);
  lines.push('');
  lines.push(separator());

  // ── Summary Counts ──
  lines.push('');
  lines.push(`  ${bold('Vulnerabilities Found:')}`);
  const severityList: VulnerabilitySeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  for (const sev of severityList) {
    const count = summary[sev];
    if (count > 0) {
      lines.push(`    ${severityBadge(sev)} ${color(String(count), COLORS.white)} found`);
    }
  }
  const total = Object.values(summary).reduce((a, b) => a + b, 0);
  lines.push(`    ${bold(`Total: ${total} issue${total !== 1 ? 's' : ''}`)}`);
  lines.push('');
  lines.push(separator());

  // ── Vulnerabilities ──
  if (vulnerabilities.length === 0) {
    lines.push('');
    lines.push(`  ${color('✅ No vulnerabilities detected!', COLORS.brightGreen)}`);
    lines.push(`  ${dim('Your code passed all VibeGuard security checks.')}`);
    lines.push('');
  } else {
    lines.push('');
    lines.push(`  ${bold('Vulnerability Details:')}`);
    lines.push('');

    // Sort by severity
    const sorted = [...vulnerabilities].sort((a, b) => {
      const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
      return order[a.severity] - order[b.severity];
    });

    for (let i = 0; i < sorted.length; i++) {
      lines.push(formatVulnerability(sorted[i], i));
      lines.push('');
    }
    lines.push(separator());
  }

  // ── Stats ──
  lines.push('');
  lines.push(`  ${bold('Scan Statistics:')}`);
  lines.push(`    ${color('Target:', COLORS.gray)}        ${report.target}`);
  lines.push(`    ${color('Files Scanned:', COLORS.gray)} ${stats.filesScanned}`);
  lines.push(`    ${color('Files Skipped:', COLORS.gray)} ${stats.filesSkipped}`);
  lines.push(`    ${color('Lines Scanned:', COLORS.gray)} ${stats.linesScanned.toLocaleString()}`);
  lines.push(`    ${color('Duration:', COLORS.gray)}      ${stats.durationMs}ms`);
  lines.push(`    ${color('Timestamp:', COLORS.gray)}     ${stats.timestamp}`);
  lines.push(`    ${color('Version:', COLORS.gray)}       v${report.version}`);
  lines.push('');

  // ── Result ──
  lines.push(separator('═'));
  if (score.passed) {
    lines.push(bold(color(`  ✅ PASSED — Score ${score.score}/100 meets the threshold`, COLORS.brightGreen)));
  } else {
    lines.push(bold(color(`  ❌ FAILED — Score ${score.score}/100 is below the threshold`, COLORS.brightRed)));
  }
  lines.push(separator('═'));
  lines.push('');

  return lines.join('\n');
}

// ─── JSON Reporter ────────────────────────────────────────────────────────────

export function generateJsonReport(report: SecurityReport): string {
  return JSON.stringify(report, null, 2);
}

// ─── HTML Reporter ────────────────────────────────────────────────────────────

export function generateHtmlReport(report: SecurityReport): string {
  const { vulnerabilities, summary, stats, target } = report;
  const totalIssues = Object.values(summary).reduce((a, b) => a + b, 0);

  const severityTabs = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as VulnerabilitySeverity[])
    .map((sev) => {
      const count = summary[sev];
      const color = SEVERITY_COLORS[sev];
      const active = count > 0 ? 'enabled' : 'disabled';
      return `
        <div class="tab ${active}" onclick="filterBySeverity('${sev}')" id="tab-${sev}">
          <span class="tab-dot" style="background:${color}"></span>
          <span class="tab-label">${sev}</span>
          <span class="tab-count">${count}</span>
        </div>`;
    }).join('');

  const vulnCards = [...vulnerabilities]
    .sort((a, b) => {
      const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
      return order[a.severity] - order[b.severity];
    })
    .map((vuln) => {
      const c = SEVERITY_COLORS[vuln.severity];
      const bg = SEVERITY_COLORS[vuln.severity] + '08';
      const fileShort = vuln.location.file.split(/[\\/]/).slice(-2).join('/');
      return `
      <div class="vuln-card severity-${vuln.severity}" style="border-left: 4px solid ${c}; background: ${bg}">
        <div class="vuln-header">
          <div class="vuln-meta">
            <span class="vuln-sev-badge" style="background:${c}20; color:${c}">${vuln.severity}</span>
            <span class="vuln-id">${vuln.id}</span>
            ${vuln.cweId ? `<span class="vuln-cwe">${vuln.cweId}</span>` : ''}
          </div>
          <div class="vuln-file">📍 ${escapeHtml(fileShort)}:${vuln.location.line}</div>
        </div>
        <div class="vuln-body">
          <div class="vuln-name">${vuln.ruleName}</div>
          <div class="vuln-msg">${escapeHtml(vuln.message)}</div>
          
          <div class="vuln-details">
            <div class="detail-section">
              <strong>💡 Description</strong>
              <p>${escapeHtml(vuln.description)}</p>
            </div>
            <div class="detail-section">
              <strong>💊 Remediation</strong>
              <div class="remediation-box">${escapeHtml(vuln.remediation)}</div>
            </div>
          </div>

          ${vuln.location.snippet ? `
          <div class="snippet-container">
            <div class="snippet-header">Code Context</div>
            <pre class="vuln-snippet"><code>${escapeHtml(vuln.location.snippet)}</code></pre>
          </div>` : ''}
        </div>
      </div>`;
    }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>VibeGuard Dashboard — ${path.basename(target)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #03060b;
      --surface: #0d1117;
      --surface-raised: #161b22;
      --border: #30363d;
      --text: #e6edf3;
      --text-muted: #7d8590;
      --accent: #2f81f7;
      --success: #3fb950;
      --danger: #f85149;
      --warning: #d29922;
    }

    * { box-sizing: border-box; }
    body { 
      background: var(--bg); 
      color: var(--text); 
      font-family: 'Inter', -apple-system, system-ui, sans-serif; 
      margin: 0; 
      line-height: 1.5;
    }

    .layout { display: grid; grid-template-columns: 320px 1fr; height: 100vh; }

    /* Sidebar */
    .sidebar { 
      background: var(--surface); 
      border-right: 1px solid var(--border); 
      padding: 32px 24px; 
      display: flex; 
      flex-direction: column;
      overflow-y: auto;
    }
    .logo { display: flex; align-items: center; gap: 12px; font-size: 20px; font-weight: 700; margin-bottom: 40px; }
    .logo-shield { font-size: 24px; }

    .stat-card { 
      background: var(--surface-raised); 
      border: 1px solid var(--border); 
      border-radius: 12px; 
      padding: 20px; 
      margin-bottom: 24px;
    }
    .score-value { font-size: 48px; font-weight: 800; text-align: center; margin: 10px 0; }
    .score-label { text-align: center; color: var(--text-muted); font-size: 14px; font-weight: 500; }
    .grade-badge { 
      display: block; 
      text-align: center; 
      padding: 6px; 
      border-radius: 6px; 
      font-weight: 700; 
      margin-top: 10px;
    }

    .tabs { margin-top: 20px; }
    .tab { 
      display: flex; 
      align-items: center; 
      padding: 10px 14px; 
      border-radius: 8px; 
      cursor: pointer; 
      margin-bottom: 4px; 
      transition: all 0.2s;
    }
    .tab:hover { background: var(--surface-raised); }
    .tab.active { background: var(--accent); color: white; }
    .tab.active .tab-count { background: rgba(255,255,255,0.2); }
    .tab-dot { width: 8px; height: 8px; border-radius: 50%; margin-right: 12px; }
    .tab-label { flex: 1; font-weight: 500; font-size: 14px; }
    .tab-count { background: var(--surface-raised); padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; }
    .tab.disabled { opacity: 0.5; pointer-events: none; }

    /* Content Area */
    .main { overflow-y: auto; padding: 40px 60px; }
    .top-bar { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 40px; }
    .page-title { margin: 0; font-size: 32px; font-weight: 700; }
    .target-path { color: var(--text-muted); font-family: 'Fira Code', monospace; font-size: 14px; margin-top: 8px; }

    .status-pill { 
      padding: 6px 16px; 
      border-radius: 100px; 
      font-weight: 600; 
      font-size: 14px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* Vulnerability Cards */
    .vuln-card { 
      border: 1px solid var(--border); 
      border-radius: 12px; 
      padding: 24px; 
      margin-bottom: 24px;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .vuln-card:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,0.3); }
    
    .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
    .vuln-meta { display: flex; align-items: center; gap: 12px; }
    .vuln-sev-badge { padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 800; letter-spacing: 0.05em; }
    .vuln-id { color: var(--text-muted); font-family: 'Fira Code', monospace; font-size: 12px; }
    .vuln-cwe { background: #2f363d; color: #8b949e; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
    .vuln-file { color: var(--accent); font-size: 13px; font-weight: 500; }

    .vuln-name { font-size: 20px; font-weight: 700; margin-bottom: 8px; }
    .vuln-msg { font-size: 15px; color: var(--text-muted); margin-bottom: 24px; border-bottom: 1px solid var(--border); padding-bottom: 16px; }

    .vuln-details { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px; }
    .detail-section strong { display: block; font-size: 12px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 8px; letter-spacing: 0.05em; }
    .detail-section p { margin: 0; font-size: 14px; color: #c9d1d9; }
    .remediation-box { background: rgba(63, 185, 80, 0.1); border: 1px solid rgba(63, 185, 80, 0.2); color: #aff5b4; padding: 12px; border-radius: 8px; font-size: 13px; }

    .snippet-container { margin-top: 24px; }
    .snippet-header { font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 8px; }
    .vuln-snippet { 
      background: #010409; 
      padding: 16px; 
      border: 1px solid var(--border); 
      border-radius: 8px; 
      margin: 0; 
      font-family: 'Fira Code', monospace; 
      font-size: 12px; 
      overflow-x: auto; 
    }

    .empty-state { text-align: center; padding: 100px 0; color: var(--text-muted); }
    .empty-icon { font-size: 64px; margin-bottom: 20px; }

    /* Filtering Classes */
    .hidden { display: none !important; }

    @media (max-width: 1200px) {
      .vuln-details { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="layout">
    <aside class="sidebar">
      <div class="logo">
        <span class="logo-shield">🛡️</span>
        <span>VibeGuard</span>
      </div>

      <div class="stat-card">
        <div class="score-label">SECURITY SCORE</div>
        <div class="score-value" style="color: ${report.score.passed ? 'var(--success)' : 'var(--danger)'}">${report.score.score}</div>
        <div class="grade-badge" style="background: ${report.score.passed ? 'var(--success)' : 'var(--danger)'}20; color: ${report.score.passed ? 'var(--success)' : 'var(--danger)'}">
          GRADE: ${report.score.grade}
        </div>
      </div>

      <div class="stat-card">
        <div class="score-label">FILES SCANNED</div>
        <div style="font-size: 20px; font-weight: 700; text-align: center; margin-top: 8px;">${stats.filesScanned}</div>
        <div style="font-size: 12px; color: var(--text-muted); text-align: center; margin-top: 4px;">in ${stats.durationMs}ms</div>
      </div>

      <div class="tabs">
        <div class="tab active" onclick="filterBySeverity('ALL')" id="tab-ALL">
          <span class="tab-dot" style="background: var(--accent)"></span>
          <span class="tab-label">All Issues</span>
          <span class="tab-count">${totalIssues}</span>
        </div>
        ${severityTabs}
      </div>

      <div style="flex: 1"></div>
      <div style="font-size: 11px; color: var(--text-muted); text-align: center;">
        VibeGuard v${report.version} • ${new Date(stats.timestamp).toLocaleDateString()}
      </div>
    </aside>

    <main class="main">
      <div class="top-bar">
        <div>
          <h1 class="page-title">Security Dashboard</h1>
          <div class="target-path">${escapeHtml(target)}</div>
        </div>
        <div class="status-pill" style="background: ${report.score.passed ? 'var(--success)' : 'var(--danger)'}20; color: ${report.score.passed ? 'var(--success)' : 'var(--danger)'}">
          ${report.score.passed ? '✓ COMPLIANT' : '⚠ VULNERABLE'}
        </div>
      </div>

      <div id="vulnerability-list">
        ${vulnerabilities.length === 0 ? `
          <div class="empty-state">
            <div class="empty-icon">✅</div>
            <h2>No Vulnerabilities Found</h2>
            <p>Your code looks clean and vibes are good!</p>
          </div>
        ` : vulnCards}
      </div>
    </main>
  </div>

  <script>
    function filterBySeverity(severity) {
      // Update tabs
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.getElementById('tab-' + severity).classList.add('active');

      // Update list
      const cards = document.querySelectorAll('.vuln-card');
      if (severity === 'ALL') {
        cards.forEach(c => c.classList.remove('hidden'));
      } else {
        cards.forEach(c => {
          if (c.classList.contains('severity-' + severity)) {
            c.classList.remove('hidden');
          } else {
            c.classList.add('hidden');
          }
        });
      }
    }
  </script>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str.replace(/[&<>"']/g, (m) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[m] || m));
}
