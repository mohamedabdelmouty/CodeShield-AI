/**
 * CodeShield AI — AI Explanation Panel (v3.0)
 *
 * A WebView panel that shows a full AI explanation for a vulnerability:
 *  - Why it's dangerous
 *  - Realistic attack scenario
 *  - Best practices & references
 */

import * as vscode from 'vscode';

interface ExplainResult {
    vuln_id: string;
    why_dangerous: string;
    attack_scenario: string;
    best_practices: string[];
    severity_rationale: string;
    references: string[];
    model_used: string;
}

interface VulnData {
    id: string;
    rule_id: string;
    rule_name: string;
    severity: string;
    message: string;
    location: { file: string; line: number; snippet?: string };
    cwe_id?: string;
    owasp_category?: string;
    remediation?: string;
}

const BACKEND_URL = 'http://localhost:8000';

// Keep a single panel instance per vulnerability ID
const _panels = new Map<string, vscode.WebviewPanel>();

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Open (or reveal) the explanation panel for a given vulnerability.
 * Calls the backend /api/explain and renders the result.
 */
export async function showExplainPanel(
    context: vscode.ExtensionContext,
    vuln: VulnData,
): Promise<void> {
    const panelKey = vuln.id;

    // Reuse existing panel if open
    if (_panels.has(panelKey)) {
        _panels.get(panelKey)!.reveal(vscode.ViewColumn.Beside);
        return;
    }

    // Create new panel
    const panel = vscode.window.createWebviewPanel(
        'codeshieldExplain',
        `🛡️ ${vuln.rule_name}`,
        vscode.ViewColumn.Beside,
        {
            enableScripts: true,
            retainContextWhenHidden: true,
            localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'dist')],
        },
    );

    _panels.set(panelKey, panel);
    panel.onDidDispose(() => _panels.delete(panelKey));

    // Show loading state immediately
    panel.webview.html = _loadingHtml(vuln);

    // Fetch explanation async
    try {
        const config = vscode.workspace.getConfiguration('vibeguard');
        const backendUrl = config.get<string>('backendUrl', BACKEND_URL);

        const resp = await fetch(`${backendUrl}/api/explain`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vuln }),
            signal: AbortSignal.timeout(30_000),
        });

        if (resp.ok) {
            const result = (await resp.json()) as ExplainResult;
            panel.webview.html = _buildHtml(vuln, result);
        } else {
            panel.webview.html = _errorHtml(vuln, `Backend returned ${resp.status}`);
        }
    } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        // Show static explanation if backend unavailable
        panel.webview.html = _buildHtml(vuln, _staticFallback(vuln));
    }
}

// ─── Static Fallback ──────────────────────────────────────────────────────────

function _staticFallback(vuln: VulnData): ExplainResult {
    return {
        vuln_id: vuln.id,
        why_dangerous: `${vuln.rule_name} vulnerabilities can be exploited by attackers to compromise application security. ${vuln.message}`,
        attack_scenario: `An attacker scans the application for ${vuln.rule_name} patterns and exploits them to gain unauthorized access or execute malicious actions.`,
        best_practices: [
            'Follow OWASP Secure Coding Guidelines',
            'Apply input validation and output encoding',
            'Use security-focused code reviews',
            'Implement automated security testing in CI/CD',
        ],
        severity_rationale: `Severity ${vuln.severity} assigned based on potential impact and exploitability.`,
        references: [
            vuln.cwe_id ? `https://cwe.mitre.org/data/definitions/${vuln.cwe_id.replace('CWE-', '')}.html` : 'https://owasp.org/www-project-top-ten/',
            'https://cheatsheetseries.owasp.org/',
        ],
        model_used: 'static',
    };
}

// ─── HTML Builders ────────────────────────────────────────────────────────────

function _escape(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function _sevColor(sev: string): string {
    const m: Record<string, string> = { CRITICAL: '#f85149', HIGH: '#ff8c00', MEDIUM: '#e3b341', LOW: '#79c0ff', INFO: '#8b949e' };
    return m[sev?.toUpperCase()] ?? '#8b949e';
}

const _commonStyles = `
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 13px;
    background: #0d1117;
    color: #e6edf3;
    padding: 0;
    line-height: 1.6;
  }
  .header {
    background: linear-gradient(135deg, #161b22, #1c2128);
    border-bottom: 1px solid #30363d;
    padding: 20px 24px;
  }
  .header-top { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
  .shield { font-size: 24px; }
  .rule-name { font-size: 18px; font-weight: 700; color: #e6edf3; }
  .sev-badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
    text-transform: uppercase;
  }
  .location { color: #8b949e; font-size: 12px; margin-top: 4px; }
  .location code { background: #161b22; padding: 1px 6px; border-radius: 4px; color: #79c0ff; }
  .tabs {
    display: flex;
    border-bottom: 1px solid #30363d;
    background: #0d1117;
    padding: 0 24px;
  }
  .tab {
    padding: 12px 16px;
    cursor: pointer;
    color: #8b949e;
    font-size: 13px;
    font-weight: 500;
    border-bottom: 2px solid transparent;
    transition: all 0.15s;
    user-select: none;
  }
  .tab:hover { color: #e6edf3; }
  .tab.active { color: #58a6ff; border-bottom-color: #58a6ff; }
  .content { padding: 24px; display: none; }
  .content.active { display: block; }
  .section {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px 20px;
    margin-bottom: 16px;
  }
  .section-title {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #8b949e;
    margin-bottom: 8px;
    font-weight: 600;
  }
  .section p { color: #c9d1d9; line-height: 1.7; }
  .practices-list { list-style: none; }
  .practices-list li {
    padding: 6px 0;
    color: #c9d1d9;
    display: flex;
    align-items: flex-start;
    gap: 8px;
  }
  .practices-list li::before { content: "✅"; flex-shrink: 0; }
  .refs-list { list-style: none; }
  .refs-list li a {
    color: #58a6ff;
    text-decoration: none;
    font-size: 12px;
  }
  .refs-list li a:hover { text-decoration: underline; }
  .refs-list li { padding: 4px 0; }
  .snippet-block {
    background: #010409;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 12px 16px;
    font-family: 'JetBrains Mono', 'Consolas', monospace;
    font-size: 12px;
    color: #e6edf3;
    overflow-x: auto;
    white-space: pre;
    margin-top: 8px;
  }
  .model-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 20px;
    padding: 2px 10px;
    font-size: 11px;
    color: #8b949e;
    margin-top: 16px;
  }
  .attack-icon { font-size: 40px; text-align: center; padding: 8px 0; }
</style>`;

function _loadingHtml(vuln: VulnData): string {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8">${_commonStyles}</head>
<body>
<div class="header">
  <div class="header-top">
    <span class="shield">🛡️</span>
    <span class="rule-name">${_escape(vuln.rule_name)}</span>
    <span class="sev-badge" style="background:${_sevColor(vuln.severity)}22;color:${_sevColor(vuln.severity)};border:1px solid ${_sevColor(vuln.severity)}44">${_escape(vuln.severity)}</span>
  </div>
</div>
<div style="padding:40px;text-align:center;color:#8b949e">
  <div style="font-size:32px;margin-bottom:16px">🤖</div>
  <div>Generating AI explanation…</div>
</div>
</body></html>`;
}

function _errorHtml(vuln: VulnData, msg: string): string {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8">${_commonStyles}</head>
<body>
<div class="header"><div class="header-top"><span class="shield">🛡️</span><span class="rule-name">${_escape(vuln.rule_name)}</span></div></div>
<div style="padding:24px;color:#f85149">⚠️ Failed to load explanation: ${_escape(msg)}<br><br>Make sure the CodeShield backend is running at http://localhost:8000</div>
</body></html>`;
}

function _buildHtml(vuln: VulnData, result: ExplainResult): string {
    const pracList = result.best_practices.map(p => `<li>${_escape(p)}</li>`).join('');
    const refList  = result.references.map(r => `<li><a href="${_escape(r)}" target="_blank">${_escape(r)}</a></li>`).join('');

    return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
${_commonStyles}
<script>
  function showTab(id) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.content').forEach(c => c.classList.remove('active'));
    document.getElementById('tab-' + id).classList.add('active');
    document.getElementById('content-' + id).classList.add('active');
  }
</script>
</head>
<body>

<div class="header">
  <div class="header-top">
    <span class="shield">🛡️</span>
    <span class="rule-name">${_escape(vuln.rule_name)}</span>
    <span class="sev-badge" style="background:${_sevColor(vuln.severity)}22;color:${_sevColor(vuln.severity)};border:1px solid ${_sevColor(vuln.severity)}44">${_escape(vuln.severity)}</span>
  </div>
  <div class="location">
    <code>${_escape(vuln.location.file)}</code> line <strong>${vuln.location.line}</strong>
    ${vuln.cwe_id ? `&nbsp;·&nbsp; <code>${_escape(vuln.cwe_id)}</code>` : ''}
    ${vuln.owasp_category ? `&nbsp;·&nbsp; ${_escape(vuln.owasp_category)}` : ''}
  </div>
</div>

<div class="tabs">
  <div class="tab active" id="tab-why" onclick="showTab('why')">❓ Why Dangerous</div>
  <div class="tab" id="tab-attack" onclick="showTab('attack')">⚔️ Attack Scenario</div>
  <div class="tab" id="tab-fix" onclick="showTab('fix')">🛠️ Best Practices</div>
</div>

<!-- Tab: Why Dangerous -->
<div class="content active" id="content-why">
  <div class="section">
    <div class="section-title">Why This Is Dangerous</div>
    <p>${_escape(result.why_dangerous)}</p>
  </div>
  <div class="section">
    <div class="section-title">Severity Rationale</div>
    <p>${_escape(result.severity_rationale)}</p>
  </div>
  ${vuln.location.snippet ? `
  <div class="section">
    <div class="section-title">Vulnerable Code Snippet</div>
    <div class="snippet-block">${_escape(vuln.location.snippet)}</div>
  </div>` : ''}
</div>

<!-- Tab: Attack Scenario -->
<div class="content" id="content-attack">
  <div class="attack-icon">⚔️</div>
  <div class="section">
    <div class="section-title">Realistic Attack Scenario</div>
    <p>${_escape(result.attack_scenario)}</p>
  </div>
  <div class="section">
    <div class="section-title">What an Attacker Could Do</div>
    <p>If this vulnerability is exploited, an attacker could gain unauthorized access to sensitive data, execute arbitrary code, or escalate privileges. The impact depends on the application context and data it handles.</p>
  </div>
</div>

<!-- Tab: Best Practices -->
<div class="content" id="content-fix">
  <div class="section">
    <div class="section-title">Secure Coding Best Practices</div>
    <ul class="practices-list">${pracList}</ul>
  </div>
  <div class="section">
    <div class="section-title">References &amp; Resources</div>
    <ul class="refs-list">${refList}</ul>
  </div>
</div>

<div style="padding:0 24px 24px">
  <span class="model-badge">🤖 Explanation by: ${_escape(result.model_used)}</span>
</div>

</body>
</html>`;
}
