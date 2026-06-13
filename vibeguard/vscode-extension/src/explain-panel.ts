/**
 * VibeGuard — AI Explanation Panel (v3.1)
 *
 * Shows a full AI explanation for a vulnerability:
 *  - Why it's dangerous
 *  - Realistic attack scenario
 *  - Best practices & references
 *
 * Calls Groq or Gemini directly — no local backend required.
 * Falls back to a static explanation if all AI calls fail.
 */

import * as vscode from 'vscode';
import { openRouterService } from './openrouter-service';

// ─── Built-in AI Config (injected by build.js at build time) ─────────────────
const BUILT_IN_GEMINI_KEY      = (process.env as any).BUILT_IN_KEY          ?? '';
const BUILT_IN_GEMINI_ENDPOINT = (process.env as any).BUILT_IN_ENDPOINT     ?? 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions';
const BUILT_IN_GEMINI_MODEL    = (process.env as any).BUILT_IN_MODEL        ?? 'gemini-2.0-flash';
const BUILT_IN_GROQ_KEY        = (process.env as any).BUILT_IN_GROQ_KEY     ?? '';
const BUILT_IN_GROQ_MODEL      = (process.env as any).BUILT_IN_GROQ_MODEL   ?? 'llama-3.3-70b-versatile';
const GROQ_ENDPOINT            = 'https://api.groq.com/openai/v1/chat/completions';

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

// Keep a single panel instance per vulnerability ID
const _panels = new Map<string, vscode.WebviewPanel>();

// ─── Public API ───────────────────────────────────────────────────────────────

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

    try {
        const config = vscode.workspace.getConfiguration('vibeguard');
        const provider = config.get<string>('aiProvider') ?? 'Groq';

        let result: ExplainResult;

        if (provider === 'OpenRouter') {
            const orResult = await openRouterService.explainVulnerability(vuln as any);
            result = {
                vuln_id: vuln.id,
                why_dangerous: orResult.explanation,
                attack_scenario: 'See full explanation above.',
                best_practices: ['Apply Secure Coding Guidelines', 'Review OpenRouter suggestions'],
                severity_rationale: `Assigned severity: ${vuln.severity}`,
                references: vuln.cwe_id
                    ? [`https://cwe.mitre.org/data/definitions/${vuln.cwe_id.replace('CWE-', '')}.html`]
                    : ['https://owasp.org/www-project-top-ten/'],
                model_used: 'OpenRouter (' + (config.get<string>('openRouterModel') ?? '') + ')',
            };
        } else {
            result = await _fetchExplainFromAI(vuln, provider, config);
        }

        panel.webview.html = _buildHtml(vuln, result);
    } catch {
        // All AI calls failed — show a useful static explanation instead of an error screen
        panel.webview.html = _buildHtml(vuln, _staticFallback(vuln));
    }
}

// ─── AI Explanation Fetcher ───────────────────────────────────────────────────

async function _fetchExplainFromAI(
    vuln: VulnData,
    provider: string,
    config: vscode.WorkspaceConfiguration,
): Promise<ExplainResult> {
    let apiKey: string;
    let endpoint: string;
    let model: string;

    if (provider === 'Groq') {
        apiKey   = config.get<string>('groqApiKey')?.trim()  || BUILT_IN_GROQ_KEY;
        endpoint = GROQ_ENDPOINT;
        model    = config.get<string>('groqModel')?.trim()   || BUILT_IN_GROQ_MODEL;
    } else {
        // Gemini
        apiKey   = config.get<string>('aiApiKey')?.trim()    || BUILT_IN_GEMINI_KEY;
        endpoint = config.get<string>('aiEndpoint')?.trim()  || BUILT_IN_GEMINI_ENDPOINT;
        model    = config.get<string>('aiModel')?.trim()     || BUILT_IN_GEMINI_MODEL;
    }

    const prompt =
`You are a security expert. Explain the following vulnerability concisely and in a structured way.

Rule: ${vuln.rule_name}
Severity: ${vuln.severity}
Issue: ${vuln.message}
File: ${vuln.location.file} line ${vuln.location.line}
${vuln.location.snippet ? `\nVulnerable code:\n\`\`\`\n${vuln.location.snippet}\n\`\`\`` : ''}

Reply with ONLY a JSON object (no markdown fences) with these exact keys:
{
  "why_dangerous": "...",
  "attack_scenario": "...",
  "best_practices": ["...", "...", "..."],
  "severity_rationale": "...",
  "references": ["https://..."]
}`;

    const tryFetch = async (ep: string, key: string, mdl: string): Promise<ExplainResult> => {
        const resp = await fetch(ep, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${key}` },
            body: JSON.stringify({ model: mdl, messages: [{ role: 'user', content: prompt }], max_tokens: 800 }),
            signal: AbortSignal.timeout(30_000),
        });
        if (!resp.ok) {
            const e = new Error(`HTTP ${resp.status}`) as any;
            e.status = resp.status;
            throw e;
        }
        const json = await resp.json() as any;
        const raw = (json.choices?.[0]?.message?.content ?? '').trim();

        // Parse JSON response — strip markdown fences if present
        const jsonStr = raw.startsWith('```') ? raw.replace(/^```[^\n]*\n?/, '').replace(/\n?```$/, '') : raw;
        const parsed = JSON.parse(jsonStr);

        return {
            vuln_id: vuln.id,
            why_dangerous:      parsed.why_dangerous      ?? '',
            attack_scenario:    parsed.attack_scenario    ?? '',
            best_practices:     Array.isArray(parsed.best_practices) ? parsed.best_practices : [],
            severity_rationale: parsed.severity_rationale ?? '',
            references:         Array.isArray(parsed.references)     ? parsed.references : [],
            model_used: mdl,
        };
    };

    // Try primary provider
    try {
        if (apiKey) return await tryFetch(endpoint, apiKey, model);
    } catch (err: any) {
        if ((err?.status ?? 0) !== 429 && (err?.status ?? 0) !== 401 && (err?.status ?? 0) !== 403) throw err;
    }

    // Fallback: try the other built-in provider
    if (provider === 'Groq' && BUILT_IN_GEMINI_KEY) {
        try { return await tryFetch(BUILT_IN_GEMINI_ENDPOINT, BUILT_IN_GEMINI_KEY, BUILT_IN_GEMINI_MODEL); } catch { /* fall through */ }
    } else if (provider !== 'Groq' && BUILT_IN_GROQ_KEY) {
        try { return await tryFetch(GROQ_ENDPOINT, BUILT_IN_GROQ_KEY, BUILT_IN_GROQ_MODEL); } catch { /* fall through */ }
    }

    // Both failed — use static
    return _staticFallback(vuln);
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
            vuln.remediation ?? 'Apply the recommended remediation for this rule.',
        ].filter(Boolean),
        severity_rationale: `Severity ${vuln.severity} assigned based on potential impact and exploitability.`,
        references: [
            vuln.cwe_id
                ? `https://cwe.mitre.org/data/definitions/${vuln.cwe_id.replace('CWE-', '')}.html`
                : 'https://owasp.org/www-project-top-ten/',
            'https://cheatsheetseries.owasp.org/',
        ],
        model_used: 'static (offline)',
    };
}

// ─── HTML Builders ────────────────────────────────────────────────────────────

function _escape(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function _sevColor(sev: string): string {
    const m: Record<string, string> = {
        CRITICAL: '#f85149', HIGH: '#ff8c00', MEDIUM: '#e3b341', LOW: '#79c0ff', INFO: '#8b949e',
    };
    return m[sev?.toUpperCase()] ?? '#8b949e';
}

const _commonStyles = `
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 13px; background: #0d1117; color: #e6edf3; padding: 0; line-height: 1.6; }
  .header { background: linear-gradient(135deg, #161b22, #1c2128); border-bottom: 1px solid #30363d; padding: 20px 24px; }
  .header-top { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
  .shield { font-size: 24px; }
  .rule-name { font-size: 18px; font-weight: 700; color: #e6edf3; }
  .sev-badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; }
  .location { color: #8b949e; font-size: 12px; margin-top: 4px; }
  .location code { background: #161b22; padding: 1px 6px; border-radius: 4px; color: #79c0ff; }
  .tabs { display: flex; border-bottom: 1px solid #30363d; background: #0d1117; padding: 0 24px; }
  .tab { padding: 12px 16px; cursor: pointer; color: #8b949e; font-size: 13px; font-weight: 500; border-bottom: 2px solid transparent; transition: all 0.15s; user-select: none; }
  .tab:hover { color: #e6edf3; }
  .tab.active { color: #58a6ff; border-bottom-color: #58a6ff; }
  .content { padding: 24px; display: none; }
  .content.active { display: block; }
  .section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 20px; margin-bottom: 16px; }
  .section-title { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #8b949e; margin-bottom: 8px; font-weight: 600; }
  .section p { color: #c9d1d9; line-height: 1.7; }
  .practices-list { list-style: none; }
  .practices-list li { padding: 6px 0; color: #c9d1d9; display: flex; align-items: flex-start; gap: 8px; }
  .practices-list li::before { content: "✅"; flex-shrink: 0; }
  .refs-list { list-style: none; }
  .refs-list li a { color: #58a6ff; text-decoration: none; font-size: 12px; }
  .refs-list li a:hover { text-decoration: underline; }
  .refs-list li { padding: 4px 0; }
  .snippet-block { background: #010409; border: 1px solid #30363d; border-radius: 6px; padding: 12px 16px; font-family: 'JetBrains Mono', 'Consolas', monospace; font-size: 12px; color: #e6edf3; overflow-x: auto; white-space: pre; margin-top: 8px; }
  .model-badge { display: inline-flex; align-items: center; gap: 4px; background: #21262d; border: 1px solid #30363d; border-radius: 20px; padding: 2px 10px; font-size: 11px; color: #8b949e; margin-top: 16px; }
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

<div class="content" id="content-attack">
  <div class="attack-icon">⚔️</div>
  <div class="section">
    <div class="section-title">Realistic Attack Scenario</div>
    <p>${_escape(result.attack_scenario)}</p>
  </div>
  <div class="section">
    <div class="section-title">What an Attacker Could Do</div>
    <p>If this vulnerability is exploited, an attacker could gain unauthorized access to sensitive data, execute arbitrary code, or escalate privileges depending on the application context.</p>
  </div>
</div>

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
  <span class="model-badge">🤖 ${_escape(result.model_used)}</span>
</div>

</body>
</html>`;
}
