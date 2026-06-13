import * as vscode from 'vscode';
import { Vulnerability } from '@vibeguard/core';
import { openRouterService } from './openrouter-service';

const BUILT_IN_GEMINI_KEY      = (process.env as any).BUILT_IN_KEY          ?? '';
const BUILT_IN_GEMINI_ENDPOINT = (process.env as any).BUILT_IN_ENDPOINT     ?? 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions';
const BUILT_IN_GEMINI_MODEL    = (process.env as any).BUILT_IN_MODEL        ?? 'gemini-2.0-flash';
const BUILT_IN_GROQ_KEY        = (process.env as any).BUILT_IN_GROQ_KEY     ?? '';
const BUILT_IN_GROQ_MODEL      = (process.env as any).BUILT_IN_GROQ_MODEL   ?? 'llama-3.3-70b-versatile';
const GROQ_ENDPOINT            = 'https://api.groq.com/openai/v1/chat/completions';

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

    const endpoint = config.get<string>('aiEndpoint')?.trim() || BUILT_IN_GEMINI_ENDPOINT;
    const apiKey   = config.get<string>('aiApiKey')?.trim()   || BUILT_IN_GEMINI_KEY;
    const model    = config.get<string>('aiModel')?.trim()    || BUILT_IN_GEMINI_MODEL;
    return { enabled, provider, endpoint, apiKey, model };
}

// ─── Direct AI call helper (outside class so it's accessible from fallback logic) ─

/** Throws an Error (with `.status` attached) on non-OK HTTP; throws on network/timeout. */
async function _callAiDirect(
    endpoint: string,
    apiKey: string,
    model: string,
    messages: Array<{ role: string; content: string }>
): Promise<string> {
    if (!apiKey) {
        const e = new Error('No API key provided') as any;
        e.status = 401;
        throw e;
    }

    const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`,
        },
        body: JSON.stringify({ model, messages, max_tokens: 1024 }),
        signal: AbortSignal.timeout(30_000),   // 30-second hard timeout
    });

    if (!response.ok) {
        const body = await response.text().catch(() => '');
        const e = new Error(`HTTP ${response.status}: ${body.slice(0, 200)}`) as any;
        e.status = response.status;
        throw e;
    }

    const json = await response.json() as any;
    return json.choices?.[0]?.message?.content ?? 'No response from AI.';
}

// ─── Chat Provider ────────────────────────────────────────────────────────────

export class VibeguardChatProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'vibeguard.chatView';
    private _view?: vscode.WebviewView;
    private _chatHistory: Array<{ role: 'user' | 'assistant'; content: string }> = [];

    // Fix B1: accept extensionContext so we can persist chat history across sidebar reopens
    constructor(
        private readonly _extensionUri: vscode.Uri,
        private readonly _context: vscode.ExtensionContext
    ) {}

    // Fix B1: load persisted history from workspaceState
    private _loadHistory(): Array<{ role: 'user' | 'assistant'; content: string }> {
        return this._context.workspaceState.get<Array<{ role: 'user' | 'assistant'; content: string }>>(
            'vibeguard.chatHistory', []
        );
    }

    // Fix B1: save history to workspaceState, capped at 50 messages to avoid unbounded growth
    private _saveHistory(): void {
        this._context.workspaceState.update('vibeguard.chatHistory', this._chatHistory.slice(-50));
    }

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        _context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ) {
        this._view = webviewView;
        webviewView.webview.options = { enableScripts: true, localResourceRoots: [this._extensionUri] };
        webviewView.webview.html = this._getHtmlForWebview();

        // Fix B1: restore persisted history on every webview open
        this._chatHistory = this._loadHistory();

        webviewView.webview.onDidReceiveMessage(async data => {
            switch (data.type) {
                case 'askAi':
                    await this._handleUserMessage(data.value);
                    break;
                case 'clearChat':
                    this._chatHistory = [];
                    // Fix B1: also clear from persistent storage
                    this._context.workspaceState.update('vibeguard.chatHistory', []);
                    this._view?.webview.postMessage({ type: 'clearChat' });
                    break;
            }
        });
    }

    public sendToChat(vuln: Vulnerability | any) {
        const msg = `Explain this vulnerability in detail and provide a secure code fix:\n\n**Rule:** ${vuln.ruleId || vuln.rule_id}\n**Message:** ${vuln.message}\n**Location:** ${vuln.location?.file}:${vuln.location?.line}`;
        if (!this._view) {
            vscode.commands.executeCommand('vibeguard.chatView.focus').then(() => {
                setTimeout(() => this._injectContext(msg), 500);
            });
            return;
        }
        this._view.show?.(true);
        this._injectContext(msg);
    }

    private _injectContext(msg: string) {
        this._view?.webview.postMessage({ type: 'setContext', value: msg });
    }

    private async _handleUserMessage(userMsg: string) {
        if (!userMsg.trim()) return;

        this._chatHistory.push({ role: 'user', content: userMsg });
        this._saveHistory();
        this._view?.webview.postMessage({ type: 'addMessage', role: 'user', content: userMsg });
        this._view?.webview.postMessage({ type: 'setTyping', value: true });

        const ai = getAiConfig();
        if (!ai.enabled) {
            const reply = '⚠️ AI is disabled in settings. Please enable `vibeguard.enableAi`.';
            this._chatHistory.push({ role: 'assistant', content: reply });
            this._saveHistory();
            this._view?.webview.postMessage({ type: 'addMessage', role: 'assistant', content: reply });
            this._view?.webview.postMessage({ type: 'setTyping', value: false });
            return;
        }

        try {
            let reply = '';

            // Build history context
            const historyContext = this._chatHistory
                .slice(-10, -1)
                .map(m => `${m.role.toUpperCase()}: ${m.content}`)
                .join('\\n');

            if (ai.provider === 'OpenRouter') {
                reply = await openRouterService.chatWithAI(userMsg, historyContext);
            } else {
                const systemPrompt = `You are VibeGuard AI, an expert security assistant. Help developers understand and fix security vulnerabilities. Be concise, practical, and always provide secure code examples. Format code with markdown code blocks.`;
                const messages = [
                    { role: 'system', content: systemPrompt },
                    ...this._chatHistory.slice(-10)
                ];

                if (!ai.apiKey && !BUILT_IN_GROQ_KEY && !BUILT_IN_GEMINI_KEY) {
                    reply = [
                        '⚠️ No AI API key configured.',
                        '',
                        'To enable the chat, add your key in VS Code settings:',
                        '• **Groq (free, fast):** Get a key at https://console.groq.com',
                        '  Then set: `vibeguard.aiProvider` = Groq and `vibeguard.groqApiKey` = your key',
                        '',
                        '• **Gemini (free):** Get a key at https://aistudio.google.com/app/apikey',
                        '  Then set: `vibeguard.aiProvider` = Gemini and `vibeguard.aiApiKey` = your key',
                    ].join('\n');
                } else {
                    reply = await this._callAiWithFallback(messages, ai);
                }
            }

            this._chatHistory.push({ role: 'assistant', content: reply });
            this._saveHistory();
            this._view?.webview.postMessage({ type: 'addMessage', role: 'assistant', content: reply });
        } catch (err) {
            const errMsg = `❌ AI request failed: ${err instanceof Error ? err.message : String(err)}`;
            this._view?.webview.postMessage({ type: 'addMessage', role: 'assistant', content: errMsg });
            vscode.window.showErrorMessage(`VibeGuard AI: ${err instanceof Error ? err.message.split('\n')[0] : String(err)}`);
        } finally {
            this._view?.webview.postMessage({ type: 'setTyping', value: false });
        }
    }

    /**
     * Call the primary AI provider; if it fails with 429 or auth error,
     * automatically fall back to the other built-in provider before giving up.
     */
    private async _callAiWithFallback(
        messages: Array<{ role: string; content: string }>,
        ai: ReturnType<typeof getAiConfig>
    ): Promise<string> {
        // Try primary provider first
        try {
            return await _callAiDirect(ai.endpoint, ai.apiKey, ai.model, messages);
        } catch (primaryErr: any) {
            const status: number = (primaryErr as any)?.status ?? 0;
            // Only fall back on rate-limit (429) or auth errors (401/403) — not on other errors
            if (status !== 429 && status !== 401 && status !== 403) throw primaryErr;

            // Determine which built-in provider to fall back to
            const useFallbackGroq = ai.provider !== 'Groq' && !!BUILT_IN_GROQ_KEY;
            const useFallbackGemini = ai.provider !== 'Gemini' && !!BUILT_IN_GEMINI_KEY;

            if (useFallbackGroq) {
                try {
                    return await _callAiDirect(GROQ_ENDPOINT, BUILT_IN_GROQ_KEY, BUILT_IN_GROQ_MODEL, messages);
                } catch { /* fall through to Gemini or final error */ }
            }

            if (useFallbackGemini) {
                try {
                    return await _callAiDirect(BUILT_IN_GEMINI_ENDPOINT, BUILT_IN_GEMINI_KEY, BUILT_IN_GEMINI_MODEL, messages);
                } catch { /* fall through to final error */ }
            }

            // All providers exhausted — give a helpful, actionable message
            const providerLabel = ai.provider === 'Groq' ? 'Groq' : 'Gemini';
            throw new Error(
                status === 429
                    ? `The ${providerLabel} API rate limit was reached (all built-in keys tried).\n\nGet your own free key:\n• Groq: https://console.groq.com → set vibeguard.groqApiKey in VS Code Settings\n• Gemini: https://aistudio.google.com/app/apikey → set vibeguard.aiApiKey`
                    : `The ${providerLabel} API key is invalid or revoked.\n\nSet your own key in VS Code Settings:\n• vibeguard.groqApiKey (for Groq)\n• vibeguard.aiApiKey (for Gemini)`
            );
        }
    }

    private _getHtmlForWebview() {
        return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>VibeGuard AI Chat</title>
  <style>
    :root {
      --bg: var(--vscode-editor-background);
      --surface: var(--vscode-editor-inactiveSelectionBackground);
      --text: var(--vscode-editor-foreground);
      --muted: var(--vscode-descriptionForeground);
      --accent: var(--vscode-textLink-foreground);
      --border: var(--vscode-widget-border, #444);
      --input-bg: var(--vscode-input-background);
      --input-fg: var(--vscode-input-foreground);
      --btn-bg: var(--vscode-button-background);
      --btn-fg: var(--vscode-button-foreground);
      --hover-bg: var(--vscode-list-hoverBackground);
      --user-msg-bg: rgba(88, 166, 255, 0.15);
      --user-msg-border: rgba(88, 166, 255, 0.3);
      --ast-msg-bg: var(--surface);
      --ast-msg-border: var(--border);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', var(--vscode-font-family); font-size: 13px; color: var(--text); background: var(--bg); display: flex; flex-direction: column; height: 100vh; overflow: hidden; }
    
    .chat-header { padding: 12px 16px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; flex-shrink: 0; background: rgba(0,0,0,0.2); }
    .chat-title { font-weight: 600; font-size: 14px; display: flex; align-items: center; gap: 8px; }
    .chat-title i { font-style: normal; font-size: 16px; }
    
    .clear-btn { background: transparent; border: 1px solid var(--border); color: var(--muted); padding: 4px 10px; border-radius: 6px; cursor: pointer; font-size: 11px; transition: all 0.2s; }
    .clear-btn:hover { background: var(--hover-bg); color: var(--text); border-color: var(--muted); }
    
    #chat-history { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 16px; scroll-behavior: smooth; }
    
    .msg-wrapper { display: flex; flex-direction: column; max-width: 90%; animation: fadeIn 0.3s ease; }
    .msg-wrapper.user { align-self: flex-end; align-items: flex-end; }
    .msg-wrapper.assistant { align-self: flex-start; align-items: flex-start; }
    
    .msg-label { font-size: 10px; color: var(--muted); margin-bottom: 4px; padding: 0 4px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
    
    .msg { padding: 12px 16px; border-radius: 12px; line-height: 1.6; font-size: 13px; word-break: break-word; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    
    .msg-user { background: var(--user-msg-bg); border: 1px solid var(--user-msg-border); border-bottom-right-radius: 2px; }
    .msg-assistant { background: var(--ast-msg-bg); border: 1px solid var(--ast-msg-border); border-bottom-left-radius: 2px; }
    
    .msg-assistant p { margin-bottom: 8px; }
    .msg-assistant p:last-child { margin-bottom: 0; }
    .msg-assistant ul, .msg-assistant ol { margin-left: 20px; margin-bottom: 8px; }
    
    /* Code block styling */
    .code-container { position: relative; margin: 10px 0; border-radius: 6px; overflow: hidden; border: 1px solid var(--border); }
    .code-header { background: rgba(0,0,0,0.3); padding: 4px 8px; font-size: 10px; color: var(--muted); display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); }
    .copy-btn { background: none; border: none; color: var(--muted); cursor: pointer; font-size: 10px; transition: color 0.2s; }
    .copy-btn:hover { color: var(--text); }
    .msg-assistant pre { margin: 0; padding: 12px; background: rgba(0,0,0,0.2); overflow-x: auto; }
    .msg-assistant code { font-family: 'Fira Code', 'Courier New', monospace; font-size: 11.5px; }
    .msg-assistant p code { background: rgba(0,0,0,0.2); padding: 2px 4px; border-radius: 3px; color: #ff7b72; }
    
    .typing { display: flex; gap: 4px; align-items: center; padding: 12px 16px; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; border-bottom-left-radius: 2px; align-self: flex-start; max-width: 80px; }
    .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--accent); animation: bounce 1.2s infinite ease-in-out both; }
    .dot:nth-child(1){ animation-delay: -0.32s; }
    .dot:nth-child(2){ animation-delay: -0.16s; }
    
    @keyframes bounce { 0%, 80%, 100% { transform: scale(0); } 40% { transform: scale(1); } }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }
    
    .input-area { padding: 12px 16px; border-top: 1px solid var(--border); display: flex; flex-direction: column; gap: 10px; flex-shrink: 0; background: rgba(0,0,0,0.1); }
    textarea { width: 100%; height: 64px; background: var(--input-bg); color: var(--input-fg); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; font-size: 13px; font-family: var(--vscode-font-family); resize: none; outline: none; transition: border-color 0.2s; box-shadow: inset 0 1px 3px rgba(0,0,0,0.1); }
    textarea:focus { border-color: var(--accent); }
    textarea::placeholder { color: var(--muted); opacity: 0.7; }
    
    .send-btn { background: var(--accent); color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; display: flex; align-items: center; justify-content: center; gap: 6px; transition: all 0.2s; align-self: flex-end; }
    .send-btn:hover { filter: brightness(1.1); transform: translateY(-1px); }
    .send-btn:active { transform: translateY(0); }
    
    .welcome { text-align: center; padding: 30px 20px; color: var(--muted); font-size: 13px; line-height: 1.6; display: flex; flex-direction: column; align-items: center; gap: 10px; margin: auto 0; }
    .welcome-icon { font-size: 42px; margin-bottom: 4px; animation: float 3s ease-in-out infinite; }
    @keyframes float { 0% { transform: translateY(0px); } 50% { transform: translateY(-8px); } 100% { transform: translateY(0px); } }
  </style>
</head>
<body>
  <div class="chat-header">
    <span class="chat-title"><i>🛡️</i> VibeGuard AI</span>
    <button class="clear-btn" id="clearBtn" title="Clear chat history">Clear</button>
  </div>
  <div id="chat-history">
    <div class="welcome" id="welcome-msg">
      <div class="welcome-icon">🤖</div>
      <h3 style="color:var(--text);font-weight:600;">How can I help?</h3>
      <p>Click <strong>Ask AI</strong> on any vulnerability, or type a security question below to get started.</p>
    </div>
    <div id="typing-indicator" style="display:none" class="msg-wrapper assistant">
      <div class="msg-label">VibeGuard AI</div>
      <div class="typing">
        <div class="dot"></div><div class="dot"></div><div class="dot"></div>
      </div>
    </div>
  </div>
  <div class="input-area">
    <textarea id="prompt" placeholder="Ask about a vulnerability, request a secure fix... (Shift+Enter for new line)"></textarea>
    <button class="send-btn" id="sendBtn">Send <span>➤</span></button>
  </div>
  <script>
    const vscode = acquireVsCodeApi();
    const history = document.getElementById('chat-history');
    const prompt = document.getElementById('prompt');
    const typing = document.getElementById('typing-indicator');

    // ── Inline markdown renderer — no CDN needed ─────────────────────────────
    function esc(s) {
      return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    function renderMarkdown(text) {
      // 1. Extract code blocks first to protect them from inline rules
      const blocks = [];
      text = text.replace(/\`\`\`([\\w.-]*)?\\n?([\\s\\S]*?)\`\`\`/g, (_, lang, code) => {
        const l = (lang || 'code').trim();
        const id = blocks.length;
        blocks.push(
          '<div class="code-container">' +
          '<div class="code-header"><span>' + esc(l) + '</span>' +
          '<button class="copy-btn" onclick="copyCode(this)">Copy</button></div>' +
          '<pre><code>' + esc(code.replace(/^\\n|\\n$/g,'')) + '</code></pre>' +
          '</div>'
        );
        return '\\x00BLOCK' + id + '\\x00';
      });

      // 2. Inline rules
      text = text
        .replace(/\`([^\`\\n]+)\`/g, '<code class="inline-code">$1</code>')
        .replace(/\\*\\*([^*]+)\\*\\*/g, '<strong>$1</strong>')
        .replace(/\\*([^*\\n]+)\\*/g, '<em>$1</em>');

      // 3. Line-by-line: lists and paragraphs
      const lines = text.split('\\n');
      let html = '';
      let inList = false;
      for (const raw of lines) {
        const line = raw.trimEnd();
        const listMatch = line.match(/^\\s*[-*•]\\s+(.+)/);
        const numMatch = line.match(/^\\s*\\d+\\.\\s+(.+)/);
        if (listMatch || numMatch) {
          if (!inList) { html += '<ul>'; inList = true; }
          html += '<li>' + (listMatch ? listMatch[1] : numMatch[1]) + '</li>';
        } else {
          if (inList) { html += '</ul>'; inList = false; }
          if (line === '') { html += '<br/>'; }
          else if (line.startsWith('\\x00BLOCK')) { html += line; }
          else { html += '<p>' + line + '</p>'; }
        }
      }
      if (inList) html += '</ul>';

      // 4. Restore code blocks
      blocks.forEach((b, i) => { html = html.replace('\\x00BLOCK' + i + '\\x00', b); });
      return html;
    }

    window.copyCode = function(btn) {
      const code = btn.closest('.code-container').querySelector('code');
      navigator.clipboard.writeText(code.innerText || code.textContent || '').then(() => {
        btn.innerText = 'Copied!';
        setTimeout(() => btn.innerText = 'Copy', 2000);
      });
    };

    function scrollToBottom() {
      history.scrollTop = history.scrollHeight;
    }

    function addMessage(role, content) {
      const wrapper = document.createElement('div');
      wrapper.className = 'msg-wrapper ' + role;

      const label = document.createElement('div');
      label.className = 'msg-label';
      label.innerText = role === 'user' ? 'You' : 'VibeGuard AI';

      const div = document.createElement('div');
      div.className = 'msg msg-' + role;

      if (role === 'user') {
        div.innerText = content;
      } else {
        div.innerHTML = renderMarkdown(content);
      }
      
      wrapper.appendChild(label);
      wrapper.appendChild(div);

      const welcome = document.getElementById('welcome-msg');
      if(welcome) welcome.style.display = 'none';
      
      history.insertBefore(wrapper, typing);
      scrollToBottom();
    }

    document.getElementById('sendBtn').addEventListener('click', send);
    prompt.addEventListener('keydown', e => { 
      if(e.key==='Enter' && !e.shiftKey) { e.preventDefault(); send(); } 
    });
    
    document.getElementById('clearBtn').addEventListener('click', () => {
      vscode.postMessage({type:'clearChat'});
    });

    function send() {
      const val = prompt.value.trim();
      if(!val) return;
      vscode.postMessage({type:'askAi', value:val});
      prompt.value = '';
    }

    window.addEventListener('message', e => {
      try {
        const msg = e.data;
        if(msg.type==='addMessage') addMessage(msg.role, msg.content);
        if(msg.type==='setTyping') {
          typing.style.display = msg.value ? 'flex' : 'none';
          if(msg.value) scrollToBottom();
        }
        if(msg.type==='setContext') { prompt.value = msg.value; prompt.focus(); }
        if(msg.type==='clearChat') {
          Array.from(history.querySelectorAll('.msg-wrapper:not(#typing-indicator)')).forEach(el => el.remove());
          const welcome = document.getElementById('welcome-msg');
          if(welcome) { welcome.style.display = 'flex'; welcome.innerHTML = '<div class="welcome-icon">🤖</div><h3 style="color:var(--text);font-weight:600;">Chat Cleared</h3><p>Ready for a new session.</p>'; }
        }
      } catch(err) {
        console.error('VibeGuard chat handler error:', err);
      }
    });
  </script>
</body>
</html>`;
    }
}
