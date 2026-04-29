import * as vscode from 'vscode';
import { Vulnerability } from '@vibeguard/core';

const BUILT_IN_GEMINI_ENDPOINT = (process.env as any).BUILT_IN_ENDPOINT ?? 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions';
const BUILT_IN_GEMINI_MODEL = (process.env as any).BUILT_IN_MODEL ?? 'gemini-2.0-flash';
const BUILT_IN_GEMINI_API_KEY = (process.env as any).BUILT_IN_KEY ?? '';

function getAiConfig() {
    const config = vscode.workspace.getConfiguration('vibeguard');
    return {
        endpoint: config.get<string>('aiEndpoint')?.trim() || BUILT_IN_GEMINI_ENDPOINT,
        apiKey: config.get<string>('aiApiKey')?.trim() || BUILT_IN_GEMINI_API_KEY,
        model: config.get<string>('aiModel')?.trim() || BUILT_IN_GEMINI_MODEL,
        enabled: config.get<boolean>('enableAi') ?? true,
    };
}

export class VibeguardChatProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'vibeguard.chatView';
    private _view?: vscode.WebviewView;
    private _chatHistory: Array<{ role: 'user' | 'assistant'; content: string }> = [];

    constructor(private readonly _extensionUri: vscode.Uri) {}

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        _context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ) {
        this._view = webviewView;
        webviewView.webview.options = { enableScripts: true, localResourceRoots: [this._extensionUri] };
        webviewView.webview.html = this._getHtmlForWebview();

        webviewView.webview.onDidReceiveMessage(async data => {
            switch (data.type) {
                case 'askAi':
                    await this._handleUserMessage(data.value);
                    break;
                case 'clearChat':
                    this._chatHistory = [];
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
        this._view?.webview.postMessage({ type: 'addMessage', role: 'user', content: userMsg });
        this._view?.webview.postMessage({ type: 'setTyping', value: true });

        const ai = getAiConfig();
        if (!ai.enabled || !ai.apiKey) {
            const reply = '⚠️ AI is disabled or no API key configured. Please set `vibeguard.aiApiKey` in VS Code settings.';
            this._chatHistory.push({ role: 'assistant', content: reply });
            this._view?.webview.postMessage({ type: 'addMessage', role: 'assistant', content: reply });
            this._view?.webview.postMessage({ type: 'setTyping', value: false });
            return;
        }

        try {
            const systemPrompt = `You are VibeGuard AI, an expert security assistant. Help developers understand and fix security vulnerabilities. Be concise, practical, and always provide secure code examples. Format code with markdown code blocks.`;

            const messages = [
                { role: 'system', content: systemPrompt },
                ...this._chatHistory.slice(-10) // last 10 messages for context
            ];

            const response = await fetch(ai.endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${ai.apiKey}`,
                },
                body: JSON.stringify({ model: ai.model, messages, max_tokens: 1024 }),
            });

            if (!response.ok) {
                throw new Error(`API error ${response.status}`);
            }

            const json = await response.json();
            const reply = json.choices?.[0]?.message?.content ?? 'No response from AI.';

            this._chatHistory.push({ role: 'assistant', content: reply });
            this._view?.webview.postMessage({ type: 'addMessage', role: 'assistant', content: reply });
        } catch (err) {
            const errMsg = `❌ AI request failed: ${err instanceof Error ? err.message : String(err)}`;
            this._view?.webview.postMessage({ type: 'addMessage', role: 'assistant', content: errMsg });
        } finally {
            this._view?.webview.postMessage({ type: 'setTyping', value: false });
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
    :root{--bg:var(--vscode-editor-background);--surface:var(--vscode-editor-inactiveSelectionBackground);--text:var(--vscode-editor-foreground);--muted:var(--vscode-descriptionForeground);--accent:var(--vscode-textLink-foreground);--border:var(--vscode-widget-border,#333);--input-bg:var(--vscode-input-background);--input-fg:var(--vscode-input-foreground);--btn-bg:var(--vscode-button-background);--btn-fg:var(--vscode-button-foreground);}
    *{box-sizing:border-box;margin:0;padding:0;}
    body{font-family:var(--vscode-font-family);font-size:13px;color:var(--text);background:var(--bg);display:flex;flex-direction:column;height:100vh;overflow:hidden;}
    .chat-header{padding:10px 12px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0;}
    .chat-title{font-weight:600;font-size:13px;}
    .clear-btn{background:transparent;border:1px solid var(--border);color:var(--muted);padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px;}
    .clear-btn:hover{color:var(--text);}
    #chat-history{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:10px;}
    .msg{padding:8px 12px;border-radius:8px;line-height:1.5;font-size:12px;max-width:100%;word-break:break-word;}
    .msg-user{background:rgba(88,166,255,.15);border:1px solid rgba(88,166,255,.2);align-self:flex-end;}
    .msg-assistant{background:var(--surface);border:1px solid var(--border);align-self:flex-start;}
    .msg-assistant pre{background:rgba(0,0,0,.3);padding:8px;border-radius:4px;overflow-x:auto;font-size:11px;margin:6px 0;}
    .msg-assistant code{font-family:'Courier New',monospace;font-size:11px;}
    .typing{display:flex;gap:4px;align-items:center;padding:10px 12px;}
    .dot{width:6px;height:6px;border-radius:50%;background:var(--accent);animation:bounce .8s infinite;}
    .dot:nth-child(2){animation-delay:.15s;} .dot:nth-child(3){animation-delay:.3s;}
    @keyframes bounce{0%,100%{transform:translateY(0)}50%{transform:translateY(-5px)}}
    .input-area{padding:10px 12px;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:8px;flex-shrink:0;}
    textarea{width:100%;height:52px;background:var(--input-bg);color:var(--input-fg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;font-size:12px;font-family:var(--vscode-font-family);resize:none;outline:none;}
    textarea:focus{border-color:var(--accent);}
    .btn-row{display:flex;gap:6px;}
    .send-btn{flex:1;background:var(--btn-bg);color:var(--btn-fg);border:none;padding:6px;border-radius:5px;cursor:pointer;font-size:12px;font-weight:600;}
    .send-btn:hover{opacity:.85;}
    .welcome{text-align:center;padding:20px 12px;color:var(--muted);font-size:12px;line-height:1.6;}
    .welcome-icon{font-size:32px;margin-bottom:8px;}
  </style>
</head>
<body>
  <div class="chat-header">
    <span class="chat-title">🛡️ VibeGuard AI</span>
    <button class="clear-btn" id="clearBtn">Clear</button>
  </div>
  <div id="chat-history">
    <div class="welcome">
      <div class="welcome-icon">🤖</div>
      <div>Hi! I'm VibeGuard AI.</div>
      <div>Click <strong>Ask AI</strong> on any vulnerability, or type a security question below.</div>
    </div>
  </div>
  <div id="typing-indicator" style="display:none" class="typing">
    <div class="dot"></div><div class="dot"></div><div class="dot"></div>
  </div>
  <div class="input-area">
    <textarea id="prompt" placeholder="Ask about a vulnerability, request a secure fix..."></textarea>
    <div class="btn-row">
      <button class="send-btn" id="sendBtn">Send ↵</button>
    </div>
  </div>
  <script>
    const vscode = acquireVsCodeApi();
    const history = document.getElementById('chat-history');
    const prompt = document.getElementById('prompt');
    const typing = document.getElementById('typing-indicator');

    function addMessage(role, content) {
      const div = document.createElement('div');
      div.className = 'msg msg-' + role;
      // Basic markdown: bold, code blocks
      let html = content
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        .replace(/\*\*(.*?)\*\*/g,'<strong>$1</strong>')
        .replace(/\`\`\`[\w]*\n([\s\S]*?)\`\`\`/g,'<pre>$1</pre>')
        .replace(/\`([^\`]+)\`/g,'<code>$1</code>')
        .replace(/\n/g,'<br>');
      div.innerHTML = html;
      // Remove welcome message
      const welcome = history.querySelector('.welcome');
      if(welcome) welcome.remove();
      history.appendChild(div);
      history.scrollTop = history.scrollHeight;
    }

    document.getElementById('sendBtn').addEventListener('click', send);
    prompt.addEventListener('keydown', e => { if(e.key==='Enter' && !e.shiftKey){e.preventDefault();send();} });
    document.getElementById('clearBtn').addEventListener('click', () => vscode.postMessage({type:'clearChat'}));

    function send() {
      const val = prompt.value.trim();
      if(!val) return;
      vscode.postMessage({type:'askAi', value:val});
      prompt.value = '';
    }

    window.addEventListener('message', e => {
      const msg = e.data;
      if(msg.type==='addMessage') addMessage(msg.role, msg.content);
      if(msg.type==='setTyping') typing.style.display = msg.value ? 'flex' : 'none';
      if(msg.type==='setContext') { prompt.value = msg.value; prompt.focus(); }
      if(msg.type==='clearChat') {
        history.innerHTML = '<div class="welcome"><div class="welcome-icon">🤖</div><div>Chat cleared.</div></div>';
      }
    });
  </script>
</body>
</html>`;
    }
}
