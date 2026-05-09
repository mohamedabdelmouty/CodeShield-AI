import * as vscode from 'vscode';
import { Vulnerability } from '@vibeguard/core';
import { openRouterService } from './openrouter-service';

const BUILT_IN_GEMINI_ENDPOINT = (process.env as any).BUILT_IN_ENDPOINT ?? 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions';
const BUILT_IN_GEMINI_MODEL = (process.env as any).BUILT_IN_MODEL ?? 'gemini-2.0-flash';
const BUILT_IN_GEMINI_API_KEY = (process.env as any).BUILT_IN_KEY ?? '';

function getAiConfig() {
    const config = vscode.workspace.getConfiguration('vibeguard');
    return {
        provider: config.get<string>('aiProvider') || 'Gemini',
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
        if (!ai.enabled) {
            const reply = '⚠️ AI is disabled in settings. Please enable `vibeguard.enableAi`.';
            this._chatHistory.push({ role: 'assistant', content: reply });
            this._view?.webview.postMessage({ type: 'addMessage', role: 'assistant', content: reply });
            this._view?.webview.postMessage({ type: 'setTyping', value: false });
            return;
        }

        try {
            let reply = '';
            
            // Build history context
            const historyContext = this._chatHistory
                .slice(-10, -1) // get previous context
                .map(m => `${m.role.toUpperCase()}: ${m.content}`)
                .join('\\n');

            if (ai.provider === 'OpenRouter') {
                reply = await openRouterService.chatWithAI(userMsg, historyContext);
            } else {
                // GEMINI Logic (Existing)
                if (!ai.apiKey) {
                     reply = '⚠️ No Gemini API key configured. Please set `vibeguard.aiApiKey`.';
                } else {
                    const systemPrompt = `You are VibeGuard AI, an expert security assistant. Help developers understand and fix security vulnerabilities. Be concise, practical, and always provide secure code examples. Format code with markdown code blocks.`;
                    const messages = [
                        { role: 'system', content: systemPrompt },
                        ...this._chatHistory.slice(-10)
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
                    reply = json.choices?.[0]?.message?.content ?? 'No response from AI.';
                }
            }

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
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/atom-one-dark.min.css">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
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
  </div>
  <div id="typing-indicator" style="display:none" class="msg-wrapper assistant">
    <div class="msg-label">VibeGuard AI</div>
    <div class="typing">
      <div class="dot"></div><div class="dot"></div><div class="dot"></div>
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

    // Configure Marked to use highlight.js
    marked.setOptions({
      highlight: function(code, lang) {
        if (lang && hljs.getLanguage(lang)) {
          return hljs.highlight(code, { language: lang }).value;
        }
        return hljs.highlightAuto(code).value;
      }
    });

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
        div.innerText = content; // raw text for user
      } else {
        // Render markdown for assistant
        const rawHtml = marked.parse(content);
        // Add copy buttons to code blocks
        div.innerHTML = rawHtml.replace(/<pre><code class="(.*?)">([\\s\\S]*?)<\\/code><\\/pre>/g, (match, langClass, code) => {
          return '<div class="code-container">' +
                   '<div class="code-header">' +
                     '<span>' + langClass.replace('language-', '') + '</span>' +
                     '<button class="copy-btn" onclick="copyToClipboard(this)">Copy</button>' +
                   '</div>' +
                   match +
                 '</div>';
        });
      }
      
      wrapper.appendChild(label);
      wrapper.appendChild(div);

      const welcome = document.getElementById('welcome-msg');
      if(welcome) welcome.style.display = 'none';
      
      history.insertBefore(wrapper, typing);
      scrollToBottom();
    }

    window.copyToClipboard = function(btn) {
      const pre = btn.parentElement.nextElementSibling;
      const text = pre.innerText;
      navigator.clipboard.writeText(text).then(() => {
        btn.innerText = 'Copied!';
        setTimeout(() => btn.innerText = 'Copy', 2000);
      });
    };

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
      const msg = e.data;
      if(msg.type==='addMessage') addMessage(msg.role, msg.content);
      if(msg.type==='setTyping') {
        typing.style.display = msg.value ? 'flex' : 'none';
        if(msg.value) scrollToBottom();
      }
      if(msg.type==='setContext') { prompt.value = msg.value; prompt.focus(); }
      if(msg.type==='clearChat') {
        Array.from(history.querySelectorAll('.msg-wrapper')).forEach(el => {
            if(el.id !== 'typing-indicator') el.remove();
        });
        const welcome = document.getElementById('welcome-msg');
        if(welcome) {
            welcome.style.display = 'flex';
            welcome.innerHTML = '<div class="welcome-icon">🤖</div><h3 style="color:var(--text);font-weight:600;">Chat Cleared</h3><p>Ready for a new session.</p>';
        }
      }
    });
  </script>
</body>
</html>`;
    }
}
