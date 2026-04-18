import * as vscode from 'vscode';
import { Vulnerability } from '@vibeguard/core';

export class VibeguardChatProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'vibeguard.chatView';
    private _view?: vscode.WebviewView;

    constructor(private readonly _extensionUri: vscode.Uri) {}

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ) {
        this._view = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this._extensionUri]
        };

        webviewView.webview.html = this._getHtmlForWebview();

        webviewView.webview.onDidReceiveMessage(data => {
            switch (data.type) {
                case 'askAi': {
                    vscode.window.showInformationMessage(`VibeGuard AI received: ${data.value}`);
                    // Trigger actual AI processing here
                    break;
                }
            }
        });
    }

    public sendToChat(vuln: Vulnerability | any) {
        if (!this._view) {
            vscode.commands.executeCommand('vibeguard.chatView.focus').then(() => {
                setTimeout(() => this.postMessage(vuln), 500);
            });
            return;
        }
        this._view.show?.(true);
        this.postMessage(vuln);
    }

    private postMessage(vuln: any) {
        this._view?.webview.postMessage({
            type: 'setContext',
            value: `Explain the vulnerability: ${vuln.message || vuln.ruleId}`
        });
    }

    private _getHtmlForWebview() {
        return `<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>VibeGuard Chat</title>
            <style>
                body { font-family: var(--vscode-font-family); padding: 10px; }
                textarea { width: 100%; height: 60px; background: var(--vscode-input-background); color: var(--vscode-input-foreground); border: 1px solid var(--vscode-input-border); resize: vertical; }
                button { background: var(--vscode-button-background); color: var(--vscode-button-foreground); border: none; padding: 8px; width: 100%; cursor: pointer; margin-top: 10px; }
                button:hover { background: var(--vscode-button-hoverBackground); }
                .message { margin-bottom: 10px; padding: 8px; background: var(--vscode-editor-inactiveSelectionBackground); border-radius: 4px; }
            </style>
        </head>
        <body>
            <div id="chat-history">
                <div class="message">Hi! I'm VibeGuard AI. Click "Ask AI" on any vulnerability to chat about it.</div>
            </div>
            <textarea id="prompt" placeholder="Ask about a vulnerability..."></textarea>
            <button id="sendBtn">Send to VibeGuard AI</button>

            <script>
                const vscode = acquireVsCodeApi();
                
                window.addEventListener('message', event => {
                    const message = event.data;
                    if (message.type === 'setContext') {
                        document.getElementById('prompt').value = message.value;
                    }
                });

                document.getElementById('sendBtn').addEventListener('click', () => {
                    const val = document.getElementById('prompt').value;
                    if(val) {
                        vscode.postMessage({ type: 'askAi', value: val });
                        
                        // Add to UI
                        const history = document.getElementById('chat-history');
                        const msg = document.createElement('div');
                        msg.className = 'message';
                        msg.textContent = val;
                        history.appendChild(msg);
                        document.getElementById('prompt').value = '';
                    }
                });
            </script>
        </body>
        </html>`;
    }
}
