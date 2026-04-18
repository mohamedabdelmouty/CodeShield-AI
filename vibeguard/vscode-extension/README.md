# VibeGuard Security Scanner

**VibeGuard** is a next-generation Application Security Posture Management (ASPM) extension for VS Code. It provides real-time, context-aware vulnerability detection, AI-powered auto-fixing, and a built-in security assistant right in your editor.

![VibeGuard Demo](https://raw.githubusercontent.com/mohamedabdelmouty/CodeShield-AI/main/assets/demo.png)

## 🚀 Features

- **Multi-Language Support**: Scans JavaScript, TypeScript, Python, Java, Go, Ruby, PHP, Dart, C/C++, HTML, Dockerfile, Terraform, YAML, JSON, and more.
- **Deep AST & Taint Analysis**: Goes beyond naive regex by tracking "tainted" variables flowing from untrusted sources to dangerous sinks.
- **Dependency Shield (SCA)**: Instantly detects vulnerable `npm` packages in your `package.json` using the OSV.dev database.
- **Entropy-based Secret Detection**: Filters out test/placeholder strings and only flags mathematically complex (high-entropy) API keys and secrets.
- **AI Auto-Fix (💡)**: Directly injects secure fixes using AI with a single click via VS Code's "Quick Fix" lightbulb.
- **Interactive Security Panel**: Click "Ask AI" on any vulnerability to instantly open a chat panel contextualized to that specific code flaw.

## 🛠️ How to Use

VibeGuard runs completely autonomously in the background! 

1. **Write Code**: Simply open any supported file or start typing.
2. **Real-time Diagnostics**: Vulnerabilities will be highlighted with red or yellow squiggly lines.
3. **Explore Details**: Hover your cursor over the highlighted code to see the vulnerability name, CWE ID, CVSS Severity, and exact remediation advice.

### Commands

Open the **Command Palette** (`Ctrl+Shift+P` or `Cmd+Shift+P`) and type `VibeGuard` to access these features:

- `VibeGuard: Scan Current Workspace`: Triggers a comprehensive scan of all files in the current open folder.
- `VibeGuard: Scan This File Now`: Forces an immediate re-scan of the file you currently have open.
- `VibeGuard: Export Security Report (PDF)`: Generates a gorgeous, executive-ready PDF audit report of all current vulnerabilities.
- `VibeGuard: Open AI Chat Panel`: Manually opens the side panel to chat with the built-in security AI.

### AI Auto-Fix & Context Actions

Above any vulnerability or inside the hover popup, you will see a **Code Lens** (clickable text):

- **`💡 Quick Fix` (Auto-Fix)**: Uses your cursor or `Ctrl+.` (`Cmd+.`) to fetch a safe rewrite of the vulnerable code and instantly apply it.
- **`🤖 Ask AI`**: Sends the highlighted context to the VibeGuard Chat Panel so you can ask follow-up questions ("Why is this dangerous?", "Can it be exploited this way?").

## ⚙️ Extension Settings

VibeGuard allows you to configure its behavior natively via VS Code settings (`Ctrl+,` or `Cmd+,` → search `VibeGuard`):

- `vibeguard.ai.enabled` (Boolean): Enable or disable the AI Quick Fix and Chat features.
- `vibeguard.ai.endpoint` (String): Your OpenAI-compatible API Endpoint (Default: `https://generativelanguage.googleapis.com/v1beta/openai/chat/completions`).
- `vibeguard.ai.apiKey` (String): If you want to use your own secure API key.
- `vibeguard.scanner.maxFileSize` (Number): Skip files larger than this size in bytes (Default: 1MB).
- `vibeguard.scanner.ignorePatterns` (Array): Ignore specific globs (e.g. `**/node_modules/**`, `**/dist/**`).

---

*Securing the software supply chain, one file at a time.* 🛡️
