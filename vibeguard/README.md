# 🛡️ VibeGuard

**Cross-platform security scanning tool for JavaScript & TypeScript codebases.**

[![npm](https://img.shields.io/npm/v/vibeguard?color=red&label=vibeguard)](https://www.npmjs.com/package/vibeguard)
[![VS Code Extension](https://img.shields.io/badge/VS%20Code-Extension-blue?logo=visual-studio-code)](https://marketplace.visualstudio.com/items?itemName=vibeguard.vibeguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Features

| Feature | Description |
|---|---|
| 🔍 AST-Based Analysis | Uses Babel parser — no regex hacks, real code understanding |
| 🛡️ 6 Built-in Rules | SQL Injection, XSS, Hardcoded Secrets, Eval, Path Traversal, Insecure Random |
| 📊 Security Score | 0–100 score with A–F grades and severity-weighted penalties |
| 🖥️ Terminal Reports | Rich ANSI color output with score bars and remediation hints |
| 📄 JSON Reports | Structured output for CI pipelines and dashboards |
| 🔄 CI/CD Ready | Exit code `0` (pass) / `1` (fail) based on score threshold |
| 🧩 VS Code Extension | Real-time diagnostics, CodeLens hints, webview dashboard |
| 🤖 AI-Ready | `aiReadyContext` fields on every vulnerability for future AI integration |

---

## Project Structure

```
vibeguard/
├── core/                  # @vibeguard/core — Framework-agnostic scan engine
│   └── src/
│       ├── scanner.ts     # AST orchestrator (Babel parser + traverse)
│       ├── score.ts       # Security score engine (0-100, A-F grades)
│       ├── reporter.ts    # Terminal & JSON report formatters
│       ├── types.ts       # All shared TypeScript types
│       └── rules/
│           ├── index.ts             # Rule registry
│           ├── sql-injection.ts     # CWE-89
│           ├── xss.ts               # CWE-79
│           ├── hardcoded-secrets.ts # CWE-798
│           ├── eval-usage.ts        # CWE-95
│           ├── path-traversal.ts    # CWE-22
│           └── insecure-random.ts   # CWE-338
├── cli/                   # vibeguard npm CLI package
│   └── src/index.ts       # scan / rules / init commands
├── vscode-extension/      # VS Code/Cursor/Windsurf extension
│   └── src/
│       ├── extension.ts   # Activation, commands, event listeners
│       ├── diagnostics.ts # Maps vulns → VS Code Diagnostics
│       ├── codelens.ts    # Inline CodeLens hints
│       └── panel.ts       # Webview security dashboard
├── examples/
│   ├── vulnerable-sample.js  # Intentionally vulnerable demo file
│   └── clean-sample.ts       # Clean file (exit code 0)
└── vibeguard.config.example.json
```

---

## Security Rules

| Rule ID | Name | Severity | CWE | OWASP |
|---|---|---|---|---|
| `VG-SQL-001` | SQL Injection | CRITICAL | CWE-89 | A03:2021 |
| `VG-SEC-001` | Hardcoded Secret | CRITICAL | CWE-798 | A07:2021 |
| `VG-XSS-001` | Cross-Site Scripting | HIGH | CWE-79 | A03:2021 |
| `VG-EVAL-001` | Dangerous Code Evaluation | HIGH | CWE-95 | A03:2021 |
| `VG-PATH-001` | Path Traversal | HIGH | CWE-22 | A01:2021 |
| `VG-RAND-001` | Insecure Random | MEDIUM | CWE-338 | A02:2021 |

---

## Getting Started

### Prerequisites

- Node.js ≥ 18
- npm ≥ 9

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/vibeguard/vibeguard.git
cd vibeguard

# 2. Install all workspace dependencies
npm install

# 3. Build all packages
npm run build
```

---

## CLI Usage

### Install Globally (after build)

```bash
cd cli
npm link
```

### Commands

```bash
# Scan a directory (terminal output, default)
vibeguard scan ./src

# Scan a single file
vibeguard scan ./src/auth.ts

# JSON output (for CI/CD)
vibeguard scan ./src --format json

# Save report to file
vibeguard scan ./src --format json --output report.json

# Custom pass threshold (default: 70)
vibeguard scan ./src --threshold 80

# Ignore specific patterns
vibeguard scan ./src --ignore "test/**,*.spec.ts"

# Only run specific rules
vibeguard scan ./src --rules "VG-SQL-001,VG-XSS-001"

# List all available rules
vibeguard rules

# List rules as JSON
vibeguard rules --json

# Initialize config file
vibeguard init
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan passed — score ≥ threshold, or no vulnerabilities |
| `1` | Scan failed — vulnerabilities found or score < threshold |
| `2` | CLI error — invalid path or configuration |

### CI/CD Example (GitHub Actions)

```yaml
- name: VibeGuard Security Scan
  run: |
    npx vibeguard scan ./src --format json --output security-report.json --threshold 75
  # The step fails (exit code 1) if score < 75

- name: Upload Security Report
  uses: actions/upload-artifact@v3
  with:
    name: vibeguard-report
    path: security-report.json
```

---

## VS Code Extension

### Development

```bash
cd vscode-extension
npm install
npm run compile

# Press F5 in VS Code to launch Extension Development Host
```

### Features

- **Real-time Diagnostics** — Red/yellow squiggles on vulnerable lines
- **Problems Panel** — All issues listed with CWE links
- **CodeLens** — Inline hints above vulnerable code with remediation preview
- **Security Dashboard** — Full webview report with score gauge and vulnerability cards
- **Status Bar** — Live score indicator with color coding
- **Auto-scan** — Scans on file save and open (configurable)

### Commands (Command Palette)

| Command | Description |
|---|---|
| `VibeGuard: Scan Workspace` | Scan the entire workspace |
| `VibeGuard: Scan Current File` | Scan the active file |
| `VibeGuard: Show Security Report` | Open the webview dashboard |
| `VibeGuard: Clear Diagnostics` | Remove all squiggles |

### Extension Settings

```json
{
  "vibeguard.enabled": true,
  "vibeguard.scanOnSave": true,
  "vibeguard.scanOnOpen": true,
  "vibeguard.threshold": 70,
  "vibeguard.showCodeLens": true,
  "vibeguard.disabledRules": [],
  "vibeguard.ignorePatterns": ["**/node_modules/**", "**/dist/**"]
}
```

---

## Packaging for Distribution

### CLI → npm

```bash
cd cli

# 1. Build
npm run build

# 2. Test locally
node dist/index.js scan ../examples/vulnerable-sample.js

# 3. Dry-run publish
npm publish --dry-run

# 4. Publish to npm (requires npm login)
npm login
npm publish --access public
```

### VS Code Extension → Marketplace

```bash
cd vscode-extension

# 1. Install vsce
npm install -g @vscode/vsce

# 2. Compile
npm run compile

# 3. Package to .vsix file
vsce package
# → produces: vibeguard-1.0.0.vsix

# 4. Install locally for testing
code --install-extension vibeguard-1.0.0.vsix

# 5. Publish to Marketplace (requires PAT from marketplace.visualstudio.com)
vsce publish
# Or with PAT:
vsce publish -p <YOUR_PERSONAL_ACCESS_TOKEN>
```

> **Note:** To publish to the VS Code Marketplace, you need:
> 1. A Microsoft account
> 2. A publisher ID registered at [marketplace.visualstudio.com/manage](https://marketplace.visualstudio.com/manage)
> 3. A Personal Access Token with **Marketplace → Manage** scope

---

## Adding Custom Rules

Create a new file in `core/src/rules/your-rule.ts`:

```typescript
import { Rule, RuleContext } from '../types';
import { BabelFile, traverse } from '../scanner';
import * as t from '@babel/types';

const myRule: Rule = {
  id: 'VG-CUSTOM-001',
  name: 'My Custom Rule',
  description: 'Describe what this rule detects.',
  severity: 'HIGH',
  enabled: true,
  tags: ['custom'],
  check(context: RuleContext, ast: BabelFile): void {
    traverse(ast, {
      CallExpression(path) {
        // Your AST detection logic here
        const loc = path.node.loc;
        if (!loc) return;
        
        context.reportVulnerability({
          ruleId: 'VG-CUSTOM-001',
          ruleName: 'My Custom Rule',
          severity: 'HIGH',
          message: 'Description of the finding.',
          description: 'Detailed explanation.',
          remediation: 'How to fix it.',
          location: { line: loc.start.line, column: loc.start.column },
        });
      },
    });
  },
};

export default myRule;
```

Then register it in `core/src/rules/index.ts`:

```typescript
import myRule from './your-rule';

const RULE_REGISTRY: Rule[] = [
  // ... existing rules
  myRule,
];
```

---

## AI Integration (Future)

Every `Vulnerability` object includes an `aiReadyContext` field designed for LLM integration:

```typescript
interface Vulnerability {
  // ... standard fields
  aiReadyContext?: Record<string, unknown>;  // Structured context for AI analysis
}
```

Planned features:
- AI-powered remediation suggestions via configurable `aiEndpoint`
- Natural language explanations of vulnerabilities
- Auto-fix PR generation via GitHub Actions integration

---

## Publishing

To publish **Core** and **CLI** to npm and the **VS Code Extension** to the Marketplace, see **[PUBLISHING.md](PUBLISHING.md)** (Arabic + English).

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-new-rule`
3. Add your rule in `core/src/rules/`
4. Register it in `core/src/rules/index.ts`
5. Add a test case to `examples/`
6. Submit a pull request

---

## License

MIT © VibeGuard Contributors
