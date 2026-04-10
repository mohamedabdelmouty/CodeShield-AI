# VibeGuard CLI

Cross-platform security scanner for JavaScript & TypeScript. Scan files or directories and get a security report with PDF export.

## Install

```bash
npm install -g vibeguard
```

Or run without installing:

```bash
npx vibeguard scan .
```

## Usage

```bash
vibeguard scan [path]     # Scan a file or directory (default: .)
vibeguard scan . --pdf   # Also write PDF report
vibeguard scan . --ai    # Enable AI detection (set VIBEGUARD_AI_ENDPOINT + VIBEGUARD_AI_API_KEY)
vibeguard rules          # List all rules
vibeguard init           # Create vibeguard.config.json
```

## Links

- [Full documentation](https://github.com/vibeguard/vibeguard#readme)
- [VS Code Extension](https://marketplace.visualstudio.com/items?itemName=vibeguard.vibeguard-vscode)

## License

MIT
