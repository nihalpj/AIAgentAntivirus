# AIAgentAntivirus (aiav)

A security scanner for AI agent files that detects prompt injections, malware, and other AI-related vulnerabilities.

## Installation

```bash
npm install -g aiagentantivirus
```

## Usage

```bash
# Scan current directory
aiav scan

# Scan specific path
aiav scan ./path/to/project

# Scan specific platform
aiav scan --platform claude

# Scan with custom extensions
aiav scan --ext js,ts,json

# Exclude patterns
aiav scan --exclude "node_modules/**,dist/**"
```

## Options

- `--platform <name>` - Target platform (claude, openai, google, cursor, all)
- `--ext <extensions>` - File extensions (default: json,py,js,ts,jsx,tsx,md)
- `--exclude <patterns>` - Exclude patterns (comma-separated)
- `--format <type>` - Output format: console, json, html, sarif
- `--verbose` - Enable verbose logging
- `--workers <number>` - Number of parallel workers

## Exit Codes

- `0` - No issues found
- `1` - Issues found (warnings/critical)
- `2` - Error occurred

## License

MIT