# AIAgentAntivirus Design Specification

**Date:** 2026-05-20
**Version:** 1.0
**Status:** Draft

## Overview

AIAgentAntivirus is a production-ready npm CLI tool (`aiav`) that scans local AI agent files for security threats including prompt injections, malware, and other AI-related vulnerabilities.

### Primary Use Cases

1. **Developer Workflow** - Check AI agent projects before deployment
2. **CI/CD Integration** - Automated security scanning in pipelines
3. **Continuous Monitoring** - Hourly scans with real-time alerts

### Core Commands

- `aiav scan ./path/to/project` - One-time security scan
- `aiav watch ./path/to/project` - Continuous monitoring with hourly scans

## Architecture

### Modular Scanner Architecture

```
aiav (CLI)
├── Scanner Engine (core orchestration)
│   ├── Pattern Scanner (regex/heuristics)
│   ├── LLM Scanner (AI analysis)
│   ├── AST Scanner (code structure analysis)
│   └── Hybrid Scanner (combined approach)
├── File Walker (recursive directory traversal with filters)
├── Output Formatters (console, JSON, HTML, SARIF)
├── Watcher (file system monitoring for hourly scans)
└── LLM Provider Interface (Anthropic, OpenAI, custom)
```

### Key Interfaces

- `Scanner` - contract all scanners implement: `scan(file): Promise<Result[]>`
- `LLMProvider` - contract for LLM integrations: `analyze(code): Promise<Analysis>`
- `Formatter` - contract for output formats: `format(results): string`

## Components

### Pattern Scanner

- Maintains library of regex patterns and heuristic rules
- Categories: prompt injection patterns, suspicious code structures, hardcoded secrets, malicious command patterns
- Fast, zero-dependency detection for immediate results

### LLM Scanner

- Analyzes code context using AI for sophisticated threat detection
- Detects subtle prompt injection attempts, obfuscated malware, social engineering patterns
- Configurable via CLI for provider selection, API keys, model selection

### AST Scanner

- Parses code into abstract syntax trees
- Analyzes structure for risky patterns: eval/exec usage, dynamic imports, unsafe deserialization
- Works with tree-sitter for multi-language support

### File Walker

- Recursive traversal with exclusion support (`--exclude` flag)
- Filters by extension: `.json`, `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.md`
- Handles symlinks, gitignore respect (optional)

### Output Formatters

- **Console**: color-coded, severity icons, summary
- **JSON**: structured for CI/CD
- **HTML**: detailed web report with drill-down
- **SARIF**: GitHub Security integration

### Watcher

- Uses chokidar for efficient file monitoring
- Runs scans hourly or on file change
- Maintains scan history and trend analysis

## Platform Path Detection

### Supported Platforms

**Core AI Platforms:** Claude, OpenAI/Codex, Google/Gemini, Perplexity, DeepSeek, Mistral, Cohere, Groq, Hugging Face

**Code Editors:** VS Code, Cursor, Windsurf, JetBrains, Zed, Nova, Vim/Neovim, Emacs

**AI Coding Tools:** Codeium, Codestral, Tabnine, AWS CodeWhisperer, Sourcegraph Cody, CodeGeeX, Replit, Blackbox, Bito

**Agent Frameworks:** AutoGPT, LangChain, CrewAI, LangFlow, Flowise, LangGraph, AutoGen, Semantic Kernel, Dust, E2B

**Cloud Platforms:** GitHub Codespaces, Gitpod, StackBlitz, Glitch

### Path Mapping

**Linux Paths:**
```
~/.claude/                     # Claude Desktop/Claude Code
~/.config/anthropic/           # Anthropic configs
~/.config/openai/              # OpenAI/Codex configs
~/.config/google/              # Google/Gemini configs
~/.config/perplexity/           # Perplexity AI
~/.config/deepseek/             # DeepSeek
~/.config/mistral/              # Mistral AI
~/.config/cohere/               # Cohere
~/.config/groq/                 # Groq
~/.cache/huggingface/           # Hugging Face
~/.vscode/extensions/          # VS Code extensions
~/.cursor/extensions/          # Cursor AI
~/.config/Code/User/           # VS Code config
~/.windsurf/                   # Windsurf AI
~/.config/Continue/            # Continue.dev
~/.codeium/                    # Codeium
~/.codestral/                  # Codestral
~/.tabnine/                    # Tabnine
~/.aws/amazon-q/               # AWS CodeWhisperer
~/.sourcegraph/                # Sourcegraph Cody
~/.codegeex/                   # CodeGeeX
~/.replit/                     # Replit
~/.blackbox/                   # Blackbox
~/.bito/                       # Bito
~/.config/JetBrains/           # JetBrains IDEs
~/.config/zed/                 # Zed editor
~/.config/nova/                # Nova editor
~/.vim/                        # Vim plugins
~/.config/nvim/                # Neovim configs
~/.emacs.d/                    # Emacs AI packages
~/.local/share/autogpt/        # AutoGPT
~/langchain-projects/          # LangChain
~/.crewai/                     # CrewAI
~/.langgraph/                  # LangGraph
~/.autogen/                    # AutoGen
~/.semantic-kernel/            # Semantic Kernel
~/.dust/                       # Dust
~/.e2b/                        # E2B
~/.gpt-engineer/               # GPT-Engineer
~/.agentgpt/                   # AgentGPT
~/.godmode/                    # GodMode
~/.phind/                      # Phind AI
~/.codespaces/                 # GitHub Codespaces
~/.gitpod/                     # Gitpod
~/.stackblitz/                 # StackBlitz
~/.glitch/                     # Glitch
```

**Windows Paths:**
```
%USERPROFILE%\AppData\Roaming\Claude\       # Claude Desktop
%USERPROFILE%\AppData\Roaming\anthropic\    # Anthropic
%USERPROFILE%\AppData\Roaming\openai\       # OpenAI/Codex
%USERPROFILE%\AppData\Roaming\google\       # Google/Gemini
%USERPROFILE%\AppData\Roaming\perplexity\   # Perplexity
%USERPROFILE%\AppData\Roaming\deepseek\     # DeepSeek
%USERPROFILE%\AppData\Roaming\mistral\      # Mistral
%USERPROFILE%\AppData\Roaming\cohere\       # Cohere
%USERPROFILE%\.cache\huggingface\           # Hugging Face
%USERPROFILE%\.vscode\extensions\           # VS Code
%USERPROFILE%\.cursor\extensions\           # Cursor AI
%USERPROFILE%\AppData\Roaming\Code\User\    # VS Code config
%USERPROFILE%\.windsurf\                    # Windsurf
%USERPROFILE%\AppData\Local\Continue\       # Continue.dev
%USERPROFILE%\.codeium\                     # Codeium
%USERPROFILE%\.codestral\                   # Codestral
%USERPROFILE%\.tabnine\                     # Tabnine
%USERPROFILE%\.aws\amazon-q\                # AWS CodeWhisperer
%USERPROFILE%\AppData\Roaming\sourcegraph\  # Sourcegraph Cody
%USERPROFILE%\.codegeex\                    # CodeGeeX
%USERPROFILE%\.replit\                      # Replit
%USERPROFILE%\.blackbox\                    # Blackbox
%USERPROFILE%\.bito\                        # Bito
%USERPROFILE%\AppData\Roaming\JetBrains\    # JetBrains
%USERPROFILE%\AppData\Roaming\zed\          # Zed
%USERPROFILE%\AppData\Local\nova\           # Nova
%USERPROFILE%\_vim\                         # Vim
%USERPROFILE%\AppData\Local\nvim\           # Neovim
%USERPROFILE%\.emacs.d\                     # Emacs
%USERPROFILE%\AppData\Local\autogpt\        # AutoGPT
%USERPROFILE%\langchain-projects\           # LangChain
%USERPROFILE%\.crewai\                      # CrewAI
%USERPROFILE%\.langgraph\                   # LangGraph
%USERPROFILE%\.autogen\                     # AutoGen
%USERPROFILE%\.semantic-kernel\             # Semantic Kernel
%USERPROFILE%\.dust\                        # Dust
%USERPROFILE%\.e2b\                         # E2B
%USERPROFILE%\.gpt-engineer\                # GPT-Engineer
%USERPROFILE%\.agentgpt\                    # AgentGPT
%USERPROFILE%\.godmode\                     # GodMode
%USERPROFILE%\.phind\                       # Phind
%USERPROFILE%\.codespaces\                  # GitHub Codespaces
%USERPROFILE%\.gitpod\                      # Gitpod
%USERPROFILE%\.stackblitz\                  # StackBlitz
%USERPROFILE%\.glitch\                      # Glitch
```

### CLI Options for Platform Detection

- `--platform <name>` - specific platform (claude, gemini, cursor, vscode, all)
- `--platforms <list>` - multiple platforms
- Default: auto-detect all platforms if no path specified

## Data Flow

### Scan Flow (`aiav scan`)

1. CLI parses arguments → validates paths/options
2. File Walker discovers files:
   - Detects platform paths (or uses custom path)
   - Filters by extension (`--ext` flag)
   - Applies exclusions (`--exclude` flag)
3. Scanner Engine processes files in parallel:
   - Pattern Scanner → immediate results
   - AST Scanner → structural analysis
   - LLM Scanner → batched for API efficiency
   - Hybrid Scanner → combines results
4. Results aggregated with severity scores
5. Formatter generates output (`--format` flag)
6. Exit code: 0 (clean), 1 (warnings), 2 (critical)

### Watch Flow (`aiav watch`)

1. Same scan flow on initial run
2. Watcher monitors file changes (debounced)
3. On change → re-run scan on changed files only
4. Every hour → full scan
5. Results compared to previous scan → trend analysis
6. Alert on new detections (`--alert` flag: email, webhook, desktop)

### LLM Provider Flow

1. User provides API key via `--api-key` or env var
2. Provider selected via `--provider` (anthropic, openai, custom)
3. Code batches sent with system prompt (security context)
4. Responses parsed into standardized findings
5. Rate limiting and retry logic

## CLI Options

### Scan Command Options

```
aiav scan [path]

Arguments:
  path                    Path to scan (default: auto-detect platform paths)

Options:
  --platform <name>       Target platform (claude, openai, google, cursor, all)
  --platforms <list>      Multiple platforms, comma-separated
  --ext <extensions>      File extensions to scan (default: json,py,js,ts,jsx,tsx,md)
  --exclude <patterns>    Files/directories to exclude (glob patterns)
  --format <type>         Output format: console, json, html, sarif (default: console)
  --provider <name>       LLM provider: anthropic, openai, custom (default: anthropic)
  --api-key <key>         LLM API key (or use env var)
  --model <name>          LLM model name (provider-specific)
  --patterns <file>       Custom pattern rules file
  --scanners <list>       Enabled scanners: pattern, ast, llm, hybrid (default: all)
  --workers <number>      Parallel workers (default: CPU cores)
  --max-cost <amount>     Maximum LLM cost in USD
  --show-cost             Show estimated token costs
  --verbose               Detailed logging
  --log-file <path>       Log file path
```

### Watch Command Options

```
aiav watch [path]

All scan options plus:
  --interval <minutes>    Scan interval (default: 60)
  --on-change             Scan on file change (default: true)
  --alert <type>          Alert type: email, webhook, desktop, none (default: none)
  --email <address>       Email for alerts
  --webhook <url>         Webhook URL for alerts
```

## Error Handling

### CLI Error Handling

- Invalid arguments → helpful error with usage example
- Missing API key → clear message on where to get it
- Path not found → verify path or auto-suggest platform paths
- Permission denied → specific file and how to fix

### Scanner Error Handling

- Parse errors (invalid JSON/syntax) → log as warning, continue scanning
- AST parse failure → fallback to pattern matching
- LLM API errors → retry with exponential backoff, max 3 attempts
- LLM rate limit → queue and retry, notify user

### Watch Error Handling

- File watcher crash → restart with backoff
- Scan failure → log error, continue watching
- Resource exhaustion → reduce parallelism, warn user

### Exit Codes

- `0` - Success, no issues found
- `1` - Issues found (warnings/critical)
- `2` - Error occurred (invalid input, scan failed)
- `3` - Critical error (cannot continue)

### Logging

- `--verbose` flag for detailed logs
- `--log-file` for persistent logging
- Structured logging (JSON option)

## Performance

### Scanning Performance

- Parallel file processing with worker pool (configurable via `--workers`)
- LLM batching: group similar files for single API call
- Caching: hash-based cache to avoid re-scanning unchanged files
- Incremental scans in watch mode: only changed files

### Memory Management

- Stream large files instead of loading entirely
- File size limit: skip files > 10MB (configurable)
- Worker pool limit: respect available CPU cores

### LLM Cost Optimization

- Smart batching: similar code patterns grouped
- Context pruning: remove comments, whitespace before LLM
- Fallback: skip LLM if cost would exceed `--max-cost`
- Token counting: real-time tracking with `--show-cost`

### Watch Mode Efficiency

- Debounce file changes (500ms default)
- Incremental scans: only modified files
- Throttle full hourly scans if system under load

## Security

### Self-Protection

- No code execution from scanned files
- Sanitize all paths (prevent path traversal)
- Validate all LLM responses (no code execution)
- Secure storage of API keys (OS keyring or env var only)

### Privacy

- No telemetry by default
- LLM prompts don't include secrets (detected secrets are redacted)
- Clear warning when sending code to external LLMs

### Supply Chain

- Pinned dependencies with `npm audit` in CI
- Dependabot for security updates
- SBOM generation for transparency

### Auditability

- All scans logged with timestamp, files scanned, results
- SARIF output for compliance

## Testing Strategy

### Unit Tests

- Pattern Scanner: test each detection rule with positive/negative samples
- LLM Scanner: mock API responses, test parsing logic
- AST Scanner: test parser for each language, verify detection logic
- Formatters: verify output format for each type
- Path detection: mock file system for each platform

### Integration Tests

- Full scan flow: test end-to-end with sample projects
- Watch mode: simulate file changes, verify re-scans
- CLI argument parsing: validate all flag combinations
- Platform detection: verify auto-discovery on mocked systems

### E2E Tests

- Real LLM integration: test with test API keys (skip in CI)
- Multiple providers: verify Anthropic, OpenAI, custom work
- Large projects: performance tests with 1000+ files

### Test Fixtures

- `fixtures/` with sample agent projects for each platform
- Vulnerable samples (prompt injections, obfuscated malware)
- Clean samples (no threats)
- Edge cases (empty files, huge files, binary files)

### Coverage

- Target 80%+ coverage for core logic
- CI runs tests on Linux, macOS, Windows

## Tech Stack

### Core

- **Language:** TypeScript
- **Runtime:** Node.js (latest stable)
- **CLI Framework:** Commander.js
- **File System:** fs-extra, chokidar (watcher)
- **Path Detection:** os, platform-specific logic

### Scanning

- **Pattern Matching:** built-in RegExp
- **AST Parsing:** tree-sitter (multi-language)
- **LLM Integration:** Anthropic SDK, OpenAI SDK

### Output

- **Formatting:** chalk (console), handlebars (HTML), fast-json-stable-stringify (JSON)
- **SARIF:** @microsoft/sarif-sdk

### Testing

- **Framework:** Jest
- **Coverage:** c8
- **E2E:** Playwright (for HTML report testing)

### Development

- **Package Manager:** npm
- **Linting:** ESLint, Prettier
- **Type Checking:** TypeScript strict mode
- **CI/CD:** GitHub Actions

## Phase-wise Implementation Plan

### Phase 1: Foundation (Weeks 1-2)

- Project scaffold with TypeScript, ESLint, Jest
- CLI framework (Commander.js) with `aiav scan` stub
- File Walker with platform path detection
- Basic pattern scanner with 10+ rules
- Console formatter
- Unit tests for walker and pattern scanner

### Phase 2: Core Scanning (Weeks 3-4)

- AST Scanner with tree-sitter (Python, JS, TS)
- LLM Scanner with Anthropic provider
- Hybrid Scanner (combine pattern + AST)
- JSON and HTML formatters
- Integration tests with sample projects
- Performance: parallel processing

### Phase 3: Additional Providers & Formats (Weeks 5-6)

- OpenAI LLM provider
- Custom LLM provider support
- SARIF formatter
- Extended pattern library (50+ rules)
- Platform-specific patterns for each AI tool
- Cost optimization (batching, pruning)

### Phase 4: Watch Mode (Weeks 7-8)

- File watcher with chokidar
- Hourly scan scheduling
- Incremental scan logic
- Trend analysis
- Alert system (email, webhook, desktop)
- E2E tests for watch mode

### Phase 5: Production Polish (Weeks 9-10)

- Comprehensive test coverage
- Documentation (README, CLI help)
- CI/CD setup (GitHub Actions)
- Release automation
- Performance benchmarking
- Security audit prep

### Phase 6: Launch & Iterate (Weeks 11-12)

- Beta release to select users
- Feedback collection
- Bug fixes
- v1.0.0 release
- Post-release monitoring

## Success Criteria

1. Comprehensive detection of prompt injections, malware, and AI-related threats
2. Support for 20+ AI platforms and coding tools
3. Multi-format output (console, JSON, HTML, SARIF)
4. Production-ready performance (scans 1000+ files efficiently)
5. Strong security posture (no code execution, secure API key handling)
6. Comprehensive test coverage (80%+)
7. Clear documentation and user experience
8. Successful v1.0.0 release with positive user feedback