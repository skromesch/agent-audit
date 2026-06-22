# agent-audit

Audit AI coding agent configurations in your project — detect tools, MCP servers, skills, secrets, and misconfigurations across all major ecosystems.

```
╭─────────────────────────────────────────────────────────────────────────╮
│  agent-audit                                                            │
│  Root: /home/user/myproject                                             │
│                                                                         │
│  ── Claude Code ──────────────────────────────────────────────────────  │
│    Skills           3  (2 project, 1 global)                           │
│    MCP Servers      4                                                   │
│    model            claude-sonnet-4-5                                   │
│    Critical         1                                                   │
│    Warnings         0                                                   │
│                                                                         │
│  ── OpenCode ─────────────────────────────────────────────────────────  │
│    Skills           0  (0 project, 0 global)                           │
│    MCP Servers      0                                                   │
│    model            anthropic/claude-sonnet-4-5                        │
│    Critical         0                                                   │
│    Warnings         0                                                   │
╰─────────────────────────────────────────────────────────────────────────╯
```

## Features

- **8 ecosystems** — Claude Code, OpenCode, Pi, Codex, Cursor, Continue.dev, Aider, Gemini CLI
- **MCP server audit** — lists all Model Context Protocol servers with command and source
- **Skills discovery** — finds and validates Claude Code and Pi skill packages
- **Secret detection** — API keys and tokens detected and masked in all output
- **Security findings** — dangerous MCP commands, wildcard permissions, disabled sandboxes
- **Four output modes** — interactive TUI, JSON, Markdown, HTML
- **Non-interactive friendly** — auto-falls back to JSON when stdin is not a TTY (CI/pipes)

## Installation

```bash
go install github.com/skromesch/agent-audit/cmd/agent-audit@latest
```

Or build from source:

```bash
git clone https://github.com/skromesch/agent-audit
cd agent-audit
make build
```

Requires Go 1.22+.

## Usage

```bash
# Interactive TUI (default)
agent-audit .
agent-audit ~/myproject

# Non-interactive report modes
agent-audit --json       # writes report.json
agent-audit --markdown   # writes report.md
agent-audit --html       # writes report.html
```

### TUI Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Next / previous tab |
| `↑` / `↓` or `k` / `j` | Scroll / navigate |
| `→` / `Enter` | Open detail panel |
| `←` / `Esc` | Back to list |
| `e` | Export `report.json` |
| `q` | Quit |

### TUI Tabs

| Tab | Contents |
|-----|----------|
| **Agents Overview** | All detected agents with settings, MCP count, finding summary |
| **MCP** | MCP server list with command, args, source file |
| **Skills** | Skill packages with validity check and description |
| **Security** | All findings grouped by severity |
| **About** | Version and scan metadata |

## Supported Ecosystems

| Tool | Config files scanned |
|------|---------------------|
| **Claude Code** | `CLAUDE.md`, `.claude/settings.json`, `.claude/skills/`, `.mcp.json`, `~/.claude/settings.json` |
| **OpenCode** | `opencode.json`, `~/.config/opencode/opencode.json` |
| **Pi** | `SYSTEM.md`, `models.json`, `AGENTS.md`, `~/.pi/agent/` |
| **Codex** | `AGENTS.md`, `.codex/config.toml`, `~/.codex/config.toml` |
| **Cursor** | `.cursor/rules/`, `.cursor/settings.json` |
| **Continue.dev** | `.continue/config.yaml` |
| **Aider** | `.aider.conf.yml`, `.aider*` |
| **Gemini CLI** | `GEMINI.md`, `~/.gemini/settings.json` |

All scanners also check for MCP server definitions in `.mcp.json` wherever present.

## Security Checks

### Secret Detection
Scans all config files for exposed credentials. Matched values are masked in every output mode (`sk-************abcd`). Detected patterns:

- OpenAI API keys (`sk-proj-…`)
- Anthropic API keys (`sk-ant-…`)
- GitHub tokens (`ghp_…`, `ghs_…`)
- Generic `*_API_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD` variables

### Permission & Sandbox Checks
- Wildcard allow permissions (`"allow": ["*"]`)
- Approval mode disabled (`approval_mode: none`)
- Sandbox disabled (`sandbox = false`)
- Unrestricted shell execution

### MCP Command Checks
- Remote code execution (`curl | sh`, `wget | sh`)
- Privilege escalation (`sudo`)
- Destructive file removal (`rm `)
- Arbitrary eval (`eval $(…)`)

## Example Output

**Markdown report** (`--markdown`):

```markdown
# agent-audit Report

**Root:** `/home/user/myproject`
**Scanned:** 2026-06-22 10:00:00

## Summary

| Metric | Count |
|--------|-------|
| Agents detected | 3 |
| MCP servers | 2 |
| Skills | 4 |
| Critical findings | 1 |
| Warning findings | 1 |

## Security Findings

- 🚨 **[CRITICAL]** `/myproject/.claude/settings.json`: Anthropic API Key detected
- ⚠️ **[WARNING]** `/myproject/.mcp.json`: MCP server "deploy" uses curl|sh (remote code execution)
```

## Architecture

agent-audit uses a concurrent scanner pipeline:

```
project directory
      │
      ▼
 Orchestrator (runs all scanners concurrently)
      │
  ┌───┴─────────────────────────────────────────────┐
  │  ClaudeScanner  OpenCodeScanner  PiScanner  …   │
  └─────────────────────────────────────────────────┘
      │
      ▼
  ScanResult  ──►  TUI
              ──►  JSON / Markdown / HTML
```

Each ecosystem is a self-contained scanner implementing a single interface. Adding support for a new tool requires one new file — see [`docs/architecture.md`](docs/architecture.md).

## Development

```bash
make test    # run tests with race detector and coverage
make lint    # run golangci-lint
make bench   # run benchmarks
make build   # build binary to ./agent-audit
```

Test coverage target: >80%. All tests run on Linux, macOS, and Windows via CI.

## License

MIT
