# agent-audit

Audit AI agent configurations in software projects.

Detects Claude Code, Codex, Cursor, Continue.dev, and Aider configurations.
Finds MCP servers, skills, secrets, dangerous commands, and misconfigurations.

## Installation

```bash
go install github.com/skromesch/agent-audit/cmd/agent-audit@latest
```

Or build from source:

```bash
make build
```

## Usage

```bash
# TUI mode (default)
agent-audit .
agent-audit ~/myproject

# Report modes
agent-audit . --json       # writes report.json
agent-audit . --markdown   # writes report.md
agent-audit . --html       # writes report.html
```

## Keyboard Shortcuts

| Key          | Action         |
|--------------|----------------|
| `q`          | Quit           |
| `Tab`        | Next view      |
| `Shift+Tab`  | Previous view  |

## Supported Ecosystems

- **Claude Code** — CLAUDE.md, .claude/settings.json, .claude/skills/, .mcp.json
- **Codex** — AGENTS.md, .codex/config.toml
- **Cursor** — .cursor/rules/, .cursor/settings.json
- **Continue.dev** — .continue/config.yaml
- **Aider** — .aider.conf.yml, .aider*

## Security Checks

- API key and token detection (masked in output)
- Dangerous MCP server commands (curl|sh, rm, sudo)
- Unrestricted permission settings
- Disabled sandbox/approval modes

## Development

```bash
make test    # run tests
make lint    # run golangci-lint
make bench   # run benchmarks
```
