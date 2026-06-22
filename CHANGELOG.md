# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-06-22

### Added

- **OpenCode scanner** — detects `opencode.json` (project and global `~/.config/opencode/`), extracts model setting, scans for secrets and permission misconfigurations
- **Pi scanner** — detects `SYSTEM.md`, `models.json`, and `~/.pi/agent/`; includes `AGENTS.md` when present; avoids false positives on Codex-only projects
- **Scrollable Overview tab** — `↑`/`↓` (or `j`/`k`) scroll through agents when content exceeds terminal height
- **Claude Code scanner** — `CLAUDE.md`, `.claude/settings.json`, `.claude/skills/`, `.mcp.json`, `~/.claude/settings.json`
- **Codex scanner** — `AGENTS.md`, `.codex/config.toml`, `~/.codex/config.toml`; parses model and approval settings
- **Cursor scanner** — `.cursor/rules/`, `.cursor/settings.json`
- **Continue.dev scanner** — `.continue/config.yaml`
- **Aider scanner** — `.aider.conf.yml` and all `.aider*` files; parses model setting
- **MCP scanner** — discovers MCP server definitions across all agent config locations; masks secrets in env vars
- **Skills scanner** — finds and validates skill packages under `skills/` and `.claude/skills/`
- **Security rules** — secret detection (OpenAI, Anthropic, GitHub, generic patterns), dangerous MCP command detection, permission misconfiguration checks
- **Interactive TUI** — tabbed Bubble Tea interface with Overview, MCP, Skills, Security, and About tabs
- **Report modes** — `--json`, `--markdown`, `--html` flags write structured reports to disk
- **CI-friendly** — auto-falls back to JSON output when stdin is not a TTY
- **Cross-platform** — Linux, macOS, Windows

[1.0.0]: https://github.com/skromesch/agent-audit/releases/tag/v1.0.0
