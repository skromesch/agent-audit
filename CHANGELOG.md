# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.0] - 2026-07-19

### Added

- **`--version` flag** — prints the build version and exits; also shown in the TUI's About tab. Version is injected at release build time via ldflags (falls back to `(dev)` for local builds)
- **Credential file scanning** — `~/.codex/auth.json`, `~/.local/share/opencode/auth.json`, home-directory `.aider.conf.yml`, git-root `.env`, and `.claude/settings.local.json` are now scanned for secrets
- **Claude Code subagents and hooks** — `.claude/agents/` and `~/.claude/agents/` subagent files are scanned for secrets and permissions; hook commands (`settings.json` `hooks` key) are checked against the same dangerous-command rules as MCP servers
- **Gemini CLI project settings** — `.gemini/settings.json` (project level) is now scanned, not just the global settings file
- **Cursor legacy rules** — root-level `.cursorrules` is scanned even when no `.cursor/` directory exists
- **Codex profile configs** — `~/.codex/*.config.toml` per-profile overrides are scanned alongside the main config
- **OpenCode `.jsonc` support** — `opencode.jsonc` / `~/.config/opencode/opencode.jsonc` are recognized alongside `.json`

### Fixed

- **Wildcard permission detection** — the `"allow": ["*"]` check used substring matching that missed pretty-printed JSON (the common case for hand-edited or tool-generated `settings.json` files); now does a real JSON parse
- **Continue.dev MCP servers were never detected** — the scanner looked for a `.continue/mcp.json` file that doesn't exist in practice; Continue.dev defines MCP servers inside `config.yaml`'s `mcpServers` block, which is now parsed
- **Pi settings not read** — `~/.pi/agent/settings.json` and `.pi/settings.json` were only checked for existence, not scanned for secrets (custom model providers can embed API keys directly)
- **Aider home-directory config skipped** — `.aider.conf.yml` in the home directory was never scanned, only the project directory

---

## [1.1.0] - 2026-06-22

### Added

- **Gemini CLI scanner** — detects `GEMINI.md` (project level) and `~/.gemini/settings.json` (global); extracts model setting, scans for secrets and permission misconfigurations
- **Gemini CLI MCP support** — `~/.gemini/settings.json` added to MCP scan locations so Gemini-configured MCP servers appear in the MCP tab

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

[1.2.0]: https://github.com/skromesch/agent-audit/releases/tag/v1.2.0
[1.1.0]: https://github.com/skromesch/agent-audit/releases/tag/v1.1.0
[1.0.0]: https://github.com/skromesch/agent-audit/releases/tag/v1.0.0
