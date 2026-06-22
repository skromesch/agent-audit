# Design: OpenCode and Pi Scanners

**Date:** 2026-06-22  
**Status:** Approved

## Goal

Add two new agent scanners to agent-audit: one for [opencode](https://opencode.ai) and one for [Pi](https://pi.dev). Both follow the existing `Scanner` interface pattern — no architectural changes required.

## Scope

- `internal/scanner/opencode.go` + `opencode_test.go`
- `internal/scanner/pi.go` + `pi_test.go`
- `internal/fixtures/sample-project/` — three new fixture files
- `internal/scanner/integration_test.go` — extend `wantTools` and `buildOrchestrator`
- `cmd/agent-audit/main.go` — two new lines in the orchestrator slice

All other packages (model, rules, report, tui) remain untouched.

## OpenCodeScanner

### Config files

| Path | Scope |
|------|-------|
| `<root>/opencode.json` | project |
| `~/.config/opencode/opencode.json` | global |

Format: JSON (opencode also supports JSONC but the scanner reads raw content for secret scanning, so comments are harmless).

### Detection

`AgentConfig` is emitted if at least one of the above paths exists.

### Settings extracted

| JSON key | `Settings` map key |
|----------|--------------------|
| `model` (string) | `"model"` |
| `permission` (object) | stringified as `"permission"` — used only for permission rule matching, not stored verbatim |

### Security checks

- `rules.ScanForSecrets(path, content)` on every found file
- `rules.CheckPermissions("OpenCode", path, content)` on every found file

### Fixture

`internal/fixtures/sample-project/opencode.json`:
```json
{
  "model": "anthropic/claude-sonnet-4-5",
  "permission": {
    "bash": "allow",
    "write": "ask"
  }
}
```

## PiScanner

### Config files

| Path | Scope | Pi-specific? |
|------|-------|-------------|
| `<root>/AGENTS.md` | project | No (shared with Codex) |
| `<root>/SYSTEM.md` | project | Yes |
| `<root>/models.json` | project | Yes |
| `~/.pi/agent/` | global | Yes |

### Detection

`AgentConfig` is emitted **only if at least one Pi-specific file is present** (`SYSTEM.md`, `models.json`, or `~/.pi/agent/` directory). This avoids false positives on pure Codex projects that only have `AGENTS.md`.

`AGENTS.md` is included in `ConfigFiles` when found, regardless of whether it triggered detection.

### Settings extracted

From `models.json` (if present): top-level string keys are stored as-is in the `Settings` map (e.g. `"default"` → model name).

### Security checks

- `rules.ScanForSecrets(path, content)` on every found file

### Fixtures

`internal/fixtures/sample-project/SYSTEM.md`:
```markdown
You are a helpful coding assistant. Always write tests.
```

`internal/fixtures/sample-project/models.json`:
```json
{
  "default": "anthropic/claude-sonnet-4-5"
}
```

## Integration test changes

`buildOrchestrator()` gains two new entries:
```go
scanner.NewOpenCodeScanner(),
scanner.NewPiScanner(),
```

`wantTools` map gains:
```go
"OpenCode": false,
"Pi":       false,
```

The fixture scan assertion `len(result.Agents) < 4` stays valid (it was already ≥4; now it'll be ≥6).

## What does NOT change

- `model/types.go` — no new fields needed
- `rules/` — existing `ScanForSecrets` and `CheckPermissions` reused as-is
- `report/` — reports iterate over `result.Agents` generically, no changes
- `tui/` — same generic iteration, no changes
- `CodexScanner` — not modified; Codex and Pi independently detect `AGENTS.md` and each produces its own `AgentConfig`
