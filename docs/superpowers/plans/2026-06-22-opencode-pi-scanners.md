# OpenCode and Pi Scanners Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add OpenCode and Pi scanners to agent-audit, following the existing Scanner interface pattern.

**Architecture:** Each new scanner is a self-contained Go file implementing `scanner.Scanner`. The OpenCode scanner reads `opencode.json` (project + global). The Pi scanner reads `SYSTEM.md`, `models.json`, and `AGENTS.md` (project), plus `~/.pi/agent/` (global); it only emits an `AgentConfig` when at least one Pi-specific file is present to avoid false positives on Codex projects. Both scanners are registered in the orchestrator and covered by integration tests with new fixture files.

**Tech Stack:** Go 1.22+, `encoding/json` (stdlib), existing `rules` and `model` packages.

## Global Constraints

- Module path: `github.com/skromesch/agent-audit`
- Use `filepath.Join` everywhere — no hardcoded `/`
- Secret values never displayed in full (masking handled by `rules.MaskSecret`)
- Severity constants: `"INFO"`, `"WARNING"`, `"CRITICAL"`
- Test coverage target: >80%; all tests pass with `go test ./...`
- Scanner interface must stay stable — new agents added by implementing `Scanner` only
- Match the existing external test package style: `package scanner_test`

---

## File Map

```
internal/scanner/opencode.go              OpenCode scanner (new)
internal/scanner/opencode_test.go         OpenCode scanner tests (new)
internal/scanner/pi.go                    Pi scanner (new)
internal/scanner/pi_test.go               Pi scanner tests (new)
internal/fixtures/sample-project/opencode.json   OpenCode fixture (new)
internal/fixtures/sample-project/SYSTEM.md       Pi fixture (new)
internal/fixtures/sample-project/models.json     Pi fixture (new)
internal/scanner/integration_test.go      Add 2 scanners + 2 tool assertions (modify)
cmd/agent-audit/main.go                   Register 2 new scanners (modify)
```

---

### Task 1: OpenCode Scanner

**Files:**
- Create: `internal/scanner/opencode.go`
- Create: `internal/scanner/opencode_test.go`
- Create: `internal/fixtures/sample-project/opencode.json`

**Interfaces:**
- Consumes: `scanner.Scanner`, `scanner.ScannerResult`, `model.AgentConfig`, `rules.ScanForSecrets`, `rules.CheckPermissions`
- Produces: `scanner.NewOpenCodeScanner() *OpenCodeScanner` — implements `scanner.Scanner`

- [ ] **Step 1: Write the failing tests**

```go
// internal/scanner/opencode_test.go
package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/skromesch/agent-audit/internal/scanner"
)

func TestOpenCodeScannerDetectsProjectConfig(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "opencode.json"), []byte(`{
		"model": "anthropic/claude-sonnet-4-5",
		"permission": {
			"bash": "allow",
			"write": "ask"
		}
	}`), 0644)

	s := scanner.NewOpenCodeScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Agent == nil {
		t.Fatal("expected agent config, got nil")
	}
	if result.Agent.Tool != "OpenCode" {
		t.Errorf("tool = %q, want %q", result.Agent.Tool, "OpenCode")
	}
	if result.Agent.Settings["model"] != "anthropic/claude-sonnet-4-5" {
		t.Errorf("model = %q", result.Agent.Settings["model"])
	}
	if len(result.Files) < 1 {
		t.Error("expected at least 1 config file")
	}
}

func TestOpenCodeScannerNoConfigReturnsNil(t *testing.T) {
	dir := t.TempDir()
	s := scanner.NewOpenCodeScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Agent != nil {
		t.Error("expected nil agent when no config present")
	}
}

func TestOpenCodeScannerDetectsSecrets(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "opencode.json"), []byte(`{
		"provider": {
			"anthropic": {
				"apiKey": "sk-ant-api03-secretkey1234567890abcdef"
			}
		}
	}`), 0644)

	s := scanner.NewOpenCodeScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var secretFindings int
	for _, f := range result.Findings {
		if f.Category == "secrets" {
			secretFindings++
		}
	}
	if secretFindings == 0 {
		t.Error("expected secret finding, got none")
	}
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
go test ./internal/scanner/... -run TestOpenCode 2>&1 | head -5
```

Expected: compile error (`undefined: scanner.NewOpenCodeScanner`)

- [ ] **Step 3: Write `internal/scanner/opencode.go`**

```go
package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

type OpenCodeScanner struct{}

func NewOpenCodeScanner() *OpenCodeScanner { return &OpenCodeScanner{} }

func (s *OpenCodeScanner) Name() string { return "OpenCode" }

func (s *OpenCodeScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}

	candidates := []string{
		filepath.Join(root, "opencode.json"),
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".config", "opencode", "opencode.json"),
		)
	}

	cfg := &model.AgentConfig{Tool: "OpenCode", Settings: map[string]string{}}
	found := false

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		found = true
		result.Files = append(result.Files, path)
		cfg.ConfigFiles = append(cfg.ConfigFiles, path)
		content := string(data)

		result.Findings = append(result.Findings, rules.ScanForSecrets(path, content)...)
		result.Findings = append(result.Findings, rules.CheckPermissions("OpenCode", path, content)...)

		var raw map[string]json.RawMessage
		if json.Unmarshal(data, &raw) == nil {
			if m, ok := raw["model"]; ok {
				var modelVal string
				if json.Unmarshal(m, &modelVal) == nil {
					cfg.Settings["model"] = modelVal
				}
			}
		}
	}

	if found {
		result.Agent = cfg
	}
	return result, nil
}
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
go test ./internal/scanner/... -run TestOpenCode -v
```

Expected: all PASS

- [ ] **Step 5: Create the fixture file**

Create `internal/fixtures/sample-project/opencode.json`:

```json
{
  "model": "anthropic/claude-sonnet-4-5",
  "permission": {
    "bash": "allow",
    "write": "ask"
  }
}
```

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/opencode.go internal/scanner/opencode_test.go \
        internal/fixtures/sample-project/opencode.json
git commit -m "feat: OpenCode scanner"
```

---

### Task 2: Pi Scanner

**Files:**
- Create: `internal/scanner/pi.go`
- Create: `internal/scanner/pi_test.go`
- Create: `internal/fixtures/sample-project/SYSTEM.md`
- Create: `internal/fixtures/sample-project/models.json`

**Interfaces:**
- Consumes: `scanner.Scanner`, `scanner.ScannerResult`, `model.AgentConfig`, `rules.ScanForSecrets`
- Produces: `scanner.NewPiScanner() *PiScanner` — implements `scanner.Scanner`

- [ ] **Step 1: Write the failing tests**

```go
// internal/scanner/pi_test.go
package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/skromesch/agent-audit/internal/scanner"
)

func TestPiScannerDetectsWithSystemMd(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "SYSTEM.md"), []byte("You are a helpful assistant."), 0644)

	s := scanner.NewPiScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Agent == nil {
		t.Fatal("expected agent config when SYSTEM.md present")
	}
	if result.Agent.Tool != "Pi" {
		t.Errorf("tool = %q, want %q", result.Agent.Tool, "Pi")
	}
}

func TestPiScannerDetectsWithModelsJson(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "models.json"), []byte(`{
		"default": "anthropic/claude-sonnet-4-5"
	}`), 0644)

	s := scanner.NewPiScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Agent == nil {
		t.Fatal("expected agent config when models.json present")
	}
	if result.Agent.Settings["default"] != "anthropic/claude-sonnet-4-5" {
		t.Errorf("default model = %q", result.Agent.Settings["default"])
	}
}

func TestPiScannerIncludesAgentsMd(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "SYSTEM.md"), []byte("Custom system prompt."), 0644)
	os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte("# Pi instructions"), 0644)

	s := scanner.NewPiScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Agent == nil {
		t.Fatal("expected agent config")
	}
	var hasAgentsMd bool
	for _, f := range result.Agent.ConfigFiles {
		if filepath.Base(f) == "AGENTS.md" {
			hasAgentsMd = true
		}
	}
	if !hasAgentsMd {
		t.Error("expected AGENTS.md in config files")
	}
}

func TestPiScannerNoFalsePositiveOnAgentsMdAlone(t *testing.T) {
	dir := t.TempDir()
	// Only AGENTS.md — no Pi-specific files
	os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte("# Codex instructions"), 0644)

	s := scanner.NewPiScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Agent != nil {
		t.Error("expected nil agent when only AGENTS.md present (no Pi-specific files)")
	}
}

func TestPiScannerDetectsSecrets(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "SYSTEM.md"), []byte("prompt"), 0644)
	os.WriteFile(filepath.Join(dir, "models.json"), []byte(`{
		"apiKey": "sk-ant-api03-secretkey1234567890abcdef"
	}`), 0644)

	s := scanner.NewPiScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var secretFindings int
	for _, f := range result.Findings {
		if f.Category == "secrets" {
			secretFindings++
		}
	}
	if secretFindings == 0 {
		t.Error("expected secret finding in models.json")
	}
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
go test ./internal/scanner/... -run TestPiScanner 2>&1 | head -5
```

Expected: compile error (`undefined: scanner.NewPiScanner`)

- [ ] **Step 3: Write `internal/scanner/pi.go`**

```go
package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

type PiScanner struct{}

func NewPiScanner() *PiScanner { return &PiScanner{} }

func (s *PiScanner) Name() string { return "Pi" }

func (s *PiScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}

	// Pi-specific files — presence of any one confirms this is a Pi project.
	piSpecific := []string{
		filepath.Join(root, "SYSTEM.md"),
		filepath.Join(root, "models.json"),
	}

	// AGENTS.md is shared with Codex; include it but don't use it for detection.
	agentsMd := filepath.Join(root, "AGENTS.md")

	// Global Pi directory also counts as a Pi-specific marker.
	globalPiDir := ""
	if home, err := os.UserHomeDir(); err == nil {
		globalPiDir = filepath.Join(home, ".pi", "agent")
	}

	cfg := &model.AgentConfig{Tool: "Pi", Settings: map[string]string{}}
	piDetected := false

	// Check Pi-specific project files.
	for _, path := range piSpecific {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		piDetected = true
		result.Files = append(result.Files, path)
		cfg.ConfigFiles = append(cfg.ConfigFiles, path)
		content := string(data)

		result.Findings = append(result.Findings, rules.ScanForSecrets(path, content)...)

		if filepath.Base(path) == "models.json" {
			var raw map[string]json.RawMessage
			if json.Unmarshal(data, &raw) == nil {
				for k, v := range raw {
					var strVal string
					if json.Unmarshal(v, &strVal) == nil {
						cfg.Settings[k] = strVal
					}
				}
			}
		}
	}

	// Check global ~/.pi/agent/ directory.
	if globalPiDir != "" {
		if info, err := os.Stat(globalPiDir); err == nil && info.IsDir() {
			piDetected = true
		}
	}

	if !piDetected {
		return result, nil
	}

	// Include AGENTS.md in config files if present.
	if data, err := os.ReadFile(agentsMd); err == nil {
		result.Files = append(result.Files, agentsMd)
		cfg.ConfigFiles = append(cfg.ConfigFiles, agentsMd)
		result.Findings = append(result.Findings, rules.ScanForSecrets(agentsMd, string(data))...)
	}

	result.Agent = cfg
	return result, nil
}
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
go test ./internal/scanner/... -run TestPiScanner -v
```

Expected: all PASS

- [ ] **Step 5: Create the fixture files**

Create `internal/fixtures/sample-project/SYSTEM.md`:

```markdown
You are a helpful coding assistant. Always write tests.
```

Create `internal/fixtures/sample-project/models.json`:

```json
{
  "default": "anthropic/claude-sonnet-4-5"
}
```

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/pi.go internal/scanner/pi_test.go \
        internal/fixtures/sample-project/SYSTEM.md \
        internal/fixtures/sample-project/models.json
git commit -m "feat: Pi scanner"
```

---

### Task 3: Wire Up and Integration Tests

**Files:**
- Modify: `cmd/agent-audit/main.go`
- Modify: `internal/scanner/integration_test.go`

**Interfaces:**
- Consumes: `scanner.NewOpenCodeScanner()`, `scanner.NewPiScanner()` (from Tasks 1 and 2)
- Produces: working end-to-end scan that detects OpenCode and Pi in the fixture directory

- [ ] **Step 1: Add the two new scanners to `cmd/agent-audit/main.go`**

The current orchestrator slice (lines 36–44) reads:

```go
orch := scanner.NewOrchestrator([]scanner.Scanner{
    scanner.NewClaudeScanner(),
    scanner.NewCodexScanner(),
    scanner.NewCursorScanner(),
    scanner.NewContinueScanner(),
    scanner.NewAiderScanner(),
    scanner.NewMCPScanner(),
    scanner.NewSkillsScanner(),
})
```

Replace it with:

```go
orch := scanner.NewOrchestrator([]scanner.Scanner{
    scanner.NewClaudeScanner(),
    scanner.NewCodexScanner(),
    scanner.NewCursorScanner(),
    scanner.NewContinueScanner(),
    scanner.NewAiderScanner(),
    scanner.NewMCPScanner(),
    scanner.NewSkillsScanner(),
    scanner.NewOpenCodeScanner(),
    scanner.NewPiScanner(),
})
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./cmd/agent-audit/...
```

Expected: exit 0, no errors

- [ ] **Step 3: Update `buildOrchestrator()` in `internal/scanner/integration_test.go`**

The current function (lines 18–28) reads:

```go
func buildOrchestrator() *scanner.Orchestrator {
    return scanner.NewOrchestrator([]scanner.Scanner{
        scanner.NewClaudeScanner(),
        scanner.NewCodexScanner(),
        scanner.NewCursorScanner(),
        scanner.NewContinueScanner(),
        scanner.NewAiderScanner(),
        scanner.NewMCPScanner(),
        scanner.NewSkillsScanner(),
    })
}
```

Replace it with:

```go
func buildOrchestrator() *scanner.Orchestrator {
    return scanner.NewOrchestrator([]scanner.Scanner{
        scanner.NewClaudeScanner(),
        scanner.NewCodexScanner(),
        scanner.NewCursorScanner(),
        scanner.NewContinueScanner(),
        scanner.NewAiderScanner(),
        scanner.NewMCPScanner(),
        scanner.NewSkillsScanner(),
        scanner.NewOpenCodeScanner(),
        scanner.NewPiScanner(),
    })
}
```

- [ ] **Step 4: Extend `wantTools` in `TestIntegrationAgentNames`**

The current `wantTools` map (lines 90–96) reads:

```go
wantTools := map[string]bool{
    "Claude Code":  false,
    "Codex":        false,
    "Cursor":       false,
    "Continue.dev": false,
    "Aider":        false,
}
```

Replace it with:

```go
wantTools := map[string]bool{
    "Claude Code":  false,
    "Codex":        false,
    "Cursor":       false,
    "Continue.dev": false,
    "Aider":        false,
    "OpenCode":     false,
    "Pi":           false,
}
```

- [ ] **Step 5: Run the full integration test suite**

```bash
go test ./internal/scanner/... -run TestIntegration -v
```

Expected: `TestIntegrationFixtureScan` and `TestIntegrationAgentNames` both PASS

- [ ] **Step 6: Run the full test suite**

```bash
go test ./...
```

Expected: all tests PASS, no compilation errors

- [ ] **Step 7: Commit**

```bash
git add cmd/agent-audit/main.go internal/scanner/integration_test.go
git commit -m "feat: register OpenCode and Pi scanners in orchestrator"
```

---

## Self-Review

**Spec coverage:**
- OpenCode config files (`opencode.json`, global `~/.config/opencode/opencode.json`) → Task 1 ✓
- OpenCode `model` extraction → Task 1 ✓
- OpenCode secret + permission checks → Task 1 ✓
- Pi detection via `SYSTEM.md`, `models.json`, `~/.pi/agent/` → Task 2 ✓
- Pi no false positive on `AGENTS.md` alone → Task 2 `TestPiScannerNoFalsePositiveOnAgentsMdAlone` ✓
- Pi includes `AGENTS.md` in ConfigFiles when Pi-specific file present → Task 2 ✓
- Pi `models.json` settings extraction → Task 2 ✓
- Fixtures for both agents → Tasks 1 and 2 ✓
- `buildOrchestrator()` updated → Task 3 ✓
- `wantTools` updated for integration test → Task 3 ✓
- `main.go` wired up → Task 3 ✓
- No changes to `model`, `rules`, `report`, `tui` → confirmed ✓

**Placeholder scan:** No TBDs, no "implement later", all steps have exact code.

**Type consistency:**
- `scanner.NewOpenCodeScanner()` defined in Task 1, consumed in Task 3 ✓
- `scanner.NewPiScanner()` defined in Task 2, consumed in Task 3 ✓
- `ScannerResult`, `model.AgentConfig`, `rules.ScanForSecrets`, `rules.CheckPermissions` — all existing, stable types ✓
