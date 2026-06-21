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
