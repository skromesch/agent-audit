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
		"env": "ANTHROPIC_API_KEY=sk-ant-api03-realkey123456789abcdef"
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
