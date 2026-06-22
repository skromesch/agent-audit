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
	if home, err := os.UserHomeDir(); err == nil {
		if _, err := os.Stat(filepath.Join(home, ".pi", "agent")); err == nil {
			t.Skip("skipping: ~/.pi/agent exists on this machine")
		}
	}

	dir := t.TempDir()
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
		"ANTHROPIC_API_KEY": "sk-ant-api03-secretkey1234567890abcdef"
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
