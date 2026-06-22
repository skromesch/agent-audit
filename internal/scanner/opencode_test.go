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
