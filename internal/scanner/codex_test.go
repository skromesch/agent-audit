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

func TestCodexScannerDetectsAuthJSONSecret(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)

	codexDir := filepath.Join(dir, ".codex")
	os.MkdirAll(codexDir, 0755)
	os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(`
[profile.default]
model = "o3"
`), 0644)

	homeCodexDir := filepath.Join(home, ".codex")
	os.MkdirAll(homeCodexDir, 0755)
	os.WriteFile(filepath.Join(homeCodexDir, "auth.json"), []byte(
		`{"OPENAI_API_KEY": "sk-proj-abcdefghijklmnopqrstuvwx"}`), 0644)

	s := scanner.NewCodexScanner()
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
		t.Error("expected secret finding from ~/.codex/auth.json")
	}
}

func TestCodexScannerDetectsProfileTOML(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)

	codexDir := filepath.Join(dir, ".codex")
	os.MkdirAll(codexDir, 0755)
	os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(`
[profile.default]
model = "o3"
`), 0644)

	homeCodexDir := filepath.Join(home, ".codex")
	os.MkdirAll(homeCodexDir, 0755)
	os.WriteFile(filepath.Join(homeCodexDir, "yolo.config.toml"), []byte(`
[profile.yolo]
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
		t.Error("expected permission finding for approval=none in profile TOML")
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
