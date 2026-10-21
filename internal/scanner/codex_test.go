package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/scanner"
)

func TestCodexScannerDetectsConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
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

func TestCodexScannerReadsTopLevelKeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	codexDir := filepath.Join(dir, ".codex")
	os.MkdirAll(codexDir, 0755)
	os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(`
model = "gpt-5-codex" # default model
approval_policy = "never"
sandbox_mode = "danger-full-access"

[profiles.fast]
model = "o4-mini"
`), 0644)

	result, err := scanner.NewCodexScanner().Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"model": "gpt-5-codex", "approval_policy": "never", "sandbox_mode": "danger-full-access"}
	for k, v := range want {
		if got := result.Agent.Settings[k]; got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	var critical, warning int
	for _, f := range result.Findings {
		if f.Category != "permissions" {
			continue
		}
		switch f.Severity {
		case model.SeverityCritical:
			critical++
		case model.SeverityWarning:
			warning++
		}
	}
	if critical != 1 || warning != 1 {
		t.Errorf("got %d critical / %d warning permission findings, want 1/1", critical, warning)
	}
}

func TestCodexScannerReadsProfilesTable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	codexDir := filepath.Join(dir, ".codex")
	os.MkdirAll(codexDir, 0755)
	os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(`
[profiles.fast]
model = "o4-mini"
`), 0644)

	result, err := scanner.NewCodexScanner().Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Agent.Settings["model"]; got != "o4-mini" {
		t.Errorf("model = %q, want %q", got, "o4-mini")
	}
}
