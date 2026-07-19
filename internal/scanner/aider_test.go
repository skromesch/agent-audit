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

func TestAiderScannerDetectsHomeConfigSecret(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)

	os.WriteFile(filepath.Join(home, ".aider.conf.yml"), []byte(
		"OPENAI_API_KEY: sk-proj-abcdefghijklmnopqrstuvwx\n"), 0644)

	s := scanner.NewAiderScanner()
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
		t.Error("expected secret finding from ~/.aider.conf.yml")
	}
}

func TestAiderScannerDetectsRootEnvSecret(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", t.TempDir())

	os.WriteFile(filepath.Join(dir, ".env"), []byte(
		"OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwx\n"), 0644)

	s := scanner.NewAiderScanner()
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
		t.Error("expected secret finding from .env")
	}
}
