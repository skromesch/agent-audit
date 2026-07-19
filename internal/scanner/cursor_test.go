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

func TestCursorScannerDetectsLegacyCursorrules(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".cursorrules"), []byte(
		"GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"), 0644)

	s := scanner.NewCursorScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Agent == nil {
		t.Fatal("expected agent from legacy .cursorrules file")
	}
	var secretFindings int
	for _, f := range result.Findings {
		if f.Category == "secrets" {
			secretFindings++
		}
	}
	if secretFindings == 0 {
		t.Error("expected secret finding from .cursorrules")
	}
}
