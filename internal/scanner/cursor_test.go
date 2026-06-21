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
