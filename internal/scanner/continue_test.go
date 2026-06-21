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
