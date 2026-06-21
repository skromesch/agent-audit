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
